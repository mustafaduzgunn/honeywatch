#!/usr/bin/env python3
"""HoneyWatch - multi-port honeypot + web dashboard + printable report. Run as root."""
import os, re, ssl, json, time, base64, socket, sqlite3, secrets, hmac, subprocess, threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import Request, urlopen
try: import paramiko
except ImportError: paramiko = None

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("HW_DATA", BASE + "/data"); os.makedirs(DATA, exist_ok=True)
OFFSET = int(os.environ.get("HW_OFFSET", 0))       # testing only
DASH_PORT = int(os.environ.get("HW_DASH", 9000))
DB = sqlite3.connect(DATA + "/hw.db", check_same_thread=False); L = threading.Lock()
DB.executescript("""CREATE TABLE IF NOT EXISTS ev(id INTEGER PRIMARY KEY,ts INT,proto TEXT,port INT,ip TEXT,user TEXT,pw TEXT,atk TEXT,info TEXT);
CREATE INDEX IF NOT EXISTS i1 ON ev(ts); CREATE INDEX IF NOT EXISTS i2 ON ev(ip);
CREATE TABLE IF NOT EXISTS geo(ip TEXT PRIMARY KEY,cc TEXT,country TEXT,city TEXT,lat REAL,lon REAL,isp TEXT);""")

def log(proto, port, ip, user="", pw="", atk="Scan/Probe", info=""):
    with L:
        DB.execute("INSERT INTO ev(ts,proto,port,ip,user,pw,atk,info) VALUES(?,?,?,?,?,?,?,?)",
                   (int(time.time()), proto, port, ip, user[:100], pw[:100], atk, info[:300])); DB.commit()

def rl(c, n=256):
    b = b""
    while len(b) < n:
        d = c.recv(1)
        if not d: break
        b += d
        if d == b"\n": break
    return re.sub(r"[^\x20-\x7e]", "", b.decode(errors="replace"))

# ---------------- service handlers ----------------
def gen(proto, banner=b""):
    def h(c, ip, port):
        if banner: c.sendall(banner)
        d = c.recv(256)
        log(proto, port, ip, info=d[:80].decode(errors="replace").strip() if d else "connect only")
    return h

def telnet(c, ip, port):
    for i in range(3):
        c.sendall(b"\r\nlogin: "); u = rl(c)
        if not u:
            if i == 0: log("TELNET", port, ip)
            return
        c.sendall(b"Password: "); p = rl(c)
        log("TELNET", port, ip, u, p, "Brute force"); c.sendall(b"\r\nLogin incorrect\r\n")

def ftp(c, ip, port):
    c.sendall(b"220 FTP server ready\r\n"); u = ""
    for _ in range(10):
        l = rl(c)
        if not l: break
        cmd, _, arg = l.partition(" "); cmd = cmd.upper()
        if cmd == "USER": u = arg; c.sendall(b"331 Password required\r\n")
        elif cmd == "PASS": log("FTP", port, ip, u, arg, "Brute force"); c.sendall(b"530 Login incorrect\r\n")
        elif cmd == "QUIT": c.sendall(b"221 Bye\r\n"); break
        else: c.sendall(b"530 Please login with USER and PASS\r\n")
    if not u: log("FTP", port, ip)

def rn(c, n):
    b = b""
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x: raise EOFError
        b += x
    return b

def rpdu(c):
    h = rn(c, 4)
    if h[0] != 3: raise EOFError
    return rn(c, int.from_bytes(h[2:4], "big") - 4)

def tpkt(c, p): c.sendall(b"\x03\x00" + (len(p) + 4).to_bytes(2, "big") + p)
def per_len(n): return bytes([n]) if n <= 0x7f else bytes([0x80 | (n >> 8), n & 255])
def ber_len(n): return bytes([n]) if n <= 0x7f else bytes([0x82]) + n.to_bytes(2, "big")
def ber_int(v):
    nb = 1 if v <= 0xff else 2 if v <= 0xffff else 4
    return bytes([0x02, nb]) + v.to_bytes(nb, "big")
def gcc_block(t, content): return t.to_bytes(2, "little") + (4 + len(content)).to_bytes(2, "little") + content

def mcs_connect_response(channel_ids):
    core = (0x00080004).to_bytes(4, "little") + bytes(8)                               # rdpVersion 5+, requestedProtocol=0, earlyCapFlags=0
    sec = bytes(8)                                                                      # encryptionMethod=0, encryptionLevel=0 (TLS carries security)
    n = len(channel_ids)
    net = ((1003).to_bytes(2, "little") + n.to_bytes(2, "little")
           + b"".join(c.to_bytes(2, "little") for c in channel_ids) + (b"\0\0" if n % 2 else b""))
    data = gcc_block(0x0C01, core) + gcc_block(0x0C02, sec) + gcc_block(0x0C03, net)
    gcc = (b"\x00" + bytes.fromhex("0500147c0001") + per_len(len(data) + 14) + b"\x14"
           + (0x79F3 - 1001).to_bytes(2, "big") + b"\x01\x01\x00\x01\xc0\x00" + b"McDn" + per_len(len(data)) + data)
    dp = b"".join(ber_int(v) for v in (22, 3, 0, 1, 0, 1, 0xfff8, 2))
    tmp = bytes([0x0a, 0x01, 0x00]) + ber_int(0) + b"\x30" + ber_len(len(dp)) + dp + b"\x04" + ber_len(len(gcc)) + gcc
    return b"\x7f\x66" + ber_len(len(tmp)) + tmp

def rdp(c, ip, port):   # RDP over TLS (non-NLA): completes MCS/GCC so the client reaches the login prompt, then captures the Client Info PDU (domain\\user + password)
    d = c.recv(1024); m = re.search(rb"mstshash=([^\r\n]*)", d or b""); ck = m[1].decode(errors="replace") if m else ""; got = False
    try:
        neg = d[-8:] if d and len(d) >= 8 and d[-8] == 1 and d[-6:-4] == b"\x08\x00" else b""
        proto = int.from_bytes(neg[4:8], "little") if neg else 0
        sel = 1 if proto & 1 else 0                                                     # offer TLS if supported, else plain legacy security
        c.sendall(bytes.fromhex("03000013" "0ed000001234" "00" "02000800") + sel.to_bytes(4, "little"))
        if sel: c = TLS.wrap_socket(c, server_side=True)
        ci = rpdu(c)                                                                    # Connect Initial -- count requested channels to size our response
        i = ci.find(b"\x03\xc0"); n = int.from_bytes(ci[i + 4:i + 8], "little") if i >= 0 else 0; n = n if 0 <= n < 31 else 0
        tpkt(c, b"\x02\xf0\x80" + mcs_connect_response(list(range(1004, 1004 + n))))
        for _ in range(40):
            q = rpdu(c)[3:]; k = q[0] >> 2
            if k == 10: tpkt(c, b"\x02\xf0\x80\x2e\x00\x00\x01")                                     # Attach User Confirm
            elif k == 14: tpkt(c, b"\x02\xf0\x80\x3e\x00" + q[1:3] + q[3:5] + q[3:5])                # Channel Join Confirm
            elif k == 25:                                                                          # Send Data Request
                pos = 6; pos += 2 if q[pos] & 0x80 else 1; pl = q[pos:]
                if len(pl) > 22 and int.from_bytes(pl[:2], "little") & 0x40:                       # SEC_INFO_PKT (Client Info PDU)
                    inf = pl[4:]; cd, cu, cw = (int.from_bytes(inf[8 + 2 * j:10 + 2 * j], "little") for j in range(3)); o = 18
                    dom = inf[o:o + cd].decode("utf-16le", "replace"); o += cd + 2
                    usr = inf[o:o + cu].decode("utf-16le", "replace"); o += cu + 2
                    pw = inf[o:o + cw].decode("utf-16le", "replace"); got = True
                    log("RDP", port, ip, ((dom + "\\") if dom else "") + (usr or ck), pw, "Brute force" if (usr or pw or ck) else "Scan/Probe", "RDP login attempt")
                    return
    except Exception: pass
    finally:
        if not got: log("RDP", port, ip, ck, "", "Brute force" if ck else "Scan/Probe", "RDP login attempt (username only)" if ck else "RDP probe")

if paramiko:
    kp = DATA + "/ssh_host_key"
    if os.path.exists(kp): HK = paramiko.RSAKey(filename=kp)
    else: HK = paramiko.RSAKey.generate(2048); HK.write_private_key_file(kp)
    class SS(paramiko.ServerInterface):
        def __init__(s, ip, port): s.ip, s.port, s.tried = ip, port, False
        def check_auth_password(s, u, p): s.tried = True; log("SSH", s.port, s.ip, u, p, "Brute force"); return paramiko.AUTH_FAILED
        def check_auth_publickey(s, u, k): s.tried = True; log("SSH", s.port, s.ip, u, "", "Brute force", "public key attempt"); return paramiko.AUTH_FAILED
        def get_allowed_auths(s, u): return "password,publickey"
    def ssh(c, ip, port):
        t = paramiko.Transport(c); t.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"; t.add_server_key(HK); s = SS(ip, port)
        try: t.start_server(server=s); t.accept(20)
        except Exception: pass
        finally:
            t.close()
            if not s.tried: log("SSH", port, ip, info="no auth attempt")
else:
    ssh = gen("SSH", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")

SIG = [("SQL injection", r"union\s+select|select.+from|'\s*or\s*'?1|sleep\(|information_schema"),
       ("XSS", r"<script|onerror=|javascript:"),
       ("Path traversal", r"\.\./|%2e%2e|/etc/passwd|win\.ini"),
       ("Command injection / RCE", r"\$\{jndi|;\s*(cat|wget|curl|sh|bash)\b|\|\s*(sh|bash)|/bin/sh|eval\(|base64_decode|cmd="),
       ("Sensitive file probe", r"\.env|\.git|wp-config|\.aws|id_rsa|\.bak|\.sql"),
       ("Admin panel probe", r"phpmyadmin|wp-login|wp-admin|/admin|manager/html|cgi-bin|boaform|actuator|solr"),
       ("Scanner", r"nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|censys|shodan")]
def classify(t):
    for n, r in SIG:
        if re.search(r, t, re.I): return n
    return "Web request"

PAGE = b"<html><head><title>Admin Login</title></head><body><h2>Administration</h2><form method=post><input name=username placeholder=Username><input name=password type=password placeholder=Password><button>Login</button></form></body></html>"
def http(c, ip, port):
    proto = "HTTPS" if isinstance(c, ssl.SSLSocket) else "HTTP"
    d = b""
    while b"\r\n\r\n" not in d and len(d) < 8192:
        x = c.recv(4096)
        if not x: break
        d += x
    if not d: return log(proto, port, ip, info="connect only")
    head, _, body = d.partition(b"\r\n\r\n"); h = head.decode(errors="replace"); first = h.split("\r\n")[0]
    m = re.search(r"content-length:\s*(\d+)", h, re.I)
    if m:
        n = min(int(m[1]), 4096)
        while len(body) < n:
            x = c.recv(4096)
            if not x: break
            body += x
    b = body.decode(errors="replace"); ua = (re.search(r"user-agent:\s*(.*)", h, re.I) or [0, ""])[1]
    q = parse_qs(b); g = lambda ks: next((q[k][0] for k in ks if k in q), "")
    u, p = g(("log", "username", "user", "email", "login")), g(("pwd", "password", "pass"))
    a = re.search(r"authorization:\s*basic\s+(\S+)", h, re.I)
    if a:
        try: u, _, p = base64.b64decode(a[1]).decode(errors="replace").partition(":")
        except Exception: pass
    atk = "Brute force" if (u or p) else classify(unquote(first) + " " + b + " " + ua)
    log(proto, port, ip, u, p, atk, first[:150] + " | UA: " + ua[:80])
    c.sendall(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(PAGE) + PAGE)

def icmp():
    try: s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except Exception as e: return print("ICMP disabled:", e)
    print("listening ICMP"); last = {}
    while True:
        p, a = s.recvfrom(2048); i = (p[0] & 15) * 4
        if len(p) > i and p[i] == 8 and time.time() - last.get(a[0], 0) > 5:
            last[a[0]] = time.time(); log("ICMP", 0, a[0], atk="Ping", info="Echo request")

SVC = {21: ftp, 22: ssh, 23: telnet, 25: gen("SMTP", b"220 mail.example.com ESMTP Postfix\r\n"), 80: http, 443: http,
       445: gen("SMB"), 1433: gen("MSSQL"), 3306: gen("MYSQL"), 3389: rdp, 5432: gen("POSTGRES"),
       5900: gen("VNC", b"RFB 003.008\n"), 6379: gen("REDIS"), 8080: http, 8443: http}
TLSP = {443, 8443}
NAME = {21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 445: "SMB", 1433: "MSSQL", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES", 5900: "VNC", 6379: "REDIS"}

def tlsctx():
    c, k = DATA + "/cert.pem", DATA + "/key.pem"
    if not os.path.exists(c):
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-keyout", k, "-out", c, "-days", "3650", "-subj", "/CN=localhost"], check=True, capture_output=True)
    x = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); x.load_cert_chain(c, k); return x

def conn(c, ip, port, h, tls):
    c.settimeout(15)
    try:
        if tls:
            try: c = tls.wrap_socket(c, server_side=True)
            except Exception: return log("HTTPS", port, ip, info="TLS handshake failed")
        h(c, ip, port)
    except Exception: pass
    finally:
        try: c.close()
        except Exception: pass

def listen(port, h, tls):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind(("0.0.0.0", port + OFFSET)); s.listen(128)
    except OSError as e: return print(f"SKIP port {port}: {e}  (already in use? move the real service first)")
    print("listening", port)
    def run():
        while True:
            c, a = s.accept(); threading.Thread(target=conn, args=(c, a[0], port, h, tls), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()

def geo_worker():
    while True:
        time.sleep(5)
        with L: ips = [r[0] for r in DB.execute("SELECT DISTINCT ip FROM ev WHERE ip NOT IN (SELECT ip FROM geo) LIMIT 100")]
        if not ips: continue
        try:
            r = urlopen(Request("http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,isp", json.dumps(ips).encode(), {"Content-Type": "application/json"}), timeout=15)
            res = {x["query"]: x for x in json.load(r)}
        except Exception: time.sleep(60); continue
        with L:
            for ip in ips:
                x = res.get(ip, {})
                row = (ip, x["countryCode"], x["country"], x["city"], x["lat"], x["lon"], x["isp"]) if x.get("status") == "success" else (ip, "??", "Unknown/Private", "", 0, 0, "")
                DB.execute("INSERT OR REPLACE INTO geo VALUES(?,?,?,?,?,?,?)", row)
            DB.commit()

TLS = None
SRV = [float(os.environ["HW_LAT"]), float(os.environ["HW_LON"])] if "HW_LAT" in os.environ else None   # optional manual server location
def srv_loc():
    global SRV
    while not SRV:
        try:
            x = json.load(urlopen("http://ip-api.com/json/?fields=status,lat,lon", timeout=10))
            if x.get("status") == "success": SRV = [x["lat"], x["lon"]]
        except Exception: pass
        if not SRV: time.sleep(30)

def live():
    with L:
        r = DB.execute("SELECT e.id,e.proto,e.atk,e.user,e.ip,g.lat,g.lon,g.country FROM ev e JOIN geo g ON g.ip=e.ip WHERE e.ts>=? AND g.cc!='??' ORDER BY e.id DESC LIMIT 60", (int(time.time()) - 90,)).fetchall()
    return {"srv": SRV, "ev": r}

def events(q):
    conds, params = ["1=1"], []
    r = q.get("r", ["0"])[0]
    if r and r != "0":
        conds.append("e.ts>=?"); params.append(int(time.time()) - int(r))
    for col, field in (("ip", "e.ip"), ("user", "e.user"), ("pw", "e.pw"), ("country", "COALESCE(g.country,'')")):
        v = q.get(col, [""])[0].strip()
        if v: conds.append(f"{field} LIKE ? ESCAPE '\\'"); params.append("%" + v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    for col, field in (("atk", "e.atk"), ("proto", "e.proto")):
        v = q.get(col, [""])[0].strip()
        if v: conds.append(f"{field}=?"); params.append(v)
    where = " AND ".join(conds)
    limit = max(1, min(int(q.get("limit", ["100"])[0]), 3000)); offset = max(0, int(q.get("offset", ["0"])[0]))
    with L:
        total = DB.execute(f"SELECT COUNT(*) FROM ev e LEFT JOIN geo g ON g.ip=e.ip WHERE {where}", params).fetchone()[0]
        rows = DB.execute(f"SELECT e.ts,e.proto,e.port,e.ip,e.user,e.pw,e.atk,e.info,COALESCE(g.country,'') FROM ev e LEFT JOIN geo g ON g.ip=e.ip WHERE {where} ORDER BY e.id DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
        atks = [x[0] for x in DB.execute("SELECT DISTINCT atk FROM ev ORDER BY 1")]
        protos = [x[0] for x in DB.execute("SELECT DISTINCT proto FROM ev ORDER BY 1")]
    return {"total": total, "limit": limit, "offset": offset, "rows": rows, "atk_opts": atks, "proto_opts": protos}

# ---------------- dashboard ----------------
def stats(rng):
    t = int(time.time()) - rng if rng else 0
    bs = 60 if 0 < rng <= 3600 else 3600 if 0 < rng <= 172800 else 86400
    q = lambda s: DB.execute(s, (t,)).fetchall()
    W = " FROM ev WHERE ts>=?"; J = " FROM ev e LEFT JOIN geo g ON g.ip=e.ip WHERE e.ts>=?"
    with L:
        return {"total": q("SELECT COUNT(*)" + W)[0][0], "ips": q("SELECT COUNT(DISTINCT ip)" + W)[0][0],
                "logins": q("SELECT COUNT(*)" + W + " AND atk='Brute force'")[0][0],
                "countries": q("SELECT COUNT(DISTINCT g.cc)" + J + " AND g.cc!='??'")[0][0],
                "timeline": q(f"SELECT ts/{bs}*{bs},COUNT(*)" + W + " GROUP BY 1 ORDER BY 1"),
                "proto": q("SELECT proto,COUNT(*)" + W + " GROUP BY 1 ORDER BY 2 DESC"),
                "atk": q("SELECT atk,COUNT(*)" + W + " GROUP BY 1 ORDER BY 2 DESC"),
                "users": q("SELECT user,COUNT(*)" + W + " AND user!='' GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
                "pws": q("SELECT pw,COUNT(*)" + W + " AND pw!='' GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
                "cty": q("SELECT COALESCE(g.country,'Resolving...'),COUNT(*)" + J + " GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
                "top": q("SELECT e.ip,COUNT(*),COALESCE(g.country,'Resolving...'),COALESCE(g.city,''),COALESCE(g.isp,'')" + J + " GROUP BY e.ip ORDER BY 2 DESC LIMIT 15"),
                "map": q("SELECT e.ip,COUNT(*),g.lat,g.lon,g.country,g.city" + J + " AND g.cc!='??' GROUP BY e.ip ORDER BY 2 DESC LIMIT 500"),
                "recent": q("SELECT e.ts,e.proto,e.port,e.ip,e.user,e.pw,e.atk,e.info,COALESCE(g.country,'')" + J + " ORDER BY e.id DESC LIMIT 50")}

INDEX = r"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>HoneyWatch</title>
<link rel=stylesheet href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script><script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>body{margin:0;font:14px system-ui;background:#0d1117;color:#e6edf3}main{max-width:1300px;margin:auto;padding:16px}
.g{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));margin-bottom:12px}.k{grid-template-columns:repeat(4,1fr)}
.c{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;overflow:auto}h1{margin:0}h3{margin:0 0 8px;font-size:14px;color:#9aa4b2}
.n{font-size:30px;font-weight:700;color:#4cc9f0}table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:4px 6px;border-bottom:1px solid #30363d;text-align:left;overflow-wrap:anywhere}
#map{height:380px;border-radius:6px}select,button{background:#21262d;color:#e6edf3;border:1px solid #30363d;padding:6px 10px;border-radius:6px;cursor:pointer}
.rep .ctl,.rep .live{display:none}#tick{position:absolute;left:10px;bottom:10px;z-index:1000;pointer-events:none;font-size:12px;background:#0d1117cc;padding:6px 8px;border-radius:6px;max-width:70%}#tick:empty{display:none}.pr{display:none}.rep .pr{display:inline-block}canvas{max-height:240px}.fr{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}.fr input,.fr select{background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:5px;padding:5px 7px;font-size:12px}.fr input{width:110px}.pg{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12px;color:#9aa4b2}.pg button{padding:4px 10px}.pg button:disabled{opacity:.4;cursor:default}
@media print{body{background:#fff;color:#000}.c{background:#fff;border-color:#ccc;overflow:visible!important}.pr,.ctl{display:none!important}.n{color:#06c}h3{color:#444}
.g,.k{display:block!important}.g>div,.k>div{margin-bottom:12px;width:100%!important}canvas{max-width:100%!important}
table{font-size:11px}#map{height:320px!important}
.c{break-inside:avoid;page-break-inside:avoid}.c.wide{break-inside:auto;page-break-inside:auto}
tr{break-inside:avoid;page-break-inside:avoid}h3{break-after:avoid;page-break-after:avoid}}
.rep .pg button{display:none}</style></head>
<body><main><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><h1 id=ttl>HoneyWatch</h1>
<div class=ctl><select id=r onchange="location.search='?r='+this.value"><option value=3600>Last hour<option value=86400>Last 24 hours<option value=604800>Last 7 days<option value=2592000>Last 30 days<option value=0>All time</select>
<button onclick="location='/report?r='+R">Create report</button></div><button class=pr onclick="fit();setTimeout(print,80)">Print / Save as PDF</button></div>
<div class=c id=sum style="display:none;margin-bottom:12px"></div>
<div class="g k"><div class=c><h3>Total events</h3><div class=n id=t></div></div><div class=c><h3>Unique attacker IPs</h3><div class=n id=i></div></div>
<div class=c><h3>Countries</h3><div class=n id=c></div></div><div class=c><h3>Login attempts</h3><div class=n id=l></div></div></div>
<div class=c style="margin-bottom:12px"><h3>Attack origins (live)</h3><div style="position:relative"><div id=map></div><div id=tick></div></div></div>
<div class=g><div class=c><h3>Events over time</h3><canvas id=tl></canvas></div><div class=c><h3>Targeted services</h3><canvas id=pr></canvas></div><div class=c><h3>Attack types</h3><canvas id=at></canvas></div></div>
<div class=g><div class=c><h3>Top countries</h3><canvas id=co></canvas></div><div class=c><h3>Top usernames tried</h3><table id=us></table></div><div class=c><h3>Top passwords tried</h3><table id=pw></table></div></div>
<div class=c style="margin-bottom:12px"><h3>Top attacker IPs</h3><table id=ip></table></div>
<div class="c live"><h3>Live feed</h3><table id=ev></table></div>
<div class="c wide"><h3>All events</h3>
<div class=fr>
<input id=fip placeholder="IP ice..."><input id=fco placeholder="Ulke..."><input id=fus placeholder="Kullanici..."><input id=fpw placeholder="Sifre...">
<select id=fat><option value="">Tum saldiri tipleri</option></select><select id=fpr><option value="">Tum servisler</option></select>
<button onclick="fe.off=0;loadEv()">Filtrele</button><button onclick="clearF()">Temizle</button>
</div>
<table id=evall></table>
<div class=pg><button id=pgPrev onclick="fe.off=Math.max(0,fe.off-fe.lim);loadEv()">&laquo; Onceki</button><span id=pgInfo></span><button id=pgNext onclick="fe.off+=fe.lim;loadEv()">Sonraki &raquo;</button></div>
</div></main>
<script>
const P=new URLSearchParams(location.search),R=P.get("r")||"86400",rep=location.pathname=="/report";let ch={},layer;
const $=i=>document.getElementById(i),esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
if(rep)document.body.classList.add("rep");$("r").value=R;
const map=L.map("map",{worldCopyJump:true}).setView([25,10],2);L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{attribution:"&copy; OpenStreetMap"}).addTo(map);layer=L.layerGroup().addTo(map);
const COL=["#4cc9f0","#f72585","#b5179e","#7209b7","#4361ee","#f8961e","#90be6d","#43aa8b","#e63946","#8d99ae"];
function chart(id,type,lb,da){if(ch[id]){ch[id].data.labels=lb;ch[id].data.datasets[0].data=da;return ch[id].update()}
ch[id]=new Chart($(id),{type,data:{labels:lb,datasets:[{data:da,backgroundColor:type=="doughnut"?COL:"#4cc9f0",borderColor:"#4cc9f0",tension:.3}]},options:{animation:false,plugins:{legend:{display:type=="doughnut"}}}})}
const tbl=(rows,h)=>"<tr>"+h.map(x=>"<th>"+x+"</th>").join("")+"</tr>"+rows.map(r=>"<tr>"+r.map(x=>"<td>"+esc(x)+"</td>").join("")+"</tr>").join("");
async function load(){const d=await(await fetch("/api/stats?r="+R)).json();
$("t").textContent=d.total;$("i").textContent=d.ips;$("c").textContent=d.countries;$("l").textContent=d.logins;
chart("tl","line",d.timeline.map(x=>new Date(x[0]*1000).toLocaleString([],{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})),d.timeline.map(x=>x[1]));
chart("pr","doughnut",d.proto.map(x=>x[0]),d.proto.map(x=>x[1]));chart("at","doughnut",d.atk.map(x=>x[0]),d.atk.map(x=>x[1]));chart("co","bar",d.cty.map(x=>x[0]),d.cty.map(x=>x[1]));
$("us").innerHTML=tbl(d.users,["Username","Count"]);$("pw").innerHTML=tbl(d.pws,["Password","Count"]);
$("ip").innerHTML=tbl(d.top.map(x=>[x[0],x[1],x[2]+(x[3]?", "+x[3]:""),x[4]]),["IP","Events","Location","ISP"]);
$("ev").innerHTML=tbl(d.recent.map(x=>[new Date(x[0]*1000).toLocaleString(),x[1]+":"+x[2],x[3],x[8],x[4],x[5],x[6]]),["Time","Service","Source IP","Country","User","Password","Type"]);
layer.clearLayers();d.map.forEach(x=>L.circleMarker([x[2],x[3]],{radius:Math.min(5+Math.log2(x[1])*3,26),color:"#f72585",fillOpacity:.5}).bindPopup(esc(x[0]+" - "+x[4]+" "+x[5]+" ("+x[1]+" events)")).addTo(layer));
if(rep){const o=$("r").selectedOptions[0].text;$("ttl").textContent="Attack Exposure Report - "+o;$("sum").style.display="block";
$("sum").innerHTML="Generated "+new Date().toLocaleString()+". In this period ("+o.toLowerCase()+") the server received <b>"+d.total+"</b> events from <b>"+d.ips+"</b> unique IPs in <b>"+d.countries+"</b> countries, including <b>"+d.logins+"</b> login attempts. Most targeted service: <b>"+esc(d.proto[0]?.[0]||"-")+"</b>. Most common activity: <b>"+esc(d.atk[0]?.[0]||"-")+"</b>. Most tried username: <b>"+esc(d.users[0]?.[0]||"-")+"</b>."}}
const fl=L.layerGroup().addTo(map),seen=new Set(),tk=[];let first=true,srvM=null;
function fly(e,s){const a=[e[5],e[6]],col=e[2]=="Brute force"?"#f72585":(e[2]=="Scan/Probe"||e[2]=="Ping")?"#f8961e":"#e63946";
const m=[(a[0]+s[0])/2+Math.abs(a[1]-s[1])*.15,(a[1]+s[1])/2],pts=[];
for(let t=0;t<=1.001;t+=.05)pts.push([(1-t)**2*a[0]+2*(1-t)*t*m[0]+t*t*s[0],(1-t)**2*a[1]+2*(1-t)*t*m[1]+t*t*s[1]]);
const glow=L.polyline(pts,{color:col,weight:9,opacity:.25}).addTo(fl),ln=L.polyline(pts,{color:col,weight:4,opacity:.95}).addTo(fl),
dot=L.circleMarker(a,{radius:7,color:"#fff",weight:2,fillColor:col,fillOpacity:1}).addTo(fl),ring=L.circleMarker(a,{radius:6,color:col,weight:3,fill:false}).addTo(fl),t0=performance.now();
(function step(n){const p=Math.min((n-t0)/1500,1);dot.setLatLng(pts[Math.round(p*(pts.length-1))]);ring.setRadius(6+p*22);ring.setStyle({opacity:1-p});ln.setStyle({opacity:.95*(1-p*.6)});glow.setStyle({opacity:.25*(1-p*.6)});
if(p<1)requestAnimationFrame(step);else setTimeout(()=>{fl.removeLayer(glow);fl.removeLayer(ln);fl.removeLayer(dot);fl.removeLayer(ring)},700)})(t0);
tk.unshift(esc(e[7]||"?")+" &rarr; "+esc(e[1])+" - "+esc(e[2])+(e[3]?" ("+esc(e[3])+")":""));tk.length=Math.min(tk.length,6);$("tick").innerHTML=tk.join("<br>")}
async function live(){try{const d=await(await fetch("/api/live")).json();if(!d.srv)return;
if(!srvM)srvM=L.circleMarker(d.srv,{radius:8,color:"#4cc9f0",fillColor:"#4cc9f0",fillOpacity:1}).bindTooltip("Your server").addTo(map);
const n=d.ev.filter(e=>!seen.has(e[0]));n.forEach(e=>seen.add(e[0]));
if(!first)n.reverse().slice(0,15).forEach((e,i)=>setTimeout(()=>fly(e,d.srv),i*200));first=false}catch(x){}}
const fe={off:0,lim:rep?3000:100,opts:false};
function clearF(){["fip","fco","fus","fpw"].forEach(i=>$(i).value="");$("fat").value="";$("fpr").value="";fe.off=0;loadEv()}
async function loadEv(){
const p=new URLSearchParams({r:R,limit:fe.lim,offset:fe.off,ip:$("fip").value,country:$("fco").value,user:$("fus").value,pw:$("fpw").value,atk:$("fat").value,proto:$("fpr").value});
const d=await(await fetch("/api/events?"+p)).json();
if(!fe.opts&&!rep){fe.opts=true;$("fat").innerHTML='<option value="">Tum saldiri tipleri</option>'+d.atk_opts.map(x=>"<option>"+esc(x)+"</option>").join("");$("fpr").innerHTML='<option value="">Tum servisler</option>'+d.proto_opts.map(x=>"<option>"+esc(x)+"</option>").join("")}
$("evall").innerHTML=tbl(d.rows.map(x=>[new Date(x[0]*1000).toLocaleString(),x[1]+":"+x[2],x[3],x[8],x[4],x[5],x[6]]),["Zaman","Servis","Kaynak IP","Ulke","Kullanici","Sifre","Tip"]);
const from=d.total?d.offset+1:0,to=Math.min(d.offset+d.rows.length,d.total);$("pgInfo").textContent=`${from}-${to} / ${d.total}`;
$("pgPrev").disabled=d.offset<=0;$("pgNext").disabled=d.offset+d.rows.length>=d.total}
load();loadEv();if(!rep){setInterval(load,10000);live();setInterval(live,3000);setInterval(()=>{if(fe.off==0)loadEv()},15000)}
function fit(){map.invalidateSize();Object.values(ch).forEach(c=>c.resize())}
if(rep){setTimeout(fit,500);setTimeout(fit,1500)}
window.addEventListener("beforeprint",fit);window.addEventListener("resize",fit);
</script></body></html>"""

class Dash(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def do_GET(s):
        if not hmac.compare_digest(s.headers.get("Authorization", ""), AUTH):
            s.send_response(401); s.send_header("WWW-Authenticate", 'Basic realm="HoneyWatch"'); s.end_headers(); return
        u = urlparse(s.path)
        if u.path == "/api/stats":
            try: r = int(parse_qs(u.query).get("r", ["86400"])[0])
            except ValueError: r = 86400
            body, ct = json.dumps(stats(r)).encode(), "application/json"
        elif u.path == "/api/live": body, ct = json.dumps(live()).encode(), "application/json"
        elif u.path == "/api/events": body, ct = json.dumps(events(parse_qs(u.query))).encode(), "application/json"
        else: body, ct = INDEX.encode(), "text/html; charset=utf-8"
        s.send_response(200); s.send_header("Content-Type", ct); s.send_header("Content-Length", str(len(body))); s.end_headers(); s.wfile.write(body)

pf = DATA + "/dash_pass"
if not os.path.exists(pf):
    with open(pf, "w") as f: f.write(secrets.token_urlsafe(9))
    os.chmod(pf, 0o600)
AUTH = "Basic " + base64.b64encode(b"admin:" + open(pf).read().strip().encode()).decode()

if __name__ == "__main__":
    TLS = tls = tlsctx()
    for p, h in SVC.items(): listen(p, h, tls if p in TLSP else None)
    threading.Thread(target=icmp, daemon=True).start(); threading.Thread(target=geo_worker, daemon=True).start(); threading.Thread(target=srv_loc, daemon=True).start()
    if not paramiko: print("WARNING: python3-paramiko missing, SSH credentials will not be captured")
    print(f"Dashboard on port {DASH_PORT}, user: admin, password in {pf}")
    ThreadingHTTPServer(("0.0.0.0", DASH_PORT), Dash).serve_forever()
