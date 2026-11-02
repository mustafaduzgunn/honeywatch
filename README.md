# HoneyWatch

Tek dosyalık (bağımlılığı minimum), Ubuntu üzerinde hızlıca kurulabilen bir honeypot.
İnternete açık bir sunucuya gelen saldırıları (bağlantı denemeleri, brute-force giriş
denemeleri, web saldırıları, ping taramaları vb.) birden çok portta dinleyip kaydeder;
sonuçları canlı harita ve grafiklerle gösteren bir web dashboard sunar; istenildiğinde
yazdırılabilir / PDF olarak kaydedilebilir bir "Attack Exposure Report" üretir.

## Özellikler

- **Dinlenen portlar:** FTP(21), SSH(22), Telnet(23), SMTP(25), HTTP(80/8080),
  HTTPS(443/8443), SMB(445), MSSQL(1433), MySQL(3306), RDP(3389), PostgreSQL(5432),
  VNC(5900), Redis(6379) ve ICMP (ping). Port yönlendirmesi gerekmez, doğrudan bu
  portlarda dinler.
- **Kimlik bilgisi yakalama:** FTP, Telnet, HTTP(S) (form/basic-auth), SSH
  (paramiko üzerinden) ve RDP (TLS güvenlik modu üzerinden — bkz. Sınırlamalar)
  için denenen kullanıcı adı/şifre kaydedilir.
- **Saldırı sınıflandırma:** HTTP istekleri içerik imzalarına göre SQLi, XSS, path
  traversal, command injection/RCE, hassas dosya/panel probe'u, scanner (nikto,
  sqlmap, nmap vb.) olarak otomatik etiketlenir.
- **Coğrafi konum:** Saldırgan IP'ler ip-api.com üzerinden ülke/şehir/ISP bilgisiyle
  zenginleştirilir.
- **Canlı dashboard:** Toplam olay, benzersiz IP, ülke sayısı, login denemesi,
  zaman grafiği, hedeflenen servisler, saldırı tipleri, en çok denenen kullanıcı
  adı/şifreler, en aktif saldırgan IP'ler ve **canlı saldırı akış haritası**
  (saldırgandan sunucuya animasyonlu çizgiler).
- **Tüm olayları görüntüleme + filtreleme:** Sunucu ilk çalıştığı andan itibaren
  kaydedilen tüm olaylar, sayfalama ile ve IP/ülke/kullanıcı/şifre/saldırı
  tipi/servis bazında filtrelenerek incelenebilir.
- **Rapor:** Seçilen zaman aralığı için yöneticilere gösterilebilecek, yazdırmaya
  uygun bir özet rapor sayfası (`/report`) üretir; tarayıcının "Print / Save as
  PDF" özelliğiyle PDF olarak kaydedilebilir.

## Kurulum (Ubuntu)

```bash
sudo bash install.sh
```

Script gerekli paketleri (`python3`, `python3-paramiko`, `openssl`) kurar,
uygulamayı `/opt/honeywatch` altına kopyalar ve `honeywatch` adında bir systemd
servisi olarak başlatır. Kurulum sonunda dashboard adresi ve rastgele üretilmiş
parola ekrana yazdırılır:

```
Dashboard: http://<sunucu-ip>:9000   user: admin   password: <rastgele>
```

Parolayı sonradan görmek için:

```bash
sudo cat /opt/honeywatch/data/dash_pass
```

Parolayı değiştirmek için:

```bash
echo -n "YeniParolan" | sudo tee /opt/honeywatch/data/dash_pass
sudo systemctl restart honeywatch
```

## Önemli: kurulumdan önce

Sunucuda gerçek SSH, web sunucusu veya RDP zaten çalışıyorsa, HoneyWatch o portu
dinlerken çakışma yaşar ve o portu atlar (`journalctl -u honeywatch` loglarında
`SKIP port ...` olarak görünür). **Gerçek servisleri honeypot kurmadan önce
başka bir porta taşıman gerekir**, aksi halde o servise hem gerçek trafik hem de
honeypot erişemez / honeypot o portu dinleyemez.

### SSH'ı taşıma örneği (port 22 → 2222)

```bash
sudo sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config
sudo systemctl disable --now ssh.socket   # Ubuntu 22.10+ için gerekli
sudo systemctl restart ssh
```

**Mevcut SSH oturumunu kapatmadan önce**, yeni bir terminalden
`ssh -p 2222 kullanici@sunucu` ile bağlanabildiğini doğrula, sonra eski
oturumu kapat. Aynı mantık 80/443 üzerinde çalışan bir web sunucusu veya 3389
üzerinde gerçek bir RDP hizmeti varsa onlar için de geçerlidir.

Dashboard portuna (varsayılan 9000) da sadece kendi IP adresinden erişime izin
vermen önerilir:

```bash
sudo ufw allow from <senin-ip> to any port 9000
```

## Dashboard

`http://<sunucu-ip>:9000` adresine `admin` kullanıcı adı ve kurulumda verilen
parola ile giriş yapılır. Üstteki zaman aralığı seçici (son 1 saat / 24 saat /
7 gün / 30 gün / tümü) tüm grafik, harita ve "All events" tablosunu etkiler.

### Rapor oluşturma

Dashboard'daki **"Create report"** butonu, seçili zaman aralığı için
`/report?r=...` sayfasını açar. Bu sayfadaki **"Print / Save as PDF"** butonu
tarayıcının yazdırma diyalogunu açar; buradan "PDF olarak kaydet" seçeneğiyle
dosya olarak saklanabilir. (Yazdırma diyalogunda "Arka plan grafikleri"
seçeneğinin açık olduğundan emin ol, aksi halde harita ve renkler çıktıya
yansımayabilir.)

## Sınırlamalar

- **RDP + NLA (varsayılan Windows modu):** Windows'un varsayılan RDP kimlik
  doğrulama yöntemi olan NLA, şifreyi hiçbir zaman ağdan açık ya da çözülebilir
  şekilde geçirmez (challenge-response tasarımı). Bu, gerçek bir RDP sunucusu
  için de geçerlidir — teknik bir eksiklik değil, protokolün güvenlik tasarımı.
  HoneyWatch bu durumda sadece **denenen kullanıcı adını** (bağlantının ilk
  isteğindeki "cookie" alanından) kaydeder, şifre alanı boş kalır.
- **RDP + TLS (NLA kapalı, çoğu brute-force/tarama aracı):** Bu modda hem
  kullanıcı adı hem de şifre açık olarak yakalanır. `mstsc` (Windows'un yerleşik
  istemcisi) ve macOS'un resmi "Microsoft Remote Desktop" uygulaması, güvenlik
  politikaları gereği NLA olmayan sunuculara bağlanmayı reddeder — bunlarla
  test etmek istersen FreeRDP (`xfreerdp ... /sec:tls /cert:ignore`) kullan.
- **RDP + "Standard RDP Security" (NLA de TLS de yok):** Bu en eski mod da artık
  desteklenir (RSA sertifikası + RC4 ile) — gerçek bir istemciyle (`xfreerdp
  /sec:rdp`) kullanıcı adı ve şifre eksiksiz yakalandığı doğrulanmıştır. Ancak
  bazı brute-force araçlarının (ör. `ncrack`) kendi RDP implementasyonu bu
  katmanı tam desteklemediği için bağlantıyı tamamlamadan takılıp kalabilir;
  bu durumda sadece aracın kendi sabit "cookie" değeri (ör. ncrack için
  `hello`) görünür, şifre alanı boş kalır — bu, HoneyWatch'ın değil, o aracın
  sınırlamasıdır.
- Konum verisi ve dashboard'daki dünya haritası için sunucunun ve dashboard'ı
  açan tarayıcının internete erişebilmesi gerekir (ip-api.com, OpenStreetMap
  kiremit sunucuları, CDN üzerinden yüklenen Leaflet/Chart.js).

## Veriler

Tüm loglar ve ayarlar `/opt/honeywatch/data/` altında tutulur
(`hw.db` — SQLite veritabanı, `dash_pass` — dashboard parolası,
`ssh_host_key` — SSH host anahtarı, `cert.pem`/`key.pem` — HTTPS sertifikası).
`honeywatch.py` dosyasını güncellemek bu klasöre dokunmaz, veriler ve parola
korunur.

## Güncelleme

```bash
sudo cp honeywatch.py /opt/honeywatch/honeywatch.py
sudo systemctl restart honeywatch
```

## Lisans

MIT
