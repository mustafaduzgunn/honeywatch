#!/bin/bash
set -e
[ "$EUID" -ne 0 ] && { echo "Run with: sudo bash install.sh"; exit 1; }
apt-get update -qq && apt-get install -y -qq python3 python3-paramiko openssl
mkdir -p /opt/honeywatch && cp "$(dirname "$0")/honeywatch.py" /opt/honeywatch/
cat > /etc/systemd/system/honeywatch.service <<EOF
[Unit]
Description=HoneyWatch honeypot
After=network.target
[Service]
WorkingDirectory=/opt/honeywatch
ExecStart=/usr/bin/python3 /opt/honeywatch/honeywatch.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now honeywatch
sleep 4; journalctl -u honeywatch -n 25 --no-pager
echo; echo "Dashboard: http://<server-ip>:9000   user: admin   password: $(cat /opt/honeywatch/data/dash_pass)"
