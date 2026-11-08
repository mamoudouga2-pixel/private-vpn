#!/usr/bin/env bash
# Installs the NovaVPN API (for the Android app), the `novavpn-admin` command and an SSH key
# that lets this server create/revoke user keys on the five country servers. No admin web panel.
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root: bash server/control/install_control_plane.sh"; exit 1; }
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ -d "$SOURCE_DIR/control_plane/app" ]] || { echo "Run this script from the extracted NovaVPN folder."; exit 1; }

read -rp "API domain (example: vpn.example.com): " DOMAIN
read -rp "Your email (for the HTTPS certificate): " ADMIN_EMAIL
[[ "$DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]] || { echo "Invalid domain name."; exit 1; }
[[ "$ADMIN_EMAIL" == *@*.* ]] || { echo "Enter a valid email."; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip nginx certbot python3-certbot-nginx openssl openssh-client

id novavpn >/dev/null 2>&1 || useradd --system --home /opt/novavpn-control --shell /usr/sbin/nologin novavpn
install -d -o root -g root -m 755 /opt/novavpn-control
rm -rf /opt/novavpn-control/app /opt/novavpn-control/admin
cp -a "$SOURCE_DIR/control_plane/app" /opt/novavpn-control/
rm -rf /opt/novavpn-control/app/__pycache__
cp "$SOURCE_DIR/control_plane/requirements.txt" /opt/novavpn-control/requirements.txt
chown -R root:root /opt/novavpn-control
find /opt/novavpn-control -type d -exec chmod 755 {} \;
find /opt/novavpn-control -type f -exec chmod 644 {} \;

python3 -m venv /opt/novavpn-control/venv
/opt/novavpn-control/venv/bin/pip install --upgrade pip
/opt/novavpn-control/venv/bin/pip install -r /opt/novavpn-control/requirements.txt

# Secrets are generated once and kept on a re-run (re-generating would make stored VPN profiles unreadable).
if [[ ! -f /etc/novavpn-control.env ]]; then
  JWT_SECRET="$(openssl rand -hex 48)"
  FERNET_KEY="$(/opt/novavpn-control/venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
  cat > /etc/novavpn-control.env <<EOT
NOVAVPN_DB=/var/lib/novavpn-control/control.sqlite3
NOVAVPN_JWT_SECRET=${JWT_SECRET}
NOVAVPN_FERNET_KEY=${FERNET_KEY}
NOVAVPN_TOKEN_TTL=28800
NOVAVPN_SSH_DIR=/var/lib/novavpn-control/ssh
EOT
fi
chown root:novavpn /etc/novavpn-control.env
chmod 640 /etc/novavpn-control.env
install -d -o novavpn -g novavpn -m 700 /var/lib/novavpn-control /var/lib/novavpn-control/ssh

# SSH key used only to reach the five country servers (they accept it for NovaVPN commands only).
if [[ ! -f /var/lib/novavpn-control/ssh/id_ed25519 ]]; then
  runuser -u novavpn -- ssh-keygen -q -t ed25519 -N "" -C novavpn-control -f /var/lib/novavpn-control/ssh/id_ed25519
fi
cp /var/lib/novavpn-control/ssh/id_ed25519.pub /etc/novavpn-control.pub
chmod 644 /etc/novavpn-control.pub

cat > /usr/local/bin/novavpn-admin <<'EOT'
#!/usr/bin/env bash
cd /opt/novavpn-control
exec runuser -u novavpn -- /opt/novavpn-control/venv/bin/python -m app.cli "$@"
EOT
chmod 755 /usr/local/bin/novavpn-admin

cat > /etc/systemd/system/novavpn-control.service <<'EOT'
[Unit]
Description=NovaVPN Private API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=novavpn
Group=novavpn
WorkingDirectory=/opt/novavpn-control
EnvironmentFile=/etc/novavpn-control.env
ExecStart=/opt/novavpn-control/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8765 --workers 1
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/novavpn-control

[Install]
WantedBy=multi-user.target
EOT

cat > /etc/nginx/conf.d/novavpn-rate-limit.conf <<'EOT'
limit_req_zone $binary_remote_addr zone=novavpn_login:10m rate=5r/s;
EOT

cat > /etc/nginx/sites-available/novavpn-control <<EOT
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    client_max_body_size 64k;
    location = /api/v1/auth/login {
        limit_req zone=novavpn_login burst=20 nodelay;
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
    }
    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
    }
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header X-Frame-Options DENY always;
}
EOT
ln -sfn /etc/nginx/sites-available/novavpn-control /etc/nginx/sites-enabled/novavpn-control
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl daemon-reload
systemctl enable novavpn-control
systemctl restart novavpn-control
systemctl reload nginx

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then ufw allow 'Nginx Full'; fi

echo
echo "Requesting HTTPS certificate. ${DOMAIN} must already point to this server, and ports 80/443 must be open."
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$ADMIN_EMAIL" --redirect || {
  echo "WARNING: HTTPS was not set up. The Android app needs HTTPS. Fix the domain/DNS, then run: certbot --nginx -d ${DOMAIN}"
}

echo
systemctl --no-pager --lines=5 status novavpn-control || true
echo
echo "Done. API: https://${DOMAIN}/health"
echo "Next: bash server/deploy_nodes.sh   (installs the five country servers)"
echo "Then create members with:  novavpn-admin add-user NAME EMAIL"
