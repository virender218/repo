#!/bin/bash
# Install the directory console on the Ubuntu server running slapd.
# Run as root on that host.
set -e

APP_DIR=/opt/ldapui

# --- 1. Files and dependencies ---------------------------------------------
apt-get update
apt-get install -y python3-pip python3-venv nginx

mkdir -p "$APP_DIR"
cp -r app.py checkpoint.py templates "$APP_DIR"/

# State directory for the Check Point connection settings. The sync password
# is never written here -- it lives in process memory only.
mkdir -p /var/lib/ldapui

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet flask ldap3 gunicorn

# --- 2. Service account ----------------------------------------------------
id -u ldapui >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ldapui
chown -R root:ldapui "$APP_DIR"
chmod -R 750 "$APP_DIR"
chown ldapui:ldapui /var/lib/ldapui
chmod 750 /var/lib/ldapui

# --- 3. Environment --------------------------------------------------------
# The app holds no directory credentials of its own. FLASK_SECRET_KEY only
# signs session cookies; rotating it logs everyone out.
cat > /etc/ldapui.env <<EOF
FLASK_SECRET_KEY=$(openssl rand -hex 32)
LDAP_URI=ldap://127.0.0.1:389
LDAP_BASE_DN=dc=cplab,dc=local
LDAP_PEOPLE_OU=ou=people,dc=cplab,dc=local
LDAP_GROUPS_OU=ou=groups,dc=cplab,dc=local
LDAPUI_SYNC_CONFIG=/var/lib/ldapui/sync.json
LDAPUI_HTTPS=1
EOF
chmod 640 /etc/ldapui.env
chown root:ldapui /etc/ldapui.env

# --- 4. Service ------------------------------------------------------------
# One worker only. Bind credentials live in process memory keyed by the
# session cookie, so a second worker would bounce users between processes
# that do not share that state.
cat > /etc/systemd/system/ldapui.service <<'EOF'
[Unit]
Description=LDAP directory console
After=network.target slapd.service
Wants=slapd.service

[Service]
Type=simple
User=ldapui
Group=ldapui
WorkingDirectory=/opt/ldapui
EnvironmentFile=/etc/ldapui.env
ExecStart=/opt/ldapui/venv/bin/gunicorn \
    --workers 1 --threads 8 \
    --timeout 120 \
    --bind 127.0.0.1:8080 \
    --access-logfile - \
    app:app
Restart=always
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ldapui
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

# --- 5. TLS front end ------------------------------------------------------
# The app never listens on a public interface directly. Passwords are typed
# into this UI, so plain HTTP is not an option.
if [ ! -f /etc/ssl/private/ldapui.key ]; then
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout /etc/ssl/private/ldapui.key \
    -out /etc/ssl/certs/ldapui.crt \
    -subj "/CN=$(hostname -f)"
  chmod 600 /etc/ssl/private/ldapui.key
fi

cat > /etc/nginx/sites-available/ldapui <<'EOF'
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/ssl/certs/ldapui.crt;
    ssl_certificate_key /etc/ssl/private/ldapui.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Restrict to your management network.
    allow 172.16.11.0/24;
    allow 127.0.0.1;
    deny  all;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
EOF

ln -sf /etc/nginx/sites-available/ldapui /etc/nginx/sites-enabled/ldapui
rm -f /etc/nginx/sites-enabled/default
nginx -t

# --- 6. Start --------------------------------------------------------------
systemctl daemon-reload
systemctl enable --now ldapui
systemctl reload nginx

echo
echo "Directory console is up:  https://$(hostname -f)/"
echo "Sign in with an LDAP DN, e.g. cn=admin,dc=cplab,dc=local"
echo
echo "Logs:  journalctl -u ldapui -f"
echo
echo "Before exposing this, edit the allow/deny block in"
echo "/etc/nginx/sites-available/ldapui to match your management subnet."
