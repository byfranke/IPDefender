#!/bin/bash

SRC_FILE="/etc/ipdefender/modules/honeypot.php"
FALLBACK_NAMES=(
  "wp-login.php"
  "admin.php"
  "cpanel.php"
  "login.php"
  "info.php"
  "admin/login.php"
  "admin/phpmyadmin/login.php"
  "webadmin.php"
  "phpmyadmin.php"
  "mysql.php"
  "shell.php"
  "setup.php"
  "server-status.php"
  "dashboard.php"
  "test.php"
  "panel.php"
  "admin123.php"
)

echo "[*] Verifying honeypot.php source..."
if [[ ! -f "$SRC_FILE" ]]; then
  echo "[!] honeypot.php not found in $SRC_FILE"
  exit 1
fi

# Detect target root
if [[ -d "/var/www/html" ]]; then
  TARGET_DIR="/var/www/html"
  OWNER="www-data"
elif [[ -d "/usr/share/nginx/html" ]]; then
  TARGET_DIR="/usr/share/nginx/html"
  OWNER="nginx"
else
  read -rp "[?] Couldn't detect web root. Enter full path manually: " TARGET_DIR
  if [[ ! -d "$TARGET_DIR" ]]; then
    echo "[!] Directory not found: $TARGET_DIR"
    exit 1
  fi
  read -rp "[?] Enter web server user (default: www-data): " OWNER
  OWNER="${OWNER:-www-data}"
fi

echo "[*] Target directory set to: $TARGET_DIR"
mkdir -p "$TARGET_DIR"

echo "[*] Creating honeypot clones with secure permissions..."
COUNT=0
for name in "${FALLBACK_NAMES[@]}"; do
  DEST="$TARGET_DIR/$name"
  if [[ ! -f "$DEST" ]]; then
    mkdir -p "$(dirname "$DEST")"
    cp "$SRC_FILE" "$DEST"
    chmod 0644 "$DEST"
    chown "$OWNER:$OWNER" "$DEST"
    echo "[+] Created honeypot: $DEST"
    ((COUNT++))
  else
    echo "[-] Skipped existing: $DEST"
  fi
done

echo "[✓] Honeypots deployed: $COUNT"