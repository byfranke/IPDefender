#!/bin/bash

# IPDefender - Intelligent IP Protection System
# byfranke.com
VERSION="2.1"
CONFIG_DIR="/etc/ipdefender"
API_KEY_FILE="$CONFIG_DIR/abuseipdb.cfg"
LOG_FILE="/var/log/ipdefender.log"
FAIL2BAN_JAIL="sshd"
REPO_URL="https://github.com/byfranke/IPDefender"

usage() {
  echo "IPDefender v$VERSION - Comprehensive IP Protection Solution | byfranke.com"
  echo "Usage:"
  echo "  IPDefender --install-deps         Install dependencies"
  echo "  IPDefender --ban <IP> [reason]    Ban IP with threat intelligence"
  echo "  IPDefender --check <IP>           Analyze IP reputation"
  echo "  IPDefender --unban <IP>           Remove IP ban"
  echo "  IPDefender --unban-all            Remove all bans"
  echo "  IPDefender --list                 Show active bans"
  echo "  IPDefender --api-abuseipdb <KEY>  Configure AbuseIPDB API key"
  echo "  IPDefender --update               Update to latest version"
  echo "  IPDefender --version              Show current version"
  echo "  IPDefender --help                 Display this help"
  exit 1
}

update_script() {
  check_root
  echo "Updating IPDefender..."
  
  local temp_dir="/tmp/IPDefender_$(date +%s)"
  mkdir -p "$temp_dir"
  
  if ! git clone --quiet "$REPO_URL" "$temp_dir" 2>/dev/null; then
    echo "Error: Failed to download updates"
    rm -rf "$temp_dir"
    exit 1
  fi
  
  if [[ -f "$temp_dir/IPDefender.sh" ]]; then
    chmod +x "$temp_dir/IPDefender.sh"
    cp "$temp_dir/IPDefender.sh" "/bin/IPDefender"
    rm -rf "$temp_dir"
    echo "Update successful! Restart your terminal."
    exit 0
  else
    echo "Error: Invalid update package"
    rm -rf "$temp_dir"
    exit 1
  fi
}

init_config() {
  mkdir -p "$CONFIG_DIR"
  chmod 0700 "$CONFIG_DIR"
  touch "$API_KEY_FILE"
  chmod 0600 "$API_KEY_FILE"
}

store_api_key() {
  [[ -z "$1" ]] && { echo "Error: API key required"; exit 1; }
  init_config
  echo "$1" > "$API_KEY_FILE"
  echo "API key stored securely in $API_KEY_FILE"
}

get_api_key() {
  [[ -f "$API_KEY_FILE" ]] && cat "$API_KEY_FILE" || echo ""
}

check_root() {
  [[ $EUID -ne 0 ]] && { echo "Error: Root privileges required"; exit 1; }
}

install_deps() {
  check_root
  if command -v apt-get >/dev/null; then
    apt-get update
    apt-get install -y ufw fail2ban iptables curl jq
  elif command -v dnf >/dev/null; then
    dnf install -y ufw fail2ban iptables curl jq
  else
    echo "Error: Install dependencies manually: ufw, fail2ban, curl, jq"
    exit 1
  fi

  systemctl enable --now ufw fail2ban
  ufw default deny incoming
  ufw enable
  echo "Dependencies installed. Enabled UFW (default deny) + Fail2Ban"
}

validate_ip() {
  local ip="$1"
  local octet="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
  [[ $ip =~ ^$octet\.$octet\.$octet\.$octet$ ]] || {
    echo "Error: Invalid IPv4: $ip"; exit 1
  }
}

log_action() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

check_abuseipdb() {
  local ip="$1"
  local api_key=$(get_api_key)
  [[ -z "$api_key" ]] && { echo "Error: AbuseIPDB API key not configured"; return 1; }

  echo "Analyzing $ip with AbuseIPDB..."
  local response=$(curl -sfG https://api.abuseipdb.com/api/v2/check \
    --data-urlencode "ipAddress=$ip" \
    -d maxAgeInDays=90 \
    -H "Key: $api_key" \
    -H "Accept: application/json")

  [[ $? -ne 0 ]] && { echo "Error: Failed to query AbuseIPDB"; return 1; }

  local score=$(jq -r '.data.abuseConfidenceScore' <<< "$response" 2>/dev/null)
  local total=$(jq -r '.data.totalReports' <<< "$response" 2>/dev/null)
  local last=$(jq -r '.data.lastReportedAt' <<< "$response" 2>/dev/null)
  local country=$(jq -r '.data.countryCode' <<< "$response" 2>/dev/null)
  local isp=$(jq -r '.data.isp' <<< "$response" 2>/dev/null)
  
  echo "Threat Report for $ip:"
  echo "---------------------------------"
  echo "Abuse Confidence: ${score:-N/A}/100"
  echo "Total Reports:    ${total:-0}"
  echo "Last Reported:    ${last:-Never}"
  echo "Country:          ${country:-Unknown}"
  echo "ISP:              ${isp:-Unknown}"
  echo "---------------------------------"
}

ban_ip() {
  local ip="$1"
  local reason="${2:-Manual ban}"
  
  if ! ufw status | grep -q "DENY.*$ip"; then
    ufw insert 1 deny from "$ip" comment "IPDefender: $reason"
    log_action "BAN $ip - Reason: $reason"
    echo "Banned $ip successfully"
  else
    echo "$ip already in blocklist"
  fi
}

unban_ip() {
  local ip="$1"
  
  while ufw status | grep -q "$ip"; do
    ufw delete deny from "$ip"
  done
  
  fail2ban-client set "$FAIL2BAN_JAIL" unbanip "$ip" &>/dev/null
  log_action "UNBAN $ip"
  echo "Removed bans for $ip"
}

unban_all() {
  local banned_ips=$(ufw status | awk '/DENY/{print $3}')
  [[ -z "$banned_ips" ]] && { echo "No active bans"; return; }
  
  echo "Active bans:"
  echo "$banned_ips"
  read -p "Remove all bans? (y/N): " answer
  [[ ! "$answer" =~ ^[yY]$ ]] && return
  
  echo "$banned_ips" | while read ip; do
    ufw delete deny from "$ip"
    fail2ban-client set "$FAIL2BAN_JAIL" unbanip "$ip" &>/dev/null
  done
  
  log_action "UNBAN_ALL - Removed $(wc -l <<< "$banned_ips") bans"
  echo "All IP bans cleared"
}

list_bans() {
  echo "UFW Blocklist:"
  ufw status | grep DENY | awk '{print " - " $3}'
  
  echo -e "\nFail2Ban Active Blocks ($FAIL2BAN_JAIL):"
  fail2ban-client get "$FAIL2BAN_JAIL" banned | sed "s/'//g; s/\[//g; s/\]//g; s/,/\n/g" | awk '{print " - " $1}'
}

check_root
init_config

case "$1" in
  --install-deps)
    install_deps ;;
    
  --ban)
    [[ -z "$2" ]] && usage
    validate_ip "$2"
    check_abuseipdb "$2"
    ban_ip "$2" "${3:-}" ;;
    
  --check)
    [[ -z "$2" ]] && usage
    validate_ip "$2"
    check_abuseipdb "$2" ;;
    
  --unban)
    [[ -z "$2" ]] && usage
    validate_ip "$2"
    unban_ip "$2" ;;
    
  --unban-all)
    unban_all ;;
    
  --list)
    list_bans ;;
    
  --api-abuseipdb)
    store_api_key "$2" ;;
    
  --update)
    update_script ;;
    
  --version)
    echo "IPDefender v$VERSION | byfranke.com" ;;
    
  --help|*)
    usage ;;
esac
