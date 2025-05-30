#!/bin/bash

# IPDefender - Intelligent IP Protection System
# byfranke.com
VERSION="2.3"
CONFIG_DIR="/etc/ipdefender"
API_KEY_FILE="$CONFIG_DIR/abuseipdb.cfg"
LOG_FILE="/var/log/ipdefender.log"
FAIL2BAN_JAIL="sshd"
REPO_URL="https://github.com/byfranke/IPDefender"
BANNED_IPS_FILE="$CONFIG_DIR/banned_ips.list"

usage() {
  echo "IPDefender v$VERSION - Comprehensive IP Protection Solution | byfranke.com"
  echo "Usage:"
  echo "  IPDefender --install-deps         Install dependencies"
  echo "  IPDefender --ban <IP> [reason]    Ban IP with threat intelligence"
  echo "  IPDefender --ban-list <file>      Ban IPs from file (one per line)"
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
    local install_path="/usr/local/bin/IPDefender"
    cp "$temp_dir/IPDefender.sh" "$install_path"
    rm -rf "$temp_dir"
    echo "Update successful! Installed in $install_path"
    echo "Restart your terminal or run 'hash -r' to use the new version"
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
  touch "$API_KEY_FILE" "$BANNED_IPS_FILE"
  chmod 0600 "$API_KEY_FILE" "$BANNED_IPS_FILE"
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
  echo "Installing dependencies: ufw, fail2ban, curl, jq..."
  
  if command -v apt-get >/dev/null; then
    apt-get update
    apt-get install -y ufw fail2ban iptables curl jq git
  elif command -v dnf >/dev/null; then
    dnf install -y ufw fail2ban iptables curl jq git
  elif command -v yum >/dev/null; then
    yum install -y ufw fail2ban iptables curl jq git
  else
    echo "Error: Install dependencies manually: ufw, fail2ban, curl, jq, git"
    exit 1
  fi

  systemctl enable --now ufw fail2ban
  ufw default deny incoming
  ufw --force enable
  echo "Dependencies installed. Enabled UFW (default deny) + Fail2Ban"
}

validate_ip() {
  local ip="$1"
  local octet="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
  [[ $ip =~ ^$octet\.$octet\.$octet\.$octet$ ]] || {
    echo "Error: Invalid IPv4: $ip"; return 1
  }
  return 0
}

is_ip_banned() {
  local ip="$1"

  ufw status | grep -q "DENY.*$ip" && return 0

  fail2ban-client status "$FAIL2BAN_JAIL" | grep -q "$ip" && return 0

  grep -q "^$ip$" "$BANNED_IPS_FILE" && return 0
  return 1
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
  
  if ! validate_ip "$ip"; then
    echo "Skipping invalid IP: $ip"
    return 1
  fi

  if is_ip_banned "$ip"; then
    echo "$ip is already banned. Skipping."
    return 0
  fi

  check_abuseipdb "$ip"
  
  ufw insert 1 deny from "$ip" comment "IPDefender: $reason"
  echo "$ip" >> "$BANNED_IPS_FILE"
  log_action "BAN $ip - Reason: $reason"
  echo "Banned $ip successfully"
}

ban_list() {
  local file="$1"
  local reason="${2:-Bulk ban}"
  
  [[ ! -f "$file" ]] && { echo "Error: File not found: $file"; return 1; }
  
  local total=0
  local banned=0
  local skipped=0
  local invalid=0

  while IFS= read -r ip; do
    # Remove leading/trailing whitespace (preserve internal formatting)
    ip=$(echo "$ip" | xargs)
    [[ -z "$ip" ]] && continue
    ((total++))

    if ! validate_ip "$ip"; then
      echo "Invalid IP: $ip"
      ((invalid++))
      continue
    fi

    if is_ip_banned "$ip"; then
      echo "$ip already banned. Skipping."
      ((skipped++))
      continue
    fi

    ufw insert 1 deny from "$ip" comment "IPDefender: $reason"
    echo "$ip" >> "$BANNED_IPS_FILE"
    log_action "BAN $ip - Reason: $reason (bulk)"
    echo "Banned $ip"
    ((banned++))
  done < "$file"

  echo "---------------------------------"
  echo "Bulk ban summary:"
  echo "Total IPs processed: $total"
  echo "New bans: $banned"
  echo "Skipped (already banned): $skipped"
  echo "Invalid IPs: $invalid"
  echo "---------------------------------"
}

unban_ip() {
  local ip="$1"
  
  if ! validate_ip "$ip"; then
    return 1
  fi

  # Remove from UFW
  while ufw status | grep -q "$ip"; do
    ufw delete deny from "$ip"
  done
  
  # Remove from Fail2Ban
  fail2ban-client set "$FAIL2BAN_JAIL" unbanip "$ip" &>/dev/null
  
  # Remove from tracking file
  sed -i "/^$ip$/d" "$BANNED_IPS_FILE"
  
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
  
  > "$BANNED_IPS_FILE" 
  log_action "UNBAN_ALL - Removed $(wc -l <<< "$banned_ips") bans"
  echo "All IP bans cleared"
}

list_bans() {
  echo "UFW Blocklist:"
  ufw status | grep DENY | awk '{print " - " $3}'
  
  echo -e "\nFail2Ban Active Blocks ($FAIL2BAN_JAIL):"
  fail2ban-client get "$FAIL2BAN_JAIL" banned | sed "s/'//g; s/\[//g; s/\]//g; s/,/\n/g" | awk '{print " - " $1}'
  
  echo -e "\nTracked Banned IPs:"
  [[ -s "$BANNED_IPS_FILE" ]] && cat "$BANNED_IPS_FILE" | awk '{print " - " $1}' || echo " (none)"
}

check_root
init_config

case "$1" in
  --install-deps)
    install_deps ;;
    
  --ban)
    [[ -z "$2" ]] && usage
    ban_ip "$2" "${3:-}" ;;
    
  --ban-list)
    [[ -z "$2" ]] && { echo "Error: File path required"; usage; }
    ban_list "$2" "${3:-}" ;;
    
  --check)
    [[ -z "$2" ]] && usage
    validate_ip "$2" && check_abuseipdb "$2" ;;
    
  --unban)
    [[ -z "$2" ]] && usage
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
