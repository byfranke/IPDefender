# IPDefender

Advanced IP Management System with Threat Intelligence Integration | [byfranke.com](https://byfranke.com)

![Firewall Protection](https://img.shields.io/badge/Firewall-UFW%20%7C%20Fail2Ban-blue)
![Version](https://img.shields.io/badge/Version-2.3-green)

## Features

- Real-time IP threat analysis via **AbuseIPDB**
- Dual firewall management (**UFW** + **Fail2Ban**)
- Automatic security updates
- Secure API key storage
- Cross-platform support (APT/DNF/YUM based systems)
- Detailed threat reporting
- One-click mass unban
- **New in v2.3**: Threat intelligence report before banning IPs

## Installation

### Quick Install
```bash
sudo curl -L https://raw.githubusercontent.com/byfranke/IPDefender/main/IPDefender.sh -o /usr/local/bin/IPDefender
sudo chmod +x /usr/local/bin/IPDefender
```

### From Source
```bash
git clone https://github.com/byfranke/IPDefender.git
cd IPDefender
chmod +x IPDefender.sh
sudo mv IPDefender.sh /usr/local/bin/IPDefender
```

## Configuration

### 1. Install Dependencies
```bash
sudo IPDefender --install-deps
```

### 2. AbuseIPDB Setup
1. Create free account at [AbuseIPDB](https://www.abuseipdb.com/register)
2. Get API key from dashboard
3. Configure in IPDefender:
```bash
sudo IPDefender --api-abuseipdb YOUR_API_KEY
```

## Usage

### Basic Commands
```bash
# Ban IP with threat intelligence report
sudo IPDefender --ban 192.0.2.5 "SSH brute force"

# Bulk ban IPs from file (one per line)
sudo IPDefender --ban-list malicious_ips.txt "Botnet activity"

# Analyze IP reputation
sudo IPDefender --check 203.0.113.1

# List active bans
sudo IPDefender --list

# Update to latest version
sudo IPDefender --update
```

### Full Command Reference
| Command                  | Description                                            |
|--------------------------|--------------------------------------------------------|
| `--install-deps`         | Install dependencies (UFW, Fail2Ban, curl, jq, git)   |
| `--ban <IP> [reason]`    | Ban IP after showing threat report + optional reason  |
| `--ban-list <file>`      | Bulk ban IPs from file (with detailed summary)        |
| `--check <IP>`           | Analyze IP reputation with AbuseIPDB                  |
| `--unban <IP>`           | Remove IP ban                                         |
| `--unban-all`            | Remove all bans (with confirmation)                   |
| `--list`                 | Show active bans across UFW, Fail2Ban and tracked IPs |
| `--api-abuseipdb <KEY>`  | Configure AbuseIPDB API key                           |
| `--update`               | Update to latest version                              |
| `--version`              | Show current version                                  |
| `--help`                 | Display help menu                                     |

## Example Workflow

```bash
# Install and configure
sudo IPDefender --install-deps
sudo IPDefender --api-abuseipdb YOUR_KEY

# Investigate suspicious IP
sudo IPDefender --check 198.51.100.2

# Ban with threat intelligence (now shows report before banning)
sudo IPDefender --ban 198.51.100.2 "High threat score"

# Bulk ban from file (one IP per line)
sudo IPDefender --ban-list malicious_ips.txt "Botnet activity"

# Weekly maintenance
sudo IPDefender --update
sudo IPDefender --list
```

## Key Improvements in v2.3

1. **Threat Intelligence Before Banning**  
   - Automatic AbuseIPDB report when using `--ban`
   - Shows confidence score, reports, location and ISP
   - Helps make informed blocking decisions

2. **Robust Bulk Processing**  
   - Improved whitespace handling in IP lists
   - Detailed summary with counts of:
     - New bans
     - Skipped (already banned)
     - Invalid IPs

3. **Enhanced Update System**  
   - Installs to `/usr/local/bin` (standard for custom tools)
   - Automatic git dependency installation
   - Clear post-update instructions

4. **Extended OS Support**  
   - Added YUM package manager (RHEL/CentOS)
   - Improved distro compatibility checks

## Requirements

- Linux (Debian/RedHat based distributions)
- Root privileges
- curl, jq, git
- UFW & Fail2Ban

## License

**Maintained by [Frank E](https://byfranke.com)** | [Report Issue](https://github.com/byfranke/IPDefender/issues)

![Screenshot 2025-06-27 at 17 31 50](https://github.com/user-attachments/assets/288ad9ca-26bb-489f-b25c-8bfb350f6d92)

## Donation Support

This tool is maintained through community support. Help keep it active:

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://donate.stripe.com/28o8zQ2wY3Dr57G001)
