# IPDefender 🔒

Advanced IP Management System with Threat Intelligence Integration | [byfranke.com](https://byfranke.com)

![Firewall Protection](https://img.shields.io/badge/Firewall-UFW%20%7C%20Fail2Ban-blue)
![Version](https://img.shields.io/badge/Version-2.1-green)
![License](https://img.shields.io/badge/License-MIT-orange)

## Features ✨

- Real-time IP threat analysis via **AbuseIPDB**
- Dual firewall management (**UFW** + **Fail2Ban**)
- Automatic security updates
- Secure API key storage
- Cross-platform support (APT/DNF based systems)
- Detailed threat reporting
- One-click mass unban

## Installation 🚀

### Quick Install
```bash
sudo curl -L https://raw.githubusercontent.com/byfranke/IPDefender/main/IPDefender.sh -o /bin/IPDefender
sudo chmod +x /bin/IPDefender
```

### From Source
```bash
git clone https://github.com/byfranke/IPDefender.git
cd IPDefender
chmod +x IPDefender.sh
sudo mv IPDefender.sh /bin/IPDefender
```

## Configuration ⚙️

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

## Usage 📖

### Basic Commands
```bash
# Ban IP with threat check
sudo IPDefender --ban 192.0.2.5 "SSH brute force"

# Analyze IP reputation
sudo IPDefender --check 203.0.113.1

# List active bans
sudo IPDefender --list

# Update to latest version
sudo IPDefender --update
```

### Full Command Reference
| Command                  | Description                          |
|--------------------------|--------------------------------------|
| `--install-deps`         | Install dependencies                |
| `--ban <IP> [reason]`    | Ban IP with optional reason         |
| `--check <IP>`           | Analyze IP reputation               |
| `--unban <IP>`           | Remove IP ban                       |
| `--unban-all`            | Remove all bans                     |
| `--list`                 | Show active bans                    |
| `--api-abuseipdb <KEY>`  | Configure AbuseIPDB API key         |
| `--update`               | Update to latest version           |
| `--version`              | Show current version               |
| `--help`                 | Display help menu                  |

## Example Workflow 🔄

```bash
# Install and configure
sudo IPDefender --install-deps
sudo IPDefender --api-abuseipdb YOUR_KEY

# Investigate suspicious IP
sudo IPDefender --check 198.51.100.2

# Ban if malicious
sudo IPDefender --ban 198.51.100.2 "High threat score"

# Weekly maintenance
sudo IPDefender --update
sudo IPDefender --list
```

## Requirements 📦

- Linux (Debian/RedHat based distributions)
- Root privileges
- curl, jq, git
- UFW & Fail2Ban

## License 📄

**Maintained by [Frank E](https://byfranke.com)** | [Report Issue](https://github.com/byfranke/IPDefender/issues)
```

