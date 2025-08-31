#!/usr/bin/env python3
"""
IPDefender Pro - Command Line Interface Examples
Demonstrates CLI usage patterns and command examples

Author: byFranke (https://byfranke.com)
"""

import subprocess
import sys
import time
from typing import List

def run_command(command: str, description: str = None) -> None:
    """Run a command and display the results"""
    if description:
        print(f"🔧 {description}")
    
    print(f"$ {command}")
    
    try:
        # In a real environment, this would execute the command
        # For demo purposes, we'll simulate the output
        print("   (Demo mode - command not actually executed)")
        print("   ✅ Command would execute successfully")
    except Exception as e:
        print(f"   ❌ Command failed: {e}")
    
    print()

def demo_service_management():
    """Demonstrate service management commands"""
    print("🔧 IPDefender Pro - Service Management")
    print("=" * 40)
    
    commands = [
        ("sudo systemctl start ipdefender-pro", "Start IPDefender Pro service"),
        ("sudo systemctl stop ipdefender-pro", "Stop IPDefender Pro service"),
        ("sudo systemctl restart ipdefender-pro", "Restart IPDefender Pro service"),
        ("sudo systemctl status ipdefender-pro", "Check service status"),
        ("sudo systemctl enable ipdefender-pro", "Enable auto-start on boot"),
        ("sudo journalctl -u ipdefender-pro -f", "Follow service logs")
    ]
    
    for command, description in commands:
        run_command(command, description)

def demo_configuration_management():
    """Demonstrate configuration management"""
    print("⚙️ Configuration Management")
    print("=" * 30)
    
    commands = [
        ("sudo nano /etc/ipdefender/config.yaml", "Edit main configuration"),
        ("sudo nano /etc/ipdefender/rules.yaml", "Edit response rules"),
        ("sudo ipdefender --validate-config", "Validate configuration"),
        ("sudo ipdefender --show-config", "Display current configuration"),
        ("sudo ipdefender --test-providers", "Test threat intelligence providers")
    ]
    
    for command, description in commands:
        run_command(command, description)

def demo_ip_management():
    """Demonstrate IP address management commands"""
    print("🛡️ IP Address Management")
    print("=" * 30)
    
    commands = [
        ("sudo ipdefender analyze 8.8.8.8", "Analyze single IP address"),
        ("sudo ipdefender analyze --file suspicious_ips.txt", "Analyze IPs from file"),
        ("sudo ipdefender block 192.0.2.1", "Block IP address"),
        ("sudo ipdefender temp-block 192.0.2.1 --duration 3600", "Temporary block (1 hour)"),
        ("sudo ipdefender unblock 192.0.2.1", "Unblock IP address"),
        ("sudo ipdefender whitelist 10.0.0.0/8", "Add to whitelist"),
        ("sudo ipdefender list-blocked", "List all blocked IPs"),
        ("sudo ipdefender list-whitelist", "List whitelisted networks")
    ]
    
    for command, description in commands:
        run_command(command, description)

def demo_monitoring_commands():
    """Demonstrate monitoring and reporting commands"""
    print("📊 Monitoring and Reporting")
    print("=" * 30)
    
    commands = [
        ("sudo ipdefender status", "Show system status"),
        ("sudo ipdefender stats", "Show detailed statistics"),
        ("sudo ipdefender stats --last-24h", "Statistics for last 24 hours"),
        ("sudo ipdefender top-threats", "Show top threat IPs"),
        ("sudo ipdefender provider-status", "Check threat intelligence providers"),
        ("sudo ipdefender firewall-status", "Check firewall provider status"),
        ("sudo ipdefender export-log --format json", "Export logs in JSON format"),
        ("sudo ipdefender generate-report --type daily", "Generate daily report")
    ]
    
    for command, description in commands:
        run_command(command, description)

def demo_wazuh_integration():
    """Demonstrate Wazuh integration commands"""
    print("🔍 Wazuh SIEM Integration")
    print("=" * 30)
    
    commands = [
        ("sudo ipdefender wazuh status", "Check Wazuh connection"),
        ("sudo ipdefender wazuh test", "Test Wazuh integration"),
        ("sudo ipdefender wazuh install-rules", "Install IPDefender rules in Wazuh"),
        ("sudo ipdefender wazuh sync-agents", "Sync with Wazuh agents"),
        ("sudo ipdefender wazuh query --rule-id 5710", "Query specific Wazuh rule")
    ]
    
    for command, description in commands:
        run_command(command, description)

def demo_api_commands():
    """Demonstrate API-related commands"""
    print("🌐 API Management")
    print("=" * 20)
    
    commands = [
        ("sudo ipdefender api start", "Start API server"),
        ("sudo ipdefender api stop", "Stop API server"),
        ("sudo ipdefender api status", "Check API server status"),
        ("sudo ipdefender api generate-key", "Generate new API key"),
        ("sudo ipdefender api list-keys", "List active API keys"),
        ("sudo ipdefender api revoke-key KEY_ID", "Revoke API key")
    ]
    
    for command, description in commands:
        run_command(command, description)

def demo_maintenance_commands():
    """Demonstrate maintenance and troubleshooting commands"""
    print("🔧 Maintenance and Troubleshooting")
    print("=" * 40)
    
    commands = [
        ("sudo ipdefender cleanup", "Clean up expired blocks and cache"),
        ("sudo ipdefender backup --output /tmp/ipdefender-backup.tar.gz", "Backup configuration"),
        ("sudo ipdefender restore --input /tmp/ipdefender-backup.tar.gz", "Restore from backup"),
        ("sudo ipdefender update-feeds", "Update threat intelligence feeds"),
        ("sudo ipdefender test-firewall", "Test firewall connectivity"),
        ("sudo ipdefender diagnose", "Run system diagnostics"),
        ("sudo ipdefender repair --auto", "Auto-repair common issues")
    ]
    
    for command, description in commands:
        run_command(command, description)

def demo_scripting_examples():
    """Show examples for scripting and automation"""
    print("🤖 Scripting and Automation Examples")
    print("=" * 40)
    
    print("📝 Bash Script Example - Monitor and Block:")
    script_example = """#!/bin/bash
# Monitor log file and auto-block suspicious IPs

LOGFILE="/var/log/auth.log"
THRESHOLD=5

# Monitor for failed SSH attempts
tail -f "$LOGFILE" | while read line; do
    if echo "$line" | grep -q "Failed password"; then
        IP=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
        
        # Count failed attempts from this IP
        ATTEMPTS=$(grep "Failed password.*$IP" "$LOGFILE" | wc -l)
        
        if [ "$ATTEMPTS" -ge "$THRESHOLD" ]; then
            echo "Blocking $IP after $ATTEMPTS failed attempts"
            sudo ipdefender block "$IP" --reason "SSH brute force"
        fi
    fi
done"""
    
    print(script_example)
    print()
    
    print("🐍 Python Integration Example:")
    python_example = """#!/usr/bin/env python3
import requests
import json

# IPDefender Pro API integration
class ThreatMonitor:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "http://localhost:8080/api/v1"
        
    def analyze_and_respond(self, ip_list):
        headers = {'Authorization': f'Bearer {self.api_key}'}
        
        for ip in ip_list:
            # Analyze IP
            response = requests.post(
                f"{self.base_url}/analyze",
                headers=headers,
                json={"ip": ip}
            )
            
            if response.status_code == 200:
                analysis = response.json()
                threat_score = analysis.get('threat_score', 0)
                
                # Auto-respond based on threat score
                if threat_score > 80:
                    self.block_ip(ip)
                    
    def block_ip(self, ip):
        # Execute block action
        pass

# Usage
monitor = ThreatMonitor("your-api-key")
suspicious_ips = ["192.0.2.1", "198.51.100.1"]
monitor.analyze_and_respond(suspicious_ips)"""
    
    print(python_example)
    print()

def demo_configuration_examples():
    """Show configuration file examples"""
    print("📋 Configuration Examples")
    print("=" * 30)
    
    print("📝 Basic Configuration (/etc/ipdefender/config.yaml):")
    config_example = """# IPDefender Pro Configuration
application:
  name: "IPDefender Pro"
  version: "1.0.0"
  author: "byFranke"
  website: "https://byfranke.com"

# Threat Intelligence Configuration
threat_intelligence:
  abuseipdb_api_key: "YOUR_ABUSEIPDB_KEY"
  otx_api_key: "YOUR_OTX_KEY"
  cache_ttl: 3600
  max_concurrent_requests: 10

# Response Engine Configuration
response_engine:
  whitelist:
    - "127.0.0.1"
    - "10.0.0.0/8" 
    - "192.168.0.0/16"
  providers:
    ufw:
      enabled: true
    cloudflare:
      enabled: true
      api_token: "YOUR_CLOUDFLARE_TOKEN"
      zone_id: "YOUR_ZONE_ID"

# API Configuration  
api:
  enabled: true
  host: "0.0.0.0"
  port: 8080
  api_keys:
    - "your-secret-api-key"

# Wazuh Integration
wazuh:
  enabled: true
  url: "https://your-wazuh-server:55000"
  username: "wazuh"
  password: "your-wazuh-password"

# Logging Configuration
logging:
  level: "INFO"
  file: "/var/log/ipdefender/ipdefender.log"
  max_size: "100MB"
  backup_count: 5"""
    
    print(config_example)
    print()
    
    print("📝 Response Rules (/etc/ipdefender/rules.yaml):")
    rules_example = """# IPDefender Pro Response Rules
response_rules:
  - name: "Critical Threat Block"
    conditions:
      threat_score:
        min: 90
    action: "block"
    priority: 100
    firewall_providers: ["ufw", "cloudflare"]
    
  - name: "High Threat Temporary Block"
    conditions:
      threat_score:
        min: 70
        max: 89
    action: "temp_block"
    duration: 3600  # 1 hour
    priority: 80
    
  - name: "SSH Brute Force Response"
    conditions:
      wazuh_rule_id: 5710
    action: "temp_block"
    duration: 1800  # 30 minutes
    priority: 90"""
    
    print(rules_example)
    print()

def main():
    """Run all CLI examples"""
    print("🛡️ IPDefender Pro CLI Examples by byFranke")
    print("Advanced Cybersecurity Defense Platform")
    print("https://byfranke.com")
    print("=" * 50)
    print()
    
    print("ℹ️ Note: Commands shown in demo mode - replace with actual usage")
    print()
    
    # Run demonstrations
    demo_service_management()
    demo_configuration_management()
    demo_ip_management()
    demo_monitoring_commands()
    demo_wazuh_integration()
    demo_api_commands()
    demo_maintenance_commands()
    demo_scripting_examples()
    demo_configuration_examples()
    
    print("✅ CLI Examples completed!")
    print()
    print("🚀 Quick Start:")
    print("1. Install: sudo ./install.sh")
    print("2. Configure: sudo nano /etc/ipdefender/config.yaml") 
    print("3. Start: sudo systemctl start ipdefender-pro")
    print("4. Check: sudo ipdefender status")
    print()
    print("📚 Full documentation: https://byfranke.com/ipdefender-pro")

if __name__ == "__main__":
    main()
