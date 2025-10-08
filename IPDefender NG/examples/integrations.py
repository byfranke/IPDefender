#!/usr/bin/env python3
"""
IPDefender Pro - Integration Examples
Demonstrates integration with various security tools and platforms

Author: byFranke (https://byfranke.com)
"""

import json
import time
from datetime import datetime
from typing import Dict, List

def demo_wazuh_integration():
    """Demonstrate Wazuh SIEM integration patterns"""
    print("🔍 Wazuh SIEM Integration Examples")
    print("=" * 40)
    
    print("📡 Custom Wazuh Rules for IPDefender Pro:")
    
    # Example Wazuh rule configuration
    wazuh_rules = """<!-- IPDefender Pro Custom Rules -->
<!-- File: /var/ossec/etc/rules/ipdefender_rules.xml -->

<group name="ipdefender,attack,">
  
  <!-- SSH Brute Force Detection -->
  <rule id="999900" level="10">
    <if_group>authentication_failed</if_group>
    <same_source_ip />
    <description>SSH brute force attack detected</description>
    <options>no_email_alert</options>
  </rule>
  
  <!-- Web Application Attack -->
  <rule id="999901" level="12">
    <if_group>web,attack</if_group>
    <description>Web application attack detected</description>
    <options>no_email_alert</options>
  </rule>
  
  <!-- Port Scan Detection -->
  <rule id="999902" level="8">
    <if_group>recon</if_group>
    <same_source_ip />
    <description>Port scan detected</description>
    <options>no_email_alert</options>
  </rule>
  
  <!-- IPDefender Response Confirmation -->
  <rule id="999903" level="3">
    <decoded_as>ipdefender</decoded_as>
    <description>IPDefender Pro response executed</description>
  </rule>
  
  <!-- Threat Intelligence Alert -->
  <rule id="999904" level="10">
    <decoded_as>ipdefender</decoded_as>
    <field name="action">threat_detected</field>
    <description>Threat intelligence match found</description>
  </rule>
  
</group>"""
    
    print(wazuh_rules)
    print()
    
    print("🎯 Active Response Configuration:")
    active_response = """<!-- Active Response Configuration -->
<!-- File: /var/ossec/etc/ossec.conf -->

<ossec_config>
  <active-response>
    <command>ipdefender-block</command>
    <location>local</location>
    <rules_id>999900,999901</rules_id>
    <timeout>3600</timeout>
  </active-response>
  
  <command>
    <name>ipdefender-block</name>
    <executable>ipdefender-response.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>
</ossec_config>"""
    
    print(active_response)
    print()
    
    print("📜 Active Response Script:")
    response_script = """#!/bin/bash
# IPDefender Pro Wazuh Active Response Script
# File: /var/ossec/active-response/bin/ipdefender-response.sh

#!/bin/bash
PWD=$(pwd)
TIMESTAMP=`date`
ACTION=$1
USER=$2
IP=$3
RULEID=$4

# Log the action
echo "$TIMESTAMP - IPDefender Pro Response: Action=$ACTION User=$USER IP=$IP Rule=$RULEID" >> /var/log/ipdefender/wazuh-response.log

case "$ACTION" in
  add)
    # Block the IP using IPDefender Pro
    /usr/local/bin/ipdefender block "$IP" --source wazuh --rule-id "$RULEID"
    ;;
  delete)
    # Unblock the IP
    /usr/local/bin/ipdefender unblock "$IP" --source wazuh
    ;;
esac

exit 0"""
    
    print(response_script)
    print()

def demo_cloudflare_integration():
    """Demonstrate Cloudflare WAF integration"""
    print("☁️ Cloudflare WAF Integration Examples")
    print("=" * 40)
    
    print("🔧 Cloudflare API Integration Pattern:")
    
    cloudflare_example = """#!/usr/bin/env python3
# Cloudflare Integration Example

import requests
from typing import Dict, List

class CloudflareIntegration:
    def __init__(self, api_token: str, zone_id: str):
        self.api_token = api_token
        self.zone_id = zone_id
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
    
    def create_firewall_rule(self, ip: str, action: str = "block") -> Dict:
        \"\"\"Create a Cloudflare firewall rule\"\"\"
        
        # Create filter first
        filter_data = {
            "expression": f"(ip.src eq {ip})",
            "description": f"IPDefender Pro - Block {ip}"
        }
        
        filter_response = requests.post(
            f"{self.base_url}/zones/{self.zone_id}/filters",
            headers=self.headers,
            json=[filter_data]
        )
        
        if filter_response.status_code == 200:
            filter_id = filter_response.json()["result"][0]["id"]
            
            # Create firewall rule
            rule_data = {
                "filter": {"id": filter_id},
                "action": action,
                "description": f"IPDefender Pro Auto-Block: {ip}",
                "paused": False,
                "priority": 1000
            }
            
            rule_response = requests.post(
                f"{self.base_url}/zones/{self.zone_id}/firewall/rules",
                headers=self.headers,
                json=[rule_data]
            )
            
            return rule_response.json()
        
        return {"success": False, "error": "Filter creation failed"}
    
    def list_blocked_ips(self) -> List[str]:
        \"\"\"List all IPs blocked by IPDefender Pro rules\"\"\"
        
        response = requests.get(
            f"{self.base_url}/zones/{self.zone_id}/firewall/rules",
            headers=self.headers,
            params={"description.contains": "IPDefender Pro"}
        )
        
        blocked_ips = []
        if response.status_code == 200:
            rules = response.json()["result"]
            for rule in rules:
                # Extract IP from filter expression
                expression = rule.get("filter", {}).get("expression", "")
                if "ip.src eq" in expression:
                    ip = expression.split("ip.src eq ")[1].split(")")[0].strip()
                    blocked_ips.append(ip)
        
        return blocked_ips
    
    def remove_firewall_rule(self, ip: str) -> Dict:
        \"\"\"Remove firewall rule for specific IP\"\"\"
        
        # Find rule for this IP
        response = requests.get(
            f"{self.base_url}/zones/{self.zone_id}/firewall/rules",
            headers=self.headers,
            params={"description.contains": f"Block {ip}"}
        )
        
        if response.status_code == 200:
            rules = response.json()["result"]
            for rule in rules:
                rule_id = rule["id"]
                filter_id = rule["filter"]["id"]
                
                # Delete rule
                requests.delete(
                    f"{self.base_url}/zones/{self.zone_id}/firewall/rules/{rule_id}",
                    headers=self.headers
                )
                
                # Delete filter
                requests.delete(
                    f"{self.base_url}/zones/{self.zone_id}/filters/{filter_id}",
                    headers=self.headers
                )
                
                return {"success": True, "message": f"Removed rule for {ip}"}
        
        return {"success": False, "error": "Rule not found"}

# Usage Example
cf = CloudflareIntegration("your-api-token", "your-zone-id")
result = cf.create_firewall_rule("192.0.2.1", "block")
print(f"Rule created: {result}")"""
    
    print(cloudflare_example)
    print()

def demo_fail2ban_integration():
    """Demonstrate Fail2ban integration"""
    print("🔒 Fail2ban Integration Examples")
    print("=" * 40)
    
    print("📝 Fail2ban Configuration for IPDefender Pro:")
    
    fail2ban_config = """# IPDefender Pro Fail2ban Configuration
# File: /etc/fail2ban/jail.d/ipdefender.conf

[ipdefender-sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
action = ipdefender-action[name=SSH, port=ssh, protocol=tcp]

[ipdefender-apache]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 3
findtime = 300
bantime = 1800
action = ipdefender-action[name=Apache, port=http, protocol=tcp]

[ipdefender-nginx]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 600
action = ipdefender-action[name=Nginx, port=http, protocol=tcp]"""
    
    print(fail2ban_config)
    print()
    
    print("🎯 Custom Fail2ban Action:")
    
    fail2ban_action = """# IPDefender Pro Fail2ban Action
# File: /etc/fail2ban/action.d/ipdefender-action.conf

[INCLUDES]
before = iptables-common.conf

[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /usr/local/bin/ipdefender block <ip> --source fail2ban --service <name>
           echo "[<F-DATE>] Fail2ban banned <ip> for <name> service" >> /var/log/ipdefender/fail2ban.log
actionunban = /usr/local/bin/ipdefender unblock <ip> --source fail2ban
             echo "[<F-DATE>] Fail2ban unbanned <ip>" >> /var/log/ipdefender/fail2ban.log

[Init]
name = default
port = ssh
protocol = tcp"""
    
    print(fail2ban_action)
    print()

def demo_api_gateway_integration():
    """Demonstrate API Gateway and reverse proxy integration"""
    print("🌐 API Gateway Integration Examples")
    print("=" * 40)
    
    print("🔧 Nginx Integration with IPDefender Pro:")
    
    nginx_config = """# Nginx Configuration with IPDefender Pro Integration
# File: /etc/nginx/sites-available/ipdefender-protected

upstream backend {
    server 127.0.0.1:8000;
}

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

# Geo-blocking (example countries)
geo $blocked_country {
    default 0;
    ~^(CN|RU|KP) 1;  # Block China, Russia, North Korea
}

server {
    listen 80;
    server_name your-api.com;
    
    # IPDefender Pro real-time blocking
    access_by_lua_block {
        local ip = ngx.var.remote_addr
        local handle = io.popen("ipdefender check " .. ip)
        local result = handle:read("*a")
        handle:close()
        
        if string.match(result, "BLOCKED") then
            ngx.status = 403
            ngx.say("Access Denied - IP Blocked by Security System")
            ngx.exit(403)
        end
    }
    
    # Block based on geo-location
    if ($blocked_country) {
        return 403 "Access denied from your location";
    }
    
    # Rate limiting
    location /api/ {
        limit_req zone=api burst=5 nodelay;
        proxy_pass http://backend;
        
        # Log for IPDefender Pro analysis
        access_log /var/log/nginx/ipdefender-api.log combined;
    }
    
    location /login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://backend;
        
        # Enhanced logging for brute force detection
        access_log /var/log/nginx/ipdefender-auth.log '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent';
    }
}"""
    
    print(nginx_config)
    print()
    
    print("🔄 Real-time Integration Script:")
    
    realtime_script = """#!/usr/bin/env python3
# Real-time Nginx Log Analysis for IPDefender Pro

import re
import time
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta

class NginxLogMonitor:
    def __init__(self, log_file="/var/log/nginx/access.log"):
        self.log_file = log_file
        self.failed_attempts = defaultdict(deque)
        self.threshold = 10
        self.time_window = 300  # 5 minutes
    
    def parse_log_line(self, line):
        \"\"\"Parse nginx log line\"\"\"
        pattern = r'(\\S+) - - \\[(.*?)\\] "(.*?)" (\\d+) \\d+'
        match = re.match(pattern, line)
        
        if match:
            ip = match.group(1)
            timestamp = datetime.strptime(match.group(2), '%d/%b/%Y:%H:%M:%S %z')
            request = match.group(3)
            status = int(match.group(4))
            
            return {
                'ip': ip,
                'timestamp': timestamp,
                'request': request,
                'status': status
            }
        return None
    
    def is_suspicious_request(self, request, status):
        \"\"\"Check if request is suspicious\"\"\"
        suspicious_patterns = [
            r'/admin',
            r'/wp-admin',
            r'\.php',
            r'/api/.*\\?.*=.*script',
            r'union.*select',
            r'<script',
            r'\\.\\./'
        ]
        
        # Failed authentication or suspicious patterns
        if status in [401, 403, 404] or any(re.search(pattern, request, re.IGNORECASE) for pattern in suspicious_patterns):
            return True
        
        return False
    
    def monitor_logs(self):
        \"\"\"Monitor nginx logs in real-time\"\"\"
        with subprocess.Popen(['tail', '-f', self.log_file], stdout=subprocess.PIPE, text=True) as proc:
            for line in proc.stdout:
                log_entry = self.parse_log_line(line.strip())
                if not log_entry:
                    continue
                
                ip = log_entry['ip']
                timestamp = log_entry['timestamp']
                
                if self.is_suspicious_request(log_entry['request'], log_entry['status']):
                    # Add to failed attempts
                    self.failed_attempts[ip].append(timestamp)
                    
                    # Clean old attempts outside time window
                    cutoff_time = timestamp - timedelta(seconds=self.time_window)
                    while self.failed_attempts[ip] and self.failed_attempts[ip][0] < cutoff_time:
                        self.failed_attempts[ip].popleft()
                    
                    # Check if threshold exceeded
                    if len(self.failed_attempts[ip]) >= self.threshold:
                        self.block_ip(ip, "Nginx suspicious activity")
                        self.failed_attempts[ip].clear()
    
    def block_ip(self, ip, reason):
        \"\"\"Block IP using IPDefender Pro\"\"\"
        try:
            subprocess.run([
                'ipdefender', 'block', ip, 
                '--source', 'nginx-monitor',
                '--reason', reason
            ], check=True)
            
            print(f"Blocked {ip}: {reason}")
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to block {ip}: {e}")

# Usage
if __name__ == "__main__":
    monitor = NginxLogMonitor()
    monitor.monitor_logs()"""
    
    print(realtime_script)
    print()

def demo_siem_integration():
    """Demonstrate SIEM platform integrations"""
    print("📊 SIEM Platform Integration Examples")
    print("=" * 40)
    
    print("🔍 Splunk Integration:")
    
    splunk_config = """# Splunk Integration Configuration
# File: /opt/splunk/etc/apps/ipdefender/local/inputs.conf

[monitor:///var/log/ipdefender/*.log]
disabled = false
index = security
sourcetype = ipdefender:log
host = ipdefender-server

[script://./bin/ipdefender_check.py]
disabled = false
index = security
interval = 300
sourcetype = ipdefender:status

# Splunk Search Examples:

# Top blocked IPs
index=security sourcetype="ipdefender:log" action=block | stats count by src_ip | sort -count

# Threat intelligence matches
index=security sourcetype="ipdefender:log" threat_score>80 | table _time, src_ip, threat_score, threat_level, action

# Response effectiveness
index=security sourcetype="ipdefender:log" | stats count by action, provider | chart count over action by provider

# Geographic analysis
index=security sourcetype="ipdefender:log" | iplocation src_ip | geostats count by Country

# Timeline of threats
index=security sourcetype="ipdefender:log" | timechart span=1h count by threat_level"""
    
    print(splunk_config)
    print()
    
    print("🔍 ELK Stack Integration:")
    
    elk_config = """# ELK Stack Integration
# Filebeat Configuration: /etc/filebeat/filebeat.yml

filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/ipdefender/*.log
  fields:
    service: ipdefender
    environment: production
  fields_under_root: true
  multiline.pattern: '^\\d{4}-\\d{2}-\\d{2}'
  multiline.negate: true
  multiline.match: after

# Logstash Configuration: /etc/logstash/conf.d/ipdefender.conf

input {
  beats {
    port => 5044
  }
}

filter {
  if [service] == "ipdefender" {
    grok {
      match => { 
        "message" => "%{TIMESTAMP_ISO8601:timestamp} - %{LOGLEVEL:level} - %{DATA:component} - %{GREEDYDATA:message_text}"
      }
    }
    
    if [message_text] =~ /IP: \\d+\\.\\d+\\.\\d+\\.\\d+/ {
      grok {
        match => {
          "message_text" => "IP: %{IP:src_ip}"
        }
      }
      
      mutate {
        add_field => { "geoip_src" => "%{src_ip}" }
      }
    }
    
    geoip {
      source => "src_ip"
      target => "geoip"
    }
    
    date {
      match => [ "timestamp", "yyyy-MM-dd HH:mm:ss,SSS" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "ipdefender-%{+YYYY.MM.dd}"
  }
}

# Kibana Dashboard Queries:

# Threat Score Distribution
GET ipdefender-*/_search
{
  "aggs": {
    "threat_score_ranges": {
      "range": {
        "field": "threat_score",
        "ranges": [
          { "to": 25, "key": "Low" },
          { "from": 25, "to": 50, "key": "Medium" },
          { "from": 50, "to": 75, "key": "High" },
          { "from": 75, "key": "Critical" }
        ]
      }
    }
  }
}"""
    
    print(elk_config)
    print()

def demo_notification_integrations():
    """Demonstrate notification and alerting integrations"""
    print("📢 Notification Integration Examples")
    print("=" * 40)
    
    print("📱 Slack Integration:")
    
    slack_integration = """#!/usr/bin/env python3
# Slack Integration for IPDefender Pro

import requests
import json
from datetime import datetime

class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_threat_alert(self, ip: str, threat_score: float, action: str):
        \"\"\"Send threat detection alert to Slack\"\"\"
        
        color = "danger" if threat_score > 80 else "warning" if threat_score > 50 else "good"
        
        message = {
            "attachments": [{
                "color": color,
                "title": "🛡️ IPDefender Pro - Threat Detected",
                "fields": [
                    {"title": "IP Address", "value": ip, "short": True},
                    {"title": "Threat Score", "value": f"{threat_score}/100", "short": True},
                    {"title": "Action Taken", "value": action.upper(), "short": True},
                    {"title": "Timestamp", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "short": True}
                ],
                "footer": "IPDefender Pro by byFranke",
                "footer_icon": "https://byfranke.com/icon.png"
            }]
        }
        
        requests.post(self.webhook_url, json=message)
    
    def send_system_status(self, status: dict):
        \"\"\"Send system status update\"\"\"
        
        message = {
            "text": "📊 IPDefender Pro Status Update",
            "attachments": [{
                "color": "good" if status["healthy"] else "danger",
                "fields": [
                    {"title": "System Status", "value": "Healthy" if status["healthy"] else "Issues Detected", "short": True},
                    {"title": "Active Blocks", "value": str(status["active_blocks"]), "short": True},
                    {"title": "Threats Today", "value": str(status["threats_today"]), "short": True},
                    {"title": "Uptime", "value": status["uptime"], "short": True}
                ]
            }]
        }
        
        requests.post(self.webhook_url, json=message)

# Usage
notifier = SlackNotifier("https://hooks.slack.com/services/YOUR/WEBHOOK/URL")
notifier.send_threat_alert("192.0.2.1", 85.0, "block")"""
    
    print(slack_integration)
    print()
    
    print("📧 Email Integration:")
    
    email_integration = """#!/usr/bin/env python3
# Email Integration for IPDefender Pro

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class EmailNotifier:
    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
    
    def send_threat_report(self, to_email: str, threats: list):
        \"\"\"Send daily threat report\"\"\"
        
        msg = MIMEMultipart()
        msg['From'] = self.username
        msg['To'] = to_email
        msg['Subject'] = f"IPDefender Pro - Daily Threat Report ({datetime.now().strftime('%Y-%m-%d')})"
        
        # HTML email content
        html_content = f\"\"\"
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #f4f4f4; padding: 10px; }}
                .threat-high {{ background-color: #ffebee; }}
                .threat-medium {{ background-color: #fff3e0; }}
                .threat-low {{ background-color: #e8f5e8; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🛡️ IPDefender Pro Daily Report</h2>
                <p>Generated by: byFranke Security Platform</p>
                <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <h3>Threat Summary</h3>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Threat Score</th>
                    <th>Action Taken</th>
                    <th>Source</th>
                    <th>Timestamp</th>
                </tr>
        \"\"\"
        
        for threat in threats:
            threat_class = "threat-high" if threat["score"] > 80 else "threat-medium" if threat["score"] > 50 else "threat-low"
            html_content += f\"\"\"
                <tr class="{threat_class}">
                    <td>{threat["ip"]}</td>
                    <td>{threat["score"]}</td>
                    <td>{threat["action"]}</td>
                    <td>{threat["source"]}</td>
                    <td>{threat["timestamp"]}</td>
                </tr>
            \"\"\"
        
        html_content += \"\"\"
            </table>
            
            <h3>System Statistics</h3>
            <ul>
                <li>Total Threats Processed: {}</li>
                <li>High Priority Threats: {}</li>
                <li>Blocked IPs: {}</li>
                <li>System Uptime: 99.9%</li>
            </ul>
            
            <p>
                <small>
                    This report was automatically generated by IPDefender Pro.<br>
                    Visit <a href="https://byfranke.com">byFranke.com</a> for more information.
                </small>
            </p>
        </body>
        </html>
        \"\"\".format(
            len(threats),
            len([t for t in threats if t["score"] > 80]),
            len([t for t in threats if t["action"] == "block"])
        )
        
        msg.attach(MIMEText(html_content, 'html'))
        
        # Send email
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)

# Usage
email_notifier = EmailNotifier("smtp.gmail.com", 587, "your-email@gmail.com", "your-password")
threats = [
    {"ip": "192.0.2.1", "score": 85, "action": "block", "source": "AbuseIPDB", "timestamp": "2024-01-15 10:30:00"},
    {"ip": "198.51.100.1", "score": 65, "action": "temp_block", "source": "OTX", "timestamp": "2024-01-15 14:15:00"}
]
email_notifier.send_threat_report("admin@yourcompany.com", threats)"""
    
    print(email_integration)
    print()

def main():
    """Run all integration examples"""
    print("🛡️ IPDefender Pro Integration Examples by byFranke")
    print("Advanced Cybersecurity Defense Platform")
    print("https://byfranke.com")
    print("=" * 60)
    print()
    
    print("🔗 This guide demonstrates integration patterns with:")
    print("• Wazuh SIEM")
    print("• Cloudflare WAF")
    print("• Fail2ban")
    print("• Nginx/API Gateways")
    print("• SIEM Platforms (Splunk, ELK)")
    print("• Notification Systems (Slack, Email)")
    print()
    
    # Run demonstrations
    demo_wazuh_integration()
    demo_cloudflare_integration()
    demo_fail2ban_integration()
    demo_api_gateway_integration()
    demo_siem_integration()
    demo_notification_integrations()
    
    print("✅ Integration Examples completed!")
    print()
    print("🚀 Implementation Steps:")
    print("1. Choose your integrations based on existing infrastructure")
    print("2. Configure API keys and credentials")
    print("3. Test each integration individually")
    print("4. Deploy in monitoring mode first")
    print("5. Gradually enable automated responses")
    print()
    print("📚 Full documentation: https://byfranke.com/ipdefender-pro")
    print("💬 Community support: https://github.com/byfranke/ipdefender-pro")

if __name__ == "__main__":
    main()
