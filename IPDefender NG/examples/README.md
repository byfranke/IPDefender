# IPDefender Pro - Examples Directory
## Comprehensive Usage Examples and Integration Guides

**Author:** byFranke (https://byfranke.com)  
**Platform:** Advanced Cybersecurity Defense Platform

---

## 📁 Directory Contents

### Core Examples
- **`demo.py`** - Complete functionality demonstration with mock data
- **`api_client.py`** - Python API client library and usage examples
- **`cli_usage.py`** - Command-line interface examples and patterns
- **`integrations.py`** - Integration patterns with security tools

---

## 🚀 Quick Start

### 1. Basic Demonstration
```bash
cd /path/to/IPDefender_Pro/examples
python3 demo.py
```
Shows core functionality including threat analysis and automated response.

### 2. API Usage Examples
```bash
python3 api_client.py
```
Demonstrates REST API usage patterns and client library.

### 3. CLI Commands Guide
```bash
python3 cli_usage.py
```
Complete guide to command-line interface and scripting.

### 4. Integration Patterns
```bash
python3 integrations.py
```
Examples for integrating with SIEM, WAF, and notification systems.

---

## 🔧 Example Categories

### Threat Intelligence Analysis
- Multi-source threat intelligence aggregation
- Real-time IP reputation checking
- Threat scoring and categorization
- Evidence collection and analysis

### Automated Response
- Rule-based response engine
- Firewall integration (UFW, Cloudflare)
- Temporary and permanent blocking
- Whitelist management

### API Integration
- REST API client usage
- Bulk operations
- Authentication patterns
- Error handling

### SIEM Integration
- **Wazuh** - Active response and custom rules
- **Splunk** - Log analysis and dashboards
- **ELK Stack** - Real-time monitoring
- Custom SIEM connectors

### Firewall Providers
- **UFW** - Linux host-based firewall
- **Cloudflare WAF** - Cloud-based protection
- **Fail2ban** - Service-specific blocking
- Custom provider development

### Notification Systems
- **Slack** - Real-time threat alerts
- **Email** - Daily reports and critical alerts
- **Webhook** - Custom notification endpoints
- **PagerDuty** - Incident management

---

## 🛡️ Security Use Cases

### 1. SSH Brute Force Protection
```bash
# Detect and block SSH attacks
sudo ipdefender analyze --log /var/log/auth.log --pattern "Failed password"
sudo ipdefender block-batch --threshold 5 --duration 3600
```

### 2. Web Application Protection
```bash
# Monitor web server logs
sudo ipdefender monitor --service nginx --auto-respond
```

### 3. Network Reconnaissance Detection
```bash
# Port scan detection and response
sudo ipdefender analyze --source wazuh --rule-id 999902
```

### 4. Threat Intelligence Monitoring
```bash
# Continuous threat feed monitoring
sudo ipdefender daemon --mode continuous --feeds abuseipdb,otx
```

---

## 📊 Monitoring and Reporting

### Real-time Dashboard
Access the web dashboard at: `http://localhost:8080/dashboard`

### API Endpoints
- **Analysis:** `POST /api/v1/analyze`
- **Response:** `POST /api/v1/respond` 
- **Status:** `GET /api/v1/status`
- **Metrics:** `GET /api/v1/metrics`

### Log Analysis
```bash
# System logs
tail -f /var/log/ipdefender/ipdefender.log

# Response logs
tail -f /var/log/ipdefender/responses.log

# API access logs
tail -f /var/log/ipdefender/api.log
```

---

## 🔗 Integration Examples

### Wazuh SIEM
```xml
<!-- Custom rule for IPDefender Pro -->
<rule id="999900" level="10">
  <if_group>authentication_failed</if_group>
  <same_source_ip />
  <description>SSH brute force - IPDefender Pro</description>
</rule>
```

### Cloudflare WAF
```python
# Cloudflare firewall rule creation
cf_client = CloudflareClient(api_token, zone_id)
cf_client.create_rule(ip="192.0.2.1", action="block")
```

### Nginx Integration
```nginx
# Real-time IP checking
access_by_lua_block {
    local result = os.execute("ipdefender check " .. ngx.var.remote_addr)
    if result ~= 0 then
        ngx.exit(403)
    end
}
```

---

## 📈 Performance Optimization

### Caching Configuration
```yaml
# Optimize threat intelligence caching
threat_intelligence:
  cache_ttl: 3600
  max_cache_size: 10000
  cache_strategy: "lru"
```

### Async Processing
```python
# Bulk analysis with async processing
async with IPDefenderClient() as client:
    results = await client.bulk_analyze(ip_list, max_concurrent=10)
```

### Database Optimization
```sql
-- Index optimization for response history
CREATE INDEX idx_response_ip_timestamp ON responses(ip, created_at);
CREATE INDEX idx_threat_score ON analyses(threat_score, analyzed_at);
```

---

## 🔐 Security Best Practices

### API Security
- Use strong API keys (32+ characters)
- Implement rate limiting
- Enable HTTPS/TLS encryption
- Rotate keys regularly

### Access Control
```yaml
# Role-based access control
api:
  authentication:
    type: "bearer_token"
    roles:
      - name: "admin"
        permissions: ["*"]
      - name: "analyst" 
        permissions: ["analyze", "view"]
```

### Network Security
```bash
# Restrict API access
sudo ufw allow from 10.0.0.0/8 to any port 8080
sudo ufw allow from 192.168.0.0/16 to any port 8080
```

---

## 🚨 Troubleshooting

### Common Issues

#### API Connection Errors
```bash
# Check service status
sudo systemctl status ipdefender-pro

# Verify API is listening
sudo netstat -tlnp | grep :8080

# Check logs
sudo journalctl -u ipdefender-pro -f
```

#### Threat Intelligence Failures
```bash
# Test provider connectivity
sudo ipdefender test-providers

# Check API keys
sudo ipdefender validate-config
```

#### Firewall Integration Issues
```bash
# Test UFW integration
sudo ipdefender test-firewall --provider ufw

# Check Cloudflare credentials
sudo ipdefender test-firewall --provider cloudflare
```

---

## 📚 Documentation Links

- **Installation Guide:** [../docs/SETUP.md](../docs/SETUP.md)
- **API Documentation:** [../docs/API.md](../docs/API.md)
- **Configuration Reference:** [../config/config.yaml](../config/config.yaml)
- **Contributing Guide:** [../docs/CONTRIBUTING.md](../docs/CONTRIBUTING.md)

---

## 🌟 Community

- **Website:** https://byfranke.com
- **Support:** support@byfranke.com
- **GitHub:** https://github.com/byfranke/ipdefender-pro
- **Documentation:** https://docs.byfranke.com/ipdefender-pro

---

## 📄 License

IPDefender Pro is developed by byFranke and distributed under the MIT License.

**Copyright © 2024 byFranke. All rights reserved.**
