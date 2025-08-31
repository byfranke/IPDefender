from typing import List, Dict
import requests

WAZUH_API_URL = "http://wazuh-api:55000"  # Update with your Wazuh API URL
WAZUH_API_USER = "your_username"  # Update with your Wazuh API username
WAZUH_API_PASSWORD = "your_password"  # Update with your Wazuh API password

def get_wazuh_alerts() -> List[Dict]:
    url = f"{WAZUH_API_URL}/alerts"
    response = requests.get(url, auth=(WAZUH_API_USER, WAZUH_API_PASSWORD))
    if response.status_code == 200:
        return response.json().get('data', [])
    return []

def extract_threat_ips(alerts: List[Dict]) -> List[str]:
    threat_ips = []
    for alert in alerts:
        if 'ip' in alert['full_log']:
            # Extract IP from the alert log
            ip = alert['full_log'].split('ip: ')[1].split()[0]
            threat_ips.append(ip)
    return threat_ips

def ban_ips(ip_list: List[str]):
    for ip in ip_list:
        # Call the Cloudflare API to block the IP
        status, response = cf_block(ip)  # Assuming cf_block is imported from cloudflare.py
        print(f"Banned IP {ip}: Status {status}, Response {response}")

def main():
    alerts = get_wazuh_alerts()
    threat_ips = extract_threat_ips(alerts)
    if threat_ips:
        ban_ips(threat_ips)

if __name__ == "__main__":
    main()