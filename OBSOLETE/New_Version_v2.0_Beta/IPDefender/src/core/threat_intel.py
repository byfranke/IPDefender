import requests
import json

class ThreatIntel:
    def __init__(self, otx_api_key, misp_url, misp_key):
        self.otx_api_key = otx_api_key
        self.misp_url = misp_url
        self.misp_key = misp_key

    def fetch_otx_threats(self):
        url = "https://otx.alienvault.com/api/v1/indicators/IPv4/"
        headers = {"X-OTX-API-KEY": self.otx_api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get("results", [])
        return []

    def fetch_misp_threats(self):
        url = f"{self.misp_url}/events/restSearch"
        headers = {"Authorization": self.misp_key, "Content-Type": "application/json"}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get("response", [])
        return []

    def process_threats(self):
        otx_threats = self.fetch_otx_threats()
        misp_threats = self.fetch_misp_threats()
        threats = otx_threats + misp_threats
        return threats

    def ban_ip_based_on_threats(self, ip_manager):
        threats = self.process_threats()
        for threat in threats:
            if 'ip' in threat:
                ip_manager.add_ip(threat['ip'])  # Assuming ip_manager has an add_ip method

    def integrate_with_wazuh(self, wazuh_client):
        alerts = wazuh_client.get_alerts()  # Assuming wazuh_client has a method to get alerts
        for alert in alerts:
            if alert['type'] == 'threat':
                self.ban_ip_based_on_threats(alert['ip'])  # Assuming alert contains the IP to ban