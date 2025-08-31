from typing import List, Dict, Any
import requests
import json

class IPManager:
    def __init__(self, cloudflare_api_token: str, zone_id: str):
        self.cloudflare_api_token = cloudflare_api_token
        self.zone_id = zone_id
        self.headers = {
            "Authorization": f"Bearer {self.cloudflare_api_token}",
            "Content-Type": "application/json"
        }

    def block_ip(self, ip: str) -> Dict[str, Any]:
        url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/firewall/access_rules/rules"
        payload = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip},
            "notes": f"Blocked by IPManager"
        }
        response = requests.post(url, headers=self.headers, json=payload)
        return {"status": response.status_code, "response": response.json()}

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        rule_id = self.find_rule(ip)
        if not rule_id:
            return {"status": 404, "response": {"success": False, "errors": [{"message": "rule not found"}]}}
        
        url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/firewall/access_rules/rules/{rule_id}"
        response = requests.delete(url, headers=self.headers)
        return {"status": response.status_code, "response": response.json()}

    def find_rule(self, ip: str) -> str:
        url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/firewall/access_rules/rules"
        params = {"configuration.target": "ip", "configuration.value": ip, "per_page": 1}
        response = requests.get(url, headers=self.headers, params=params)
        if response.status_code == 200 and response.json().get("result"):
            return response.json()["result"][0]["id"]
        return None

    def process_threats(self, threats: List[str]) -> None:
        for ip in threats:
            self.block_ip(ip)

    def remove_threats(self, threats: List[str]) -> None:
        for ip in threats:
            self.unblock_ip(ip)