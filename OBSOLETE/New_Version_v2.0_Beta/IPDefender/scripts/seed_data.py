#!/usr/bin/env python3
import json
import requests

# Sample data for seeding
sample_ips = [
    {"ip": "192.0.2.1", "reason": "Malicious activity detected"},
    {"ip": "203.0.113.5", "reason": "Brute force attack"},
    {"ip": "198.51.100.10", "reason": "Suspicious behavior"},
]

def seed_data(api_token, zone_id):
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    for entry in sample_ips:
        ip = entry["ip"]
        reason = entry["reason"]
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
        payload = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip},
            "notes": reason
        }
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            print(f"Successfully blocked IP: {ip} - {reason}")
        else:
            print(f"Failed to block IP: {ip} - {response.text}")

if __name__ == "__main__":
    API_TOKEN = "****"  # Replace with your Cloudflare API token
    ZONE_ID = "****"    # Replace with your Cloudflare Zone ID
    seed_data(API_TOKEN, ZONE_ID)