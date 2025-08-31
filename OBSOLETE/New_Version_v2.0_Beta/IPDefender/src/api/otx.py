import requests
import json
import time

OTX_API_KEY = "****"  # Replace with your OTX API key
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/"

def fetch_threats():
    url = f"{OTX_BASE_URL}indicators/OTX"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("results", [])
    return []

def get_ip_threats(ip):
    url = f"{OTX_BASE_URL}indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def main():
    threats = fetch_threats()
    for threat in threats:
        print(json.dumps(threat, indent=2))

if __name__ == "__main__":
    main()