import requests
import json
import time

MISP_URL = "https://your-misp-instance.com"  # Replace with your MISP instance URL
MISP_API_KEY = "****"  # Replace with your MISP API key

HEADERS = {
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def get_threats():
    url = f"{MISP_URL}/attributes/restSearch"
    params = {
        "type": "ip-src",
        "limit": 100,  # Adjust limit as needed
        "timestamp": int(time.time()) - 86400  # Last 24 hours
    }
    response = requests.get(url, headers=HEADERS, params=params)
    if response.status_code == 200:
        return response.json().get("response", [])
    return []

def ban_ip(ip: str):
    # Function to ban IP using Cloudflare or other methods
    pass  # Implement the ban logic here

def main():
    threats = get_threats()
    for threat in threats:
        ip = threat.get("value")
        if ip:
            ban_ip(ip)

if __name__ == "__main__":
    main()