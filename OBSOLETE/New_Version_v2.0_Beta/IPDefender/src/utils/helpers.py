def fetch_otx_threats(api_key):
    url = "https://otx.alienvault.com/api/v1/indicators/last"
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("results", [])
    return []

def fetch_misp_events(api_url, api_key):
    url = f"{api_url}/events"
    headers = {"Authorization": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("response", [])
    return []

def extract_ip_from_wazuh_alert(alert):
    return alert.get("agent", {}).get("ip", None)

def is_ip_blocked(ip, blocked_ips):
    return ip in blocked_ips

def log_action(action, ip):
    print(f"{action} action performed on IP: {ip}")