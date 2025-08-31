from typing import List, Dict, Any
import requests
import time

API_TOKEN = "****"
ZONE_ID = "****"

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

def cf_block(ip: str) -> (int, str):
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules"
    payload = {
        "mode": "block",
        "configuration": {"target": "ip", "value": ip},
        "notes": f"Blocked by IPDefender {int(time.time())}"
    }
    r = requests.post(url, headers=HEADERS, json=payload, timeout=10)
    return r.status_code, r.text

def cf_find_rule(ip: str) -> str:
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules"
    params = {"configuration.target": "ip", "configuration.value": ip, "per_page": 1}
    r = requests.get(url, headers=HEADERS, params=params, timeout=10)
    if r.status_code == 200 and r.json().get("result"):
        return r.json()["result"][0]["id"]
    return None

def cf_unblock(ip: str) -> (int, str):
    rule_id = cf_find_rule(ip)
    if not rule_id:
        return 404, '{"success":false,"errors":[{"message":"rule not found"}]}'
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules/{rule_id}"
    r = requests.delete(url, headers=HEADERS, timeout=10)
    return r.status_code, r.text

def cf_bulk_block(ip_list: List[str]) -> List[Dict[str, Any]]:
    results = []
    for ip in ip_list:
        status, response = cf_block(ip)
        results.append({"ip": ip, "status": status, "response": response})
    return results

def cf_bulk_unblock(ip_list: List[str]) -> List[Dict[str, Any]]:
    results = []
    for ip in ip_list:
        status, response = cf_unblock(ip)
        results.append({"ip": ip, "status": status, "response": response})
    return results

def cf_check_ip(ip: str) -> Dict[str, Any]:
    rule_id = cf_find_rule(ip)
    return {"ip": ip, "exists": rule_id is not None}

def cf_get_blocked_ips() -> List[str]:
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules"
    params = {"per_page": 100}
    r = requests.get(url, headers=HEADERS, params=params, timeout=10)
    if r.status_code == 200:
        return [rule["configuration"]["value"] for rule in r.json().get("result", [])]
    return []

def cf_block_ips_from_threats(threats: List[str]) -> List[Dict[str, Any]]:
    blocked_ips = []
    for threat in threats:
        status, response = cf_block(threat)
        blocked_ips.append({"ip": threat, "status": status, "response": response})
    return blocked_ips

def cf_unblock_ips_from_threats(threats: List[str]) -> List[Dict[str, Any]]:
    unblocked_ips = []
    for threat in threats:
        status, response = cf_unblock(threat)
        unblocked_ips.append({"ip": threat, "status": status, "response": response})
    return unblocked_ips