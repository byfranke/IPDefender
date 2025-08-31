#!/usr/bin/env python3
import sys, time, json, requests

API_TOKEN = "****"
ZONE_ID = "****"

HEADERS = {"Authorization": f"Bearer {API_TOKEN}",
           "Content-Type": "application/json"}

def cf_block(ip: str):
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules"
    payload = {"mode": "block",
               "configuration": {"target": "ip", "value": ip},
               "notes": f"Blocked by Wazuh {int(time.time())}"}
    r = requests.post(url, headers=HEADERS, json=payload, timeout=10)
    return r.status_code, r.text

def cf_find_rule(ip: str):
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules"
    params = {"configuration.target": "ip", "configuration.value": ip, "per_page": 1}
    r = requests.get(url, headers=HEADERS, params=params, timeout=10)
    if r.status_code == 200 and r.json().get("result"):
        return r.json()["result"][0]["id"]
    return None

def cf_unblock(ip: str):
    rule_id = cf_find_rule(ip)
    if not rule_id:
        return 404, '{"success":false,"errors":[{"message":"rule not found"}]}'
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules/{rule_id}"
    r = requests.delete(url, headers=HEADERS, timeout=10)
    return r.status_code, r.text

def main():
    if len(sys.argv) < 3:
        sys.exit(1)
    action, ip = sys.argv[1], sys.argv[2]
    if action == "add":
        status, body = cf_block(ip)
    elif action in ("delete", "del"):
        status, body = cf_unblock(ip)
    else:
        sys.exit(0)
    print(json.dumps({"status": status, "response": body}))
    sys.exit(0 if 200 <= status < 300 else 1)

if __name__ == "__main__":
    main()