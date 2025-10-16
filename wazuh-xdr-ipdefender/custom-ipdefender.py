#!/var/ossec/framework/python/bin/python3

import json
import sys
import time
import os
import subprocess
from socket import socket, AF_UNIX, SOCK_DGRAM

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    debug("# IPDefender Integration Starting")

    # Read args
    alert_file_location = args[1]

    debug("# Alert file location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)

    debug("# Processing alert")
    debug(json.dumps(json_alert, indent=2))

    # Extract source IP from alert
    srcip = extract_source_ip(json_alert)

    if not srcip:
        debug("# No source IP found in alert")
        return

    debug(f"# Source IP detected: {srcip}")

    # Ban IP using IPDefender
    result = ban_ip(srcip, json_alert)

    # Send event back to Wazuh
    if result:
        send_event(result, json_alert.get("agent", {}))

def extract_source_ip(alert):
    """Extract source IP from various alert data locations"""

    # Try data.srcip first (most common)
    if "data" in alert and "srcip" in alert["data"]:
        return alert["data"]["srcip"]

    # Try data.src_ip
    if "data" in alert and "src_ip" in alert["data"]:
        return alert["data"]["src_ip"]

    # Try data.source.ip
    if "data" in alert and "source" in alert["data"] and "ip" in alert["data"]["source"]:
        return alert["data"]["source"]["ip"]

    # Try full_log parsing for common patterns
    if "full_log" in alert:
        log = alert["full_log"]
        # Basic regex-like IP extraction
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, log)
        if matches:
            return matches[0]  # Return first IP found

    return None

def ban_ip(srcip, alert):
    """Ban IP using IPDefender command"""

    rule_id = alert.get("rule", {}).get("id", "unknown")
    rule_description = alert.get("rule", {}).get("description", "Wazuh alert")
    rule_level = alert.get("rule", {}).get("level", 0)

    reason = f"Wazuh Alert {rule_id} (Level {rule_level}): {rule_description}"

    debug(f"# Attempting to ban IP: {srcip}")
    debug(f"# Reason: {reason}")

    try:
        # Execute IPDefender command
        cmd = ["/usr/local/bin/IPDefender", "--ban", srcip, reason]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        debug(f"# IPDefender exit code: {result.returncode}")
        debug(f"# IPDefender stdout: {result.stdout}")

        if result.returncode == 0:
            msg = {
                "ipdefender": {
                    "action": "ban",
                    "ip": srcip,
                    "reason": reason,
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "status": "success",
                    "message": result.stdout.strip()
                }
            }
            debug("# Successfully banned IP")
            return msg
        else:
            debug(f"# Failed to ban IP: {result.stderr}")
            msg = {
                "ipdefender": {
                    "action": "ban",
                    "ip": srcip,
                    "reason": reason,
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "status": "failed",
                    "error": result.stderr.strip()
                }
            }
            return msg

    except subprocess.TimeoutExpired:
        debug("# IPDefender command timed out")
        return None
    except Exception as e:
        debug(f"# Exception running IPDefender: {str(e)}")
        return None

def send_event(msg, agent):
    """Send event back to Wazuh manager"""

    string = f"1:ipdefender:{json.dumps(msg)}"

    debug("# Sending event to Wazuh")
    debug(string)

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        debug(f"# Error sending event: {str(e)}")

def debug(msg):
    """Write debug messages to log file"""
    if debug_enabled:
        msg = f"{now}: {msg}\n"

        print(msg)

        try:
            with open(log_file, "a") as f:
                f.write(msg)
        except Exception as e:
            print(f"Error writing to log: {e}")

if __name__ == "__main__":
    try:
        # Check if we have the required arguments
        if len(sys.argv) < 2:
            debug("# Usage: custom-ipdefender.py <alert_file>")
            sys.exit(1)

        main(sys.argv)
    except Exception as e:
        debug(f"# Fatal error: {str(e)}")
        sys.exit(1)