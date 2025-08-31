#!/usr/bin/env python3
import sys
from src.api.cloudflare import cf_block, cf_unblock
from src.api.otx import fetch_threats as fetch_otx_threats
from src.api.misp import fetch_threats as fetch_misp_threats
from src.api.wazuh import fetch_wazuh_alerts
from src.core.threat_intel import process_threats
from src.core.ip_manager import manage_ip
from src.utils.config import load_config
from src.utils.logger import setup_logging

def main():
    setup_logging()
    config = load_config()

    # Fetch threats from OTX and MISP
    otx_threats = fetch_otx_threats(config['otx_api_key'])
    misp_threats = fetch_misp_threats(config['misp_api_key'])
    
    # Process and manage threats
    threats = process_threats(otx_threats, misp_threats)
    
    # Fetch alerts from Wazuh
    wazuh_alerts = fetch_wazuh_alerts(config['wazuh_api_key'])
    
    # Manage IPs based on threats and alerts
    for threat in threats:
        manage_ip(threat['ip'], cf_block)
    
    for alert in wazuh_alerts:
        manage_ip(alert['ip'], cf_block)

if __name__ == "__main__":
    main()