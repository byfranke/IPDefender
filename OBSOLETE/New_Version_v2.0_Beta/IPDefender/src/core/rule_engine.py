# filepath: /IPDefender/IPDefender/src/core/rule_engine.py
import json
from src.api.wazuh import get_wazuh_alerts
from src.api.otx import fetch_otx_threats
from src.api.misp import fetch_misp_threats
from src.api.cloudflare import cf_block
from src.core.ip_manager import IPManager

class RuleEngine:
    def __init__(self):
        self.ip_manager = IPManager()

    def apply_rules(self):
        alerts = get_wazuh_alerts()
        otx_threats = fetch_otx_threats()
        misp_threats = fetch_misp_threats()

        all_threats = self._combine_threats(alerts, otx_threats, misp_threats)

        for threat in all_threats:
            ip = threat.get('ip')
            if ip and not self.ip_manager.is_blocked(ip):
                status, response = cf_block(ip)
                if status == 200:
                    self.ip_manager.add_ip(ip)

    def _combine_threats(self, alerts, otx_threats, misp_threats):
        combined = []
        combined.extend(alerts)
        combined.extend(otx_threats)
        combined.extend(misp_threats)
        return combined

    def load_rules_from_config(self, config_file):
        with open(config_file, 'r') as file:
            rules = json.load(file)
            for rule in rules:
                self._apply_rule(rule)

    def _apply_rule(self, rule):
        ip = rule.get('ip')
        if ip and not self.ip_manager.is_blocked(ip):
            status, response = cf_block(ip)
            if status == 200:
                self.ip_manager.add_ip(ip)