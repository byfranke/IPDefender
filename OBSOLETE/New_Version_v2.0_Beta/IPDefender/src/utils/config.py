# filepath: /IPDefender/IPDefender/src/utils/config.py
import os
import yaml

class Config:
    def __init__(self, config_file='config/config.yaml'):
        self.config_file = config_file
        self.load_config()

    def load_config(self):
        with open(self.config_file, 'r') as file:
            config = yaml.safe_load(file)
            self.api_token = config.get('api_token', os.getenv('API_TOKEN'))
            self.zone_id = config.get('zone_id', os.getenv('ZONE_ID'))
            self.otx_api_key = config.get('otx_api_key', os.getenv('OTX_API_KEY'))
            self.misp_url = config.get('misp_url', os.getenv('MISP_URL'))
            self.misp_key = config.get('misp_key', os.getenv('MISP_KEY'))
            self.wazuh_url = config.get('wazuh_url', os.getenv('WAZUH_URL'))
            self.wazuh_user = config.get('wazuh_user', os.getenv('WAZUH_USER'))
            self.wazuh_password = config.get('wazuh_password', os.getenv('WAZUH_PASSWORD'))

    def get(self, key):
        return getattr(self, key, None)

config = Config()