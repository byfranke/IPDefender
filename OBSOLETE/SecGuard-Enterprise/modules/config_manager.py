"""
Configuration Manager Module for SecGuard Enterprise
==================================================

Handles all configuration management including:
- API keys storage and retrieval
- Application settings
- Security credentials management
- Configuration validation
"""

import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional
import keyring


class ConfigManager:
    """Secure configuration management with encrypted credential storage"""
    
    def __init__(self, config_dir: Path = Path("/etc/secguard")):
        self.config_dir = config_dir
        self.config_file = config_dir / "secguard.conf"
        self.service_name = "secguard-enterprise"
        
        # Ensure config directory exists with proper permissions
        self.config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.config_dir, stat.S_IRWXU)  # 700 permissions
        
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return self._default_config()
        return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "version": "1.0.0",
            "features": {
                "threat_hunting": True,
                "ip_defense": True,
                "scheduled_scans": False,
                "email_reports": False,
                "cloudflare_integration": False,
                "webhook_notifications": False,
                "wazuh_integration": False
            },
            "hunting": {
                "deep_scan": False,
                "virustotal_enabled": False,
                "check_services": True,
                "check_users": True,
                "check_persistence": True,
                "check_network": True
            },
            "ip_defense": {
                "use_ufw": True,
                "use_fail2ban": True,
                "use_cloudflare": False,
                "geolocation_enabled": True,
                "auto_ban_threshold": 80
            },
            "email": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "use_tls": True,
                "sender_email": "",
                "recipient_emails": []
            },
            "webhooks": {
                "enabled": False,
                "configurations": [
                    {
                        "name": "discord_security",
                        "type": "discord",
                        "url": "",
                        "enabled": False
                    },
                    {
                        "name": "slack_alerts",
                        "type": "slack", 
                        "url": "",
                        "enabled": False
                    }
                ]
            },
            "wazuh": {
                "enabled": False,
                "log_format": "json",
                "syslog_facility": "local0",
                "remote_host": "",
                "remote_port": 514
            },
            "scheduling": {
                "hunt_frequency": "weekly",
                "hunt_enabled": False,
                "hunt_time": "02:00"
            },
            "paths": {
                "log_dir": "/var/log/secguard",
                "data_dir": "/var/lib/secguard",
                "quarantine_dir": "/var/lib/secguard/quarantine",
                "reports_dir": "/var/lib/secguard/reports"
            },
            "web_dashboard": {
                "enabled": False,
                "host": "127.0.0.1",
                "port": 8888,
                "allowed_ips": ["127.0.0.1", "::1"],
                "api_key": None,
                "auto_open": True
            }
        }
    
    def save_config(self):
        """Save configuration to file with proper permissions"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self._config, f, indent=2)
            os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)  # 600 permissions
        except IOError as e:
            raise Exception(f"Failed to save configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config()
    
    def is_configured(self) -> bool:
        """Check if basic configuration is complete"""
        required_checks = [
            self.get('features.threat_hunting'),
            self.get('features.ip_defense')
        ]
        return all(required_checks)
    
    def set_api_key(self, service: str, api_key: str):
        """Securely store API key using keyring"""
        try:
            keyring.set_password(self.service_name, service, api_key)
        except Exception as e:
            raise Exception(f"Failed to store API key for {service}: {e}")
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Retrieve API key from secure storage"""
        try:
            return keyring.get_password(self.service_name, service)
        except Exception:
            return None
    
    def set_email_password(self, password: str):
        """Securely store email password"""
        self.set_api_key("email_password", password)
    
    def get_email_password(self) -> Optional[str]:
        """Retrieve email password"""
        return self.get_api_key("email_password")
    
    def validate_email_config(self) -> bool:
        """Validate email configuration"""
        if not self.get('email.enabled'):
            return True
            
        required_fields = [
            'email.smtp_server',
            'email.sender_email',
            'email.recipient_emails'
        ]
        
        for field in required_fields:
            if not self.get(field):
                return False
        
        return bool(self.get_email_password())
    
    def validate_virustotal_config(self) -> bool:
        """Validate VirusTotal configuration"""
        if not self.get('hunting.virustotal_enabled'):
            return True
        return bool(self.get_api_key('virustotal'))
    
    def validate_cloudflare_config(self) -> bool:
        """Validate CloudFlare configuration"""
        if not self.get('ip_defense.use_cloudflare'):
            return True
        
        return bool(
            self.get_api_key('cloudflare_token') and 
            self.get_api_key('cloudflare_zone_id')
        )
    
    def get_full_config(self) -> Dict[str, Any]:
        """Get full configuration (without sensitive data)"""
        config = self._config.copy()
        
        # Add API key status (but not actual keys)
        config['api_keys'] = {
            'virustotal': bool(self.get_api_key('virustotal')),
            'cloudflare_token': bool(self.get_api_key('cloudflare_token')),
            'cloudflare_zone_id': bool(self.get_api_key('cloudflare_zone_id')),
            'email_password': bool(self.get_email_password())
        }
        
        return config
    
    def create_directories(self):
        """Create necessary directories with proper permissions"""
        directories = [
            self.get('paths.log_dir'),
            self.get('paths.data_dir'),
            self.get('paths.quarantine_dir'),
            self.get('paths.reports_dir')
        ]
        
        for directory in directories:
            path = Path(directory)
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)  # 750 permissions
    
    def export_config(self, export_path: Path, include_keys: bool = False):
        """Export configuration to file"""
        config = self.get_full_config()
        
        if include_keys:
            config['sensitive_data'] = {
                'virustotal_key': self.get_api_key('virustotal'),
                'cloudflare_token': self.get_api_key('cloudflare_token'),
                'cloudflare_zone_id': self.get_api_key('cloudflare_zone_id'),
                'email_password': self.get_email_password()
            }
        
        with open(export_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Secure permissions if including sensitive data
        if include_keys:
            os.chmod(export_path, stat.S_IRUSR | stat.S_IWUSR)  # 600 permissions
    
    def import_config(self, import_path: Path):
        """Import configuration from file"""
        with open(import_path, 'r') as f:
            imported_config = json.load(f)
        
        # Import API keys if present
        if 'sensitive_data' in imported_config:
            sensitive = imported_config.pop('sensitive_data')
            for service, value in sensitive.items():
                if value:
                    if service == 'email_password':
                        self.set_email_password(value)
                    else:
                        service_name = service.replace('_key', '').replace('_token', '').replace('_id', '')
                        self.set_api_key(service_name, value)
        
        # Remove API key status from imported config
        imported_config.pop('api_keys', None)
        
        # Merge with current config
        self._config.update(imported_config)
        self.save_config()
