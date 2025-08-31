"""
Wazuh Integration Module for SecGuard Enterprise
==============================================

Provides structured logging for Wazuh SIEM integration:
- JSON structured logs
- CEF format support  
- Custom rule triggers
- Event classification
- Real-time log shipping
"""

import json
import logging
import socket
import syslog
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from enum import Enum


class EventSeverity(Enum):
    """Event severity levels for SIEM integration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventCategory(Enum):
    """Event categories for better classification"""
    THREAT_DETECTION = "threat_detection"
    IP_MANAGEMENT = "ip_management"
    USER_ACTIVITY = "user_activity"
    SYSTEM_HEALTH = "system_health"
    CONFIGURATION = "configuration"
    AUTHENTICATION = "authentication"
    NETWORK_SECURITY = "network_security"


class WazuhLogger:
    """Advanced structured logging for Wazuh SIEM"""
    
    def __init__(self, config_manager, base_logger):
        self.config = config_manager
        self.base_logger = base_logger
        
        # Wazuh configuration
        self.wazuh_enabled = config_manager.get('wazuh.enabled', False)
        self.log_format = config_manager.get('wazuh.log_format', 'json')  # json, cef, syslog
        self.facility = config_manager.get('wazuh.syslog_facility', 'local0')
        self.remote_host = config_manager.get('wazuh.remote_host')
        self.remote_port = config_manager.get('wazuh.remote_port', 514)
        
        # Log paths
        self.structured_log_path = Path(config_manager.get('paths.log_dir')) / 'secguard_structured.log'
        self.wazuh_log_path = Path(config_manager.get('paths.log_dir')) / 'secguard_wazuh.log'
        
        # Initialize structured logger
        self._setup_structured_logger()
        
        # Initialize syslog if remote logging is enabled
        if self.wazuh_enabled and self.remote_host:
            self._setup_remote_logging()
    
    def _setup_structured_logger(self):
        """Setup structured JSON logger for Wazuh"""
        self.structured_logger = logging.getLogger('secguard.wazuh')
        self.structured_logger.setLevel(logging.INFO)
        
        # Prevent duplicate logs
        if not self.structured_logger.handlers:
            # File handler for structured logs
            structured_handler = logging.FileHandler(self.structured_log_path)
            
            # Custom formatter for JSON output
            json_formatter = JsonFormatter()
            structured_handler.setFormatter(json_formatter)
            
            self.structured_logger.addHandler(structured_handler)
            
            # Separate handler for Wazuh-specific logs
            wazuh_handler = logging.FileHandler(self.wazuh_log_path)
            wazuh_formatter = WazuhFormatter()
            wazuh_handler.setFormatter(wazuh_formatter)
            
            self.structured_logger.addHandler(wazuh_handler)
    
    def _setup_remote_logging(self):
        """Setup remote syslog for real-time shipping to Wazuh"""
        try:
            # Setup remote syslog handler
            syslog_handler = logging.handlers.SysLogHandler(
                address=(self.remote_host, self.remote_port),
                facility=getattr(syslog, f'LOG_{self.facility.upper()}', syslog.LOG_LOCAL0)
            )
            
            # Custom formatter for syslog
            syslog_formatter = SyslogFormatter()
            syslog_handler.setFormatter(syslog_formatter)
            
            self.structured_logger.addHandler(syslog_handler)
            
        except Exception as e:
            self.base_logger.warning(f"Failed to setup remote logging: {e}")
    
    def log_threat_detection(self, threat_data: Dict[str, Any]):
        """Log threat detection event"""
        event = self._create_base_event(
            category=EventCategory.THREAT_DETECTION,
            severity=EventSeverity(threat_data.get('severity', 'medium').lower()),
            action="threat_detected",
            description=f"Threat detected: {threat_data.get('threat_type', 'Unknown')}"
        )
        
        # Add threat-specific fields
        event.update({
            'threat_type': threat_data.get('threat_type'),
            'detection_method': threat_data.get('detection_method'),
            'risk_score': threat_data.get('risk_score', 0),
            'affected_resource': threat_data.get('resource'),
            'process_name': threat_data.get('process_name'),
            'process_path': threat_data.get('process_path'),
            'file_hash': threat_data.get('file_hash'),
            'vt_detection': threat_data.get('vt_detection'),
            'indicators': threat_data.get('indicators', [])
        })
        
        self._log_event(event)
        
        # Trigger high severity alerts
        if event['severity'] in ['critical', 'high']:
            self._trigger_alert(event)
    
    def log_ip_ban(self, ip_data: Dict[str, Any]):
        """Log IP ban event"""
        event = self._create_base_event(
            category=EventCategory.IP_MANAGEMENT,
            severity=EventSeverity.MEDIUM,
            action="ip_banned",
            description=f"IP address {ip_data.get('ip')} banned"
        )
        
        # Add IP-specific fields
        event.update({
            'src_ip': ip_data.get('ip'),
            'country': ip_data.get('country'),
            'city': ip_data.get('city'),
            'isp': ip_data.get('isp'),
            'risk_score': ip_data.get('score', 0),
            'ban_reason': ip_data.get('reason'),
            'ban_methods': ip_data.get('banned_by', []),
            'total_reports': ip_data.get('total_reports', 0),
            'geolocation': {
                'country': ip_data.get('country'),
                'city': ip_data.get('city')
            }
        })
        
        self._log_event(event)
    
    def log_ip_unban(self, ip: str, success: bool, methods: List[str]):
        """Log IP unban event"""
        event = self._create_base_event(
            category=EventCategory.IP_MANAGEMENT,
            severity=EventSeverity.LOW,
            action="ip_unbanned" if success else "ip_unban_failed",
            description=f"IP address {ip} {'unbanned' if success else 'unban failed'}"
        )
        
        event.update({
            'src_ip': ip,
            'success': success,
            'unban_methods': methods
        })
        
        self._log_event(event)
    
    def log_user_discovery(self, user_data: Dict[str, Any]):
        """Log new or suspicious user discovery"""
        severity = EventSeverity.HIGH if user_data.get('is_suspicious') else EventSeverity.LOW
        
        event = self._create_base_event(
            category=EventCategory.USER_ACTIVITY,
            severity=severity,
            action="user_discovered",
            description=f"User account discovered: {user_data.get('username')}"
        )
        
        event.update({
            'username': user_data.get('username'),
            'uid': user_data.get('uid'),
            'gid': user_data.get('gid'),
            'home_directory': user_data.get('home_dir'),
            'shell': user_data.get('shell'),
            'is_suspicious': user_data.get('is_suspicious', False),
            'is_new': user_data.get('is_new', False),
            'risk_factors': user_data.get('risk_factors', []),
            'last_login': user_data.get('last_login')
        })
        
        self._log_event(event)
        
        if user_data.get('is_suspicious'):
            self._trigger_alert(event)
    
    def log_network_connection(self, connection_data: Dict[str, Any]):
        """Log suspicious network connection"""
        if not connection_data.get('suspicious'):
            return  # Only log suspicious connections
        
        event = self._create_base_event(
            category=EventCategory.NETWORK_SECURITY,
            severity=EventSeverity.MEDIUM,
            action="suspicious_connection",
            description=f"Suspicious network connection detected"
        )
        
        event.update({
            'src_ip': connection_data.get('local_addr'),
            'src_port': connection_data.get('local_port'),
            'dst_ip': connection_data.get('remote_addr'),
            'dst_port': connection_data.get('remote_port'),
            'protocol': connection_data.get('protocol', 'TCP'),
            'connection_state': connection_data.get('status'),
            'process_name': connection_data.get('process_name'),
            'process_pid': connection_data.get('pid'),
            'risk_factors': connection_data.get('risk_factors', [])
        })
        
        self._log_event(event)
    
    def log_persistence_mechanism(self, persistence_data: Dict[str, Any]):
        """Log persistence mechanism discovery"""
        if not persistence_data.get('suspicious'):
            return  # Only log suspicious persistence
        
        event = self._create_base_event(
            category=EventCategory.THREAT_DETECTION,
            severity=EventSeverity.HIGH,
            action="persistence_detected",
            description=f"Suspicious persistence mechanism: {persistence_data.get('type')}"
        )
        
        event.update({
            'persistence_type': persistence_data.get('type'),
            'location': persistence_data.get('location'),
            'command': persistence_data.get('command'),
            'user': persistence_data.get('user'),
            'risk_factors': persistence_data.get('risk_factors', []),
            'created_date': persistence_data.get('created_date')
        })
        
        self._log_event(event)
        self._trigger_alert(event)
    
    def log_scan_summary(self, scan_results: Dict[str, Any]):
        """Log scan summary for audit trail"""
        event = self._create_base_event(
            category=EventCategory.SYSTEM_HEALTH,
            severity=EventSeverity.INFO,
            action="security_scan_completed",
            description="Security scan completed"
        )
        
        summary = scan_results.get('summary', {})
        event.update({
            'scan_duration': scan_results.get('scan_info', {}).get('duration', 0),
            'scan_types': scan_results.get('scan_info', {}).get('scan_types', []),
            'total_services': summary.get('total_services', 0),
            'suspicious_services': summary.get('suspicious_services', 0),
            'total_users': summary.get('total_users', 0),
            'suspicious_users': summary.get('suspicious_users', 0),
            'new_users': summary.get('new_users', 0),
            'network_connections': summary.get('total_connections', 0),
            'suspicious_connections': summary.get('suspicious_connections', 0),
            'persistence_items': summary.get('total_persistence', 0),
            'suspicious_persistence': summary.get('suspicious_persistence', 0),
            'overall_risk_level': summary.get('overall_risk_level', 'Unknown')
        })
        
        self._log_event(event)
    
    def log_configuration_change(self, change_data: Dict[str, Any]):
        """Log configuration changes"""
        event = self._create_base_event(
            category=EventCategory.CONFIGURATION,
            severity=EventSeverity.LOW,
            action="configuration_changed",
            description=f"Configuration changed: {change_data.get('setting')}"
        )
        
        event.update({
            'setting': change_data.get('setting'),
            'old_value': change_data.get('old_value'),
            'new_value': change_data.get('new_value'),
            'changed_by': change_data.get('user', 'system')
        })
        
        self._log_event(event)
    
    def _create_base_event(self, category: EventCategory, severity: EventSeverity, 
                          action: str, description: str) -> Dict[str, Any]:
        """Create base event structure"""
        return {
            'timestamp': datetime.now().isoformat(),
            'source': 'SecGuard Enterprise',
            'version': '1.0.0',
            'hostname': socket.gethostname(),
            'category': category.value,
            'severity': severity.value,
            'action': action,
            'description': description,
            'event_id': f"secguard_{action}_{int(datetime.now().timestamp())}",
            'rule_id': self._get_rule_id(category, action)
        }
    
    def _get_rule_id(self, category: EventCategory, action: str) -> int:
        """Generate rule ID for Wazuh rules"""
        # Custom rule IDs for SecGuard events (range: 100000-199999)
        rule_map = {
            'threat_detection': {
                'threat_detected': 100001,
                'persistence_detected': 100002,
                'suspicious_service': 100003
            },
            'ip_management': {
                'ip_banned': 100101,
                'ip_unbanned': 100102
            },
            'user_activity': {
                'user_discovered': 100201,
                'suspicious_user': 100202
            },
            'network_security': {
                'suspicious_connection': 100301
            },
            'system_health': {
                'security_scan_completed': 100401
            },
            'configuration': {
                'configuration_changed': 100501
            }
        }
        
        return rule_map.get(category.value, {}).get(action, 100000)
    
    def _log_event(self, event: Dict[str, Any]):
        """Log structured event"""
        if self.wazuh_enabled:
            self.structured_logger.info("", extra={'structured_data': event})
        else:
            # Fallback to regular logging
            self.base_logger.info(f"[{event['category']}] {event['description']}")
    
    def _trigger_alert(self, event: Dict[str, Any]):
        """Trigger high-priority alert"""
        alert_event = event.copy()
        alert_event['alert'] = True
        alert_event['urgent'] = True
        
        self.structured_logger.warning("SECURITY_ALERT", extra={'structured_data': alert_event})
    
    def generate_wazuh_rules(self) -> str:
        """Generate Wazuh rules for SecGuard events"""
        rules_xml = '''
<!-- SecGuard Enterprise Rules -->
<group name="secguard">

  <!-- Threat Detection Rules -->
  <rule id="100001" level="10">
    <decoded_as>secguard</decoded_as>
    <field name="action">threat_detected</field>
    <description>SecGuard: Threat detected</description>
    <group>secguard,threat_detection</group>
  </rule>
  
  <rule id="100002" level="12">
    <decoded_as>secguard</decoded_as>
    <field name="action">persistence_detected</field>
    <description>SecGuard: Persistence mechanism detected</description>
    <group>secguard,persistence</group>
  </rule>
  
  <!-- IP Management Rules -->
  <rule id="100101" level="5">
    <decoded_as>secguard</decoded_as>
    <field name="action">ip_banned</field>
    <description>SecGuard: IP address banned</description>
    <group>secguard,ip_ban</group>
  </rule>
  
  <!-- User Activity Rules -->
  <rule id="100201" level="7">
    <decoded_as>secguard</decoded_as>
    <field name="action">user_discovered</field>
    <field name="is_suspicious">true</field>
    <description>SecGuard: Suspicious user discovered</description>
    <group>secguard,user_activity</group>
  </rule>
  
  <!-- Network Security Rules -->
  <rule id="100301" level="8">
    <decoded_as>secguard</decoded_as>
    <field name="action">suspicious_connection</field>
    <description>SecGuard: Suspicious network connection</description>
    <group>secguard,network</group>
  </rule>
  
  <!-- System Health Rules -->
  <rule id="100401" level="3">
    <decoded_as>secguard</decoded_as>
    <field name="action">security_scan_completed</field>
    <description>SecGuard: Security scan completed</description>
    <group>secguard,scan</group>
  </rule>

</group>
'''
        return rules_xml


class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        if hasattr(record, 'structured_data'):
            return json.dumps(record.structured_data, default=str, separators=(',', ':'))
        else:
            # Fallback to structured format
            log_entry = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }
            
            if record.exc_info:
                log_entry['exception'] = self.formatException(record.exc_info)
            
            return json.dumps(log_entry, default=str, separators=(',', ':'))


class WazuhFormatter(logging.Formatter):
    """Wazuh-specific formatter"""
    
    def format(self, record):
        if hasattr(record, 'structured_data'):
            data = record.structured_data
            # Wazuh prefers key=value format
            formatted_fields = []
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value)
                formatted_fields.append(f"{key}={value}")
            
            return f"secguard: {' '.join(formatted_fields)}"
        else:
            return super().format(record)


class SyslogFormatter(logging.Formatter):
    """Syslog formatter for remote logging"""
    
    def format(self, record):
        if hasattr(record, 'structured_data'):
            data = record.structured_data
            # RFC 5424 structured data format
            timestamp = data.get('timestamp', datetime.now().isoformat())
            hostname = data.get('hostname', socket.gethostname())
            
            structured_data = []
            for key, value in data.items():
                if key not in ['timestamp', 'hostname']:
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value)
                    structured_data.append(f'{key}="{value}"')
            
            return f"<134>{timestamp} {hostname} secguard: [{' '.join(structured_data)}] {data.get('description', '')}"
        else:
            return super().format(record)
