"""
IPDefender Pro - Plugin System Base Classes
Extensible architecture for threat intelligence and firewall providers

Author: byFranke (https://byfranke.com)
"""

import abc
import asyncio
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)

class PluginType(Enum):
    """Plugin type enumeration"""
    THREAT_PROVIDER = "threat_provider"
    FIREWALL_PROVIDER = "firewall_provider"
    NOTIFICATION_PROVIDER = "notification_provider"

class PluginStatus(Enum):
    """Plugin status enumeration"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    DISABLED = "disabled"

class ThreatCategory(Enum):
    """Threat categories"""
    MALWARE = "malware"
    BOTNET = "botnet"
    PHISHING = "phishing"
    SPAM = "spam"
    SCANNING = "scanning"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    SUSPICIOUS = "suspicious"
    REPUTATION = "reputation"
    UNKNOWN = "unknown"

class ThreatLevel(Enum):
    """Threat level enumeration"""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatEvidence:
    """Evidence from threat intelligence providers"""
    
    def __init__(self, provider: str, category: ThreatCategory, 
                 confidence: float, details: Dict[str, Any]):
        self.provider = provider
        self.category = category
        self.confidence = confidence  # 0.0 to 1.0
        self.details = details
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'provider': self.provider,
            'category': self.category.value,
            'confidence': self.confidence,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }

class ThreatAnalysisResult:
    """Threat analysis result from providers"""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.threat_score: float = 0.0
        self.confidence: float = 0.0
        self.threat_level: ThreatLevel = ThreatLevel.UNKNOWN
        self.categories: List[ThreatCategory] = []
        self.evidence: List[ThreatEvidence] = []
        self.sources_queried: int = 0
        self.sources_responded: int = 0
        self.geolocation: Optional[Dict[str, str]] = None
        self.reputation_history: List[Dict[str, Any]] = []
        self.recommendation: str = "UNKNOWN"
        self.expires_at: Optional[datetime] = None
        self.analyzed_at: datetime = datetime.now()
    
    def add_evidence(self, evidence: ThreatEvidence):
        """Add evidence to the analysis"""
        self.evidence.append(evidence)
        if evidence.category not in self.categories:
            self.categories.append(evidence.category)
    
    def calculate_threat_level(self):
        """Calculate threat level based on score"""
        if self.threat_score >= 90:
            self.threat_level = ThreatLevel.CRITICAL
            self.recommendation = "BLOCK"
        elif self.threat_score >= 70:
            self.threat_level = ThreatLevel.HIGH
            self.recommendation = "BLOCK"
        elif self.threat_score >= 40:
            self.threat_level = ThreatLevel.MEDIUM
            self.recommendation = "MONITOR"
        elif self.threat_score >= 20:
            self.threat_level = ThreatLevel.LOW
            self.recommendation = "ALLOW"
        else:
            self.threat_level = ThreatLevel.UNKNOWN
            self.recommendation = "ALLOW"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip,
            'threat_score': self.threat_score,
            'confidence': self.confidence,
            'threat_level': self.threat_level.value,
            'categories': [cat.value for cat in self.categories],
            'evidence': [ev.to_dict() for ev in self.evidence],
            'sources_queried': self.sources_queried,
            'sources_responded': self.sources_responded,
            'geolocation': self.geolocation,
            'reputation_history': self.reputation_history,
            'recommendation': self.recommendation,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'analyzed_at': self.analyzed_at.isoformat()
        }

class BasePlugin(abc.ABC):
    """Base class for all plugins"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.status = PluginStatus.INACTIVE
        self.last_error: Optional[str] = None
        self.last_used: Optional[datetime] = None
        self.usage_count: int = 0
        self.logger = logging.getLogger(f"plugin.{name}")
    
    @abc.abstractmethod
    def get_plugin_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        pass
    
    @abc.abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin"""
        pass
    
    @abc.abstractmethod
    async def cleanup(self):
        """Cleanup plugin resources"""
        pass
    
    @abc.abstractmethod
    async def health_check(self) -> bool:
        """Check if plugin is healthy"""
        pass
    
    def update_usage(self):
        """Update plugin usage statistics"""
        self.last_used = datetime.now()
        self.usage_count += 1
    
    def set_error(self, error: str):
        """Set plugin error status"""
        self.status = PluginStatus.ERROR
        self.last_error = error
        self.logger.error(f"Plugin error: {error}")
    
    def clear_error(self):
        """Clear plugin error status"""
        if self.status == PluginStatus.ERROR:
            self.status = PluginStatus.ACTIVE
            self.last_error = None

class ThreatIntelligenceProvider(BasePlugin):
    """Base class for threat intelligence providers"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.weight = config.get('weight', 1.0)
        self.cache_ttl = config.get('cache_ttl', 3600)
        self.timeout = config.get('timeout', 30)
        self.rate_limit = config.get('rate_limit', 100)  # per hour
    
    @abc.abstractmethod
    async def analyze_ip(self, ip: str) -> Optional[ThreatEvidence]:
        """
        Analyze an IP address for threats
        
        Args:
            ip: IP address to analyze
            
        Returns:
            ThreatEvidence if threats found, None otherwise
        """
        pass
    
    @abc.abstractmethod
    async def bulk_analyze(self, ips: List[str]) -> Dict[str, Optional[ThreatEvidence]]:
        """
        Analyze multiple IP addresses
        
        Args:
            ips: List of IP addresses to analyze
            
        Returns:
            Dictionary mapping IP to ThreatEvidence
        """
        pass
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Get threat provider information"""
        return {
            'name': self.name,
            'type': PluginType.THREAT_PROVIDER.value,
            'status': self.status.value,
            'weight': self.weight,
            'cache_ttl': self.cache_ttl,
            'timeout': self.timeout,
            'rate_limit': self.rate_limit,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count,
            'last_error': self.last_error
        }

class FirewallProvider(BasePlugin):
    """Base class for firewall providers"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.priority = config.get('priority', 50)
        self.timeout = config.get('timeout', 30)
    
    @abc.abstractmethod
    async def block_ip(self, ip: str, reason: str = None, duration: int = None) -> bool:
        """
        Block an IP address
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (None for permanent)
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abc.abstractmethod
    async def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address
        
        Args:
            ip: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abc.abstractmethod
    async def is_blocked(self, ip: str) -> bool:
        """
        Check if IP is blocked
        
        Args:
            ip: IP address to check
            
        Returns:
            True if blocked, False otherwise
        """
        pass
    
    @abc.abstractmethod
    async def list_blocked_ips(self) -> List[str]:
        """
        List all blocked IP addresses
        
        Returns:
            List of blocked IP addresses
        """
        pass
    
    async def bulk_block(self, ips: List[str], reason: str = None, duration: int = None) -> Dict[str, bool]:
        """
        Block multiple IP addresses
        
        Args:
            ips: List of IP addresses to block
            reason: Reason for blocking
            duration: Block duration in seconds
            
        Returns:
            Dictionary mapping IP to success status
        """
        results = {}
        for ip in ips:
            try:
                results[ip] = await self.block_ip(ip, reason, duration)
            except Exception as e:
                self.logger.error(f"Failed to block {ip}: {e}")
                results[ip] = False
        return results
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Get firewall provider information"""
        return {
            'name': self.name,
            'type': PluginType.FIREWALL_PROVIDER.value,
            'status': self.status.value,
            'priority': self.priority,
            'timeout': self.timeout,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count,
            'last_error': self.last_error
        }

class NotificationProvider(BasePlugin):
    """Base class for notification providers"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.priority = config.get('priority', 50)
        self.timeout = config.get('timeout', 30)
    
    @abc.abstractmethod
    async def send_notification(self, title: str, message: str, 
                              severity: str = "info", metadata: Dict[str, Any] = None) -> bool:
        """
        Send a notification
        
        Args:
            title: Notification title
            message: Notification message
            severity: Severity level (info, warning, error, critical)
            metadata: Additional metadata
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    async def send_threat_alert(self, ip: str, threat_score: float, 
                               action: str, metadata: Dict[str, Any] = None) -> bool:
        """
        Send threat detection alert
        
        Args:
            ip: IP address
            threat_score: Threat score (0-100)
            action: Action taken
            metadata: Additional metadata
            
        Returns:
            True if successful, False otherwise
        """
        severity = "critical" if threat_score >= 90 else "error" if threat_score >= 70 else "warning"
        
        title = f"🛡️ IPDefender Pro - Threat Detected"
        message = f"IP {ip} detected with threat score {threat_score:.1f}/100. Action: {action.upper()}"
        
        return await self.send_notification(title, message, severity, metadata)
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Get notification provider information"""
        return {
            'name': self.name,
            'type': PluginType.NOTIFICATION_PROVIDER.value,
            'status': self.status.value,
            'priority': self.priority,
            'timeout': self.timeout,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count,
            'last_error': self.last_error
        }
