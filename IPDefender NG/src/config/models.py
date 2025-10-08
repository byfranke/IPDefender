"""
IPDefender Pro - Configuration Models with Pydantic Validation
Advanced configuration validation and management system

Author: byFranke (https://byfranke.com)
"""

import yaml
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, HttpUrl, validator, root_validator
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ApplicationConfig(BaseModel):
    """Application-level configuration"""
    name: str = "IPDefender Pro"
    version: str = "2.0.0"
    author: str = "byFranke"
    website: HttpUrl = "https://byfranke.com"
    environment: str = Field("production", regex="^(development|testing|production)$")
    debug: bool = False

class DatabaseConfig(BaseModel):
    """Database configuration with support for SQLite and PostgreSQL"""
    type: str = Field("sqlite", regex="^(sqlite|postgresql)$")
    path: Optional[str] = "/var/lib/ipdefender/ipdefender.db"  # For SQLite
    host: Optional[str] = None  # For PostgreSQL
    port: Optional[int] = Field(None, gt=1023, lt=65536)
    database: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    pool_size: int = Field(5, gt=0, le=50)
    max_overflow: int = Field(10, ge=0, le=100)

    @root_validator
    def validate_database_config(cls, values):
        """Validate database configuration based on type"""
        db_type = values.get('type')
        
        if db_type == 'postgresql':
            required_fields = ['host', 'port', 'database', 'username', 'password']
            for field in required_fields:
                if not values.get(field):
                    raise ValueError(f"PostgreSQL requires {field} to be configured")
        
        return values

class ThreatIntelligenceProviderConfig(BaseModel):
    """Configuration for individual threat intelligence providers"""
    enabled: bool = False
    api_key: Optional[str] = None
    weight: float = Field(1.0, ge=0.0, le=10.0)
    cache_ttl: int = Field(3600, gt=0)
    timeout: int = Field(30, gt=0, le=300)
    rate_limit: int = Field(100, gt=0)  # Requests per hour

class ThreatIntelligenceConfig(BaseModel):
    """Threat intelligence configuration"""
    cache_ttl: int = Field(3600, gt=0)
    max_concurrent_requests: int = Field(10, gt=0, le=100)
    confidence_threshold: float = Field(0.7, ge=0.0, le=1.0)
    
    # Provider configurations
    abuseipdb: ThreatIntelligenceProviderConfig = ThreatIntelligenceProviderConfig()
    otx: ThreatIntelligenceProviderConfig = ThreatIntelligenceProviderConfig()
    virustotal: ThreatIntelligenceProviderConfig = ThreatIntelligenceProviderConfig()
    misp: ThreatIntelligenceProviderConfig = ThreatIntelligenceProviderConfig()

class FirewallProviderConfig(BaseModel):
    """Configuration for individual firewall providers"""
    enabled: bool = False
    priority: int = Field(50, ge=1, le=100)
    timeout: int = Field(30, gt=0, le=300)
    
class UFWProviderConfig(FirewallProviderConfig):
    """UFW-specific configuration"""
    enabled: bool = True
    priority: int = 90

class CloudflareProviderConfig(FirewallProviderConfig):
    """Cloudflare-specific configuration"""
    api_token: Optional[str] = None
    zone_id: Optional[str] = None
    priority: int = 80

    @validator('api_token', 'zone_id')
    def validate_required_when_enabled(cls, v, values):
        """Validate required fields when Cloudflare is enabled"""
        if values.get('enabled') and not v:
            raise ValueError("api_token and zone_id are required when Cloudflare is enabled")
        return v

class ResponseEngineConfig(BaseModel):
    """Response engine configuration"""
    whitelist: List[str] = Field(default_factory=lambda: [
        "127.0.0.1",
        "10.0.0.0/8", 
        "192.168.0.0/16",
        "172.16.0.0/12"
    ])
    
    default_block_duration: int = Field(3600, gt=0)  # 1 hour
    max_block_duration: int = Field(86400, gt=0)     # 24 hours
    cleanup_interval: int = Field(300, gt=0)         # 5 minutes
    
    # Provider configurations
    ufw: UFWProviderConfig = UFWProviderConfig()
    cloudflare: CloudflareProviderConfig = CloudflareProviderConfig()

class APISecurityConfig(BaseModel):
    """API security configuration"""
    api_keys: List[str] = Field(default_factory=list, min_items=1)
    enable_cors: bool = False
    cors_origins: List[str] = Field(default_factory=list)
    rate_limit: int = Field(100, gt=0)  # Requests per minute per IP
    rate_limit_window: int = Field(60, gt=0)  # Window in seconds

class APIConfig(BaseModel):
    """API server configuration"""
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = Field(8080, gt=1023, lt=65536)
    workers: int = Field(1, gt=0, le=8)
    
    # Security settings
    security: APISecurityConfig = APISecurityConfig()

class WazuhConfig(BaseModel):
    """Wazuh SIEM integration configuration"""
    enabled: bool = False
    url: Optional[HttpUrl] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = Field(30, gt=0, le=300)
    
    @root_validator
    def validate_wazuh_config(cls, values):
        """Validate Wazuh configuration when enabled"""
        if values.get('enabled'):
            required_fields = ['url', 'username', 'password']
            for field in required_fields:
                if not values.get(field):
                    raise ValueError(f"Wazuh integration requires {field} to be configured")
        return values

class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = Field("INFO", regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    file: str = "/var/log/ipdefender/ipdefender.log"
    max_size: str = "100MB"
    backup_count: int = Field(5, ge=1, le=20)
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

class MonitoringConfig(BaseModel):
    """Monitoring and metrics configuration"""
    enabled: bool = True
    prometheus_enabled: bool = False
    prometheus_port: int = Field(9090, gt=1023, lt=65536)
    health_check_interval: int = Field(60, gt=0)
    metrics_retention_days: int = Field(30, gt=0, le=365)

class NotificationConfig(BaseModel):
    """Notification configuration"""
    enabled: bool = False
    
    # Email notifications
    email_enabled: bool = False
    smtp_server: Optional[str] = None
    smtp_port: int = Field(587, gt=0, lt=65536)
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    from_email: Optional[str] = None
    to_emails: List[str] = Field(default_factory=list)
    
    # Slack notifications
    slack_enabled: bool = False
    slack_webhook_url: Optional[HttpUrl] = None
    
    # Webhook notifications
    webhook_enabled: bool = False
    webhook_urls: List[HttpUrl] = Field(default_factory=list)

class IPDefenderProConfig(BaseModel):
    """Main IPDefender Pro configuration model"""
    
    application: ApplicationConfig = ApplicationConfig()
    database: DatabaseConfig = DatabaseConfig()
    threat_intelligence: ThreatIntelligenceConfig = ThreatIntelligenceConfig()
    response_engine: ResponseEngineConfig = ResponseEngineConfig()
    api: APIConfig = APIConfig()
    wazuh: WazuhConfig = WazuhConfig()
    logging: LoggingConfig = LoggingConfig()
    monitoring: MonitoringConfig = MonitoringConfig()
    notifications: NotificationConfig = NotificationConfig()

    class Config:
        """Pydantic model configuration"""
        validate_assignment = True
        extra = "forbid"  # Reject unknown fields
        allow_population_by_field_name = True

def load_config(config_path: str) -> IPDefenderProConfig:
    """
    Load and validate configuration from YAML file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Validated configuration object
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If configuration is invalid
        yaml.YAMLError: If YAML is malformed
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            raw_config = yaml.safe_load(f)
        
        if not raw_config:
            raw_config = {}
            
        # Validate and create configuration object
        config = IPDefenderProConfig(**raw_config)
        
        logger.info(f"Configuration loaded successfully from {config_path}")
        return config
        
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in configuration file: {e}")
    except Exception as e:
        raise ValueError(f"Configuration validation failed: {e}")

def save_config(config: IPDefenderProConfig, config_path: str) -> None:
    """
    Save configuration to YAML file
    
    Args:
        config: Configuration object to save
        config_path: Path to save configuration file
    """
    config_file = Path(config_path)
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Convert to dict and save as YAML
    config_dict = config.dict()
    
    with open(config_file, 'w', encoding='utf-8') as f:
        yaml.safe_dump(config_dict, f, default_flow_style=False, sort_keys=False)
    
    logger.info(f"Configuration saved to {config_path}")

def validate_config_file(config_path: str) -> tuple[bool, str]:
    """
    Validate configuration file without loading it into the application
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        load_config(config_path)
        return True, "Configuration is valid"
    except Exception as e:
        return False, str(e)

# Configuration singleton
_config_instance: Optional[IPDefenderProConfig] = None

def get_config() -> IPDefenderProConfig:
    """Get the current configuration instance"""
    global _config_instance
    if _config_instance is None:
        raise RuntimeError("Configuration not loaded. Call load_config() first.")
    return _config_instance

def set_config(config: IPDefenderProConfig) -> None:
    """Set the current configuration instance"""
    global _config_instance
    _config_instance = config
