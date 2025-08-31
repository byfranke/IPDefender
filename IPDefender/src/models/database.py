"""
IPDefender Pro - Database Models and ORM
SQLAlchemy models for persistent data storage and audit trails

Author: byFranke (https://byfranke.com)
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, Any, List
import json

try:
    from sqlalchemy import (
        Column, Integer, String, DateTime, Boolean, Text, Float,
        ForeignKey, Index, UniqueConstraint, JSON
    )
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import relationship
    from sqlalchemy.sql import func
except ImportError:
    # Mock for development environment
    pass

Base = declarative_base()

class ThreatLevel(Enum):
    """Threat level enumeration"""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ActionType(Enum):
    """Response action type enumeration"""
    BLOCK = "block"
    TEMP_BLOCK = "temp_block"
    WHITELIST = "whitelist"
    MONITOR = "monitor"
    UNBLOCK = "unblock"

class ResponseStatus(Enum):
    """Response status enumeration"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    PENDING = "pending"

class ThreatAnalysis(Base):
    """Threat intelligence analysis results"""
    __tablename__ = "threat_analyses"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, index=True)  # IPv4/IPv6
    threat_score = Column(Float, nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    threat_level = Column(String(20), nullable=False, index=True)
    
    # Analysis metadata
    sources_queried = Column(Integer, nullable=False, default=0)
    sources_responded = Column(Integer, nullable=False, default=0)
    categories = Column(JSON)  # List of threat categories
    evidence = Column(JSON)    # Evidence from providers
    
    # Geolocation data
    country_code = Column(String(2))
    country_name = Column(String(100))
    isp = Column(String(200))
    asn = Column(String(50))
    
    # Timing
    analyzed_at = Column(DateTime, nullable=False, default=func.now(), index=True)
    expires_at = Column(DateTime, index=True)
    
    # Analysis results
    recommendation = Column(String(50))  # BLOCK, ALLOW, MONITOR
    provider_responses = Column(JSON)    # Raw responses from providers
    
    # Relationships
    responses = relationship("ResponseAction", back_populates="analysis")
    
    # Indexes
    __table_args__ = (
        Index('ix_ip_analyzed_at', 'ip_address', 'analyzed_at'),
        Index('ix_threat_score_analyzed_at', 'threat_score', 'analyzed_at'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'threat_score': self.threat_score,
            'confidence': self.confidence,
            'threat_level': self.threat_level,
            'sources_queried': self.sources_queried,
            'sources_responded': self.sources_responded,
            'categories': self.categories or [],
            'evidence': self.evidence or [],
            'country_code': self.country_code,
            'country_name': self.country_name,
            'isp': self.isp,
            'asn': self.asn,
            'analyzed_at': self.analyzed_at.isoformat() if self.analyzed_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'recommendation': self.recommendation,
        }

class ResponseAction(Base):
    """Response actions taken against IPs"""
    __tablename__ = "response_actions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, index=True)
    action = Column(String(20), nullable=False, index=True)  # ActionType
    status = Column(String(20), nullable=False, index=True)  # ResponseStatus
    
    # Action metadata
    rule_name = Column(String(100))
    priority = Column(Integer, default=50)
    duration = Column(Integer)  # Duration in seconds for temporary actions
    providers_used = Column(JSON)  # List of firewall providers used
    
    # Timing
    created_at = Column(DateTime, nullable=False, default=func.now(), index=True)
    executed_at = Column(DateTime, index=True)
    expires_at = Column(DateTime, index=True)
    
    # Results
    success = Column(Boolean, default=False)
    error_message = Column(Text)
    provider_results = Column(JSON)  # Results from each provider
    
    # Source information
    source = Column(String(50))  # wazuh, api, manual, etc.
    source_rule_id = Column(String(50))
    reason = Column(Text)
    
    # Relationships
    analysis_id = Column(Integer, ForeignKey('threat_analyses.id'), index=True)
    analysis = relationship("ThreatAnalysis", back_populates="responses")
    
    # Indexes
    __table_args__ = (
        Index('ix_ip_action_created_at', 'ip_address', 'action', 'created_at'),
        Index('ix_expires_at_status', 'expires_at', 'status'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'action': self.action,
            'status': self.status,
            'rule_name': self.rule_name,
            'priority': self.priority,
            'duration': self.duration,
            'providers_used': self.providers_used or [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'success': self.success,
            'error_message': self.error_message,
            'source': self.source,
            'reason': self.reason,
        }

class BlockedIP(Base):
    """Currently blocked IPs (active blocks)"""
    __tablename__ = "blocked_ips"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    
    # Block metadata
    block_type = Column(String(20), nullable=False)  # permanent, temporary
    providers = Column(JSON, nullable=False)  # Active providers blocking this IP
    
    # Timing
    blocked_at = Column(DateTime, nullable=False, default=func.now(), index=True)
    expires_at = Column(DateTime, index=True)  # NULL for permanent blocks
    
    # Source information
    source = Column(String(50))
    reason = Column(Text)
    threat_score = Column(Float, index=True)
    
    # Block management
    block_count = Column(Integer, default=1)  # How many times this IP was blocked
    last_seen = Column(DateTime, default=func.now())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'block_type': self.block_type,
            'providers': self.providers or [],
            'blocked_at': self.blocked_at.isoformat() if self.blocked_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'source': self.source,
            'reason': self.reason,
            'threat_score': self.threat_score,
            'block_count': self.block_count,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }

class WhitelistedIP(Base):
    """Whitelisted IPs and networks"""
    __tablename__ = "whitelisted_ips"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_network = Column(String(50), nullable=False, unique=True, index=True)  # IP or CIDR
    
    # Whitelist metadata
    description = Column(String(200))
    source = Column(String(50))  # manual, config, auto
    
    # Timing
    created_at = Column(DateTime, nullable=False, default=func.now())
    expires_at = Column(DateTime, index=True)  # NULL for permanent
    
    # Usage tracking
    hit_count = Column(Integer, default=0)  # How many times this rule was used
    last_hit = Column(DateTime)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'ip_network': self.ip_network,
            'description': self.description,
            'source': self.source,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'hit_count': self.hit_count,
            'last_hit': self.last_hit.isoformat() if self.last_hit else None,
        }

class SystemMetric(Base):
    """System metrics and performance data"""
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    metric_type = Column(String(20), default='gauge')  # gauge, counter, histogram
    
    # Metadata
    tags = Column(JSON)  # Additional tags for the metric
    timestamp = Column(DateTime, nullable=False, default=func.now(), index=True)
    
    # Indexes
    __table_args__ = (
        Index('ix_metric_name_timestamp', 'metric_name', 'timestamp'),
    )

class AuditLog(Base):
    """Audit trail for all system actions"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Action information
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50))  # ip, config, user, etc.
    resource_id = Column(String(100))
    
    # Actor information
    actor_type = Column(String(20), default='system')  # system, user, api
    actor_id = Column(String(100))  # username, api_key_id, etc.
    
    # Request information
    source_ip = Column(String(45))
    user_agent = Column(String(500))
    
    # Details
    details = Column(JSON)  # Additional action details
    result = Column(String(20))  # success, failure, error
    error_message = Column(Text)
    
    # Timing
    timestamp = Column(DateTime, nullable=False, default=func.now(), index=True)
    
    # Indexes
    __table_args__ = (
        Index('ix_action_timestamp', 'action', 'timestamp'),
        Index('ix_resource_type_id', 'resource_type', 'resource_id'),
        Index('ix_actor_type_id', 'actor_type', 'actor_id'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'actor_type': self.actor_type,
            'actor_id': self.actor_id,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
            'details': self.details or {},
            'result': self.result,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }

# Database utility functions
def create_tables(engine):
    """Create all database tables"""
    Base.metadata.create_all(engine)

def drop_tables(engine):
    """Drop all database tables"""
    Base.metadata.drop_all(engine)
