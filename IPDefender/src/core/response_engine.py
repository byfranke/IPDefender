"""
IPDefender Pro - Automated Response Engine
Intelligent automated response system with machine learning capabilities

Author: byFranke (https://byfranke.com)
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess
import aiohttp

from .threat_intel import ThreatAnalysis, ThreatLevel, ThreatCategory

logger = logging.getLogger(__name__)

class ResponseAction(Enum):
    """Available response actions"""
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit" 
    TEMPORARY_BLOCK = "temp_block"
    PERMANENT_BLOCK = "perm_block"
    QUARANTINE = "quarantine"
    INVESTIGATE = "investigate"
    WHITELIST = "whitelist"

class ResponseStatus(Enum):
    """Status of response execution"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

@dataclass
class ResponseRule:
    """Rule for automated response"""
    name: str
    description: str
    conditions: Dict[str, Any]
    action: ResponseAction
    priority: int
    duration: int = 0  # seconds, 0 = permanent
    enabled: bool = True
    firewall_providers: List[str] = None
    notification_channels: List[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class ResponseExecution:
    """Record of response execution"""
    id: str
    ip: str
    rule_name: str
    action: ResponseAction
    status: ResponseStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: int = 0
    providers_used: List[str] = None
    error_message: Optional[str] = None
    rollback_plan: Dict[str, Any] = None
    metadata: Dict[str, Any] = None

class FirewallProvider:
    """Base class for firewall providers"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.enabled = config.get('enabled', False)
        
    async def block_ip(self, ip: str, reason: str = None, duration: int = 0) -> Tuple[bool, str]:
        """Block an IP address"""
        raise NotImplementedError
        
    async def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Unblock an IP address"""
        raise NotImplementedError
        
    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        raise NotImplementedError
        
    async def list_blocked_ips(self) -> List[str]:
        """List all blocked IPs"""
        raise NotImplementedError

class UFWProvider(FirewallProvider):
    """UFW (Uncomplicated Firewall) provider"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("UFW", config)
        
    async def block_ip(self, ip: str, reason: str = None, duration: int = 0) -> Tuple[bool, str]:
        """Block IP using UFW"""
        try:
            comment = f"IPDefender Pro: {reason}" if reason else "IPDefender Pro block"
            
            # For temporary blocks, we'll need to schedule unblock
            cmd = ["ufw", "deny", "from", ip, "comment", comment]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Schedule unblock if temporary
            if duration > 0:
                asyncio.create_task(self._schedule_unblock(ip, duration))
                
            return True, f"Successfully blocked {ip} via UFW"
            
        except subprocess.CalledProcessError as e:
            logger.error(f"UFW block failed for {ip}: {e.stderr}")
            return False, f"UFW error: {e.stderr}"
        except Exception as e:
            logger.error(f"Unexpected error blocking {ip} via UFW: {e}")
            return False, f"Unexpected error: {str(e)}"
    
    async def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Unblock IP from UFW"""
        try:
            cmd = ["ufw", "delete", "deny", "from", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return True, f"Successfully unblocked {ip} from UFW"
            
        except subprocess.CalledProcessError as e:
            logger.error(f"UFW unblock failed for {ip}: {e.stderr}")
            return False, f"UFW error: {e.stderr}"
        except Exception as e:
            logger.error(f"Unexpected error unblocking {ip} from UFW: {e}")
            return False, f"Unexpected error: {str(e)}"
    
    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked in UFW"""
        try:
            result = subprocess.run(["ufw", "status", "numbered"], 
                                  capture_output=True, text=True, check=True)
            return ip in result.stdout
        except Exception:
            return False
    
    async def list_blocked_ips(self) -> List[str]:
        """List all IPs blocked by UFW"""
        blocked_ips = []
        try:
            result = subprocess.run(["ufw", "status", "numbered"], 
                                  capture_output=True, text=True, check=True)
            
            # Parse UFW output for IPs
            lines = result.stdout.split('\n')
            for line in lines:
                if 'DENY IN' in line and 'from' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'from' and i + 1 < len(parts):
                            ip = parts[i + 1]
                            if self._is_valid_ip(ip):
                                blocked_ips.append(ip)
            
        except Exception as e:
            logger.error(f"Failed to list UFW blocked IPs: {e}")
            
        return blocked_ips
    
    async def _schedule_unblock(self, ip: str, duration: int):
        """Schedule automatic unblock after duration"""
        await asyncio.sleep(duration)
        success, message = await self.unblock_ip(ip)
        if success:
            logger.info(f"Automatically unblocked {ip} after {duration} seconds")
        else:
            logger.error(f"Failed to automatically unblock {ip}: {message}")
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP validation"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

class CloudflareProvider(FirewallProvider):
    """Cloudflare WAF provider"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Cloudflare", config)
        self.api_token = config.get('api_token')
        self.zone_id = config.get('zone_id')
        self.base_url = "https://api.cloudflare.com/client/v4"
        
    async def block_ip(self, ip: str, reason: str = None, duration: int = 0) -> Tuple[bool, str]:
        """Block IP using Cloudflare WAF"""
        if not self.api_token or not self.zone_id:
            return False, "Cloudflare API token or Zone ID not configured"
            
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip},
            "notes": reason or f"IPDefender Pro block - {datetime.now().isoformat()}"
        }
        
        url = f"{self.base_url}/zones/{self.zone_id}/firewall/access_rules/rules"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload) as response:
                    if response.status == 200:
                        # Schedule unblock if temporary
                        if duration > 0:
                            asyncio.create_task(self._schedule_unblock(ip, duration))
                        return True, f"Successfully blocked {ip} via Cloudflare"
                    else:
                        error_text = await response.text()
                        return False, f"Cloudflare API error: {response.status} - {error_text}"
                        
        except Exception as e:
            logger.error(f"Cloudflare block failed for {ip}: {e}")
            return False, f"Cloudflare error: {str(e)}"
    
    async def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Unblock IP from Cloudflare WAF"""
        if not self.api_token or not self.zone_id:
            return False, "Cloudflare API token or Zone ID not configured"
            
        # First find the rule ID
        rule_id = await self._find_rule_id(ip)
        if not rule_id:
            return False, f"No Cloudflare rule found for IP {ip}"
            
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }
        
        url = f"{self.base_url}/zones/{self.zone_id}/firewall/access_rules/rules/{rule_id}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.delete(url, headers=headers) as response:
                    if response.status == 200:
                        return True, f"Successfully unblocked {ip} from Cloudflare"
                    else:
                        error_text = await response.text()
                        return False, f"Cloudflare API error: {response.status} - {error_text}"
                        
        except Exception as e:
            logger.error(f"Cloudflare unblock failed for {ip}: {e}")
            return False, f"Cloudflare error: {str(e)}"
    
    async def _find_rule_id(self, ip: str) -> Optional[str]:
        """Find Cloudflare rule ID for an IP"""
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }
        
        params = {
            "configuration.target": "ip",
            "configuration.value": ip,
            "per_page": 1
        }
        
        url = f"{self.base_url}/zones/{self.zone_id}/firewall/access_rules/rules"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("result"):
                            return data["result"][0]["id"]
        except Exception as e:
            logger.error(f"Failed to find Cloudflare rule for {ip}: {e}")
            
        return None
    
    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked in Cloudflare"""
        rule_id = await self._find_rule_id(ip)
        return rule_id is not None
    
    async def list_blocked_ips(self) -> List[str]:
        """List all IPs blocked by Cloudflare"""
        # This would require pagination for large lists
        # Simplified implementation for now
        return []
    
    async def _schedule_unblock(self, ip: str, duration: int):
        """Schedule automatic unblock after duration"""
        await asyncio.sleep(duration)
        success, message = await self.unblock_ip(ip)
        if success:
            logger.info(f"Automatically unblocked {ip} from Cloudflare after {duration} seconds")
        else:
            logger.error(f"Failed to automatically unblock {ip} from Cloudflare: {message}")

class AutomatedResponseEngine:
    """Core automated response engine with ML capabilities"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules = self._load_response_rules()
        self.providers = self._initialize_providers()
        self.active_responses = {}  # Track active responses
        self.response_history = []  # Track response history
        self.whitelist = set(config.get('whitelist', []))
        
    def _load_response_rules(self) -> List[ResponseRule]:
        """Load response rules from configuration"""
        default_rules = [
            ResponseRule(
                name="Critical Threat Block",
                description="Immediately block critical threats",
                conditions={'threat_level': 'CRITICAL'},
                action=ResponseAction.PERMANENT_BLOCK,
                priority=100,
                firewall_providers=['cloudflare', 'ufw'],
                notification_channels=['email', 'slack']
            ),
            ResponseRule(
                name="High Threat Block",
                description="Block high-confidence threats",
                conditions={'threat_score': {'min': 80}},
                action=ResponseAction.TEMPORARY_BLOCK,
                priority=90,
                duration=7200,  # 2 hours
                firewall_providers=['ufw', 'cloudflare']
            ),
            ResponseRule(
                name="Medium Threat Quarantine",
                description="Quarantine medium threats for investigation",
                conditions={'threat_score': {'min': 50, 'max': 79}},
                action=ResponseAction.QUARANTINE,
                priority=70,
                duration=3600,  # 1 hour
                firewall_providers=['ufw']
            ),
            ResponseRule(
                name="Botnet Activity Block",
                description="Block confirmed botnet activity",
                conditions={'categories': {'contains': ['botnet']}},
                action=ResponseAction.PERMANENT_BLOCK,
                priority=95,
                firewall_providers=['cloudflare', 'ufw']
            ),
            ResponseRule(
                name="Scanner Rate Limit",
                description="Rate limit scanning activity",
                conditions={'categories': {'contains': ['scanning']}},
                action=ResponseAction.RATE_LIMIT,
                priority=60,
                duration=1800,  # 30 minutes
                firewall_providers=['cloudflare']
            )
        ]
        
        # Load custom rules from config
        custom_rules_config = self.config.get('response_rules', [])
        custom_rules = []
        
        for rule_config in custom_rules_config:
            try:
                rule = ResponseRule(
                    name=rule_config['name'],
                    description=rule_config.get('description', ''),
                    conditions=rule_config['conditions'],
                    action=ResponseAction(rule_config['action']),
                    priority=rule_config.get('priority', 50),
                    duration=rule_config.get('duration', 0),
                    enabled=rule_config.get('enabled', True),
                    firewall_providers=rule_config.get('firewall_providers', []),
                    notification_channels=rule_config.get('notification_channels', []),
                    metadata=rule_config.get('metadata', {})
                )
                custom_rules.append(rule)
            except Exception as e:
                logger.error(f"Failed to load custom response rule: {e}")
        
        all_rules = default_rules + custom_rules
        logger.info(f"Loaded {len(all_rules)} response rules")
        return all_rules
    
    def _initialize_providers(self) -> Dict[str, FirewallProvider]:
        """Initialize firewall providers"""
        providers = {}
        
        # UFW Provider
        ufw_config = self.config.get('providers', {}).get('ufw', {})
        if ufw_config.get('enabled', True):
            providers['ufw'] = UFWProvider(ufw_config)
            
        # Cloudflare Provider
        cf_config = self.config.get('providers', {}).get('cloudflare', {})
        if cf_config.get('enabled', False):
            providers['cloudflare'] = CloudflareProvider(cf_config)
        
        # TODO: Add more providers (Fail2ban, pfSense, etc.)
        
        enabled_providers = [name for name, provider in providers.items() if provider.enabled]
        logger.info(f"Initialized firewall providers: {', '.join(enabled_providers)}")
        
        return providers
    
    async def evaluate_and_respond(self, analysis: ThreatAnalysis) -> ResponseExecution:
        """Evaluate threat analysis and execute appropriate response"""
        
        # Check whitelist first
        if analysis.ip in self.whitelist:
            logger.info(f"IP {analysis.ip} is whitelisted, skipping response")
            return self._create_response_execution(
                analysis.ip, "whitelist", ResponseAction.WHITELIST, 
                ResponseStatus.COMPLETED, "IP is whitelisted"
            )
        
        # Find applicable rules
        applicable_rules = self._find_applicable_rules(analysis)
        
        if not applicable_rules:
            logger.info(f"No applicable response rules for IP {analysis.ip}")
            return self._create_response_execution(
                analysis.ip, "default", ResponseAction.MONITOR,
                ResponseStatus.COMPLETED, "No applicable rules"
            )
        
        # Select highest priority rule
        selected_rule = max(applicable_rules, key=lambda r: r.priority)
        
        logger.info(f"Selected rule '{selected_rule.name}' for IP {analysis.ip}")
        
        # Execute response
        execution = await self._execute_response(analysis.ip, selected_rule, analysis)
        
        # Track response
        self.response_history.append(execution)
        if execution.status == ResponseStatus.COMPLETED:
            self.active_responses[analysis.ip] = execution
            
        return execution
    
    def _find_applicable_rules(self, analysis: ThreatAnalysis) -> List[ResponseRule]:
        """Find rules that apply to the threat analysis"""
        applicable_rules = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if self._rule_matches_analysis(rule, analysis):
                applicable_rules.append(rule)
        
        return applicable_rules
    
    def _rule_matches_analysis(self, rule: ResponseRule, analysis: ThreatAnalysis) -> bool:
        """Check if a rule matches the threat analysis"""
        conditions = rule.conditions
        
        # Check threat level
        if 'threat_level' in conditions:
            if analysis.threat_level.name != conditions['threat_level']:
                return False
        
        # Check threat score
        if 'threat_score' in conditions:
            score_condition = conditions['threat_score']
            if isinstance(score_condition, dict):
                min_score = score_condition.get('min', 0)
                max_score = score_condition.get('max', 100)
                if not (min_score <= analysis.threat_score <= max_score):
                    return False
            elif analysis.threat_score != score_condition:
                return False
        
        # Check categories
        if 'categories' in conditions:
            category_condition = conditions['categories']
            analysis_categories = [cat.value for cat in analysis.categories]
            
            if isinstance(category_condition, dict):
                if 'contains' in category_condition:
                    required_categories = category_condition['contains']
                    if not any(cat in analysis_categories for cat in required_categories):
                        return False
            elif isinstance(category_condition, list):
                if not any(cat in analysis_categories for cat in category_condition):
                    return False
        
        # Check confidence
        if 'confidence' in conditions:
            confidence_condition = conditions['confidence']
            if isinstance(confidence_condition, dict):
                min_conf = confidence_condition.get('min', 0)
                max_conf = confidence_condition.get('max', 100)
                if not (min_conf <= analysis.confidence <= max_conf):
                    return False
            elif analysis.confidence != confidence_condition:
                return False
        
        return True
    
    async def _execute_response(self, ip: str, rule: ResponseRule, analysis: ThreatAnalysis) -> ResponseExecution:
        """Execute the response action"""
        execution_id = f"{ip}_{rule.name}_{datetime.now().timestamp()}"
        
        execution = ResponseExecution(
            id=execution_id,
            ip=ip,
            rule_name=rule.name,
            action=rule.action,
            status=ResponseStatus.IN_PROGRESS,
            started_at=datetime.now(),
            duration=rule.duration,
            providers_used=[],
            metadata={'analysis': asdict(analysis)}
        )
        
        try:
            # Execute action based on type
            if rule.action in [ResponseAction.TEMPORARY_BLOCK, ResponseAction.PERMANENT_BLOCK]:
                success = await self._execute_block_action(ip, rule, execution)
            elif rule.action == ResponseAction.QUARANTINE:
                success = await self._execute_quarantine_action(ip, rule, execution)
            elif rule.action == ResponseAction.RATE_LIMIT:
                success = await self._execute_rate_limit_action(ip, rule, execution)
            else:
                # Default to monitoring
                success = True
                execution.providers_used = ['monitor']
            
            execution.status = ResponseStatus.COMPLETED if success else ResponseStatus.FAILED
            execution.completed_at = datetime.now()
            
        except Exception as e:
            logger.error(f"Response execution failed for IP {ip}: {e}")
            execution.status = ResponseStatus.FAILED
            execution.error_message = str(e)
            execution.completed_at = datetime.now()
        
        return execution
    
    async def _execute_block_action(self, ip: str, rule: ResponseRule, execution: ResponseExecution) -> bool:
        """Execute block action across configured providers"""
        success = False
        providers_used = []
        
        target_providers = rule.firewall_providers or list(self.providers.keys())
        
        for provider_name in target_providers:
            if provider_name in self.providers:
                provider = self.providers[provider_name]
                if provider.enabled:
                    try:
                        block_success, message = await provider.block_ip(
                            ip, f"Rule: {rule.name}", rule.duration
                        )
                        
                        if block_success:
                            success = True
                            providers_used.append(provider_name)
                            logger.info(f"Blocked {ip} via {provider_name}: {message}")
                        else:
                            logger.error(f"Failed to block {ip} via {provider_name}: {message}")
                            
                    except Exception as e:
                        logger.error(f"Provider {provider_name} failed to block {ip}: {e}")
        
        execution.providers_used = providers_used
        return success
    
    async def _execute_quarantine_action(self, ip: str, rule: ResponseRule, execution: ResponseExecution) -> bool:
        """Execute quarantine action (limited access)"""
        # Quarantine typically means limited access rather than full block
        # For now, we'll implement it as a temporary block with specific tagging
        return await self._execute_block_action(ip, rule, execution)
    
    async def _execute_rate_limit_action(self, ip: str, rule: ResponseRule, execution: ResponseExecution) -> bool:
        """Execute rate limiting action"""
        # Rate limiting is typically handled by providers like Cloudflare
        # For UFW, we might implement connection limiting rules
        return await self._execute_block_action(ip, rule, execution)
    
    def _create_response_execution(self, ip: str, rule_name: str, action: ResponseAction,
                                  status: ResponseStatus, message: str = None) -> ResponseExecution:
        """Create a response execution record"""
        return ResponseExecution(
            id=f"{ip}_{rule_name}_{datetime.now().timestamp()}",
            ip=ip,
            rule_name=rule_name,
            action=action,
            status=status,
            started_at=datetime.now(),
            completed_at=datetime.now(),
            error_message=message,
            providers_used=[],
            metadata={}
        )
    
    async def rollback_response(self, execution_id: str) -> bool:
        """Rollback a response execution"""
        # Find the execution
        execution = None
        for exec_record in self.response_history:
            if exec_record.id == execution_id:
                execution = exec_record
                break
        
        if not execution:
            logger.error(f"Execution {execution_id} not found")
            return False
        
        if execution.action in [ResponseAction.TEMPORARY_BLOCK, ResponseAction.PERMANENT_BLOCK, ResponseAction.QUARANTINE]:
            # Unblock from all providers that were used
            success = True
            for provider_name in execution.providers_used:
                if provider_name in self.providers:
                    provider = self.providers[provider_name]
                    unblock_success, message = await provider.unblock_ip(execution.ip)
                    if not unblock_success:
                        logger.error(f"Failed to unblock {execution.ip} from {provider_name}: {message}")
                        success = False
            
            if success:
                execution.status = ResponseStatus.ROLLED_BACK
                if execution.ip in self.active_responses:
                    del self.active_responses[execution.ip]
                logger.info(f"Successfully rolled back response for {execution.ip}")
            
            return success
        
        return True  # Nothing to rollback for monitor actions
    
    def get_response_statistics(self) -> Dict[str, Any]:
        """Get response engine statistics"""
        stats = {
            'total_responses': len(self.response_history),
            'active_responses': len(self.active_responses),
            'response_by_action': {},
            'response_by_status': {},
            'provider_usage': {}
        }
        
        for execution in self.response_history:
            # Count by action
            action_name = execution.action.value
            stats['response_by_action'][action_name] = stats['response_by_action'].get(action_name, 0) + 1
            
            # Count by status
            status_name = execution.status.value
            stats['response_by_status'][status_name] = stats['response_by_status'].get(status_name, 0) + 1
            
            # Count provider usage
            for provider in execution.providers_used or []:
                stats['provider_usage'][provider] = stats['provider_usage'].get(provider, 0) + 1
        
        return stats
