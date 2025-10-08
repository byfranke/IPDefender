"""
IPDefender Pro - Enhanced Response Engine V2
Advanced automated response system with plugin architecture

Author: byFranke (https://byfranke.com)
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from plugins.manager import PluginManager
from database.manager import DatabaseManager
from monitoring.metrics import MonitoringManager
from core.response_engine import AutomatedResponseEngine
from core.threat_intel_v2 import ThreatAnalysisResult

logger = logging.getLogger(__name__)

class ResponseAction(Enum):
    """Response action types"""
    BLOCK_IP = "block_ip"
    BLOCK_NETWORK = "block_network"
    RATE_LIMIT = "rate_limit"
    CAPTCHA_CHALLENGE = "captcha_challenge"
    MONITOR_ONLY = "monitor_only"
    QUARANTINE = "quarantine"
    NOTIFY_ADMIN = "notify_admin"

class ResponsePriority(Enum):
    """Response priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ResponseRequest:
    """Request for automated response"""
    ip_address: str
    threat_analysis: ThreatAnalysisResult
    requested_actions: List[ResponseAction]
    priority: ResponsePriority
    metadata: Dict[str, Any]
    source: str
    timestamp: datetime

@dataclass
class ResponseResult:
    """Result of automated response execution"""
    request_id: str
    ip_address: str
    actions_executed: List[ResponseAction]
    actions_failed: List[ResponseAction]
    success_rate: float
    execution_time: float
    provider_results: Dict[str, Any]
    metadata: Dict[str, Any]
    timestamp: datetime

class AutomatedResponseEngineV2(AutomatedResponseEngine):
    """Enhanced automated response engine with plugin system and database persistence"""
    
    def __init__(self, config: Dict[str, Any], plugin_manager: PluginManager,
                 db_manager: DatabaseManager, monitoring_manager: MonitoringManager):
        """Initialize enhanced response engine"""
        self.config = config
        self.plugin_manager = plugin_manager
        self.db_manager = db_manager
        self.monitoring = monitoring_manager
        
        # Response tracking
        self.active_responses = {}
        self.response_stats = {
            'total_requests': 0,
            'successful_responses': 0,
            'failed_responses': 0,
            'blocked_ips': set(),
            'temporary_blocks': {}
        }
        
        # Provider health tracking
        self.provider_health = {}
        
        # Rate limiting for response actions
        self.action_rate_limits = {}
        
        # Response rules engine
        self.response_rules = self._load_response_rules()
        
        logger.info("AutomatedResponseEngineV2 initialized")
    
    async def initialize(self):
        """Initialize the response engine"""
        try:
            logger.info("Initializing Enhanced Response Engine...")
            
            # Get available firewall/response providers
            self.providers = self.plugin_manager.get_plugins_by_type('firewall')
            
            logger.info(f"Loaded {len(self.providers)} response providers")
            
            # Initialize provider health tracking
            for provider_name, provider in self.providers.items():
                self.provider_health[provider_name] = {
                    'status': 'unknown',
                    'last_check': datetime.now(),
                    'response_time': 0.0,
                    'error_count': 0,
                    'success_count': 0,
                    'actions_executed': 0
                }
            
            # Initial health check
            await self._health_check_providers()
            
            # Start background tasks
            asyncio.create_task(self._cleanup_temporary_blocks())
            asyncio.create_task(self._periodic_health_checks())
            
            logger.info("Enhanced Response Engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize response engine: {e}")
            raise
    
    async def execute_response(self, threat_analysis: ThreatAnalysisResult, 
                              source: str = "auto") -> ResponseResult:
        """Execute automated response based on threat analysis"""
        start_time = datetime.now()
        request_id = f"resp_{int(start_time.timestamp())}_{threat_analysis.ip_address}"
        
        try:
            logger.info(f"Processing response for IP: {threat_analysis.ip_address} "
                       f"(Score: {threat_analysis.threat_score})")
            
            # Determine appropriate response actions
            response_actions = self._determine_response_actions(threat_analysis)
            priority = self._determine_priority(threat_analysis)
            
            # Create response request
            request = ResponseRequest(
                ip_address=threat_analysis.ip_address,
                threat_analysis=threat_analysis,
                requested_actions=response_actions,
                priority=priority,
                metadata={'source': source},
                source=source,
                timestamp=start_time
            )
            
            # Track active response
            self.active_responses[request_id] = request
            
            # Execute response actions
            execution_results = await self._execute_response_actions(request)
            
            # Calculate success rate
            total_actions = len(response_actions)
            successful_actions = len(execution_results['successful'])
            success_rate = successful_actions / total_actions if total_actions > 0 else 0
            
            # Create response result
            result = ResponseResult(
                request_id=request_id,
                ip_address=threat_analysis.ip_address,
                actions_executed=execution_results['successful'],
                actions_failed=execution_results['failed'],
                success_rate=success_rate,
                execution_time=(datetime.now() - start_time).total_seconds(),
                provider_results=execution_results['provider_details'],
                metadata={
                    'threat_score': threat_analysis.threat_score,
                    'threat_types': threat_analysis.threat_types,
                    'sources': threat_analysis.sources
                },
                timestamp=datetime.now()
            )
            
            # Store in database
            await self._store_response_result(result)
            
            # Update statistics
            self.response_stats['total_requests'] += 1
            if success_rate > 0.5:  # Consider successful if more than half actions succeeded
                self.response_stats['successful_responses'] += 1
            else:
                self.response_stats['failed_responses'] += 1
            
            # Record metrics
            self.monitoring.record_metric('response_engine_requests', 1)
            self.monitoring.record_metric('response_engine_execution_time', result.execution_time)
            self.monitoring.record_metric('response_engine_success_rate', success_rate)
            
            # Track blocked IPs
            if ResponseAction.BLOCK_IP in result.actions_executed:
                self.response_stats['blocked_ips'].add(threat_analysis.ip_address)
                self.monitoring.record_metric('response_engine_ips_blocked', 1)
            
            # Remove from active responses
            del self.active_responses[request_id]
            
            logger.info(f"Response executed for {threat_analysis.ip_address}: "
                       f"{len(result.actions_executed)} actions successful, "
                       f"{len(result.actions_failed)} failed")
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing response for {threat_analysis.ip_address}: {e}")
            self.monitoring.record_metric('response_engine_errors', 1)
            
            # Clean up active response
            if request_id in self.active_responses:
                del self.active_responses[request_id]
            
            # Return error result
            return ResponseResult(
                request_id=request_id,
                ip_address=threat_analysis.ip_address,
                actions_executed=[],
                actions_failed=response_actions if 'response_actions' in locals() else [],
                success_rate=0.0,
                execution_time=(datetime.now() - start_time).total_seconds(),
                provider_results={},
                metadata={'error': str(e)},
                timestamp=datetime.now()
            )
    
    def _determine_response_actions(self, threat_analysis: ThreatAnalysisResult) -> List[ResponseAction]:
        """Determine appropriate response actions based on threat analysis"""
        actions = []
        score = threat_analysis.threat_score
        threat_types = set(threat_analysis.threat_types)
        
        # Apply response rules
        for rule in self.response_rules:
            if self._evaluate_rule_conditions(rule, threat_analysis):
                actions.extend(rule.get('actions', []))
        
        # Default scoring-based rules if no custom rules matched
        if not actions:
            if score >= 90:
                # Critical threat
                actions = [ResponseAction.BLOCK_IP, ResponseAction.NOTIFY_ADMIN]
            elif score >= 70:
                # High threat
                actions = [ResponseAction.BLOCK_IP]
            elif score >= 50:
                # Medium threat
                actions = [ResponseAction.RATE_LIMIT]
            elif score >= 30:
                # Low threat
                actions = [ResponseAction.CAPTCHA_CHALLENGE]
            else:
                # Monitor only
                actions = [ResponseAction.MONITOR_ONLY]
        
        # Add specialized actions based on threat types
        if 'botnet' in threat_types or 'malware' in threat_types:
            if ResponseAction.QUARANTINE not in actions:
                actions.append(ResponseAction.QUARANTINE)
        
        if 'brute_force' in threat_types or 'scanning' in threat_types:
            if ResponseAction.RATE_LIMIT not in actions:
                actions.append(ResponseAction.RATE_LIMIT)
        
        # Remove duplicates while preserving order
        unique_actions = []
        for action in actions:
            if action not in unique_actions:
                unique_actions.append(action)
        
        logger.debug(f"Determined response actions for {threat_analysis.ip_address}: {unique_actions}")
        
        return unique_actions
    
    def _determine_priority(self, threat_analysis: ThreatAnalysisResult) -> ResponsePriority:
        """Determine response priority based on threat analysis"""
        score = threat_analysis.threat_score
        
        if score >= 90:
            return ResponsePriority.CRITICAL
        elif score >= 70:
            return ResponsePriority.HIGH
        elif score >= 50:
            return ResponsePriority.MEDIUM
        else:
            return ResponsePriority.LOW
    
    async def _execute_response_actions(self, request: ResponseRequest) -> Dict[str, Any]:
        """Execute response actions using available providers"""
        successful_actions = []
        failed_actions = []
        provider_details = {}
        
        for action in request.requested_actions:
            try:
                # Find suitable providers for this action
                suitable_providers = self._get_providers_for_action(action)
                
                if not suitable_providers:
                    logger.warning(f"No providers available for action: {action}")
                    failed_actions.append(action)
                    continue
                
                # Execute action with best available provider
                success = await self._execute_single_action(
                    action, request, suitable_providers
                )
                
                if success:
                    successful_actions.append(action)
                    provider_details[action.value] = success
                else:
                    failed_actions.append(action)
                
            except Exception as e:
                logger.error(f"Error executing action {action} for {request.ip_address}: {e}")
                failed_actions.append(action)
        
        return {
            'successful': successful_actions,
            'failed': failed_actions,
            'provider_details': provider_details
        }
    
    async def _execute_single_action(self, action: ResponseAction, 
                                   request: ResponseRequest, 
                                   providers: List[Tuple[str, Any]]) -> Optional[Dict[str, Any]]:
        """Execute a single response action"""
        # Sort providers by priority and health
        sorted_providers = sorted(providers, 
                                key=lambda x: (x[1].priority, 
                                             self.provider_health[x[0]]['success_count']),
                                reverse=True)
        
        for provider_name, provider in sorted_providers:
            try:
                # Check provider health
                if self.provider_health[provider_name]['status'] != 'healthy':
                    logger.warning(f"Skipping unhealthy provider: {provider_name}")
                    continue
                
                # Check rate limits
                if not await self._check_action_rate_limit(provider_name, action):
                    logger.warning(f"Rate limit exceeded for provider {provider_name}, action {action}")
                    continue
                
                # Execute the action
                start_time = datetime.now()
                
                if action == ResponseAction.BLOCK_IP:
                    result = await provider.block_ip(
                        request.ip_address,
                        duration=request.metadata.get('block_duration'),
                        reason=f"Threat score: {request.threat_analysis.threat_score}"
                    )
                elif action == ResponseAction.BLOCK_NETWORK:
                    network = request.metadata.get('network', f"{request.ip_address}/32")
                    result = await provider.block_network(network)
                elif action == ResponseAction.RATE_LIMIT:
                    result = await provider.rate_limit_ip(
                        request.ip_address,
                        limit=request.metadata.get('rate_limit', 10)
                    )
                elif action == ResponseAction.QUARANTINE:
                    result = await provider.quarantine_ip(request.ip_address)
                else:
                    # For actions not directly supported by provider
                    result = await self._execute_custom_action(action, request, provider)
                
                # Update provider health
                execution_time = (datetime.now() - start_time).total_seconds()
                self.provider_health[provider_name].update({
                    'status': 'healthy',
                    'last_check': datetime.now(),
                    'response_time': execution_time,
                    'success_count': self.provider_health[provider_name]['success_count'] + 1,
                    'actions_executed': self.provider_health[provider_name]['actions_executed'] + 1
                })
                
                # Record metrics
                self.monitoring.record_metric(f'response_provider_{provider_name}_actions', 1)
                self.monitoring.record_metric(f'response_provider_{provider_name}_response_time', execution_time)
                
                logger.info(f"Successfully executed {action} for {request.ip_address} using {provider_name}")
                
                return {
                    'provider': provider_name,
                    'execution_time': execution_time,
                    'result': result
                }
                
            except Exception as e:
                logger.error(f"Provider {provider_name} failed to execute {action}: {e}")
                
                # Update provider health
                self.provider_health[provider_name].update({
                    'status': 'unhealthy',
                    'error_count': self.provider_health[provider_name]['error_count'] + 1
                })
                
                self.monitoring.record_metric(f'response_provider_{provider_name}_errors', 1)
                
                # Try next provider
                continue
        
        # All providers failed
        logger.error(f"All providers failed to execute {action} for {request.ip_address}")
        return None
    
    def _get_providers_for_action(self, action: ResponseAction) -> List[Tuple[str, Any]]:
        """Get providers that support a specific action"""
        suitable_providers = []
        
        for provider_name, provider in self.providers.items():
            if not provider.is_enabled():
                continue
            
            # Check if provider supports the action
            if hasattr(provider, 'supports_action') and provider.supports_action(action):
                suitable_providers.append((provider_name, provider))
            else:
                # Check for specific methods
                method_map = {
                    ResponseAction.BLOCK_IP: 'block_ip',
                    ResponseAction.BLOCK_NETWORK: 'block_network',
                    ResponseAction.RATE_LIMIT: 'rate_limit_ip',
                    ResponseAction.QUARANTINE: 'quarantine_ip'
                }
                
                if action in method_map and hasattr(provider, method_map[action]):
                    suitable_providers.append((provider_name, provider))
        
        return suitable_providers
    
    async def _execute_custom_action(self, action: ResponseAction, 
                                   request: ResponseRequest, provider: Any) -> Dict[str, Any]:
        """Execute custom actions that don't map directly to provider methods"""
        if action == ResponseAction.NOTIFY_ADMIN:
            # Send notification (could be email, webhook, etc.)
            return await self._send_admin_notification(request)
        elif action == ResponseAction.MONITOR_ONLY:
            # Just log the event
            logger.info(f"Monitoring IP {request.ip_address} - Threat score: {request.threat_analysis.threat_score}")
            return {'action': 'logged'}
        elif action == ResponseAction.CAPTCHA_CHALLENGE:
            # This would typically be handled by a web application firewall
            return {'action': 'captcha_flagged'}
        else:
            raise NotImplementedError(f"Custom action {action} not implemented")
    
    async def _send_admin_notification(self, request: ResponseRequest) -> Dict[str, Any]:
        """Send notification to administrators"""
        try:
            # This could integrate with various notification systems
            notification_data = {
                'ip_address': request.ip_address,
                'threat_score': request.threat_analysis.threat_score,
                'threat_types': request.threat_analysis.threat_types,
                'timestamp': request.timestamp.isoformat(),
                'priority': request.priority.name
            }
            
            logger.warning(f"ADMIN ALERT: High threat detected from {request.ip_address} "
                          f"(Score: {request.threat_analysis.threat_score})")
            
            # Record the notification
            self.monitoring.record_metric('response_engine_admin_notifications', 1)
            
            return {'notification_sent': True, 'data': notification_data}
            
        except Exception as e:
            logger.error(f"Failed to send admin notification: {e}")
            return {'notification_sent': False, 'error': str(e)}
    
    def _load_response_rules(self) -> List[Dict[str, Any]]:
        """Load response rules from configuration"""
        rules = self.config.get('response_rules', [])
        
        # Add default rules if none configured
        if not rules:
            rules = [
                {
                    'name': 'critical_threat',
                    'conditions': {
                        'threat_score_min': 90,
                        'threat_types': ['botnet', 'malware']
                    },
                    'actions': [ResponseAction.BLOCK_IP, ResponseAction.NOTIFY_ADMIN]
                },
                {
                    'name': 'brute_force',
                    'conditions': {
                        'threat_types': ['brute_force'],
                        'confidence_min': 0.7
                    },
                    'actions': [ResponseAction.RATE_LIMIT, ResponseAction.BLOCK_IP]
                }
            ]
        
        logger.info(f"Loaded {len(rules)} response rules")
        return rules
    
    def _evaluate_rule_conditions(self, rule: Dict[str, Any], 
                                threat_analysis: ThreatAnalysisResult) -> bool:
        """Evaluate if a rule's conditions match the threat analysis"""
        conditions = rule.get('conditions', {})
        
        # Check minimum threat score
        if 'threat_score_min' in conditions:
            if threat_analysis.threat_score < conditions['threat_score_min']:
                return False
        
        # Check minimum confidence
        if 'confidence_min' in conditions:
            if threat_analysis.confidence < conditions['confidence_min']:
                return False
        
        # Check threat types
        if 'threat_types' in conditions:
            required_types = set(conditions['threat_types'])
            analysis_types = set(threat_analysis.threat_types)
            if not required_types.intersection(analysis_types):
                return False
        
        # Check sources
        if 'sources' in conditions:
            required_sources = set(conditions['sources'])
            analysis_sources = set(threat_analysis.sources)
            if not required_sources.intersection(analysis_sources):
                return False
        
        return True
    
    async def _check_action_rate_limit(self, provider_name: str, action: ResponseAction) -> bool:
        """Check if action is within rate limits for provider"""
        key = f"{provider_name}_{action.value}"
        
        if key not in self.action_rate_limits:
            self.action_rate_limits[key] = {
                'count': 0,
                'window_start': datetime.now()
            }
        
        rate_info = self.action_rate_limits[key]
        current_time = datetime.now()
        
        # Rate limit: max 100 actions per minute per provider/action combination
        max_actions_per_minute = self.config.get('action_rate_limit', 100)
        
        # Reset window if more than 1 minute has passed
        if (current_time - rate_info['window_start']).total_seconds() >= 60:
            rate_info['count'] = 0
            rate_info['window_start'] = current_time
        
        # Check if within limits
        if rate_info['count'] >= max_actions_per_minute:
            return False
        
        # Increment count
        rate_info['count'] += 1
        return True
    
    async def _store_response_result(self, result: ResponseResult):
        """Store response result in database"""
        try:
            response_repo = self.db_manager.get_repository('response_action')
            
            await response_repo.create_response_action(
                ip_address=result.ip_address,
                actions=result.actions_executed,
                success_rate=result.success_rate,
                execution_time=result.execution_time,
                metadata=result.metadata
            )
            
            logger.debug(f"Stored response result in database for {result.ip_address}")
            
        except Exception as e:
            logger.error(f"Error storing response result: {e}")
    
    async def _health_check_providers(self):
        """Perform health checks on all providers"""
        logger.info("Performing response provider health checks...")
        
        for provider_name, provider in self.providers.items():
            try:
                # Basic health check
                health_result = await provider.health_check()
                
                if health_result.get('healthy', False):
                    self.provider_health[provider_name]['status'] = 'healthy'
                else:
                    self.provider_health[provider_name]['status'] = 'unhealthy'
                
                self.provider_health[provider_name]['last_check'] = datetime.now()
                
                logger.debug(f"Provider {provider_name}: {self.provider_health[provider_name]['status']}")
                
            except Exception as e:
                logger.warning(f"Health check failed for response provider {provider_name}: {e}")
                self.provider_health[provider_name]['status'] = 'unhealthy'
    
    async def _cleanup_temporary_blocks(self):
        """Background task to cleanup expired temporary blocks"""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                current_time = datetime.now()
                expired_blocks = []
                
                for ip, block_info in self.response_stats['temporary_blocks'].items():
                    if current_time > block_info['expires']:
                        expired_blocks.append(ip)
                
                # Remove expired blocks
                for ip in expired_blocks:
                    try:
                        # Unblock IP using available providers
                        for provider_name, provider in self.providers.items():
                            if hasattr(provider, 'unblock_ip'):
                                await provider.unblock_ip(ip)
                        
                        del self.response_stats['temporary_blocks'][ip]
                        logger.info(f"Removed expired temporary block for {ip}")
                        
                    except Exception as e:
                        logger.error(f"Error removing expired block for {ip}: {e}")
                
                if expired_blocks:
                    self.monitoring.record_metric('response_engine_expired_blocks_cleaned', len(expired_blocks))
                
            except Exception as e:
                logger.error(f"Error in cleanup_temporary_blocks: {e}")
    
    async def _periodic_health_checks(self):
        """Background task for periodic health checks"""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                await self._health_check_providers()
            except Exception as e:
                logger.error(f"Error in periodic health checks: {e}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        return {
            'providers': [
                {
                    'name': name,
                    'status': health['status'],
                    'last_check': health['last_check'].isoformat(),
                    'response_time': health['response_time'],
                    'error_count': health['error_count'],
                    'success_count': health['success_count'],
                    'actions_executed': health['actions_executed']
                }
                for name, health in self.provider_health.items()
            ],
            'statistics': {
                'total_requests': self.response_stats['total_requests'],
                'successful_responses': self.response_stats['successful_responses'],
                'failed_responses': self.response_stats['failed_responses'],
                'blocked_ips_count': len(self.response_stats['blocked_ips']),
                'active_responses': len(self.active_responses),
                'temporary_blocks': len(self.response_stats['temporary_blocks'])
            },
            'healthy': len([h for h in self.provider_health.values() if h['status'] == 'healthy']) > 0
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up Response Engine...")
        
        # Cancel any active responses
        self.active_responses.clear()
        
        # Clear statistics
        self.response_stats['blocked_ips'].clear()
        self.response_stats['temporary_blocks'].clear()
        
        logger.info("Response Engine cleanup complete")
