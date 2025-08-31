"""
IPDefender Pro - Enhanced Threat Intelligence Engine V2
Advanced threat intelligence with plugin system integration

Author: byFranke (https://byfranke.com)
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import ipaddress
from dataclasses import dataclass

from plugins.manager import PluginManager
from database.manager import DatabaseManager
from monitoring.metrics import MonitoringManager
from core.threat_intel import ThreatIntelligenceEngine

logger = logging.getLogger(__name__)

@dataclass
class ThreatAnalysisResult:
    """Enhanced threat analysis result with metadata"""
    ip_address: str
    threat_score: float
    confidence: float
    threat_types: List[str]
    sources: List[str]
    metadata: Dict[str, Any]
    analysis_time: datetime
    cache_hit: bool = False
    provider_data: Dict[str, Any] = None
    geolocation: Dict[str, Any] = None

class ThreatIntelligenceEngineV2(ThreatIntelligenceEngine):
    """Enhanced threat intelligence engine with plugin system and database persistence"""
    
    def __init__(self, config: Dict[str, Any], plugin_manager: PluginManager, 
                 db_manager: DatabaseManager, monitoring_manager: MonitoringManager):
        """Initialize enhanced threat intelligence engine"""
        self.config = config
        self.plugin_manager = plugin_manager
        self.db_manager = db_manager
        self.monitoring = monitoring_manager
        
        # Enhanced caching system
        self.cache = {}
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'size': 0
        }
        
        # Analysis tracking
        self.analysis_stats = {
            'total_analyzed': 0,
            'threats_found': 0,
            'false_positives': 0,
            'cache_hits': 0
        }
        
        # Provider status tracking
        self.provider_health = {}
        
        # Rate limiting
        self.rate_limits = {}
        
        logger.info("ThreatIntelligenceEngineV2 initialized")
    
    async def initialize(self):
        """Initialize the threat intelligence engine"""
        try:
            logger.info("Initializing Enhanced Threat Intelligence Engine...")
            
            # Get available threat intelligence providers
            self.providers = self.plugin_manager.get_plugins_by_type('threat_intelligence')
            
            logger.info(f"Loaded {len(self.providers)} threat intelligence providers")
            
            # Initialize provider health tracking
            for provider_name, provider in self.providers.items():
                self.provider_health[provider_name] = {
                    'status': 'unknown',
                    'last_check': datetime.now(),
                    'response_time': 0.0,
                    'error_count': 0,
                    'success_count': 0
                }
            
            # Initial health check
            await self._health_check_providers()
            
            logger.info("Enhanced Threat Intelligence Engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize threat intelligence engine: {e}")
            raise
    
    async def analyze_ip(self, ip_address: str, force_refresh: bool = False) -> ThreatAnalysisResult:
        """Analyze IP address with enhanced features and database persistence"""
        start_time = datetime.now()
        
        try:
            # Validate IP address
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private or ip_obj.is_loopback:
                    logger.debug(f"Skipping analysis of private/loopback IP: {ip_address}")
                    return ThreatAnalysisResult(
                        ip_address=ip_address,
                        threat_score=0.0,
                        confidence=1.0,
                        threat_types=[],
                        sources=[],
                        metadata={'skip_reason': 'private_ip'},
                        analysis_time=start_time
                    )
            except ValueError as e:
                logger.warning(f"Invalid IP address: {ip_address}")
                raise ValueError(f"Invalid IP address: {ip_address}")
            
            # Check cache first (unless force refresh)
            if not force_refresh:
                cached_result = await self._get_cached_result(ip_address)
                if cached_result:
                    self.cache_stats['hits'] += 1
                    self.analysis_stats['cache_hits'] += 1
                    cached_result.cache_hit = True
                    
                    # Update metrics
                    self.monitoring.record_metric('threat_intel_cache_hits', 1)
                    
                    return cached_result
            
            self.cache_stats['misses'] += 1
            
            # Check database for recent analysis
            if not force_refresh:
                db_result = await self._get_database_result(ip_address)
                if db_result:
                    logger.debug(f"Found recent database analysis for {ip_address}")
                    return db_result
            
            # Perform new analysis
            logger.info(f"Analyzing IP address: {ip_address}")
            
            # Get analysis from all available providers
            provider_results = await self._query_providers(ip_address)
            
            # Aggregate results
            analysis_result = await self._aggregate_results(ip_address, provider_results)
            
            # Store in cache
            await self._cache_result(ip_address, analysis_result)
            
            # Store in database
            await self._store_database_result(analysis_result)
            
            # Update statistics
            self.analysis_stats['total_analyzed'] += 1
            if analysis_result.threat_score > self.config.get('threat_threshold', 50.0):
                self.analysis_stats['threats_found'] += 1
            
            # Record metrics
            analysis_time = (datetime.now() - start_time).total_seconds()
            self.monitoring.record_metric('threat_intel_analysis_time', analysis_time)
            self.monitoring.record_metric('threat_intel_analyses_total', 1)
            
            if analysis_result.threat_score > 0:
                self.monitoring.record_metric('threat_intel_threats_found', 1)
            
            logger.info(f"IP analysis completed: {ip_address} - Score: {analysis_result.threat_score}")
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing IP {ip_address}: {e}")
            self.monitoring.record_metric('threat_intel_analysis_errors', 1)
            
            # Return safe default result
            return ThreatAnalysisResult(
                ip_address=ip_address,
                threat_score=0.0,
                confidence=0.0,
                threat_types=[],
                sources=[],
                metadata={'error': str(e)},
                analysis_time=start_time
            )
    
    async def _query_providers(self, ip_address: str) -> Dict[str, Any]:
        """Query all available threat intelligence providers"""
        results = {}
        tasks = []
        
        for provider_name, provider in self.providers.items():
            if provider.is_enabled():
                task = asyncio.create_task(
                    self._query_single_provider(provider_name, provider, ip_address)
                )
                tasks.append((provider_name, task))
        
        # Wait for all providers to complete
        for provider_name, task in tasks:
            try:
                result = await asyncio.wait_for(task, timeout=30.0)
                results[provider_name] = result
            except asyncio.TimeoutError:
                logger.warning(f"Provider {provider_name} timed out for IP {ip_address}")
                self.provider_health[provider_name]['error_count'] += 1
                results[provider_name] = None
            except Exception as e:
                logger.error(f"Provider {provider_name} failed for IP {ip_address}: {e}")
                self.provider_health[provider_name]['error_count'] += 1
                results[provider_name] = None
        
        return results
    
    async def _query_single_provider(self, provider_name: str, provider: Any, ip_address: str) -> Optional[Dict[str, Any]]:
        """Query a single threat intelligence provider"""
        start_time = datetime.now()
        
        try:
            # Check rate limits
            if not await self._check_rate_limit(provider_name):
                logger.warning(f"Rate limit exceeded for provider {provider_name}")
                return None
            
            # Query the provider
            result = await provider.analyze_ip(ip_address)
            
            # Update provider health
            response_time = (datetime.now() - start_time).total_seconds()
            self.provider_health[provider_name].update({
                'status': 'healthy',
                'last_check': datetime.now(),
                'response_time': response_time,
                'success_count': self.provider_health[provider_name]['success_count'] + 1
            })
            
            # Record metrics
            self.monitoring.record_metric(f'threat_intel_provider_{provider_name}_queries', 1)
            self.monitoring.record_metric(f'threat_intel_provider_{provider_name}_response_time', response_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Error querying provider {provider_name}: {e}")
            
            # Update provider health
            self.provider_health[provider_name].update({
                'status': 'unhealthy',
                'last_check': datetime.now(),
                'error_count': self.provider_health[provider_name]['error_count'] + 1
            })
            
            self.monitoring.record_metric(f'threat_intel_provider_{provider_name}_errors', 1)
            
            return None
    
    async def _aggregate_results(self, ip_address: str, provider_results: Dict[str, Any]) -> ThreatAnalysisResult:
        """Aggregate results from multiple providers using weighted scoring"""
        total_weight = 0
        weighted_score = 0
        threat_types = set()
        sources = []
        all_metadata = {}
        provider_data = {}
        
        for provider_name, result in provider_results.items():
            if result is None:
                continue
            
            # Get provider configuration
            provider = self.providers[provider_name]
            weight = getattr(provider, 'weight', 1.0)
            
            # Extract data from result
            score = result.get('threat_score', 0)
            confidence = result.get('confidence', 0.5)
            types = result.get('threat_types', [])
            metadata = result.get('metadata', {})
            
            # Apply confidence weighting
            adjusted_weight = weight * confidence
            weighted_score += score * adjusted_weight
            total_weight += adjusted_weight
            
            # Collect threat types
            threat_types.update(types)
            
            # Track sources
            sources.append(provider_name)
            
            # Collect metadata
            all_metadata[provider_name] = metadata
            provider_data[provider_name] = result
        
        # Calculate final score
        final_score = weighted_score / total_weight if total_weight > 0 else 0
        
        # Calculate confidence based on consensus
        confidence = min(1.0, total_weight / len(self.providers)) if self.providers else 0.0
        
        return ThreatAnalysisResult(
            ip_address=ip_address,
            threat_score=final_score,
            confidence=confidence,
            threat_types=list(threat_types),
            sources=sources,
            metadata=all_metadata,
            analysis_time=datetime.now(),
            provider_data=provider_data
        )
    
    async def _get_cached_result(self, ip_address: str) -> Optional[ThreatAnalysisResult]:
        """Get result from cache if still valid"""
        cache_entry = self.cache.get(ip_address)
        if cache_entry is None:
            return None
        
        result, timestamp = cache_entry
        cache_ttl = self.config.get('cache_ttl', 3600)  # 1 hour default
        
        if (datetime.now() - timestamp).total_seconds() < cache_ttl:
            logger.debug(f"Cache hit for IP: {ip_address}")
            return result
        else:
            # Remove expired entry
            del self.cache[ip_address]
            self.cache_stats['evictions'] += 1
            return None
    
    async def _cache_result(self, ip_address: str, result: ThreatAnalysisResult):
        """Store result in cache"""
        self.cache[ip_address] = (result, datetime.now())
        self.cache_stats['size'] = len(self.cache)
        
        # Cleanup old entries if cache is too large
        max_cache_size = self.config.get('max_cache_size', 10000)
        if len(self.cache) > max_cache_size:
            await self._cleanup_cache()
    
    async def _cleanup_cache(self):
        """Clean up old cache entries"""
        current_time = datetime.now()
        cache_ttl = self.config.get('cache_ttl', 3600)
        
        # Remove expired entries
        expired_keys = []
        for ip_address, (result, timestamp) in self.cache.items():
            if (current_time - timestamp).total_seconds() > cache_ttl:
                expired_keys.append(ip_address)
        
        for key in expired_keys:
            del self.cache[key]
            self.cache_stats['evictions'] += 1
        
        self.cache_stats['size'] = len(self.cache)
        
        logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    async def _get_database_result(self, ip_address: str) -> Optional[ThreatAnalysisResult]:
        """Get recent analysis result from database"""
        try:
            # Check if we have a recent analysis (within last hour by default)
            ttl_minutes = self.config.get('db_cache_ttl_minutes', 60)
            
            threat_repo = self.db_manager.get_repository('threat_analysis')
            analysis = await threat_repo.get_recent_analysis(ip_address, ttl_minutes)
            
            if analysis:
                logger.debug(f"Found recent database analysis for {ip_address}")
                
                return ThreatAnalysisResult(
                    ip_address=ip_address,
                    threat_score=analysis.threat_score,
                    confidence=analysis.confidence,
                    threat_types=analysis.threat_types or [],
                    sources=analysis.sources or [],
                    metadata=analysis.metadata or {},
                    analysis_time=analysis.created_at,
                    cache_hit=True
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving database result for {ip_address}: {e}")
            return None
    
    async def _store_database_result(self, result: ThreatAnalysisResult):
        """Store analysis result in database"""
        try:
            threat_repo = self.db_manager.get_repository('threat_analysis')
            
            await threat_repo.create_analysis(
                ip_address=result.ip_address,
                threat_score=result.threat_score,
                confidence=result.confidence,
                threat_types=result.threat_types,
                sources=result.sources,
                metadata=result.metadata
            )
            
            logger.debug(f"Stored analysis result in database for {result.ip_address}")
            
        except Exception as e:
            logger.error(f"Error storing database result for {result.ip_address}: {e}")
    
    async def _check_rate_limit(self, provider_name: str) -> bool:
        """Check if provider is within rate limits"""
        if provider_name not in self.rate_limits:
            self.rate_limits[provider_name] = {
                'requests': 0,
                'window_start': datetime.now()
            }
        
        rate_limit_info = self.rate_limits[provider_name]
        current_time = datetime.now()
        
        # Get provider rate limit configuration
        provider = self.providers[provider_name]
        requests_per_minute = getattr(provider, 'rate_limit', 60)  # Default 60 requests per minute
        
        # Reset window if more than 1 minute has passed
        if (current_time - rate_limit_info['window_start']).total_seconds() >= 60:
            rate_limit_info['requests'] = 0
            rate_limit_info['window_start'] = current_time
        
        # Check if within limits
        if rate_limit_info['requests'] >= requests_per_minute:
            return False
        
        # Increment request count
        rate_limit_info['requests'] += 1
        return True
    
    async def _health_check_providers(self):
        """Perform health checks on all providers"""
        logger.info("Performing provider health checks...")
        
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
                logger.warning(f"Health check failed for provider {provider_name}: {e}")
                self.provider_health[provider_name]['status'] = 'unhealthy'
    
    def get_provider_status(self) -> Dict[str, Any]:
        """Get current status of all providers"""
        return {
            'providers': [
                {
                    'name': name,
                    'status': health['status'],
                    'last_check': health['last_check'].isoformat(),
                    'response_time': health['response_time'],
                    'error_count': health['error_count'],
                    'success_count': health['success_count']
                }
                for name, health in self.provider_health.items()
            ],
            'total_providers': len(self.providers),
            'healthy_providers': len([h for h in self.provider_health.values() if h['status'] == 'healthy'])
        }
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'cache_stats': self.cache_stats.copy(),
            'analysis_stats': self.analysis_stats.copy()
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up Threat Intelligence Engine...")
        
        # Clear cache
        self.cache.clear()
        self.cache_stats['size'] = 0
        
        logger.info("Threat Intelligence Engine cleanup complete")
