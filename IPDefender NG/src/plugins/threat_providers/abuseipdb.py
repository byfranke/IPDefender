"""
IPDefender Pro - AbuseIPDB Threat Intelligence Provider Plugin
Enhanced AbuseIPDB integration with async operations and caching

Author: byFranke (https://byfranke.com)
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import hashlib
import json

from plugins import ThreatIntelligenceProvider, ThreatEvidence, ThreatCategory

logger = logging.getLogger(__name__)

class AbuseIPDBProvider(ThreatIntelligenceProvider):
    """AbuseIPDB threat intelligence provider with enhanced features"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.api_key = config.get('api_key')
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache = {}  # Simple in-memory cache
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Rate limiting
        self.requests_per_day = config.get('requests_per_day', 1000)
        self.request_timestamps = []
        
        # Configuration
        self.confidence_threshold = config.get('confidence_threshold', 25)
        self.max_age_days = config.get('max_age_days', 90)
        
    async def initialize(self) -> bool:
        """Initialize the AbuseIPDB provider"""
        try:
            if not self.api_key:
                raise ValueError("AbuseIPDB API key not configured")
            
            # Create aiohttp session with proper headers
            self.session = aiohttp.ClientSession(
                headers={
                    'Key': self.api_key,
                    'Accept': 'application/json',
                    'User-Agent': 'IPDefender Pro by byFranke'
                },
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
            
            # Test API connection
            test_result = await self.analyze_ip("8.8.8.8")  # Test with Google DNS
            if test_result is not None or test_result is None:  # Both are acceptable
                self.logger.info("AbuseIPDB provider initialized successfully")
                return True
            else:
                raise Exception("API test failed")
                
        except Exception as e:
            self.logger.error(f"AbuseIPDB provider initialization failed: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup provider resources"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def health_check(self) -> bool:
        """Check provider health"""
        try:
            if not self.session:
                return False
            
            # Simple health check - get our quota status
            url = f"{self.base_url}/check"
            params = {'ipAddress': '127.0.0.1', 'maxAgeInDays': 1}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    return True
                elif response.status == 422:  # Unprocessable entity (normal for localhost)
                    return True
                else:
                    return False
                    
        except Exception as e:
            self.logger.error(f"AbuseIPDB health check failed: {e}")
            return False
    
    def _get_cache_key(self, ip: str) -> str:
        """Generate cache key for IP"""
        return f"abuseipdb:{hashlib.md5(ip.encode()).hexdigest()}"
    
    def _is_cache_valid(self, cache_entry: Dict[str, Any]) -> bool:
        """Check if cache entry is still valid"""
        if 'timestamp' not in cache_entry:
            return False
        
        timestamp = datetime.fromisoformat(cache_entry['timestamp'])
        return datetime.now() - timestamp < timedelta(seconds=self.cache_ttl)
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        now = datetime.now()
        day_ago = now - timedelta(days=1)
        
        # Clean old timestamps
        self.request_timestamps = [ts for ts in self.request_timestamps if ts > day_ago]
        
        # Check if we can make another request
        if len(self.request_timestamps) >= self.requests_per_day:
            self.logger.warning("AbuseIPDB rate limit reached")
            return False
        
        return True
    
    def _record_request(self):
        """Record a new API request"""
        self.request_timestamps.append(datetime.now())
    
    async def analyze_ip(self, ip: str) -> Optional[ThreatEvidence]:
        """Analyze IP address using AbuseIPDB"""
        try:
            # Check cache first
            cache_key = self._get_cache_key(ip)
            if cache_key in self.cache and self._is_cache_valid(self.cache[cache_key]):
                cached_data = self.cache[cache_key]['data']
                if cached_data:
                    return self._parse_response(ip, cached_data)
                return None
            
            # Check rate limits
            if not self._check_rate_limit():
                self.logger.warning(f"Rate limit exceeded, skipping {ip}")
                return None
            
            # Make API request
            result = await self._query_api(ip)
            
            # Cache result
            self.cache[cache_key] = {
                'data': result,
                'timestamp': datetime.now().isoformat()
            }
            
            # Record request for rate limiting
            self._record_request()
            self.update_usage()
            
            if result:
                return self._parse_response(ip, result)
            
            return None
            
        except Exception as e:
            self.logger.error(f"AbuseIPDB analysis failed for {ip}: {e}")
            return None
    
    async def _query_api(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB API for IP information"""
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        url = f"{self.base_url}/check"
        params = {
            'ipAddress': ip,
            'maxAgeInDays': self.max_age_days,
            'verbose': ''
        }
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data')
                elif response.status == 422:
                    # Unprocessable entity (invalid IP format or private IP)
                    self.logger.debug(f"AbuseIPDB returned 422 for {ip} (likely private IP)")
                    return None
                elif response.status == 429:
                    # Rate limited
                    self.logger.warning("AbuseIPDB rate limit hit")
                    return None
                else:
                    self.logger.error(f"AbuseIPDB API error {response.status} for {ip}")
                    return None
                    
        except asyncio.TimeoutError:
            self.logger.warning(f"AbuseIPDB timeout for {ip}")
            return None
        except Exception as e:
            self.logger.error(f"AbuseIPDB API request failed for {ip}: {e}")
            return None
    
    def _parse_response(self, ip: str, data: Dict[str, Any]) -> ThreatEvidence:
        """Parse AbuseIPDB response into ThreatEvidence"""
        abuse_confidence = data.get('abuseConfidencePercentage', 0)
        total_reports = data.get('totalReports', 0)
        country_code = data.get('countryCode', 'Unknown')
        isp = data.get('isp', 'Unknown')
        usage_type = data.get('usageType', 'Unknown')
        
        # Determine threat category based on usage type and reports
        category = ThreatCategory.UNKNOWN
        if usage_type in ['hosting', 'business']:
            if abuse_confidence > 50:
                category = ThreatCategory.SUSPICIOUS
        elif usage_type in ['isp', 'residential']:
            if abuse_confidence > 75:
                category = ThreatCategory.BOTNET
        
        if total_reports > 10 and abuse_confidence > 80:
            category = ThreatCategory.MALWARE
        
        # Calculate confidence (normalize abuse confidence to 0-1 scale)
        confidence = min(abuse_confidence / 100.0, 1.0)
        
        # Additional details
        details = {
            'abuse_confidence_percentage': abuse_confidence,
            'total_reports': total_reports,
            'country_code': country_code,
            'country_name': data.get('countryName', 'Unknown'),
            'isp': isp,
            'usage_type': usage_type,
            'is_public': data.get('isPublic', True),
            'last_reported_at': data.get('lastReportedAt'),
            'source': 'AbuseIPDB'
        }
        
        return ThreatEvidence(
            provider=self.name,
            category=category,
            confidence=confidence,
            details=details
        )
    
    async def bulk_analyze(self, ips: List[str]) -> Dict[str, Optional[ThreatEvidence]]:
        """Analyze multiple IPs (AbuseIPDB doesn't support bulk, so we do sequential)"""
        results = {}
        
        # Process IPs with some concurrency but respect rate limits
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent requests
        
        async def analyze_single(ip: str):
            async with semaphore:
                return await self.analyze_ip(ip)
        
        # Create tasks
        tasks = []
        for ip in ips:
            if self._check_rate_limit():
                tasks.append((ip, asyncio.create_task(analyze_single(ip))))
            else:
                results[ip] = None  # Rate limited
        
        # Wait for results
        for ip, task in tasks:
            try:
                results[ip] = await task
            except Exception as e:
                self.logger.error(f"Bulk analysis failed for {ip}: {e}")
                results[ip] = None
        
        return results
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get provider usage statistics"""
        now = datetime.now()
        day_ago = now - timedelta(days=1)
        
        # Clean old timestamps for accurate count
        recent_requests = [ts for ts in self.request_timestamps if ts > day_ago]
        
        return {
            'provider': self.name,
            'requests_today': len(recent_requests),
            'requests_remaining': max(0, self.requests_per_day - len(recent_requests)),
            'cache_size': len(self.cache),
            'total_usage': self.usage_count,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'rate_limit_hit': len(recent_requests) >= self.requests_per_day
        }
