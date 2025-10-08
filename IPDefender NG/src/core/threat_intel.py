"""
IPDefender Pro - Threat Intelligence Engine
Advanced multi-source threat intelligence aggregation and analysis

Author: byFranke (https://byfranke.com)
"""

import asyncio
import aiohttp
import logging
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels"""
    UNKNOWN = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 90

class ThreatCategory(Enum):
    """Categories of threats"""
    MALWARE = "malware"
    BOTNET = "botnet"
    SCANNING = "scanning" 
    BRUTE_FORCE = "brute_force"
    PHISHING = "phishing"
    C2 = "c2_communication"
    SUSPICIOUS = "suspicious"

@dataclass
class ThreatEvidence:
    """Single piece of threat evidence from a source"""
    source: str
    category: ThreatCategory
    confidence: float  # 0-100
    description: str
    first_seen: datetime
    last_seen: datetime
    metadata: Dict[str, Any]

@dataclass 
class ThreatAnalysis:
    """Comprehensive threat analysis result"""
    ip: str
    threat_score: float  # 0-100 aggregated score
    confidence: float    # 0-100 confidence in assessment
    threat_level: ThreatLevel
    categories: List[ThreatCategory]
    evidence: List[ThreatEvidence]
    sources_queried: int
    sources_responded: int
    geolocation: Optional[Dict[str, str]]
    reputation_history: List[Dict]
    recommendation: str
    expires_at: datetime
    analyzed_at: datetime

class ThreatIntelProvider:
    """Base class for threat intelligence providers"""
    
    def __init__(self, name: str, api_key: str = None, weight: float = 1.0):
        self.name = name
        self.api_key = api_key
        self.weight = weight
        self.enabled = bool(api_key) if api_key else True
        self.rate_limit = 60  # requests per minute
        self.last_request = datetime.min
        
    async def query_ip(self, ip: str) -> Optional[ThreatEvidence]:
        """Query this provider for IP information"""
        raise NotImplementedError
        
    async def is_rate_limited(self) -> bool:
        """Check if we're rate limited"""
        now = datetime.now()
        if (now - self.last_request).total_seconds() < (60 / self.rate_limit):
            return True
        return False
        
    def _update_rate_limit(self):
        """Update last request time"""
        self.last_request = datetime.now()

class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB threat intelligence provider"""
    
    def __init__(self, api_key: str):
        super().__init__("AbuseIPDB", api_key, weight=0.35)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        
    async def query_ip(self, ip: str) -> Optional[ThreatEvidence]:
        """Query AbuseIPDB for IP information"""
        if not self.enabled or await self.is_rate_limited():
            return None
            
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/check",
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    self._update_rate_limit()
                    
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_abuseipdb_response(ip, data)
                    else:
                        logger.warning(f"AbuseIPDB API error {response.status} for IP {ip}")
                        return None
                        
        except Exception as e:
            logger.error(f"AbuseIPDB query failed for IP {ip}: {e}")
            return None
    
    def _parse_abuseipdb_response(self, ip: str, data: Dict) -> Optional[ThreatEvidence]:
        """Parse AbuseIPDB API response"""
        try:
            ip_data = data.get('data', {})
            
            abuse_confidence = ip_data.get('abuseConfidencePercentage', 0)
            total_reports = ip_data.get('totalReports', 0)
            
            if abuse_confidence == 0 and total_reports == 0:
                return None
                
            # Determine category based on usage type and reports
            usage_type = ip_data.get('usageType', 'unknown').lower()
            category = ThreatCategory.SUSPICIOUS
            
            if 'botnet' in usage_type or abuse_confidence > 80:
                category = ThreatCategory.BOTNET
            elif total_reports > 10:
                category = ThreatCategory.MALWARE
                
            return ThreatEvidence(
                source=self.name,
                category=category,
                confidence=float(abuse_confidence),
                description=f"AbuseIPDB confidence: {abuse_confidence}%, Reports: {total_reports}",
                first_seen=datetime.now() - timedelta(days=90),  # AbuseIPDB doesn't provide this
                last_seen=datetime.fromisoformat(ip_data.get('lastReportedAt', datetime.now().isoformat())),
                metadata={
                    'country_code': ip_data.get('countryCode'),
                    'isp': ip_data.get('isp'),
                    'usage_type': ip_data.get('usageType'),
                    'is_public': ip_data.get('isPublic', False),
                    'total_reports': total_reports,
                    'abuse_confidence': abuse_confidence
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to parse AbuseIPDB response for IP {ip}: {e}")
            return None

class OTXProvider(ThreatIntelProvider):
    """AlienVault OTX threat intelligence provider"""
    
    def __init__(self, api_key: str):
        super().__init__("AlienVault_OTX", api_key, weight=0.25)
        self.base_url = "https://otx.alienvault.com/api/v1"
        
    async def query_ip(self, ip: str) -> Optional[ThreatEvidence]:
        """Query OTX for IP information"""
        if not self.enabled or await self.is_rate_limited():
            return None
            
        headers = {
            'X-OTX-API-KEY': self.api_key,
            'Accept': 'application/json'
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/indicators/IPv4/{ip}/reputation",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    self._update_rate_limit()
                    
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_otx_response(ip, data)
                    else:
                        logger.warning(f"OTX API error {response.status} for IP {ip}")
                        return None
                        
        except Exception as e:
            logger.error(f"OTX query failed for IP {ip}: {e}")
            return None
    
    def _parse_otx_response(self, ip: str, data: Dict) -> Optional[ThreatEvidence]:
        """Parse OTX API response"""
        try:
            reputation = data.get('reputation', {})
            
            if not reputation:
                return None
                
            threat_score = reputation.get('threat_score', 0)
            activities = reputation.get('activities', [])
            
            if threat_score == 0 and not activities:
                return None
                
            # Determine category from activities
            category = ThreatCategory.SUSPICIOUS
            for activity in activities:
                if 'malware' in activity.lower():
                    category = ThreatCategory.MALWARE
                    break
                elif 'scan' in activity.lower():
                    category = ThreatCategory.SCANNING
                    break
                elif 'botnet' in activity.lower():
                    category = ThreatCategory.BOTNET
                    break
                    
            return ThreatEvidence(
                source=self.name,
                category=category,
                confidence=float(threat_score * 20),  # Convert 0-5 scale to 0-100
                description=f"OTX threat score: {threat_score}, Activities: {', '.join(activities[:3])}",
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now(),
                metadata={
                    'threat_score': threat_score,
                    'activities': activities,
                    'reputation_data': reputation
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to parse OTX response for IP {ip}: {e}")
            return None

class ThreatIntelligenceEngine:
    """Core threat intelligence aggregation engine"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.providers = self._initialize_providers()
        self.cache = {}  # Simple in-memory cache, could be Redis
        self.cache_ttl = config.get('cache_ttl', 3600)  # 1 hour default
        
    def _initialize_providers(self) -> List[ThreatIntelProvider]:
        """Initialize all configured threat intelligence providers"""
        providers = []
        
        # AbuseIPDB
        abuseipdb_key = self.config.get('abuseipdb_api_key')
        if abuseipdb_key:
            providers.append(AbuseIPDBProvider(abuseipdb_key))
            
        # OTX
        otx_key = self.config.get('otx_api_key')
        if otx_key:
            providers.append(OTXProvider(otx_key))
            
        # TODO: Add more providers (MISP, VirusTotal, etc.)
        
        logger.info(f"Initialized {len(providers)} threat intelligence providers")
        return providers
    
    async def analyze_ip(self, ip: str, force_refresh: bool = False) -> ThreatAnalysis:
        """Perform comprehensive threat analysis of an IP address"""
        
        # Check cache first
        if not force_refresh:
            cached_result = self._get_cached_analysis(ip)
            if cached_result:
                return cached_result
        
        logger.info(f"Analyzing IP {ip} with {len(self.providers)} providers")
        
        # Query all providers concurrently
        tasks = []
        for provider in self.providers:
            if provider.enabled:
                task = asyncio.create_task(
                    self._safe_provider_query(provider, ip)
                )
                tasks.append(task)
        
        # Wait for all queries to complete
        evidence_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        evidence = []
        sources_responded = 0
        
        for result in evidence_results:
            if isinstance(result, ThreatEvidence):
                evidence.append(result)
                sources_responded += 1
            elif result is not None and not isinstance(result, Exception):
                logger.warning(f"Unexpected result type: {type(result)}")
        
        # Aggregate results
        analysis = self._aggregate_threat_data(ip, evidence, len(self.providers), sources_responded)
        
        # Cache the result
        self._cache_analysis(ip, analysis)
        
        logger.info(f"Analysis complete for {ip}: {analysis.threat_level.name} threat")
        return analysis
    
    async def _safe_provider_query(self, provider: ThreatIntelProvider, ip: str) -> Optional[ThreatEvidence]:
        """Safely query a provider with error handling"""
        try:
            return await provider.query_ip(ip)
        except Exception as e:
            logger.error(f"Provider {provider.name} failed for IP {ip}: {e}")
            return None
    
    def _aggregate_threat_data(self, ip: str, evidence: List[ThreatEvidence], 
                              sources_queried: int, sources_responded: int) -> ThreatAnalysis:
        """Aggregate evidence from multiple sources into final analysis"""
        
        if not evidence:
            # No evidence found
            return ThreatAnalysis(
                ip=ip,
                threat_score=0.0,
                confidence=0.0,
                threat_level=ThreatLevel.UNKNOWN,
                categories=[],
                evidence=[],
                sources_queried=sources_queried,
                sources_responded=sources_responded,
                geolocation=None,
                reputation_history=[],
                recommendation="MONITOR - No threat intelligence available",
                expires_at=datetime.now() + timedelta(seconds=self.cache_ttl),
                analyzed_at=datetime.now()
            )
        
        # Calculate weighted threat score
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for ev in evidence:
            # Find provider weight
            provider_weight = 1.0
            for provider in self.providers:
                if provider.name == ev.source:
                    provider_weight = provider.weight
                    break
                    
            weighted_score = ev.confidence * provider_weight
            total_weighted_score += weighted_score
            total_weight += provider_weight
        
        # Normalize threat score
        threat_score = min(100.0, total_weighted_score / total_weight if total_weight > 0 else 0.0)
        
        # Calculate confidence based on number of sources and agreement
        confidence_base = (sources_responded / sources_queried) * 100 if sources_queried > 0 else 0
        confidence_agreement = self._calculate_evidence_agreement(evidence)
        confidence = min(100.0, (confidence_base + confidence_agreement) / 2)
        
        # Determine threat level
        threat_level = self._determine_threat_level(threat_score)
        
        # Extract categories
        categories = list(set(ev.category for ev in evidence))
        
        # Generate recommendation
        recommendation = self._generate_recommendation(threat_score, len(evidence), categories)
        
        # Extract geolocation from evidence
        geolocation = self._extract_geolocation(evidence)
        
        return ThreatAnalysis(
            ip=ip,
            threat_score=threat_score,
            confidence=confidence,
            threat_level=threat_level,
            categories=categories,
            evidence=evidence,
            sources_queried=sources_queried,
            sources_responded=sources_responded,
            geolocation=geolocation,
            reputation_history=self._build_reputation_history(evidence),
            recommendation=recommendation,
            expires_at=datetime.now() + timedelta(seconds=self.cache_ttl),
            analyzed_at=datetime.now()
        )
    
    def _calculate_evidence_agreement(self, evidence: List[ThreatEvidence]) -> float:
        """Calculate how much the evidence sources agree with each other"""
        if len(evidence) <= 1:
            return 100.0
            
        # Simple agreement based on confidence variance
        confidences = [ev.confidence for ev in evidence]
        mean_confidence = sum(confidences) / len(confidences)
        variance = sum((c - mean_confidence) ** 2 for c in confidences) / len(confidences)
        
        # Convert variance to agreement score (lower variance = higher agreement)
        agreement = max(0.0, 100.0 - variance)
        return agreement
    
    def _determine_threat_level(self, threat_score: float) -> ThreatLevel:
        """Determine threat level based on aggregated score"""
        if threat_score >= 90:
            return ThreatLevel.CRITICAL
        elif threat_score >= 75:
            return ThreatLevel.HIGH
        elif threat_score >= 50:
            return ThreatLevel.MEDIUM
        elif threat_score >= 25:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.UNKNOWN
    
    def _generate_recommendation(self, threat_score: float, evidence_count: int, 
                                categories: List[ThreatCategory]) -> str:
        """Generate actionable recommendation based on analysis"""
        if threat_score >= 90:
            return "BLOCK IMMEDIATELY - Critical threat detected"
        elif threat_score >= 75:
            return "BLOCK - High threat score from multiple sources"
        elif threat_score >= 50:
            return "QUARANTINE - Medium threat, investigate further"
        elif threat_score >= 25:
            return "MONITOR - Low threat, continue observation"
        else:
            return "ALLOW - No significant threat detected"
    
    def _extract_geolocation(self, evidence: List[ThreatEvidence]) -> Optional[Dict[str, str]]:
        """Extract geolocation information from evidence"""
        for ev in evidence:
            if 'country_code' in ev.metadata:
                return {
                    'country_code': ev.metadata.get('country_code'),
                    'isp': ev.metadata.get('isp', 'Unknown')
                }
        return None
    
    def _build_reputation_history(self, evidence: List[ThreatEvidence]) -> List[Dict]:
        """Build reputation history from evidence"""
        history = []
        for ev in evidence:
            history.append({
                'source': ev.source,
                'first_seen': ev.first_seen.isoformat(),
                'last_seen': ev.last_seen.isoformat(),
                'category': ev.category.value,
                'confidence': ev.confidence
            })
        return sorted(history, key=lambda x: x['last_seen'], reverse=True)
    
    def _get_cached_analysis(self, ip: str) -> Optional[ThreatAnalysis]:
        """Retrieve cached analysis if available and not expired"""
        cache_key = self._generate_cache_key(ip)
        
        if cache_key in self.cache:
            cached_analysis = self.cache[cache_key]
            if datetime.now() < cached_analysis.expires_at:
                logger.debug(f"Cache hit for IP {ip}")
                return cached_analysis
            else:
                # Expired, remove from cache
                del self.cache[cache_key]
                logger.debug(f"Cache expired for IP {ip}")
        
        return None
    
    def _cache_analysis(self, ip: str, analysis: ThreatAnalysis):
        """Cache analysis result"""
        cache_key = self._generate_cache_key(ip)
        self.cache[cache_key] = analysis
        logger.debug(f"Cached analysis for IP {ip}")
    
    def _generate_cache_key(self, ip: str) -> str:
        """Generate cache key for IP"""
        return hashlib.md5(f"threat_analysis_{ip}".encode()).hexdigest()
    
    def get_provider_status(self) -> Dict[str, Any]:
        """Get status of all providers"""
        status = {
            'total_providers': len(self.providers),
            'enabled_providers': len([p for p in self.providers if p.enabled]),
            'providers': []
        }
        
        for provider in self.providers:
            status['providers'].append({
                'name': provider.name,
                'enabled': provider.enabled,
                'weight': provider.weight,
                'rate_limit': provider.rate_limit,
                'last_request': provider.last_request.isoformat() if provider.last_request != datetime.min else None
            })
            
        return status
