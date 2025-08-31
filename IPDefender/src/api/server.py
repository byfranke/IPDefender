"""
IPDefender Pro - RESTful API Server
FastAPI-based REST API for IPDefender Pro

Author: byFranke (https://byfranke.com)
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import uvicorn

from ..core.threat_intel import ThreatIntelligenceEngine, ThreatAnalysis
from ..core.response_engine import AutomatedResponseEngine, ResponseAction, ResponseExecution

logger = logging.getLogger(__name__)

# Pydantic models for API
class ThreatAnalysisRequest(BaseModel):
    ip: str
    force_refresh: bool = False
    sources: Optional[List[str]] = None
    
    @validator('ip')
    def validate_ip(cls, v):
        import ipaddress
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address format')

class ThreatAnalysisResponse(BaseModel):
    ip: str
    threat_score: float
    confidence: float
    threat_level: str
    categories: List[str]
    sources_queried: int
    sources_responded: int
    recommendation: str
    geolocation: Optional[Dict[str, str]]
    analyzed_at: str
    expires_at: str

class ResponseRequest(BaseModel):
    ip: str
    action: ResponseAction
    reason: Optional[str] = None
    duration: Optional[int] = 0
    providers: Optional[List[str]] = None

class ResponseExecutionResponse(BaseModel):
    id: str
    ip: str
    rule_name: str
    action: str
    status: str
    started_at: str
    completed_at: Optional[str]
    providers_used: List[str]
    error_message: Optional[str]

class BulkAnalysisRequest(BaseModel):
    ips: List[str]
    force_refresh: bool = False
    
    @validator('ips')
    def validate_ips(cls, v):
        if len(v) > 100:  # Limit bulk requests
            raise ValueError('Maximum 100 IPs per bulk request')
        
        import ipaddress
        for ip in v:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f'Invalid IP address format: {ip}')
        return v

class SystemStatusResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    threat_intel_providers: Dict[str, Any]
    firewall_providers: Dict[str, Any]
    response_statistics: Dict[str, Any]
    cache_statistics: Dict[str, Any]

class IPDefenderProAPI:
    """Main API class for IPDefender Pro"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.app = FastAPI(
            title="IPDefender Pro API",
            description="Advanced Cybersecurity Defense Platform by byFranke",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        # Initialize engines
        self.threat_intel = ThreatIntelligenceEngine(config.get('threat_intel', {}))
        self.response_engine = AutomatedResponseEngine(config.get('response_engine', {}))
        
        # Security
        self.security = HTTPBearer()
        self.api_keys = set(config.get('api_keys', []))
        
        # Track API statistics
        self.start_time = datetime.now()
        self.request_count = 0
        
        # Setup middleware and routes
        self._setup_middleware()
        self._setup_routes()
        
    def _setup_middleware(self):
        """Setup CORS and other middleware"""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.get('cors_origins', ["*"]),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Request tracking middleware
        @self.app.middleware("http")
        async def track_requests(request, call_next):
            self.request_count += 1
            start_time = datetime.now()
            response = await call_next(request)
            process_time = (datetime.now() - start_time).total_seconds()
            
            logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
            return response
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/", tags=["Root"])
        async def root():
            """Root endpoint"""
            return {
                "message": "IPDefender Pro API by byFranke",
                "version": "1.0.0",
                "docs": "/docs",
                "status": "/api/v1/status"
            }
        
        @self.app.get("/health", tags=["Health"])
        async def health_check():
            """Health check endpoint"""
            return {"status": "healthy", "timestamp": datetime.now().isoformat()}
        
        @self.app.get("/api/v1/status", response_model=SystemStatusResponse, tags=["System"])
        async def get_system_status():
            """Get comprehensive system status"""
            uptime = (datetime.now() - self.start_time).total_seconds()
            
            return SystemStatusResponse(
                status="operational",
                version="1.0.0",
                uptime_seconds=uptime,
                threat_intel_providers=self.threat_intel.get_provider_status(),
                firewall_providers=self._get_firewall_provider_status(),
                response_statistics=self.response_engine.get_response_statistics(),
                cache_statistics=self._get_cache_statistics()
            )
        
        @self.app.post("/api/v1/analyze", response_model=ThreatAnalysisResponse, tags=["Threat Intelligence"])
        async def analyze_ip(
            request: ThreatAnalysisRequest,
            credentials: HTTPAuthorizationCredentials = Security(self.security)
        ):
            """Analyze a single IP address for threats"""
            await self._verify_api_key(credentials)
            
            try:
                analysis = await self.threat_intel.analyze_ip(
                    request.ip, 
                    force_refresh=request.force_refresh
                )
                
                return ThreatAnalysisResponse(
                    ip=analysis.ip,
                    threat_score=analysis.threat_score,
                    confidence=analysis.confidence,
                    threat_level=analysis.threat_level.name,
                    categories=[cat.value for cat in analysis.categories],
                    sources_queried=analysis.sources_queried,
                    sources_responded=analysis.sources_responded,
                    recommendation=analysis.recommendation,
                    geolocation=analysis.geolocation,
                    analyzed_at=analysis.analyzed_at.isoformat(),
                    expires_at=analysis.expires_at.isoformat()
                )
                
            except Exception as e:
                logger.error(f"Analysis failed for IP {request.ip}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Analysis failed: {str(e)}"
                )
        
        @self.app.post("/api/v1/analyze/bulk", tags=["Threat Intelligence"])
        async def analyze_bulk_ips(
            request: BulkAnalysisRequest,
            credentials: HTTPAuthorizationCredentials = Security(self.security)
        ):
            """Analyze multiple IP addresses for threats"""
            await self._verify_api_key(credentials)
            
            try:
                tasks = [
                    self.threat_intel.analyze_ip(ip, force_refresh=request.force_refresh)
                    for ip in request.ips
                ]
                
                analyses = await asyncio.gather(*tasks, return_exceptions=True)
                
                results = []
                for i, analysis in enumerate(analyses):
                    if isinstance(analysis, Exception):
                        results.append({
                            "ip": request.ips[i],
                            "error": str(analysis),
                            "success": False
                        })
                    else:
                        results.append({
                            "ip": analysis.ip,
                            "threat_score": analysis.threat_score,
                            "confidence": analysis.confidence,
                            "threat_level": analysis.threat_level.name,
                            "recommendation": analysis.recommendation,
                            "success": True
                        })
                
                return {
                    "total": len(request.ips),
                    "successful": len([r for r in results if r.get("success")]),
                    "failed": len([r for r in results if not r.get("success")]),
                    "results": results
                }
                
            except Exception as e:
                logger.error(f"Bulk analysis failed: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Bulk analysis failed: {str(e)}"
                )
        
        @self.app.post("/api/v1/respond", response_model=ResponseExecutionResponse, tags=["Response"])
        async def execute_response(
            request: ResponseRequest,
            credentials: HTTPAuthorizationCredentials = Security(self.security)
        ):
            """Execute manual response action for an IP"""
            await self._verify_api_key(credentials)
            
            try:
                # First analyze the IP if not already done
                analysis = await self.threat_intel.analyze_ip(request.ip)
                
                # Execute automated response
                execution = await self.response_engine.evaluate_and_respond(analysis)
                
                return ResponseExecutionResponse(
                    id=execution.id,
                    ip=execution.ip,
                    rule_name=execution.rule_name,
                    action=execution.action.value,
                    status=execution.status.value,
                    started_at=execution.started_at.isoformat(),
                    completed_at=execution.completed_at.isoformat() if execution.completed_at else None,
                    providers_used=execution.providers_used or [],
                    error_message=execution.error_message
                )
                
            except Exception as e:
                logger.error(f"Response execution failed for IP {request.ip}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Response execution failed: {str(e)}"
                )
        
        @self.app.delete("/api/v1/response/{execution_id}", tags=["Response"])
        async def rollback_response(
            execution_id: str,
            credentials: HTTPAuthorizationCredentials = Security(self.security)
        ):
            """Rollback a response execution"""
            await self._verify_api_key(credentials)
            
            try:
                success = await self.response_engine.rollback_response(execution_id)
                
                if success:
                    return {"message": f"Response {execution_id} rolled back successfully"}
                else:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Response {execution_id} not found or rollback failed"
                    )
                    
            except Exception as e:
                logger.error(f"Rollback failed for execution {execution_id}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Rollback failed: {str(e)}"
                )
        
        @self.app.get("/api/v1/blocked-ips", tags=["Status"])
        async def get_blocked_ips(
            provider: Optional[str] = None,
            credentials: HTTPAuthorizationCredentials = Security(self.security)
        ):
            """Get list of currently blocked IPs"""
            await self._verify_api_key(credentials)
            
            try:
                blocked_ips = {}
                
                for provider_name, provider in self.response_engine.providers.items():
                    if provider is None:
                        continue
                    if provider_name == provider or provider is None:
                        ips = await provider.list_blocked_ips()
                        blocked_ips[provider_name] = ips
                
                return {
                    "providers": blocked_ips,
                    "total_unique_ips": len(set().union(*blocked_ips.values())) if blocked_ips else 0
                }
                
            except Exception as e:
                logger.error(f"Failed to get blocked IPs: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to get blocked IPs: {str(e)}"
                )
        
        @self.app.get("/api/v1/providers", tags=["Status"])
        async def get_providers():
            """Get status of all providers (public endpoint)"""
            return {
                "threat_intelligence": self.threat_intel.get_provider_status(),
                "firewall": self._get_firewall_provider_status()
            }
    
    async def _verify_api_key(self, credentials: HTTPAuthorizationCredentials):
        """Verify API key from Authorization header"""
        if not self.api_keys:
            return  # No API key validation if none configured
            
        if not credentials or credentials.credentials not in self.api_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def _get_firewall_provider_status(self) -> Dict[str, Any]:
        """Get firewall provider status"""
        status = {}
        
        for name, provider in self.response_engine.providers.items():
            status[name] = {
                "enabled": provider.enabled,
                "name": provider.name
            }
            
        return status
    
    def _get_cache_statistics(self) -> Dict[str, Any]:
        """Get cache statistics"""
        cache = self.threat_intel.cache
        return {
            "entries": len(cache),
            "memory_usage_mb": 0,  # TODO: Calculate actual memory usage
            "hit_rate": 0.0  # TODO: Track cache hit rate
        }
    
    def run(self, host: str = "0.0.0.0", port: int = 8080, debug: bool = False):
        """Run the API server"""
        logger.info(f"Starting IPDefender Pro API server on {host}:{port}")
        
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="debug" if debug else "info",
            access_log=True
        )
