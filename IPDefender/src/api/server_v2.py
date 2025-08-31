"""
IPDefender Pro - Enhanced API Server V2
Advanced REST API with plugin system integration

Author: byFranke (https://byfranke.com)
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import json

# FastAPI and related imports
from fastapi import FastAPI, HTTPException, Depends, Security, status, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field
import uvicorn

# Local imports
from config.models import APIConfig
from plugins.manager import PluginManager
from monitoring.metrics import MonitoringManager
from core.threat_intel_v2 import ThreatIntelligenceEngineV2, ThreatAnalysisResult
from core.response_engine_v2 import AutomatedResponseEngineV2, ResponseResult, ResponseAction

logger = logging.getLogger(__name__)

# Request/Response Models
class ThreatAnalysisRequest(BaseModel):
    """Request model for threat analysis"""
    ip_address: str = Field(..., description="IP address to analyze")
    force_refresh: bool = Field(False, description="Force refresh of cached data")
    include_metadata: bool = Field(True, description="Include detailed metadata in response")

class ThreatAnalysisResponse(BaseModel):
    """Response model for threat analysis"""
    ip_address: str
    threat_score: float
    confidence: float
    threat_types: List[str]
    sources: List[str]
    analysis_time: str
    cache_hit: bool
    metadata: Optional[Dict[str, Any]] = None

class ResponseRequest(BaseModel):
    """Request model for response execution"""
    ip_address: str = Field(..., description="IP address to respond to")
    actions: List[str] = Field(..., description="Response actions to execute")
    priority: str = Field("medium", description="Response priority (low/medium/high/critical)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class ResponseResponse(BaseModel):
    """Response model for response execution"""
    request_id: str
    ip_address: str
    actions_executed: List[str]
    actions_failed: List[str]
    success_rate: float
    execution_time: float
    timestamp: str

class SystemStatusResponse(BaseModel):
    """Response model for system status"""
    status: str
    version: str
    uptime_seconds: float
    components: Dict[str, Any]
    statistics: Dict[str, Any]

class PluginInfo(BaseModel):
    """Plugin information model"""
    name: str
    type: str
    enabled: bool
    status: str
    version: Optional[str] = None
    description: Optional[str] = None

class MetricsResponse(BaseModel):
    """Metrics response model"""
    metrics: Dict[str, Any]
    timestamp: str

# Authentication
class APIKeyAuthentication:
    """API key authentication handler"""
    
    def __init__(self, api_keys: List[str]):
        self.api_keys = set(api_keys) if api_keys else set()
        self.security = HTTPBearer(auto_error=False)
    
    async def authenticate(self, credentials: Optional[HTTPAuthorizationCredentials] = Security(HTTPBearer(auto_error=False))):
        """Authenticate request using API key"""
        if not self.api_keys:
            # No authentication configured
            return True
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key required"
            )
        
        if credentials.credentials not in self.api_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
        return credentials.credentials

class IPDefenderProAPIV2:
    """Enhanced FastAPI-based REST API server"""
    
    def __init__(self, config: APIConfig, threat_engine: ThreatIntelligenceEngineV2,
                 response_engine: AutomatedResponseEngineV2, plugin_manager: PluginManager,
                 monitoring_manager: MonitoringManager):
        """Initialize the API server"""
        self.config = config
        self.threat_engine = threat_engine
        self.response_engine = response_engine
        self.plugin_manager = plugin_manager
        self.monitoring = monitoring_manager
        
        # API statistics
        self.start_time = datetime.now()
        self.request_count = 0
        self.error_count = 0
        
        # Create FastAPI app
        self.app = FastAPI(
            title="IPDefender Pro API",
            description="Advanced Cybersecurity Defense Platform API",
            version="2.0.0",
            docs_url="/docs" if config.enable_docs else None,
            redoc_url="/redoc" if config.enable_docs else None,
            openapi_url="/openapi.json" if config.enable_docs else None
        )
        
        # Setup authentication
        self.auth = APIKeyAuthentication(config.api_keys)
        
        # Setup middleware
        self._setup_middleware()
        
        # Setup routes
        self._setup_routes()
        
        # Server instance
        self.server = None
        
        logger.info("IPDefender Pro API v2.0.0 initialized")
    
    def _setup_middleware(self):
        """Setup FastAPI middleware"""
        # CORS middleware
        if self.config.cors_origins:
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=self.config.cors_origins,
                allow_credentials=True,
                allow_methods=["GET", "POST", "PUT", "DELETE"],
                allow_headers=["*"]
            )
        
        # Compression middleware
        self.app.add_middleware(GZipMiddleware, minimum_size=1000)
        
        # Request logging middleware
        @self.app.middleware("http")
        async def request_logging(request: Request, call_next):
            """Log all requests and track metrics"""
            start_time = datetime.now()
            
            # Process request
            try:
                response = await call_next(request)
                
                # Track successful request
                self.request_count += 1
                processing_time = (datetime.now() - start_time).total_seconds()
                
                # Record metrics
                self.monitoring.record_metric('api_requests_total', 1)
                self.monitoring.record_metric('api_request_duration', processing_time)
                
                logger.info(f"{request.method} {request.url.path} - {response.status_code} - {processing_time:.3f}s")
                
                return response
                
            except Exception as e:
                # Track error
                self.error_count += 1
                processing_time = (datetime.now() - start_time).total_seconds()
                
                # Record metrics
                self.monitoring.record_metric('api_requests_total', 1)
                self.monitoring.record_metric('api_request_errors', 1)
                self.monitoring.record_metric('api_request_duration', processing_time)
                
                logger.error(f"{request.method} {request.url.path} - ERROR - {processing_time:.3f}s: {e}")
                
                # Re-raise the exception
                raise
    
    def _setup_routes(self):
        """Setup API routes"""
        
        # Health check endpoint (no auth required)
        @self.app.get("/health", 
                     response_model=Dict[str, str],
                     summary="Health Check",
                     description="Check if the API server is running")
        async def health_check():
            """Basic health check endpoint"""
            return {"status": "healthy", "timestamp": datetime.now().isoformat()}
        
        # System status endpoint
        @self.app.get("/status", 
                     response_model=SystemStatusResponse,
                     dependencies=[Depends(self.auth.authenticate)],
                     summary="System Status",
                     description="Get detailed system status information")
        async def system_status():
            """Get comprehensive system status"""
            uptime = (datetime.now() - self.start_time).total_seconds()
            
            # Get component statuses
            threat_status = self.threat_engine.get_provider_status()
            response_status = self.response_engine.get_system_status()
            plugin_status = await self.plugin_manager.health_check_plugins()
            
            return SystemStatusResponse(
                status="healthy",
                version="2.0.0",
                uptime_seconds=uptime,
                components={
                    "threat_intelligence": {
                        "healthy_providers": threat_status.get("healthy_providers", 0),
                        "total_providers": threat_status.get("total_providers", 0),
                        "cache_stats": self.threat_engine.get_cache_stats()
                    },
                    "response_engine": {
                        "healthy": response_status.get("healthy", False),
                        "statistics": response_status.get("statistics", {})
                    },
                    "plugins": {
                        "total": len(plugin_status),
                        "healthy": len([p for p in plugin_status.values() if p.get('status') == 'healthy'])
                    }
                },
                statistics={
                    "api_requests": self.request_count,
                    "api_errors": self.error_count,
                    "uptime_seconds": uptime
                }
            )
        
        # Threat analysis endpoints
        @self.app.post("/analyze", 
                      response_model=ThreatAnalysisResponse,
                      dependencies=[Depends(self.auth.authenticate)],
                      summary="Analyze IP Address",
                      description="Analyze an IP address for threats using threat intelligence providers")
        async def analyze_ip(request: ThreatAnalysisRequest, background_tasks: BackgroundTasks):
            """Analyze IP address for threats"""
            try:
                # Perform threat analysis
                result = await self.threat_engine.analyze_ip(
                    request.ip_address, 
                    force_refresh=request.force_refresh
                )
                
                # Background task to trigger automated response if needed
                if result.threat_score > self.config.auto_response_threshold:
                    background_tasks.add_task(
                        self._trigger_automated_response, 
                        result, 
                        "api_analysis"
                    )
                
                # Build response
                response_data = {
                    "ip_address": result.ip_address,
                    "threat_score": result.threat_score,
                    "confidence": result.confidence,
                    "threat_types": result.threat_types,
                    "sources": result.sources,
                    "analysis_time": result.analysis_time.isoformat(),
                    "cache_hit": result.cache_hit
                }
                
                if request.include_metadata:
                    response_data["metadata"] = result.metadata
                
                return ThreatAnalysisResponse(**response_data)
                
            except Exception as e:
                logger.error(f"Error analyzing IP {request.ip_address}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Analysis failed: {str(e)}"
                )
        
        @self.app.post("/analyze/batch", 
                      response_model=List[ThreatAnalysisResponse],
                      dependencies=[Depends(self.auth.authenticate)],
                      summary="Batch Analyze IP Addresses",
                      description="Analyze multiple IP addresses in batch")
        async def batch_analyze(ip_addresses: List[str], force_refresh: bool = False):
            """Batch analyze multiple IP addresses"""
            if len(ip_addresses) > self.config.max_batch_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Batch size exceeds maximum of {self.config.max_batch_size}"
                )
            
            results = []
            tasks = []
            
            # Create analysis tasks
            for ip in ip_addresses:
                task = asyncio.create_task(
                    self.threat_engine.analyze_ip(ip, force_refresh=force_refresh)
                )
                tasks.append((ip, task))
            
            # Wait for all analyses to complete
            for ip, task in tasks:
                try:
                    result = await task
                    response_data = ThreatAnalysisResponse(
                        ip_address=result.ip_address,
                        threat_score=result.threat_score,
                        confidence=result.confidence,
                        threat_types=result.threat_types,
                        sources=result.sources,
                        analysis_time=result.analysis_time.isoformat(),
                        cache_hit=result.cache_hit
                    )
                    results.append(response_data)
                except Exception as e:
                    logger.error(f"Error analyzing IP {ip}: {e}")
                    # Add error result
                    results.append(ThreatAnalysisResponse(
                        ip_address=ip,
                        threat_score=0.0,
                        confidence=0.0,
                        threat_types=[],
                        sources=[],
                        analysis_time=datetime.now().isoformat(),
                        cache_hit=False,
                        metadata={"error": str(e)}
                    ))
            
            return results
        
        # Response execution endpoints
        @self.app.post("/respond", 
                      response_model=ResponseResponse,
                      dependencies=[Depends(self.auth.authenticate)],
                      summary="Execute Response Actions",
                      description="Execute automated response actions for an IP address")
        async def execute_response(request: ResponseRequest):
            """Execute response actions for an IP address"""
            try:
                # First analyze the IP if we don't have recent data
                threat_analysis = await self.threat_engine.analyze_ip(request.ip_address)
                
                # Execute response
                result = await self.response_engine.execute_response(
                    threat_analysis, 
                    source="api_manual"
                )
                
                return ResponseResponse(
                    request_id=result.request_id,
                    ip_address=result.ip_address,
                    actions_executed=[action.value for action in result.actions_executed],
                    actions_failed=[action.value for action in result.actions_failed],
                    success_rate=result.success_rate,
                    execution_time=result.execution_time,
                    timestamp=result.timestamp.isoformat()
                )
                
            except Exception as e:
                logger.error(f"Error executing response for {request.ip_address}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Response execution failed: {str(e)}"
                )
        
        # Plugin management endpoints
        @self.app.get("/plugins", 
                     response_model=List[PluginInfo],
                     dependencies=[Depends(self.auth.authenticate)],
                     summary="List Plugins",
                     description="Get information about all loaded plugins")
        async def list_plugins():
            """List all loaded plugins with their status"""
            plugins = []
            all_plugins = self.plugin_manager.get_all_plugins()
            
            for plugin_name, plugin in all_plugins.items():
                plugin_info = PluginInfo(
                    name=plugin_name,
                    type=getattr(plugin, 'plugin_type', 'unknown'),
                    enabled=plugin.is_enabled() if hasattr(plugin, 'is_enabled') else True,
                    status=getattr(plugin, 'status', 'unknown'),
                    version=getattr(plugin, 'version', None),
                    description=getattr(plugin, 'description', None)
                )
                plugins.append(plugin_info)
            
            return plugins
        
        @self.app.post("/plugins/{plugin_name}/enable", 
                      dependencies=[Depends(self.auth.authenticate)],
                      summary="Enable Plugin",
                      description="Enable a specific plugin")
        async def enable_plugin(plugin_name: str):
            """Enable a plugin"""
            try:
                result = await self.plugin_manager.enable_plugin(plugin_name)
                if result:
                    return {"message": f"Plugin {plugin_name} enabled successfully"}
                else:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Plugin {plugin_name} not found"
                    )
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to enable plugin: {str(e)}"
                )
        
        @self.app.post("/plugins/{plugin_name}/disable", 
                      dependencies=[Depends(self.auth.authenticate)],
                      summary="Disable Plugin",
                      description="Disable a specific plugin")
        async def disable_plugin(plugin_name: str):
            """Disable a plugin"""
            try:
                result = await self.plugin_manager.disable_plugin(plugin_name)
                if result:
                    return {"message": f"Plugin {plugin_name} disabled successfully"}
                else:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Plugin {plugin_name} not found"
                    )
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to disable plugin: {str(e)}"
                )
        
        # Metrics endpoint
        @self.app.get("/metrics", 
                     response_model=MetricsResponse,
                     dependencies=[Depends(self.auth.authenticate)],
                     summary="Get Metrics",
                     description="Get system metrics in JSON format")
        async def get_metrics():
            """Get system metrics"""
            metrics = await self.monitoring.get_metrics()
            
            return MetricsResponse(
                metrics=metrics,
                timestamp=datetime.now().isoformat()
            )
        
        # Prometheus metrics endpoint (plain text)
        @self.app.get("/metrics/prometheus", 
                     dependencies=[Depends(self.auth.authenticate)],
                     summary="Get Prometheus Metrics",
                     description="Get metrics in Prometheus format")
        async def get_prometheus_metrics():
            """Get metrics in Prometheus format"""
            try:
                from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
                metrics_data = generate_latest()
                return Response(content=metrics_data, media_type=CONTENT_TYPE_LATEST)
            except ImportError:
                raise HTTPException(
                    status_code=status.HTTP_501_NOT_IMPLEMENTED,
                    detail="Prometheus metrics not available (prometheus_client not installed)"
                )
        
        # Configuration endpoints
        @self.app.get("/config/validate", 
                     dependencies=[Depends(self.auth.authenticate)],
                     summary="Validate Configuration",
                     description="Validate current configuration")
        async def validate_config():
            """Validate current configuration"""
            try:
                from config.models import get_config
                config = get_config()
                return {
                    "valid": True,
                    "message": "Configuration is valid",
                    "config_sections": list(config.__dict__.keys())
                }
            except Exception as e:
                return {
                    "valid": False,
                    "message": f"Configuration validation failed: {str(e)}"
                }
    
    async def _trigger_automated_response(self, threat_analysis: ThreatAnalysisResult, source: str):
        """Background task to trigger automated response"""
        try:
            logger.info(f"Triggering automated response for {threat_analysis.ip_address} "
                       f"(Score: {threat_analysis.threat_score})")
            
            await self.response_engine.execute_response(threat_analysis, source=source)
            
        except Exception as e:
            logger.error(f"Error in automated response for {threat_analysis.ip_address}: {e}")
    
    async def initialize(self):
        """Initialize the API server"""
        try:
            logger.info("Initializing API server...")
            
            # Validate configuration
            if not self.config.api_keys and not self.config.disable_auth:
                logger.warning("API server running without authentication!")
            
            logger.info("API server initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize API server: {e}")
            raise
    
    async def start(self):
        """Start the API server"""
        try:
            logger.info(f"Starting API server on {self.config.host}:{self.config.port}")
            
            # Configure uvicorn server
            server_config = uvicorn.Config(
                self.app,
                host=self.config.host,
                port=self.config.port,
                log_level=self.config.log_level.lower(),
                access_log=self.config.access_log,
                reload=False,  # Disable in production
                workers=1  # Single worker for now
            )
            
            self.server = uvicorn.Server(server_config)
            await self.server.serve()
            
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown the API server"""
        try:
            logger.info("Shutting down API server...")
            
            if self.server:
                self.server.should_exit = True
                await self.server.shutdown()
            
            logger.info("API server shutdown complete")
            
        except Exception as e:
            logger.error(f"Error shutting down API server: {e}")

# For backwards compatibility
IPDefenderProAPI = IPDefenderProAPIV2
