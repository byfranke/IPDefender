"""
Web Dashboard Module for SecGuard Enterprise
==========================================

Secure local web interface for system monitoring and security visualization:
- Real-time system health dashboard
- Security metrics and threat visualization
- Local-only access with firewall restrictions
- Professional web interface
- REST API for live data
"""

import asyncio
import json
import logging
import socket
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from aiohttp import web, web_request
    from aiohttp.web_ws import WSMsgType
    import aiohttp_cors
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Run: pip install aiohttp aiohttp-cors")
    raise


class SecGuardWebDashboard:
    """Secure local web dashboard for SecGuard Enterprise"""
    
    def __init__(self, config_manager, logger, threat_hunter, ip_defender, scheduler, reporter):
        self.config = config_manager
        self.logger = logger
        self.threat_hunter = threat_hunter
        self.ip_defender = ip_defender
        self.scheduler = scheduler
        self.reporter = reporter
        
        # Web server configuration
        self.host = config_manager.get('web_dashboard.host', '127.0.0.1')
        self.port = config_manager.get('web_dashboard.port', 8888)
        self.enable_dashboard = config_manager.get('web_dashboard.enabled', False)
        
        # Security settings
        self.allowed_ips = config_manager.get('web_dashboard.allowed_ips', ['127.0.0.1', '::1'])
        self.api_key = config_manager.get('web_dashboard.api_key', None)
        
        # Dashboard paths
        self.web_dir = Path(__file__).parent.parent / 'web'
        self.templates_dir = self.web_dir / 'templates'
        self.static_dir = self.web_dir / 'static'
        
        # Initialize web components
        self.app = None
        self.websockets = set()
        self.running = False
        
    async def start_server(self):
        """Start the web dashboard server"""
        if not self.enable_dashboard:
            self.logger.info("Web dashboard is disabled in configuration")
            return {"success": False, "message": "Dashboard disabled in config"}
        
        try:
            # Create web directories
            await self._ensure_web_directories()
            
            # Generate web assets
            await self._generate_web_assets()
            
            # Configure firewall restrictions
            firewall_result = await self._configure_firewall_access()
            if not firewall_result['success']:
                self.logger.warning(f"Firewall configuration warning: {firewall_result['message']}")
            
            # Setup web application
            self.app = web.Application()
            
            # Setup CORS for local access only
            cors = aiohttp_cors.setup(self.app, defaults={
                f"http://{self.host}:{self.port}": aiohttp_cors.ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods="*"
                )
            })
            
            # Setup routes
            self._setup_routes()
            
            # Add CORS to all routes
            for route in list(self.app.router.routes()):
                cors.add(route)
            
            # Start server
            runner = web.AppRunner(self.app)
            await runner.setup()
            
            site = web.TCPSite(runner, self.host, self.port)
            await site.start()
            
            self.running = True
            
            self.logger.info(f"SecGuard Dashboard started at http://{self.host}:{self.port}")
            self.logger.info(f"Access restricted to IPs: {', '.join(self.allowed_ips)}")
            
            return {
                "success": True,
                "url": f"http://{self.host}:{self.port}",
                "port": self.port,
                "firewall_configured": firewall_result['success']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to start web dashboard: {e}")
            return {"success": False, "error": str(e)}
    
    def _setup_routes(self):
        """Setup web application routes"""
        # Static files
        self.app.router.add_static('/', self.static_dir, name='static')
        
        # Main dashboard
        self.app.router.add_get('/', self._dashboard_handler)
        self.app.router.add_get('/dashboard', self._dashboard_handler)
        
        # API endpoints
        self.app.router.add_get('/api/health', self._api_health)
        self.app.router.add_get('/api/security-status', self._api_security_status)
        self.app.router.add_get('/api/threat-summary', self._api_threat_summary)
        self.app.router.add_get('/api/ip-bans', self._api_ip_bans)
        self.app.router.add_get('/api/scheduled-jobs', self._api_scheduled_jobs)
        self.app.router.add_get('/api/system-metrics', self._api_system_metrics)
        
        # WebSocket for real-time updates
        self.app.router.add_get('/ws', self._websocket_handler)
        
        # Security middleware
        self.app.middlewares.append(self._security_middleware)
    
    @web.middleware
    async def _security_middleware(self, request: web_request.Request, handler):
        """Security middleware for IP filtering and API key validation"""
        # Get client IP
        client_ip = request.remote
        if request.headers.get('X-Forwarded-For'):
            client_ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        
        # Check if IP is allowed
        if client_ip not in self.allowed_ips:
            self.logger.warning(f"Blocked access attempt from {client_ip}")
            raise web.HTTPForbidden(text="Access denied: IP not allowed")
        
        # Check API key for API endpoints (optional)
        if request.path.startswith('/api/') and self.api_key:
            provided_key = request.headers.get('X-API-Key') or request.query.get('api_key')
            if provided_key != self.api_key:
                raise web.HTTPUnauthorized(text="Invalid API key")
        
        return await handler(request)
    
    async def _dashboard_handler(self, request):
        """Main dashboard page handler"""
        html_content = await self._generate_dashboard_html()
        return web.Response(text=html_content, content_type='text/html')
    
    async def _api_health(self, request):
        """API endpoint for system health"""
        try:
            import psutil
            
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Get network stats
            network = psutil.net_io_counters()
            
            # Get process count
            processes = len(psutil.pids())
            
            health_data = {
                "timestamp": datetime.now().isoformat(),
                "status": "healthy",
                "system": {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_used_gb": round(memory.used / (1024**3), 2),
                    "memory_total_gb": round(memory.total / (1024**3), 2),
                    "disk_percent": (disk.used / disk.total) * 100,
                    "disk_used_gb": round(disk.used / (1024**3), 2),
                    "disk_total_gb": round(disk.total / (1024**3), 2),
                    "processes": processes
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                }
            }
            
            return web.json_response(health_data)
            
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    async def _api_security_status(self, request):
        """API endpoint for security status"""
        try:
            # Get current security status
            security_status = {
                "timestamp": datetime.now().isoformat(),
                "ufw_status": await self._get_ufw_status(),
                "fail2ban_status": await self._get_fail2ban_status(),
                "services_status": await self._get_critical_services_status(),
                "last_scan": await self._get_last_scan_info(),
                "active_threats": await self._get_active_threats_count()
            }
            
            return web.json_response(security_status)
            
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    async def _api_threat_summary(self, request):
        """API endpoint for threat summary"""
        try:
            # Get threat summary data
            threat_summary = {
                "timestamp": datetime.now().isoformat(),
                "total_scans": await self._get_total_scans(),
                "threats_detected": await self._get_threats_detected(),
                "threats_by_type": await self._get_threats_by_type(),
                "recent_detections": await self._get_recent_detections(limit=10)
            }
            
            return web.json_response(threat_summary)
            
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    async def _api_ip_bans(self, request):
        """API endpoint for IP ban information"""
        try:
            # Get IP ban statistics
            bans = await self.ip_defender.list_bans()
            
            ip_ban_data = {
                "timestamp": datetime.now().isoformat(),
                "total_bans": len(bans),
                "active_bans": len([b for b in bans if b.get('active', True)]),
                "recent_bans": [b for b in bans[:10]],  # Last 10 bans
                "ban_countries": self._get_country_stats(bans),
                "ban_reasons": self._get_ban_reason_stats(bans)
            }
            
            return web.json_response(ip_ban_data)
            
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    async def _api_scheduled_jobs(self, request):
        """API endpoint for scheduled jobs status"""
        try:
            jobs_status = await self.scheduler.get_status()
            
            job_data = {
                "timestamp": datetime.now().isoformat(),
                "jobs": jobs_status,
                "total_jobs": len(jobs_status),
                "active_jobs": len([j for j in jobs_status if j['status'] == 'Enabled'])
            }
            
            return web.json_response(job_data)
            
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    async def _api_system_metrics(self, request):
        """API endpoint for detailed system metrics"""
        try:
            import psutil
            
            # Get detailed metrics
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "uptime_hours": round(uptime.total_seconds() / 3600, 2),
                "boot_time": boot_time.isoformat(),
                "cpu_count": psutil.cpu_count(),
                "load_average": list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else None,
                "memory_available_gb": round(psutil.virtual_memory().available / (1024**3), 2),
                "disk_io": psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else None,
                "network_connections": len(psutil.net_connections()),
            }
            
            return web.json_response(metrics)
            
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    async def _websocket_handler(self, request):
        """WebSocket handler for real-time updates"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        self.websockets.add(ws)
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    if msg.data == 'close':
                        await ws.close()
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f'WebSocket error: {ws.exception()}')
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
        finally:
            self.websockets.discard(ws)
        
        return ws
    
    async def broadcast_update(self, data):
        """Broadcast update to all connected WebSocket clients"""
        if not self.websockets:
            return
        
        message = json.dumps({
            "type": "update",
            "data": data,
            "timestamp": datetime.now().isoformat()
        })
        
        # Send to all connected clients
        dead_sockets = set()
        for ws in self.websockets:
            try:
                await ws.send_str(message)
            except Exception:
                dead_sockets.add(ws)
        
        # Remove dead connections
        self.websockets -= dead_sockets
    
    async def _configure_firewall_access(self):
        """Configure UFW to allow local access to dashboard port"""
        try:
            # Check if UFW is active
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if result.returncode != 0:
                return {"success": False, "message": "UFW not available"}
            
            # Add rule for localhost access only
            cmd = [
                'ufw', 'allow', 'from', '127.0.0.1', 
                'to', 'any', 'port', str(self.port), 
                'comment', f'SecGuard Dashboard {self.port}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"UFW rule added for dashboard port {self.port}")
                return {"success": True, "message": f"Firewall configured for port {self.port}"}
            else:
                return {"success": False, "message": f"Failed to configure UFW: {result.stderr}"}
                
        except Exception as e:
            return {"success": False, "message": f"Firewall configuration error: {e}"}
    
    async def _ensure_web_directories(self):
        """Ensure web directories exist"""
        self.web_dir.mkdir(exist_ok=True)
        self.templates_dir.mkdir(exist_ok=True)
        self.static_dir.mkdir(exist_ok=True)
        (self.static_dir / 'css').mkdir(exist_ok=True)
        (self.static_dir / 'js').mkdir(exist_ok=True)
    
    async def _generate_web_assets(self):
        """Generate HTML, CSS, and JS files for the dashboard"""
        await self._generate_dashboard_html_file()
        await self._generate_dashboard_css()
        await self._generate_dashboard_js()
    
    async def _generate_dashboard_html(self):
        """Generate the main dashboard HTML"""
        return """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecGuard Enterprise - Dashboard</title>
    <link rel="stylesheet" href="/static/css/dashboard.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <header class="dashboard-header">
            <div class="header-content">
                <h1>SecGuard Enterprise</h1>
                <div class="header-status">
                    <span class="status-indicator" id="connection-status">●</span>
                    <span id="last-update">Conectando...</span>
                </div>
            </div>
        </header>

        <!-- Main Dashboard -->
        <main class="dashboard-main">
            <!-- System Health Cards -->
            <section class="health-cards">
                <div class="card cpu-card">
                    <div class="card-header">
                        <h3>CPU</h3>
                        <span class="card-value" id="cpu-usage">--</span>
                    </div>
                    <div class="card-chart">
                        <canvas id="cpu-chart"></canvas>
                    </div>
                </div>

                <div class="card memory-card">
                    <div class="card-header">
                        <h3>Memória</h3>
                        <span class="card-value" id="memory-usage">--</span>
                    </div>
                    <div class="card-chart">
                        <canvas id="memory-chart"></canvas>
                    </div>
                </div>

                <div class="card disk-card">
                    <div class="card-header">
                        <h3>Disco</h3>
                        <span class="card-value" id="disk-usage">--</span>
                    </div>
                    <div class="card-chart">
                        <canvas id="disk-chart"></canvas>
                    </div>
                </div>

                <div class="card security-card">
                    <div class="card-header">
                        <h3>Status Segurança</h3>
                        <span class="card-status" id="security-status">--</span>
                    </div>
                    <div class="security-indicators">
                        <div class="indicator">
                            <span class="indicator-label">UFW:</span>
                            <span class="indicator-status" id="ufw-status">--</span>
                        </div>
                        <div class="indicator">
                            <span class="indicator-label">Fail2Ban:</span>
                            <span class="indicator-status" id="fail2ban-status">--</span>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Threat Detection Section -->
            <section class="threats-section">
                <div class="section-header">
                    <h2>Detecção de Ameaças</h2>
                    <div class="section-controls">
                        <button class="refresh-btn" onclick="refreshData()">Atualizar</button>
                    </div>
                </div>
                
                <div class="threats-content">
                    <div class="threats-summary">
                        <div class="summary-card">
                            <h4>Total de Scans</h4>
                            <span class="summary-value" id="total-scans">0</span>
                        </div>
                        <div class="summary-card">
                            <h4>Ameaças Detectadas</h4>
                            <span class="summary-value threat-count" id="threats-detected">0</span>
                        </div>
                        <div class="summary-card">
                            <h4>IPs Banidos</h4>
                            <span class="summary-value" id="banned-ips">0</span>
                        </div>
                        <div class="summary-card">
                            <h4>Jobs Agendados</h4>
                            <span class="summary-value" id="scheduled-jobs">0</span>
                        </div>
                    </div>

                    <div class="threats-charts">
                        <div class="chart-container">
                            <h4>Tipos de Ameaças</h4>
                            <canvas id="threats-type-chart"></canvas>
                        </div>
                        <div class="chart-container">
                            <h4>Países - IPs Banidos</h4>
                            <canvas id="banned-countries-chart"></canvas>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Recent Activities -->
            <section class="activities-section">
                <div class="section-header">
                    <h2>Atividades Recentes</h2>
                </div>
                
                <div class="activities-content">
                    <div class="activity-log" id="activity-log">
                        <div class="log-entry">Carregando atividades...</div>
                    </div>
                </div>
            </section>

            <!-- Jobs Schedule Status -->
            <section class="jobs-section">
                <div class="section-header">
                    <h2>Jobs Agendados</h2>
                </div>
                
                <div class="jobs-content">
                    <div class="jobs-table-container">
                        <table class="jobs-table" id="jobs-table">
                            <thead>
                                <tr>
                                    <th>Tipo</th>
                                    <th>Frequência</th>
                                    <th>Status</th>
                                    <th>Próxima Execução</th>
                                    <th>Última Execução</th>
                                </tr>
                            </thead>
                            <tbody id="jobs-table-body">
                                <tr>
                                    <td colspan="5">Carregando jobs...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <script src="/static/js/dashboard.js"></script>
</body>
</html>"""
    
    async def _generate_dashboard_html_file(self):
        """Write dashboard HTML to file"""
        html_content = await self._generate_dashboard_html()
        with open(self.templates_dir / 'dashboard.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    async def _generate_dashboard_css(self):
        """Generate dashboard CSS styles"""
        css_content = """/* SecGuard Enterprise Dashboard Styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: #f5f5f7;
    color: #1d1d1f;
    line-height: 1.6;
}

.dashboard-container {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Header */
.dashboard-header {
    background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
    color: white;
    padding: 1rem 2rem;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    max-width: 1400px;
    margin: 0 auto;
}

.header-content h1 {
    font-size: 1.8rem;
    font-weight: 600;
}

.header-status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.status-indicator {
    font-size: 1.2rem;
    color: #27ae60;
}

.status-indicator.disconnected {
    color: #e74c3c;
}

/* Main Dashboard */
.dashboard-main {
    flex: 1;
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
    width: 100%;
}

/* Health Cards */
.health-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
}

.card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    transition: transform 0.2s ease;
}

.card:hover {
    transform: translateY(-2px);
}

.card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}

.card-header h3 {
    color: #2c3e50;
    font-size: 1.1rem;
    font-weight: 600;
}

.card-value {
    font-size: 1.8rem;
    font-weight: 700;
    color: #3498db;
}

.card-chart {
    height: 120px;
    position: relative;
}

.security-indicators {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.indicator {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem;
    background: #f8f9fa;
    border-radius: 6px;
}

.indicator-status.active {
    color: #27ae60;
    font-weight: 600;
}

.indicator-status.inactive {
    color: #e74c3c;
    font-weight: 600;
}

/* Sections */
section {
    background: white;
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 2rem;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid #ecf0f1;
}

.section-header h2 {
    color: #2c3e50;
    font-size: 1.4rem;
    font-weight: 600;
}

.refresh-btn {
    background: #3498db;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 500;
    transition: background-color 0.2s ease;
}

.refresh-btn:hover {
    background: #2980b9;
}

/* Threats Section */
.threats-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.summary-card {
    background: #f8f9fa;
    padding: 1.5rem;
    border-radius: 8px;
    text-align: center;
    border-left: 4px solid #3498db;
}

.summary-card h4 {
    color: #7f8c8d;
    font-size: 0.9rem;
    margin-bottom: 0.5rem;
}

.summary-value {
    font-size: 2rem;
    font-weight: 700;
    color: #2c3e50;
}

.threat-count {
    color: #e74c3c;
}

.threats-charts {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
}

.chart-container {
    background: #f8f9fa;
    padding: 1.5rem;
    border-radius: 8px;
}

.chart-container h4 {
    color: #2c3e50;
    margin-bottom: 1rem;
    text-align: center;
}

/* Activities Section */
.activity-log {
    max-height: 400px;
    overflow-y: auto;
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1rem;
}

.log-entry {
    padding: 0.5rem;
    margin-bottom: 0.5rem;
    background: white;
    border-radius: 4px;
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.9rem;
    border-left: 3px solid #3498db;
}

.log-entry.warning {
    border-left-color: #f39c12;
}

.log-entry.error {
    border-left-color: #e74c3c;
}

/* Jobs Table */
.jobs-table-container {
    overflow-x: auto;
}

.jobs-table {
    width: 100%;
    border-collapse: collapse;
    background: white;
}

.jobs-table th,
.jobs-table td {
    padding: 1rem;
    text-align: left;
    border-bottom: 1px solid #ecf0f1;
}

.jobs-table th {
    background: #f8f9fa;
    font-weight: 600;
    color: #2c3e50;
}

.jobs-table tbody tr:hover {
    background: #f8f9fa;
}

.status-enabled {
    color: #27ae60;
    font-weight: 600;
}

.status-disabled {
    color: #e74c3c;
    font-weight: 600;
}

/* Responsive Design */
@media (max-width: 768px) {
    .dashboard-main {
        padding: 1rem;
    }
    
    .health-cards {
        grid-template-columns: 1fr;
    }
    
    .threats-charts {
        grid-template-columns: 1fr;
    }
    
    .header-content {
        flex-direction: column;
        gap: 1rem;
    }
    
    section {
        padding: 1.5rem;
    }
}

/* Animation */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.card, section {
    animation: fadeIn 0.5s ease-out;
}

/* Scrollbar Styling */
.activity-log::-webkit-scrollbar {
    width: 6px;
}

.activity-log::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 3px;
}

.activity-log::-webkit-scrollbar-thumb {
    background: #c1c1c1;
    border-radius: 3px;
}

.activity-log::-webkit-scrollbar-thumb:hover {
    background: #a8a8a8;
}"""
        
        with open(self.static_dir / 'css' / 'dashboard.css', 'w', encoding='utf-8') as f:
            f.write(css_content)
    
    async def _generate_dashboard_js(self):
        """Generate dashboard JavaScript functionality"""
        js_content = """// SecGuard Enterprise Dashboard JavaScript
class SecGuardDashboard {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.updateInterval = null;
        this.isConnected = false;
        
        this.init();
    }
    
    init() {
        this.connectWebSocket();
        this.initCharts();
        this.startDataRefresh();
        this.bindEvents();
    }
    
    connectWebSocket() {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.updateConnectionStatus(true);
        };
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.isConnected = false;
            this.updateConnectionStatus(false);
            
            // Reconnect after 5 seconds
            setTimeout(() => this.connectWebSocket(), 5000);
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    handleWebSocketMessage(data) {
        if (data.type === 'update') {
            this.updateDashboard(data.data);
        }
    }
    
    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connection-status');
        const lastUpdateElement = document.getElementById('last-update');
        
        if (connected) {
            statusElement.textContent = '●';
            statusElement.style.color = '#27ae60';
            lastUpdateElement.textContent = 'Conectado';
        } else {
            statusElement.textContent = '●';
            statusElement.style.color = '#e74c3c';
            lastUpdateElement.textContent = 'Desconectado';
        }
    }
    
    async fetchData(endpoint) {
        try {
            const response = await fetch(`/api/${endpoint}`);
            if (!response.ok) throw new Error('Network response was not ok');
            return await response.json();
        } catch (error) {
            console.error(`Error fetching ${endpoint}:`, error);
            return null;
        }
    }
    
    async updateDashboard(data = null) {
        // Update system health
        await this.updateSystemHealth();
        
        // Update security status
        await this.updateSecurityStatus();
        
        // Update threat information
        await this.updateThreatInfo();
        
        // Update IP bans
        await this.updateIPBans();
        
        // Update scheduled jobs
        await this.updateScheduledJobs();
        
        // Update activity log
        await this.updateActivityLog();
        
        // Update last refresh time
        document.getElementById('last-update').textContent = 
            'Atualizado: ' + new Date().toLocaleTimeString('pt-BR');
    }
    
    async updateSystemHealth() {
        const healthData = await this.fetchData('health');
        if (!healthData) return;
        
        const { system } = healthData;
        
        // Update CPU
        document.getElementById('cpu-usage').textContent = `${system.cpu_percent.toFixed(1)}%`;
        this.updateChart('cpu-chart', [system.cpu_percent]);
        
        // Update Memory
        document.getElementById('memory-usage').textContent = `${system.memory_percent.toFixed(1)}%`;
        this.updateChart('memory-chart', [system.memory_percent]);
        
        // Update Disk
        document.getElementById('disk-usage').textContent = `${system.disk_percent.toFixed(1)}%`;
        this.updateChart('disk-chart', [system.disk_percent]);
    }
    
    async updateSecurityStatus() {
        const securityData = await this.fetchData('security-status');
        if (!securityData) return;
        
        // Update UFW status
        const ufwElement = document.getElementById('ufw-status');
        ufwElement.textContent = securityData.ufw_status ? 'Ativo' : 'Inativo';
        ufwElement.className = `indicator-status ${securityData.ufw_status ? 'active' : 'inactive'}`;
        
        // Update Fail2Ban status
        const fail2banElement = document.getElementById('fail2ban-status');
        fail2banElement.textContent = securityData.fail2ban_status ? 'Ativo' : 'Inativo';
        fail2banElement.className = `indicator-status ${securityData.fail2ban_status ? 'active' : 'inactive'}`;
        
        // Update overall security status
        const overallSecure = securityData.ufw_status && securityData.fail2ban_status;
        document.getElementById('security-status').textContent = overallSecure ? 'Seguro' : 'Atenção';
    }
    
    async updateThreatInfo() {
        const threatData = await this.fetchData('threat-summary');
        if (!threatData) return;
        
        document.getElementById('total-scans').textContent = threatData.total_scans || 0;
        document.getElementById('threats-detected').textContent = threatData.threats_detected || 0;
        
        // Update threat types chart
        if (threatData.threats_by_type) {
            this.updateThreatTypesChart(threatData.threats_by_type);
        }
    }
    
    async updateIPBans() {
        const banData = await this.fetchData('ip-bans');
        if (!banData) return;
        
        document.getElementById('banned-ips').textContent = banData.total_bans || 0;
        
        // Update banned countries chart
        if (banData.ban_countries) {
            this.updateBannedCountriesChart(banData.ban_countries);
        }
    }
    
    async updateScheduledJobs() {
        const jobsData = await this.fetchData('scheduled-jobs');
        if (!jobsData) return;
        
        document.getElementById('scheduled-jobs').textContent = jobsData.active_jobs || 0;
        
        // Update jobs table
        const tableBody = document.getElementById('jobs-table-body');
        tableBody.innerHTML = '';
        
        if (jobsData.jobs && jobsData.jobs.length > 0) {
            jobsData.jobs.forEach(job => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${job.type || 'N/A'}</td>
                    <td>${job.frequency || 'N/A'}</td>
                    <td><span class="status-${job.status === 'Enabled' ? 'enabled' : 'disabled'}">${job.status}</span></td>
                    <td>${job.next_run ? new Date(job.next_run).toLocaleString('pt-BR') : 'N/A'}</td>
                    <td>${job.last_run ? new Date(job.last_run).toLocaleString('pt-BR') : 'Nunca'}</td>
                `;
                tableBody.appendChild(row);
            });
        } else {
            tableBody.innerHTML = '<tr><td colspan="5">Nenhum job agendado</td></tr>';
        }
    }
    
    async updateActivityLog() {
        // Simulate activity log entries
        const logEntries = [
            { time: new Date(), message: 'Sistema funcionando normalmente', type: 'info' },
            { time: new Date(Date.now() - 300000), message: 'Verificação de ameaças concluída', type: 'info' },
            { time: new Date(Date.now() - 600000), message: 'Novo IP banido: 192.168.1.100', type: 'warning' }
        ];
        
        const logContainer = document.getElementById('activity-log');
        logContainer.innerHTML = '';
        
        logEntries.forEach(entry => {
            const logElement = document.createElement('div');
            logElement.className = `log-entry ${entry.type}`;
            logElement.textContent = `[${entry.time.toLocaleTimeString('pt-BR')}] ${entry.message}`;
            logContainer.appendChild(logElement);
        });
    }
    
    initCharts() {
        // Initialize CPU chart
        this.charts.cpu = this.createGaugeChart('cpu-chart', 'CPU Usage', '#3498db');
        
        // Initialize Memory chart
        this.charts.memory = this.createGaugeChart('memory-chart', 'Memory Usage', '#e74c3c');
        
        // Initialize Disk chart
        this.charts.disk = this.createGaugeChart('disk-chart', 'Disk Usage', '#f39c12');
        
        // Initialize threat types chart
        this.charts.threatTypes = this.createDoughnutChart('threats-type-chart', 'Tipos de Ameaças');
        
        // Initialize banned countries chart
        this.charts.bannedCountries = this.createDoughnutChart('banned-countries-chart', 'Países Banidos');
    }
    
    createGaugeChart(canvasId, label, color) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [color, '#ecf0f1'],
                    borderWidth: 0,
                    cutout: '70%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });
    }
    
    createDoughnutChart(canvasId, label) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#3498db', '#e74c3c', '#f39c12', '#27ae60', '#9b59b6'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 10,
                            font: { size: 10 }
                        }
                    }
                }
            }
        });
    }
    
    updateChart(chartName, values) {
        const chart = this.charts[chartName.replace('-chart', '')];
        if (chart && values.length > 0) {
            chart.data.datasets[0].data = [values[0], 100 - values[0]];
            chart.update('none');
        }
    }
    
    updateThreatTypesChart(data) {
        const chart = this.charts.threatTypes;
        if (chart && data) {
            const labels = Object.keys(data);
            const values = Object.values(data);
            
            chart.data.labels = labels;
            chart.data.datasets[0].data = values;
            chart.update();
        }
    }
    
    updateBannedCountriesChart(data) {
        const chart = this.charts.bannedCountries;
        if (chart && data) {
            const labels = Object.keys(data).slice(0, 5); // Top 5 countries
            const values = Object.values(data).slice(0, 5);
            
            chart.data.labels = labels;
            chart.data.datasets[0].data = values;
            chart.update();
        }
    }
    
    startDataRefresh() {
        // Initial load
        this.updateDashboard();
        
        // Refresh every 30 seconds
        this.updateInterval = setInterval(() => {
            this.updateDashboard();
        }, 30000);
    }
    
    bindEvents() {
        // Global refresh function
        window.refreshData = () => {
            this.updateDashboard();
        };
        
        // Handle visibility change to pause/resume updates
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                if (this.updateInterval) {
                    clearInterval(this.updateInterval);
                    this.updateInterval = null;
                }
            } else {
                this.startDataRefresh();
            }
        });
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SecGuardDashboard();
});"""
        
        with open(self.static_dir / 'js' / 'dashboard.js', 'w', encoding='utf-8') as f:
            f.write(js_content)
    
    # Helper methods for data collection
    async def _get_ufw_status(self):
        """Get UFW firewall status"""
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            return 'Status: active' in result.stdout
        except:
            return False
    
    async def _get_fail2ban_status(self):
        """Get Fail2Ban service status"""
        try:
            result = subprocess.run(['systemctl', 'is-active', 'fail2ban'], capture_output=True, text=True)
            return result.stdout.strip() == 'active'
        except:
            return False
    
    async def _get_critical_services_status(self):
        """Get status of critical services"""
        services = ['ssh', 'ufw', 'fail2ban']
        status = {}
        
        for service in services:
            try:
                result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
                status[service] = result.stdout.strip() == 'active'
            except:
                status[service] = False
        
        return status
    
    async def _get_last_scan_info(self):
        """Get information about the last security scan"""
        try:
            # This would typically read from a scan log or database
            scan_log = Path('/var/log/secguard/threat_scan.log')
            if scan_log.exists():
                stat = scan_log.stat()
                return {
                    'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'status': 'completed'
                }
        except:
            pass
        
        return {
            'timestamp': None,
            'status': 'never'
        }
    
    async def _get_active_threats_count(self):
        """Get count of active threats"""
        try:
            # This would typically query the threat database
            return 0  # Placeholder
        except:
            return 0
    
    async def _get_total_scans(self):
        """Get total number of scans performed"""
        try:
            # This would typically query scan statistics
            return 42  # Placeholder
        except:
            return 0
    
    async def _get_threats_detected(self):
        """Get total threats detected"""
        try:
            # This would typically query threat statistics
            return 3  # Placeholder
        except:
            return 0
    
    async def _get_threats_by_type(self):
        """Get threats breakdown by type"""
        try:
            # This would typically query threat database
            return {
                'Malware': 2,
                'Suspicious Files': 1,
                'Network Intrusion': 0
            }
        except:
            return {}
    
    async def _get_recent_detections(self, limit=10):
        """Get recent threat detections"""
        try:
            # This would typically query detection logs
            return [
                {
                    'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                    'type': 'Malware',
                    'file': '/tmp/suspicious_file.sh',
                    'action': 'quarantined'
                },
                {
                    'timestamp': (datetime.now() - timedelta(hours=6)).isoformat(),
                    'type': 'Suspicious File',
                    'file': '/var/www/upload.php',
                    'action': 'flagged'
                }
            ]
        except:
            return []
    
    def _get_country_stats(self, bans):
        """Get country statistics from IP bans"""
        countries = {}
        for ban in bans:
            country = ban.get('country', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
        return countries
    
    def _get_ban_reason_stats(self, bans):
        """Get ban reason statistics"""
        reasons = {}
        for ban in bans:
            reason = ban.get('reason', 'Unknown')
            reasons[reason] = reasons.get(reason, 0) + 1
        return reasons
    
    async def stop_server(self):
        """Stop the web dashboard server"""
        self.running = False
        
        # Close all websocket connections
        for ws in self.websockets:
            await ws.close()
        self.websockets.clear()
        
        if self.app:
            await self.app.cleanup()
        
        self.logger.info("Web dashboard stopped")
