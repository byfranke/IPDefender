"""
IPDefender Pro - Monitoring and Metrics System
Performance monitoring, metrics collection, and health checks

Author: byFranke (https://byfranke.com)
"""

import asyncio
import logging
import time
import psutil
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import deque, defaultdict
import json

logger = logging.getLogger(__name__)

@dataclass
class Metric:
    """Metric data point"""
    name: str
    value: float
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)
    metric_type: str = "gauge"  # gauge, counter, histogram

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'tags': self.tags,
            'type': self.metric_type
        }

@dataclass
class HealthCheckResult:
    """Health check result"""
    component: str
    healthy: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'component': self.component,
            'healthy': self.healthy,
            'message': self.message,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }

class MetricsCollector:
    """Collects and manages system metrics"""
    
    def __init__(self, max_metrics: int = 10000):
        self.metrics: deque[Metric] = deque(maxlen=max_metrics)
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.start_time = datetime.now()
    
    def record_counter(self, name: str, value: float = 1.0, tags: Dict[str, str] = None):
        """Record a counter metric"""
        self.counters[name] += value
        metric = Metric(
            name=name,
            value=self.counters[name],
            tags=tags or {},
            metric_type="counter"
        )
        self.metrics.append(metric)
    
    def record_gauge(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record a gauge metric"""
        self.gauges[name] = value
        metric = Metric(
            name=name,
            value=value,
            tags=tags or {},
            metric_type="gauge"
        )
        self.metrics.append(metric)
    
    def record_histogram(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record a histogram metric"""
        self.histograms[name].append(value)
        # Keep only last 1000 values per histogram
        if len(self.histograms[name]) > 1000:
            self.histograms[name] = self.histograms[name][-1000:]
        
        metric = Metric(
            name=name,
            value=value,
            tags=tags or {},
            metric_type="histogram"
        )
        self.metrics.append(metric)
    
    def get_counter(self, name: str) -> float:
        """Get counter value"""
        return self.counters.get(name, 0.0)
    
    def get_gauge(self, name: str) -> Optional[float]:
        """Get gauge value"""
        return self.gauges.get(name)
    
    def get_histogram_stats(self, name: str) -> Dict[str, float]:
        """Get histogram statistics"""
        values = self.histograms.get(name, [])
        if not values:
            return {}
        
        values_sorted = sorted(values)
        count = len(values)
        
        return {
            'count': count,
            'min': min(values),
            'max': max(values),
            'mean': sum(values) / count,
            'median': values_sorted[count // 2],
            'p95': values_sorted[int(count * 0.95)] if count > 1 else values[0],
            'p99': values_sorted[int(count * 0.99)] if count > 1 else values[0]
        }
    
    def get_metrics(self, since: Optional[datetime] = None) -> List[Metric]:
        """Get metrics since specified time"""
        if since is None:
            return list(self.metrics)
        
        return [m for m in self.metrics if m.timestamp >= since]
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.record_gauge("system.cpu.percent", cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.record_gauge("system.memory.percent", memory.percent)
            self.record_gauge("system.memory.available_mb", memory.available / 1024 / 1024)
            self.record_gauge("system.memory.used_mb", memory.used / 1024 / 1024)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.record_gauge("system.disk.percent", (disk.used / disk.total) * 100)
            self.record_gauge("system.disk.free_gb", disk.free / 1024 / 1024 / 1024)
            
            # Network I/O
            network = psutil.net_io_counters()
            self.record_gauge("system.network.bytes_sent", network.bytes_sent)
            self.record_gauge("system.network.bytes_recv", network.bytes_recv)
            
            # Process information
            process = psutil.Process()
            self.record_gauge("process.memory.rss_mb", process.memory_info().rss / 1024 / 1024)
            self.record_gauge("process.cpu.percent", process.cpu_percent())
            
            # Uptime
            uptime = (datetime.now() - self.start_time).total_seconds()
            self.record_gauge("system.uptime.seconds", uptime)
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_mb': memory.available / 1024 / 1024,
                'disk_percent': (disk.used / disk.total) * 100,
                'disk_free_gb': disk.free / 1024 / 1024 / 1024,
                'uptime_seconds': uptime,
                'process_memory_mb': process.memory_info().rss / 1024 / 1024,
                'process_cpu_percent': process.cpu_percent()
            }
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
            return {}
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format"""
        lines = []
        
        # Counters
        for name, value in self.counters.items():
            lines.append(f'# TYPE {name.replace(".", "_")} counter')
            lines.append(f'{name.replace(".", "_")} {value}')
        
        # Gauges
        for name, value in self.gauges.items():
            lines.append(f'# TYPE {name.replace(".", "_")} gauge')
            lines.append(f'{name.replace(".", "_")} {value}')
        
        # Histograms (simplified)
        for name, values in self.histograms.items():
            if values:
                stats = self.get_histogram_stats(name)
                metric_name = name.replace(".", "_")
                lines.append(f'# TYPE {metric_name} histogram')
                lines.append(f'{metric_name}_count {stats["count"]}')
                lines.append(f'{metric_name}_sum {sum(values)}')
                lines.append(f'{metric_name}_bucket{{le="0.5"}} {stats["median"]}')
                lines.append(f'{metric_name}_bucket{{le="0.95"}} {stats["p95"]}')
                lines.append(f'{metric_name}_bucket{{le="0.99"}} {stats["p99"]}')
                lines.append(f'{metric_name}_bucket{{le="+Inf"}} {stats["count"]}')
        
        return '\n'.join(lines)

class HealthChecker:
    """Performs health checks on system components"""
    
    def __init__(self):
        self.health_checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self.last_results: Dict[str, HealthCheckResult] = {}
    
    def register_health_check(self, component: str, check_func: Callable[[], HealthCheckResult]):
        """Register a health check function"""
        self.health_checks[component] = check_func
    
    async def run_health_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all health checks"""
        results = {}
        
        for component, check_func in self.health_checks.items():
            try:
                if asyncio.iscoroutinefunction(check_func):
                    result = await check_func()
                else:
                    result = await asyncio.to_thread(check_func)
                
                results[component] = result
                self.last_results[component] = result
                
            except Exception as e:
                result = HealthCheckResult(
                    component=component,
                    healthy=False,
                    message=f"Health check failed: {e}",
                    details={'exception': str(e)}
                )
                results[component] = result
                self.last_results[component] = result
        
        return results
    
    def get_overall_health(self) -> HealthCheckResult:
        """Get overall system health"""
        if not self.last_results:
            return HealthCheckResult(
                component="system",
                healthy=False,
                message="No health checks performed",
                details={}
            )
        
        healthy_count = sum(1 for result in self.last_results.values() if result.healthy)
        total_count = len(self.last_results)
        
        overall_healthy = healthy_count == total_count
        health_percentage = (healthy_count / total_count) * 100 if total_count > 0 else 0
        
        return HealthCheckResult(
            component="system",
            healthy=overall_healthy,
            message=f"System health: {health_percentage:.1f}% ({healthy_count}/{total_count} components healthy)",
            details={
                'healthy_components': healthy_count,
                'total_components': total_count,
                'health_percentage': health_percentage,
                'components': {name: result.healthy for name, result in self.last_results.items()}
            }
        )

class MonitoringManager:
    """Main monitoring manager"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics_collector = MetricsCollector()
        self.health_checker = HealthChecker()
        self.monitoring_task: Optional[asyncio.Task] = None
        self.health_check_task: Optional[asyncio.Task] = None
        
        # Monitoring intervals
        self.metrics_interval = config.get('metrics_interval', 60)  # seconds
        self.health_check_interval = config.get('health_check_interval', 120)  # seconds
        
        # Setup default health checks
        self._setup_default_health_checks()
    
    def _setup_default_health_checks(self):
        """Setup default health checks"""
        
        def check_system_resources() -> HealthCheckResult:
            """Check system resource usage"""
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                issues = []
                if cpu_percent > 90:
                    issues.append(f"High CPU usage: {cpu_percent:.1f}%")
                if memory.percent > 90:
                    issues.append(f"High memory usage: {memory.percent:.1f}%")
                if (disk.used / disk.total) * 100 > 90:
                    issues.append(f"High disk usage: {(disk.used / disk.total) * 100:.1f}%")
                
                healthy = len(issues) == 0
                message = "System resources OK" if healthy else f"Resource issues: {', '.join(issues)}"
                
                return HealthCheckResult(
                    component="system_resources",
                    healthy=healthy,
                    message=message,
                    details={
                        'cpu_percent': cpu_percent,
                        'memory_percent': memory.percent,
                        'disk_percent': (disk.used / disk.total) * 100
                    }
                )
                
            except Exception as e:
                return HealthCheckResult(
                    component="system_resources",
                    healthy=False,
                    message=f"Failed to check system resources: {e}"
                )
        
        def check_disk_space() -> HealthCheckResult:
            """Check available disk space"""
            try:
                disk = psutil.disk_usage('/')
                free_gb = disk.free / 1024 / 1024 / 1024
                
                if free_gb < 1:
                    healthy = False
                    message = f"Critical: Only {free_gb:.1f} GB free disk space"
                elif free_gb < 5:
                    healthy = False
                    message = f"Warning: Only {free_gb:.1f} GB free disk space"
                else:
                    healthy = True
                    message = f"Disk space OK: {free_gb:.1f} GB free"
                
                return HealthCheckResult(
                    component="disk_space",
                    healthy=healthy,
                    message=message,
                    details={'free_gb': free_gb}
                )
                
            except Exception as e:
                return HealthCheckResult(
                    component="disk_space",
                    healthy=False,
                    message=f"Failed to check disk space: {e}"
                )
        
        self.health_checker.register_health_check("system_resources", check_system_resources)
        self.health_checker.register_health_check("disk_space", check_disk_space)
    
    async def start_monitoring(self):
        """Start monitoring tasks"""
        if self.monitoring_task is not None:
            return  # Already started
        
        self.monitoring_task = asyncio.create_task(self._metrics_collection_loop())
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        
        logger.info("Monitoring started")
    
    async def stop_monitoring(self):
        """Stop monitoring tasks"""
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
            self.monitoring_task = None
        
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
            self.health_check_task = None
        
        logger.info("Monitoring stopped")
    
    async def _metrics_collection_loop(self):
        """Main metrics collection loop"""
        try:
            while True:
                # Collect system metrics
                self.metrics_collector.get_system_metrics()
                
                # Wait for next collection
                await asyncio.sleep(self.metrics_interval)
                
        except asyncio.CancelledError:
            logger.info("Metrics collection stopped")
        except Exception as e:
            logger.error(f"Metrics collection error: {e}")
    
    async def _health_check_loop(self):
        """Main health check loop"""
        try:
            while True:
                # Run health checks
                await self.health_checker.run_health_checks()
                
                # Wait for next check
                await asyncio.sleep(self.health_check_interval)
                
        except asyncio.CancelledError:
            logger.info("Health checks stopped")
        except Exception as e:
            logger.error(f"Health check error: {e}")
    
    def record_threat_analysis(self, ip: str, threat_score: float, duration: float):
        """Record threat analysis metrics"""
        self.metrics_collector.record_counter("threat_analysis.total")
        self.metrics_collector.record_histogram("threat_analysis.duration", duration)
        self.metrics_collector.record_gauge("threat_analysis.last_score", threat_score)
        
        if threat_score > 80:
            self.metrics_collector.record_counter("threat_analysis.high_threat")
        elif threat_score > 50:
            self.metrics_collector.record_counter("threat_analysis.medium_threat")
        else:
            self.metrics_collector.record_counter("threat_analysis.low_threat")
    
    def record_response_action(self, action: str, success: bool, duration: float):
        """Record response action metrics"""
        self.metrics_collector.record_counter(f"response_action.{action}")
        self.metrics_collector.record_histogram("response_action.duration", duration)
        
        if success:
            self.metrics_collector.record_counter(f"response_action.{action}.success")
        else:
            self.metrics_collector.record_counter(f"response_action.{action}.failure")
    
    def record_api_request(self, endpoint: str, method: str, status_code: int, duration: float):
        """Record API request metrics"""
        tags = {'endpoint': endpoint, 'method': method, 'status': str(status_code)}
        
        self.metrics_collector.record_counter("api.requests.total", tags=tags)
        self.metrics_collector.record_histogram("api.request.duration", duration, tags=tags)
        
        if status_code >= 400:
            self.metrics_collector.record_counter("api.requests.errors", tags=tags)
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring system status"""
        overall_health = self.health_checker.get_overall_health()
        system_metrics = self.metrics_collector.get_system_metrics()
        
        return {
            'monitoring_active': self.monitoring_task is not None and not self.monitoring_task.done(),
            'health_checking_active': self.health_check_task is not None and not self.health_check_task.done(),
            'overall_health': overall_health.to_dict(),
            'system_metrics': system_metrics,
            'metrics_count': len(self.metrics_collector.metrics),
            'last_health_checks': {
                name: result.to_dict() 
                for name, result in self.health_checker.last_results.items()
            }
        }

# Global monitoring manager
monitoring_manager: Optional[MonitoringManager] = None

def get_monitoring_manager() -> MonitoringManager:
    """Get the global monitoring manager"""
    global monitoring_manager
    if monitoring_manager is None:
        raise RuntimeError("Monitoring manager not initialized")
    return monitoring_manager

def initialize_monitoring(config: Dict[str, Any]) -> MonitoringManager:
    """Initialize the global monitoring manager"""
    global monitoring_manager
    monitoring_manager = MonitoringManager(config)
    return monitoring_manager
