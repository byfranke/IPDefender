#!/usr/bin/env python3
"""
IPDefender Pro - Enhanced Main Application
Advanced cybersecurity defense platform with plugin architecture

Author: byFranke (https://byfranke.com)
Version: 2.0.0
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import configuration and core modules
from config.models import load_config, get_config, set_config, IPDefenderProConfig
from database.manager import initialize_database, get_db_manager
from plugins.manager import initialize_plugin_manager, get_plugin_manager
from monitoring.metrics import initialize_monitoring, get_monitoring_manager

# Core engines
from core.threat_intel_v2 import ThreatIntelligenceEngineV2
from core.response_engine_v2 import AutomatedResponseEngineV2

# API server
from api.server_v2 import IPDefenderProAPIV2

# Integrations
from integrations.wazuh import WazuhIntegration

# Logging setup
from logging.handlers import RotatingFileHandler
import structlog

logger = logging.getLogger(__name__)

class IPDefenderProApplication:
    """Main IPDefender Pro application with enhanced architecture"""
    
    def __init__(self, config_path: str = "/etc/ipdefender/config.yaml"):
        """Initialize the application"""
        self.config_path = config_path
        self.config: Optional[IPDefenderProConfig] = None
        
        # Core components
        self.db_manager = None
        self.plugin_manager = None
        self.monitoring_manager = None
        self.threat_engine = None
        self.response_engine = None
        self.api_server = None
        self.wazuh_integration = None
        
        # Runtime state
        self.running = False
        self.tasks = []
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating shutdown...")
            if self.running:
                asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def initialize(self) -> bool:
        """Initialize all application components"""
        try:
            logger.info("🛡️ Starting IPDefender Pro v2.0.0 by byFranke")
            logger.info("=" * 60)
            
            # 1. Load and validate configuration
            logger.info("📝 Loading configuration...")
            self.config = load_config(self.config_path)
            set_config(self.config)
            
            # Setup logging based on config
            self._setup_logging()
            
            logger.info(f"✅ Configuration loaded from {self.config_path}")
            
            # 2. Initialize database
            logger.info("🗄️ Initializing database...")
            self.db_manager = initialize_database(self.config.database)
            logger.info(f"✅ Database initialized ({self.config.database.type})")
            
            # 3. Initialize plugin system
            logger.info("🔌 Loading plugins...")
            plugins_dir = Path(__file__).parent / "plugins"
            plugin_configs = {
                'abuseipdb': {
                    'enabled': self.config.threat_intelligence.abuseipdb.enabled,
                    'api_key': self.config.threat_intelligence.abuseipdb.api_key,
                    'weight': self.config.threat_intelligence.abuseipdb.weight,
                    'cache_ttl': self.config.threat_intelligence.abuseipdb.cache_ttl,
                    'timeout': self.config.threat_intelligence.abuseipdb.timeout,
                    'rate_limit': self.config.threat_intelligence.abuseipdb.rate_limit
                },
                'ufw': {
                    'enabled': self.config.response_engine.ufw.enabled,
                    'priority': self.config.response_engine.ufw.priority,
                    'timeout': self.config.response_engine.ufw.timeout
                },
                'cloudflare': {
                    'enabled': self.config.response_engine.cloudflare.enabled,
                    'api_token': self.config.response_engine.cloudflare.api_token,
                    'zone_id': self.config.response_engine.cloudflare.zone_id,
                    'priority': self.config.response_engine.cloudflare.priority,
                    'timeout': self.config.response_engine.cloudflare.timeout
                }
            }
            
            self.plugin_manager = await initialize_plugin_manager(str(plugins_dir), plugin_configs)
            active_plugins = len(self.plugin_manager.get_all_plugins())
            logger.info(f"✅ Plugin system initialized with {active_plugins} plugins")
            
            # 4. Initialize monitoring
            logger.info("📊 Starting monitoring system...")
            self.monitoring_manager = initialize_monitoring(self.config.monitoring.dict())
            await self.monitoring_manager.start_monitoring()
            logger.info("✅ Monitoring system started")
            
            # 5. Initialize core engines
            logger.info("🧠 Initializing threat intelligence engine...")
            self.threat_engine = ThreatIntelligenceEngineV2(
                self.config.threat_intelligence.dict(),
                self.plugin_manager,
                self.db_manager,
                self.monitoring_manager
            )
            await self.threat_engine.initialize()
            logger.info("✅ Threat intelligence engine initialized")
            
            logger.info("⚡ Initializing response engine...")
            self.response_engine = AutomatedResponseEngineV2(
                self.config.response_engine.dict(),
                self.plugin_manager,
                self.db_manager,
                self.monitoring_manager
            )
            await self.response_engine.initialize()
            logger.info("✅ Response engine initialized")
            
            # 6. Initialize API server
            if self.config.api.enabled:
                logger.info("🌐 Starting API server...")
                self.api_server = IPDefenderProAPIV2(
                    self.config.api,
                    self.threat_engine,
                    self.response_engine,
                    self.plugin_manager,
                    self.monitoring_manager
                )
                await self.api_server.initialize()
                
                # Start API server task
                api_task = asyncio.create_task(self.api_server.start())
                self.tasks.append(api_task)
                
                logger.info(f"✅ API server started on {self.config.api.host}:{self.config.api.port}")
            
            # 7. Initialize Wazuh integration
            if self.config.wazuh.enabled:
                logger.info("🔍 Initializing Wazuh integration...")
                self.wazuh_integration = WazuhIntegration(
                    self.config.wazuh.dict(),
                    self.threat_engine,
                    self.response_engine
                )
                
                if await self.wazuh_integration.initialize():
                    # Start Wazuh monitoring task
                    wazuh_task = asyncio.create_task(self.wazuh_integration.start_monitoring())
                    self.tasks.append(wazuh_task)
                    logger.info("✅ Wazuh integration started")
                else:
                    logger.warning("⚠️ Wazuh integration failed to initialize")
            
            # 8. Start background tasks
            logger.info("🔄 Starting background tasks...")
            
            # Database cleanup task
            cleanup_task = asyncio.create_task(self._database_cleanup_loop())
            self.tasks.append(cleanup_task)
            
            # Plugin health check task
            health_task = asyncio.create_task(self._plugin_health_check_loop())
            self.tasks.append(health_task)
            
            logger.info("✅ Background tasks started")
            
            # Mark as running
            self.running = True
            
            logger.info("=" * 60)
            logger.info("🚀 IPDefender Pro v2.0.0 initialized successfully!")
            logger.info(f"📍 Configuration: {self.config_path}")
            logger.info(f"🗄️ Database: {self.config.database.type}")
            logger.info(f"🔌 Plugins: {len(self.plugin_manager.get_all_plugins())}")
            logger.info(f"🌐 API: {'Enabled' if self.config.api.enabled else 'Disabled'}")
            logger.info(f"🔍 Wazuh: {'Enabled' if self.config.wazuh.enabled else 'Disabled'}")
            logger.info("=" * 60)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize IPDefender Pro: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    def _setup_logging(self):
        """Setup enhanced logging configuration"""
        log_config = self.config.logging
        
        # Create log directory
        log_file = Path(log_config.file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup structured logging
        structlog.configure(
            processors=[
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # Setup file handler with rotation
        file_handler = RotatingFileHandler(
            log_config.file,
            maxBytes=int(log_config.max_size.replace('MB', '')) * 1024 * 1024,
            backupCount=log_config.backup_count
        )
        file_handler.setFormatter(
            logging.Formatter(log_config.format)
        )
        
        # Setup console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_config.level))
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
    
    async def run(self):
        """Main application run loop"""
        if not self.running:
            logger.error("Application not initialized")
            return
        
        try:
            logger.info("🏃 IPDefender Pro is now running...")
            
            # Wait for all tasks to complete (or be cancelled)
            if self.tasks:
                await asyncio.gather(*self.tasks, return_exceptions=True)
                
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        except Exception as e:
            logger.error(f"Application error: {e}")
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Graceful application shutdown"""
        if not self.running:
            return
        
        logger.info("🛑 Initiating graceful shutdown...")
        self.running = False
        
        try:
            # Cancel all tasks
            if self.tasks:
                for task in self.tasks:
                    if not task.done():
                        task.cancel()
                
                # Wait for tasks to complete or timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self.tasks, return_exceptions=True),
                        timeout=30.0
                    )
                except asyncio.TimeoutError:
                    logger.warning("Some tasks didn't complete within timeout")
            
            # Shutdown components in reverse order
            
            # Shutdown Wazuh integration
            if self.wazuh_integration:
                await self.wazuh_integration.cleanup()
                logger.info("✅ Wazuh integration stopped")
            
            # Shutdown API server
            if self.api_server:
                await self.api_server.shutdown()
                logger.info("✅ API server stopped")
            
            # Shutdown core engines
            if self.response_engine:
                await self.response_engine.cleanup()
                logger.info("✅ Response engine stopped")
            
            if self.threat_engine:
                await self.threat_engine.cleanup()
                logger.info("✅ Threat intelligence engine stopped")
            
            # Shutdown monitoring
            if self.monitoring_manager:
                await self.monitoring_manager.stop_monitoring()
                logger.info("✅ Monitoring stopped")
            
            # Shutdown plugin manager
            if self.plugin_manager:
                await self.plugin_manager.cleanup_plugins()
                logger.info("✅ Plugins cleaned up")
            
            # Close database
            if self.db_manager:
                self.db_manager.close()
                logger.info("✅ Database closed")
            
            logger.info("🏁 IPDefender Pro shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    async def _database_cleanup_loop(self):
        """Background database cleanup loop"""
        try:
            while self.running:
                # Wait for cleanup interval (default 1 hour)
                await asyncio.sleep(3600)
                
                if not self.running:
                    break
                
                logger.info("🧹 Running database cleanup...")
                try:
                    await self.db_manager.cleanup_expired_data()
                    logger.info("✅ Database cleanup completed")
                except Exception as e:
                    logger.error(f"Database cleanup failed: {e}")
        
        except asyncio.CancelledError:
            logger.info("Database cleanup task cancelled")
    
    async def _plugin_health_check_loop(self):
        """Background plugin health check loop"""
        try:
            while self.running:
                # Wait for health check interval (default 5 minutes)
                await asyncio.sleep(300)
                
                if not self.running:
                    break
                
                logger.debug("🏥 Running plugin health checks...")
                try:
                    health_results = await self.plugin_manager.health_check_plugins()
                    
                    # Log any unhealthy plugins
                    for plugin_name, result in health_results.items():
                        if result.get('status') != 'healthy':
                            logger.warning(f"Plugin {plugin_name} health check: {result}")
                
                except Exception as e:
                    logger.error(f"Plugin health check failed: {e}")
        
        except asyncio.CancelledError:
            logger.info("Plugin health check task cancelled")

async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='IPDefender Pro - Advanced Cybersecurity Defense Platform')
    parser.add_argument('--config', '-c', 
                       default='/etc/ipdefender/config.yaml',
                       help='Configuration file path')
    parser.add_argument('--version', '-v', 
                       action='store_true',
                       help='Show version and exit')
    parser.add_argument('--validate-config', 
                       action='store_true',
                       help='Validate configuration and exit')
    parser.add_argument('--test-plugins', 
                       action='store_true',
                       help='Test plugin loading and exit')
    
    args = parser.parse_args()
    
    if args.version:
        print("IPDefender Pro v2.0.0")
        print("Advanced Cybersecurity Defense Platform")
        print("Author: byFranke (https://byfranke.com)")
        sys.exit(0)
    
    if args.validate_config:
        try:
            from config.models import validate_config_file
            valid, message = validate_config_file(args.config)
            if valid:
                print(f"✅ Configuration is valid: {message}")
                sys.exit(0)
            else:
                print(f"❌ Configuration is invalid: {message}")
                sys.exit(1)
        except Exception as e:
            print(f"❌ Configuration validation failed: {e}")
            sys.exit(1)
    
    if args.test_plugins:
        try:
            # Test plugin loading
            plugins_dir = Path(__file__).parent / "plugins"
            plugin_manager = await initialize_plugin_manager(str(plugins_dir), {})
            print(f"✅ Successfully loaded {len(plugin_manager.get_all_plugins())} plugins")
            sys.exit(0)
        except Exception as e:
            print(f"❌ Plugin loading failed: {e}")
            sys.exit(1)
    
    # Initialize and run application
    app = IPDefenderProApplication(args.config)
    
    try:
        # Initialize application
        if not await app.initialize():
            logger.error("Failed to initialize application")
            sys.exit(1)
        
        # Run application
        await app.run()
        
    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 IPDefender Pro stopped by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
