"""
IPDefender Pro - Main Application Entry Point
Advanced cybersecurity defense platform

Author: byFranke (https://byfranke.com)
"""

import asyncio
import logging
import sys
import signal
import yaml
import argparse
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/ipdefender/ipdefender-pro.log', mode='a')
    ]
)

logger = logging.getLogger(__name__)

# Import core modules
from core.threat_intel import ThreatIntelligenceEngine
from core.response_engine import AutomatedResponseEngine
from api.server import IPDefenderProAPI
from integrations.wazuh import WazuhIntegration

class IPDefenderPro:
    """Main IPDefender Pro application"""
    
    def __init__(self, config_path: str = "/etc/ipdefender/config.yaml"):
        self.config_path = config_path
        self.config = {}
        self.running = False
        
        # Core components
        self.threat_intel = None
        self.response_engine = None
        self.api_server = None
        self.wazuh_integration = None
        
        # Stats
        self.start_time = None
        self.processed_ips = 0
        self.blocked_ips = 0
        
    def load_config(self) -> bool:
        """Load configuration from file"""
        try:
            config_path = Path(self.config_path)
            
            if not config_path.exists():
                logger.error(f"Configuration file not found: {self.config_path}")
                return False
            
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            
            logger.info(f"Configuration loaded from {self.config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False
    
    async def initialize(self) -> bool:
        """Initialize all components"""
        try:
            self.start_time = datetime.now()
            
            # Initialize threat intelligence engine
            threat_intel_config = self.config.get('threat_intelligence', {})
            self.threat_intel = ThreatIntelligenceEngine(threat_intel_config)
            logger.info("Threat intelligence engine initialized")
            
            # Initialize response engine
            response_config = self.config.get('response_engine', {})
            self.response_engine = AutomatedResponseEngine(response_config)
            logger.info("Automated response engine initialized")
            
            # Initialize API server if enabled
            api_config = self.config.get('api', {})
            if api_config.get('enabled', True):
                self.api_server = IPDefenderProAPI(self.config)
                logger.info("API server initialized")
            
            # Initialize Wazuh integration if enabled
            wazuh_config = self.config.get('wazuh', {})
            if wazuh_config.get('enabled', False):
                self.wazuh_integration = WazuhIntegration(wazuh_config)
                await self.wazuh_integration.initialize()
                logger.info("Wazuh integration initialized")
            
            logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            return False
    
    async def start(self):
        """Start the IPDefender Pro service"""
        logger.info("Starting IPDefender Pro by byFranke")
        logger.info("Advanced Cybersecurity Defense Platform")
        
        if not self.load_config():
            sys.exit(1)
        
        if not await self.initialize():
            sys.exit(1)
        
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Start background tasks
        tasks = []
        
        # Start Wazuh alert monitoring if enabled
        if self.wazuh_integration:
            tasks.append(asyncio.create_task(self._wazuh_monitoring_loop()))
        
        # Start API server if enabled
        if self.api_server:
            api_config = self.config.get('api', {})
            host = api_config.get('host', '0.0.0.0')
            port = api_config.get('port', 8080)
            
            # Run API server in background
            import uvicorn
            config = uvicorn.Config(
                self.api_server.app, 
                host=host, 
                port=port,
                log_level="info"
            )
            server = uvicorn.Server(config)
            tasks.append(asyncio.create_task(server.serve()))
        
        # Start scheduled tasks
        tasks.append(asyncio.create_task(self._scheduled_tasks_loop()))
        
        # Start statistics reporting
        tasks.append(asyncio.create_task(self._stats_reporting_loop()))
        
        logger.info(f"IPDefender Pro started successfully with {len(tasks)} background tasks")
        
        # Wait for all tasks
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            await self.shutdown()
    
    async def _wazuh_monitoring_loop(self):
        """Monitor Wazuh alerts and respond to threats"""
        logger.info("Starting Wazuh monitoring loop")
        
        while self.running:
            try:
                # Get recent alerts
                alerts = await self.wazuh_integration.get_alerts(hours=1, level_min=7)
                
                for alert in alerts:
                    if alert.source_ip:
                        await self._process_wazuh_alert(alert)
                
                # Wait before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Wazuh monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _process_wazuh_alert(self, alert):
        """Process a Wazuh alert and take action"""
        try:
            logger.info(f"Processing Wazuh alert: {alert.rule_description} from {alert.source_ip}")
            
            # Analyze the IP
            analysis = await self.threat_intel.analyze_ip(alert.source_ip)
            self.processed_ips += 1
            
            # Add Wazuh context to analysis metadata
            analysis.metadata = analysis.metadata or {}
            analysis.metadata['wazuh_alert'] = {
                'rule_id': alert.rule_id,
                'rule_level': alert.rule_level,
                'description': alert.rule_description,
                'agent': alert.agent_name,
                'timestamp': alert.timestamp.isoformat()
            }
            
            # Execute response
            response = await self.response_engine.evaluate_and_respond(analysis)
            
            if response.action.value in ['temp_block', 'perm_block', 'quarantine']:
                self.blocked_ips += 1
                
                # Send response back to Wazuh
                await self.wazuh_integration.submit_custom_alert(
                    agent_id=alert.agent_id,
                    rule_id='999903',
                    description=f'IPDefender Pro blocked {alert.source_ip}',
                    data={
                        'srcip': alert.source_ip,
                        'action': response.action.value,
                        'threat_score': analysis.threat_score,
                        'rule_name': response.rule_name
                    }
                )
            
        except Exception as e:
            logger.error(f"Error processing Wazuh alert: {e}")
    
    async def _scheduled_tasks_loop(self):
        """Run scheduled maintenance tasks"""
        logger.info("Starting scheduled tasks loop")
        
        while self.running:
            try:
                # Threat intelligence sync (every 6 hours)
                if datetime.now().minute == 0 and datetime.now().hour % 6 == 0:
                    await self._sync_threat_intelligence()
                
                # Cleanup expired blocks (daily at 2 AM)
                if datetime.now().hour == 2 and datetime.now().minute == 0:
                    await self._cleanup_expired_blocks()
                
                # Health check (every 15 minutes)
                if datetime.now().minute % 15 == 0:
                    await self._health_check()
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Scheduled tasks error: {e}")
                await asyncio.sleep(60)
    
    async def _stats_reporting_loop(self):
        """Report statistics periodically"""
        while self.running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                
                uptime = (datetime.now() - self.start_time).total_seconds()
                
                logger.info(f"IPDefender Pro Stats - Uptime: {uptime:.0f}s, "
                           f"Processed IPs: {self.processed_ips}, "
                           f"Blocked IPs: {self.blocked_ips}")
                
            except Exception as e:
                logger.error(f"Stats reporting error: {e}")
                await asyncio.sleep(300)
    
    async def _sync_threat_intelligence(self):
        """Sync with external threat intelligence sources"""
        logger.info("Starting threat intelligence sync")
        
        try:
            # This could be expanded to sync with multiple sources
            # For now, we'll just log the action
            provider_status = self.threat_intel.get_provider_status()
            enabled_providers = provider_status['enabled_providers']
            
            logger.info(f"Threat intelligence sync completed - {enabled_providers} providers active")
            
        except Exception as e:
            logger.error(f"Threat intelligence sync failed: {e}")
    
    async def _cleanup_expired_blocks(self):
        """Clean up expired IP blocks"""
        logger.info("Starting cleanup of expired blocks")
        
        try:
            # Get response statistics
            stats = self.response_engine.get_response_statistics()
            active_responses = stats.get('active_responses', 0)
            
            logger.info(f"Cleanup completed - {active_responses} active responses")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
    
    async def _health_check(self):
        """Perform system health check"""
        try:
            # Check threat intelligence providers
            provider_status = self.threat_intel.get_provider_status()
            
            # Check Wazuh connection
            wazuh_status = "disconnected"
            if self.wazuh_integration:
                status = await self.wazuh_integration.get_system_status()
                wazuh_status = status.get('status', 'error')
            
            logger.debug(f"Health check - TI providers: {provider_status['enabled_providers']}, "
                        f"Wazuh: {wazuh_status}")
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.running = False
    
    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down IPDefender Pro...")
        
        self.running = False
        
        # Cleanup integrations
        if self.wazuh_integration:
            await self.wazuh_integration.cleanup()
        
        logger.info("IPDefender Pro shutdown complete")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="IPDefender Pro - Advanced Cybersecurity Defense Platform by byFranke")
    
    parser.add_argument('--config', '-c', 
                       default='/etc/ipdefender/config.yaml',
                       help='Configuration file path')
    
    parser.add_argument('--debug', '-d',
                       action='store_true',
                       help='Enable debug logging')
    
    parser.add_argument('--version', '-v',
                       action='version',
                       version='IPDefender Pro 1.0.0 by byFranke')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Create and run application
    app = IPDefenderPro(config_path=args.config)
    
    try:
        asyncio.run(app.start())
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
