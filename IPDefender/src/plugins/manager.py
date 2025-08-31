"""
IPDefender Pro - Plugin Manager
Dynamic plugin loading and management system

Author: byFranke (https://byfranke.com)
"""

import os
import sys
import importlib
import importlib.util
import asyncio
import logging
from typing import Dict, List, Optional, Type, Any
from pathlib import Path

from plugins import (
    BasePlugin, ThreatIntelligenceProvider, FirewallProvider, 
    NotificationProvider, PluginType, PluginStatus
)

logger = logging.getLogger(__name__)

class PluginManager:
    """Manages plugin loading, initialization, and lifecycle"""
    
    def __init__(self, plugins_dir: str = "plugins"):
        """
        Initialize plugin manager
        
        Args:
            plugins_dir: Directory containing plugin modules
        """
        self.plugins_dir = Path(plugins_dir)
        self.threat_providers: Dict[str, ThreatIntelligenceProvider] = {}
        self.firewall_providers: Dict[str, FirewallProvider] = {}
        self.notification_providers: Dict[str, NotificationProvider] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        
    async def initialize(self, config: Dict[str, Any]):
        """
        Initialize plugin manager and load plugins
        
        Args:
            config: Plugin configurations
        """
        self.plugin_configs = config
        
        # Load plugins from directory
        await self.load_plugins_from_directory()
        
        # Initialize loaded plugins
        await self.initialize_plugins()
        
        logger.info(f"Plugin manager initialized with {len(self.get_all_plugins())} plugins")
    
    async def load_plugins_from_directory(self):
        """Load plugins from the plugins directory"""
        if not self.plugins_dir.exists():
            logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            return
        
        # Load threat intelligence providers
        threat_providers_dir = self.plugins_dir / "threat_providers"
        if threat_providers_dir.exists():
            await self._load_plugin_type(threat_providers_dir, "threat_providers")
        
        # Load firewall providers
        firewall_providers_dir = self.plugins_dir / "firewall_providers"
        if firewall_providers_dir.exists():
            await self._load_plugin_type(firewall_providers_dir, "firewall_providers")
        
        # Load notification providers
        notification_providers_dir = self.plugins_dir / "notification_providers"
        if notification_providers_dir.exists():
            await self._load_plugin_type(notification_providers_dir, "notification_providers")
    
    async def _load_plugin_type(self, directory: Path, plugin_type: str):
        """Load plugins of a specific type from directory"""
        for plugin_file in directory.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue  # Skip private files
            
            try:
                await self._load_plugin_file(plugin_file, plugin_type)
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file}: {e}")
    
    async def _load_plugin_file(self, plugin_file: Path, plugin_type: str):
        """Load a single plugin file"""
        module_name = f"plugins.{plugin_type}.{plugin_file.stem}"
        
        # Load module dynamically
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load plugin spec from {plugin_file}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        # Find plugin classes in module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            
            if (isinstance(attr, type) and 
                issubclass(attr, BasePlugin) and 
                attr != BasePlugin and
                not attr.__name__.startswith('Base')):
                
                plugin_name = attr.__name__.lower().replace('provider', '').replace('plugin', '')
                config = self.plugin_configs.get(plugin_name, {})
                
                if not config.get('enabled', False):
                    logger.info(f"Plugin {plugin_name} is disabled, skipping")
                    continue
                
                # Create plugin instance
                plugin_instance = attr(plugin_name, config)
                
                # Add to appropriate collection
                if isinstance(plugin_instance, ThreatIntelligenceProvider):
                    self.threat_providers[plugin_name] = plugin_instance
                elif isinstance(plugin_instance, FirewallProvider):
                    self.firewall_providers[plugin_name] = plugin_instance
                elif isinstance(plugin_instance, NotificationProvider):
                    self.notification_providers[plugin_name] = plugin_instance
                
                logger.info(f"Loaded plugin: {plugin_name} ({attr.__name__})")
    
    async def initialize_plugins(self):
        """Initialize all loaded plugins"""
        all_plugins = self.get_all_plugins()
        
        for plugin_name, plugin in all_plugins.items():
            try:
                success = await plugin.initialize()
                if success:
                    plugin.status = PluginStatus.ACTIVE
                    logger.info(f"Plugin {plugin_name} initialized successfully")
                else:
                    plugin.status = PluginStatus.ERROR
                    logger.warning(f"Plugin {plugin_name} initialization failed")
            except Exception as e:
                plugin.set_error(f"Initialization failed: {e}")
                logger.error(f"Plugin {plugin_name} initialization error: {e}")
    
    async def cleanup_plugins(self):
        """Cleanup all plugins"""
        all_plugins = self.get_all_plugins()
        
        for plugin_name, plugin in all_plugins.items():
            try:
                await plugin.cleanup()
                logger.info(f"Plugin {plugin_name} cleaned up")
            except Exception as e:
                logger.error(f"Plugin {plugin_name} cleanup error: {e}")
    
    async def health_check_plugins(self):
        """Perform health checks on all plugins"""
        all_plugins = self.get_all_plugins()
        results = {}
        
        for plugin_name, plugin in all_plugins.items():
            try:
                healthy = await plugin.health_check()
                if healthy:
                    plugin.clear_error()
                    results[plugin_name] = {'status': 'healthy'}
                else:
                    plugin.set_error("Health check failed")
                    results[plugin_name] = {'status': 'unhealthy'}
            except Exception as e:
                plugin.set_error(f"Health check error: {e}")
                results[plugin_name] = {'status': 'error', 'error': str(e)}
        
        return results
    
    def get_all_plugins(self) -> Dict[str, BasePlugin]:
        """Get all loaded plugins"""
        all_plugins = {}
        all_plugins.update(self.threat_providers)
        all_plugins.update(self.firewall_providers)
        all_plugins.update(self.notification_providers)
        return all_plugins
    
    def get_active_threat_providers(self) -> Dict[str, ThreatIntelligenceProvider]:
        """Get active threat intelligence providers"""
        return {
            name: provider for name, provider in self.threat_providers.items()
            if provider.status == PluginStatus.ACTIVE
        }
    
    def get_active_firewall_providers(self) -> Dict[str, FirewallProvider]:
        """Get active firewall providers"""
        return {
            name: provider for name, provider in self.firewall_providers.items()
            if provider.status == PluginStatus.ACTIVE
        }
    
    def get_active_notification_providers(self) -> Dict[str, NotificationProvider]:
        """Get active notification providers"""
        return {
            name: provider for name, provider in self.notification_providers.items()
            if provider.status == PluginStatus.ACTIVE
        }
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific plugin"""
        all_plugins = self.get_all_plugins()
        plugin = all_plugins.get(plugin_name)
        if plugin:
            return plugin.get_plugin_info()
        return None
    
    def get_all_plugins_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all plugins"""
        all_plugins = self.get_all_plugins()
        return {name: plugin.get_plugin_info() for name, plugin in all_plugins.items()}
    
    async def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a specific plugin"""
        try:
            # Find and cleanup existing plugin
            all_plugins = self.get_all_plugins()
            if plugin_name in all_plugins:
                await all_plugins[plugin_name].cleanup()
                
                # Remove from collections
                if plugin_name in self.threat_providers:
                    del self.threat_providers[plugin_name]
                elif plugin_name in self.firewall_providers:
                    del self.firewall_providers[plugin_name]
                elif plugin_name in self.notification_providers:
                    del self.notification_providers[plugin_name]
            
            # Reload plugin
            await self.load_plugins_from_directory()
            await self.initialize_plugins()
            
            logger.info(f"Plugin {plugin_name} reloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload plugin {plugin_name}: {e}")
            return False
    
    async def register_plugin(self, plugin: BasePlugin) -> bool:
        """Manually register a plugin instance"""
        try:
            # Initialize plugin
            success = await plugin.initialize()
            if not success:
                return False
            
            # Add to appropriate collection
            if isinstance(plugin, ThreatIntelligenceProvider):
                self.threat_providers[plugin.name] = plugin
            elif isinstance(plugin, FirewallProvider):
                self.firewall_providers[plugin.name] = plugin
            elif isinstance(plugin, NotificationProvider):
                self.notification_providers[plugin.name] = plugin
            else:
                logger.error(f"Unknown plugin type: {type(plugin)}")
                return False
            
            plugin.status = PluginStatus.ACTIVE
            logger.info(f"Plugin {plugin.name} registered successfully")
            return True
            
        except Exception as e:
            plugin.set_error(f"Registration failed: {e}")
            logger.error(f"Failed to register plugin {plugin.name}: {e}")
            return False
    
    async def unregister_plugin(self, plugin_name: str) -> bool:
        """Unregister a plugin"""
        try:
            all_plugins = self.get_all_plugins()
            if plugin_name not in all_plugins:
                return False
            
            plugin = all_plugins[plugin_name]
            await plugin.cleanup()
            
            # Remove from collections
            if plugin_name in self.threat_providers:
                del self.threat_providers[plugin_name]
            elif plugin_name in self.firewall_providers:
                del self.firewall_providers[plugin_name]
            elif plugin_name in self.notification_providers:
                del self.notification_providers[plugin_name]
            
            logger.info(f"Plugin {plugin_name} unregistered successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unregister plugin {plugin_name}: {e}")
            return False
    
    def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get plugin usage statistics"""
        all_plugins = self.get_all_plugins()
        
        total_plugins = len(all_plugins)
        active_plugins = len([p for p in all_plugins.values() if p.status == PluginStatus.ACTIVE])
        error_plugins = len([p for p in all_plugins.values() if p.status == PluginStatus.ERROR])
        
        # Plugin type counts
        threat_count = len(self.threat_providers)
        firewall_count = len(self.firewall_providers)
        notification_count = len(self.notification_providers)
        
        # Usage statistics
        most_used = max(all_plugins.values(), key=lambda p: p.usage_count, default=None)
        total_usage = sum(p.usage_count for p in all_plugins.values())
        
        return {
            'total_plugins': total_plugins,
            'active_plugins': active_plugins,
            'error_plugins': error_plugins,
            'plugin_types': {
                'threat_providers': threat_count,
                'firewall_providers': firewall_count,
                'notification_providers': notification_count
            },
            'usage_statistics': {
                'total_usage': total_usage,
                'most_used_plugin': most_used.name if most_used else None,
                'most_used_count': most_used.usage_count if most_used else 0
            }
        }

# Global plugin manager instance
plugin_manager: Optional[PluginManager] = None

def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance"""
    global plugin_manager
    if plugin_manager is None:
        raise RuntimeError("Plugin manager not initialized")
    return plugin_manager

async def initialize_plugin_manager(plugins_dir: str, config: Dict[str, Any]) -> PluginManager:
    """Initialize the global plugin manager"""
    global plugin_manager
    plugin_manager = PluginManager(plugins_dir)
    await plugin_manager.initialize(config)
    return plugin_manager
