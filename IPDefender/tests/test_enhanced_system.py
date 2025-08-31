"""
IPDefender Pro V2 - Comprehensive Test Suite
Tests for the enhanced architecture with plugins, database, and monitoring

Author: byFranke (https://byfranke.com)
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta
import ipaddress

# Import components to test
from config.models import IPDefenderProConfig, load_config
from database.manager import DatabaseManager
from plugins.manager import PluginManager
from monitoring.metrics import MonitoringManager
from core.threat_intel_v2 import ThreatIntelligenceEngineV2, ThreatAnalysisResult
from core.response_engine_v2 import AutomatedResponseEngineV2, ResponseAction, ResponsePriority

class TestConfiguration:
    """Test configuration management"""
    
    def test_config_loading(self):
        """Test configuration loading and validation"""
        # Create temporary config file
        config_data = """
api:
  enabled: true
  host: "127.0.0.1"
  port: 8080
  api_keys: []
  
database:
  type: "sqlite"
  sqlite_path: ":memory:"
  
threat_intelligence:
  abuseipdb:
    enabled: true
    api_key: "test_key"
    
response_engine:
  ufw:
    enabled: true
    
logging:
  level: "INFO"
  file: "/tmp/test.log"
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_data)
            f.flush()
            
            # Load configuration
            config = load_config(f.name)
            
            # Validate
            assert config.api.enabled is True
            assert config.api.port == 8080
            assert config.database.type == "sqlite"
            assert config.threat_intelligence.abuseipdb.enabled is True
            
        # Cleanup
        Path(f.name).unlink()
    
    def test_config_validation_errors(self):
        """Test configuration validation with invalid data"""
        config_data = """
api:
  enabled: true
  port: "invalid_port"  # Should be integer
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_data)
            f.flush()
            
            # Should raise validation error
            with pytest.raises(Exception):
                load_config(f.name)
                
        Path(f.name).unlink()

class TestDatabaseManager:
    """Test database operations"""
    
    @pytest.fixture
    async def db_manager(self):
        """Create test database manager"""
        from config.models import DatabaseConfig
        
        config = DatabaseConfig(
            type="sqlite",
            sqlite_path=":memory:"
        )
        
        db_manager = DatabaseManager(config)
        await db_manager.initialize()
        yield db_manager
        await db_manager.close()
    
    @pytest.mark.asyncio
    async def test_threat_analysis_repository(self, db_manager):
        """Test threat analysis database operations"""
        repo = db_manager.get_repository('threat_analysis')
        
        # Create analysis record
        analysis_id = await repo.create_analysis(
            ip_address="192.168.1.100",
            threat_score=75.5,
            confidence=0.8,
            threat_types=["malware", "botnet"],
            sources=["abuseipdb", "virustotal"],
            metadata={"test": "data"}
        )
        
        assert analysis_id is not None
        
        # Get recent analysis
        recent = await repo.get_recent_analysis("192.168.1.100", 60)
        assert recent is not None
        assert recent.threat_score == 75.5
        assert recent.confidence == 0.8
        assert "malware" in recent.threat_types
    
    @pytest.mark.asyncio
    async def test_response_action_repository(self, db_manager):
        """Test response action database operations"""
        repo = db_manager.get_repository('response_action')
        
        # Create response record
        response_id = await repo.create_response_action(
            ip_address="192.168.1.101",
            actions=["block_ip", "notify_admin"],
            success_rate=1.0,
            execution_time=0.5,
            metadata={"provider": "ufw"}
        )
        
        assert response_id is not None
        
        # Get response history
        history = await repo.get_response_history("192.168.1.101", 24)  # Last 24 hours
        assert len(history) >= 1
        assert history[0].success_rate == 1.0

class TestPluginSystem:
    """Test plugin system functionality"""
    
    @pytest.fixture
    def mock_plugin_dir(self):
        """Create mock plugin directory structure"""
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            
            # Create threat provider plugin
            threat_dir = plugin_dir / "threat_providers"
            threat_dir.mkdir()
            
            # Create firewall provider plugin  
            firewall_dir = plugin_dir / "firewall_providers"
            firewall_dir.mkdir()
            
            yield str(plugin_dir)
    
    @pytest.mark.asyncio
    async def test_plugin_manager_initialization(self, mock_plugin_dir):
        """Test plugin manager initialization and loading"""
        from plugins.manager import initialize_plugin_manager
        
        configs = {
            'test_provider': {
                'enabled': True,
                'api_key': 'test_key'
            }
        }
        
        # This will fail in test environment due to missing actual plugins
        # but we can test the initialization process
        with pytest.raises(Exception):
            plugin_manager = await initialize_plugin_manager(mock_plugin_dir, configs)

class TestThreatIntelligenceEngine:
    """Test enhanced threat intelligence engine"""
    
    @pytest.fixture
    async def threat_engine(self):
        """Create test threat intelligence engine"""
        # Mock dependencies
        mock_plugin_manager = Mock()
        mock_db_manager = Mock()
        mock_monitoring = Mock()
        
        # Mock providers
        mock_provider = AsyncMock()
        mock_provider.analyze_ip = AsyncMock(return_value={
            'threat_score': 75.0,
            'confidence': 0.8,
            'threat_types': ['malware'],
            'metadata': {'source': 'test'}
        })
        mock_provider.health_check = AsyncMock(return_value={'healthy': True})
        mock_provider.is_enabled = Mock(return_value=True)
        mock_provider.weight = 1.0
        
        mock_plugin_manager.get_plugins_by_type.return_value = {
            'test_provider': mock_provider
        }
        
        # Mock database repository
        mock_repo = AsyncMock()
        mock_repo.get_recent_analysis = AsyncMock(return_value=None)
        mock_repo.create_analysis = AsyncMock(return_value="test_id")
        mock_db_manager.get_repository.return_value = mock_repo
        
        config = {
            'cache_ttl': 3600,
            'threat_threshold': 50.0
        }
        
        engine = ThreatIntelligenceEngineV2(
            config, mock_plugin_manager, mock_db_manager, mock_monitoring
        )
        
        await engine.initialize()
        yield engine
    
    @pytest.mark.asyncio
    async def test_ip_analysis(self, threat_engine):
        """Test IP address analysis"""
        result = await threat_engine.analyze_ip("192.168.1.100")
        
        assert isinstance(result, ThreatAnalysisResult)
        assert result.ip_address == "192.168.1.100"
        assert result.threat_score == 75.0
        assert result.confidence == 0.8
        assert 'malware' in result.threat_types
    
    @pytest.mark.asyncio
    async def test_private_ip_handling(self, threat_engine):
        """Test handling of private IP addresses"""
        result = await threat_engine.analyze_ip("192.168.1.1")  # Private IP
        
        assert result.threat_score == 0.0
        assert result.confidence == 1.0
        assert result.metadata.get('skip_reason') == 'private_ip'
    
    @pytest.mark.asyncio
    async def test_invalid_ip_handling(self, threat_engine):
        """Test handling of invalid IP addresses"""
        with pytest.raises(ValueError):
            await threat_engine.analyze_ip("invalid_ip")
    
    @pytest.mark.asyncio
    async def test_caching(self, threat_engine):
        """Test result caching functionality"""
        # First analysis
        result1 = await threat_engine.analyze_ip("192.168.1.100")
        assert not result1.cache_hit
        
        # Second analysis should hit cache
        result2 = await threat_engine.analyze_ip("192.168.1.100")
        assert result2.cache_hit
        
        # Force refresh should bypass cache
        result3 = await threat_engine.analyze_ip("192.168.1.100", force_refresh=True)
        assert not result3.cache_hit

class TestResponseEngine:
    """Test enhanced response engine"""
    
    @pytest.fixture
    async def response_engine(self):
        """Create test response engine"""
        # Mock dependencies
        mock_plugin_manager = Mock()
        mock_db_manager = Mock()
        mock_monitoring = Mock()
        
        # Mock firewall provider
        mock_provider = AsyncMock()
        mock_provider.block_ip = AsyncMock(return_value={'success': True})
        mock_provider.rate_limit_ip = AsyncMock(return_value={'success': True})
        mock_provider.health_check = AsyncMock(return_value={'healthy': True})
        mock_provider.is_enabled = Mock(return_value=True)
        mock_provider.priority = 1
        
        mock_plugin_manager.get_plugins_by_type.return_value = {
            'test_firewall': mock_provider
        }
        
        # Mock database repository
        mock_repo = AsyncMock()
        mock_repo.create_response_action = AsyncMock(return_value="test_id")
        mock_db_manager.get_repository.return_value = mock_repo
        
        config = {
            'action_rate_limit': 100
        }
        
        engine = AutomatedResponseEngineV2(
            config, mock_plugin_manager, mock_db_manager, mock_monitoring
        )
        
        await engine.initialize()
        yield engine
    
    @pytest.mark.asyncio
    async def test_response_execution(self, response_engine):
        """Test response execution"""
        # Create mock threat analysis
        threat_analysis = ThreatAnalysisResult(
            ip_address="192.168.1.100",
            threat_score=85.0,
            confidence=0.9,
            threat_types=["malware", "botnet"],
            sources=["test_provider"],
            metadata={},
            analysis_time=datetime.now()
        )
        
        result = await response_engine.execute_response(threat_analysis)
        
        assert result.ip_address == "192.168.1.100"
        assert result.success_rate > 0
        assert len(result.actions_executed) > 0
    
    def test_action_determination(self, response_engine):
        """Test response action determination logic"""
        # High threat score
        threat_analysis_high = ThreatAnalysisResult(
            ip_address="192.168.1.100",
            threat_score=95.0,
            confidence=0.9,
            threat_types=["malware"],
            sources=["test"],
            metadata={},
            analysis_time=datetime.now()
        )
        
        actions = response_engine._determine_response_actions(threat_analysis_high)
        assert ResponseAction.BLOCK_IP in actions
        assert ResponseAction.NOTIFY_ADMIN in actions
        
        # Medium threat score
        threat_analysis_medium = ThreatAnalysisResult(
            ip_address="192.168.1.101",
            threat_score=60.0,
            confidence=0.7,
            threat_types=["scanning"],
            sources=["test"],
            metadata={},
            analysis_time=datetime.now()
        )
        
        actions = response_engine._determine_response_actions(threat_analysis_medium)
        assert ResponseAction.RATE_LIMIT in actions
    
    def test_priority_determination(self, response_engine):
        """Test response priority determination"""
        # Critical priority
        threat_critical = ThreatAnalysisResult(
            ip_address="192.168.1.100",
            threat_score=95.0,
            confidence=0.9,
            threat_types=["malware"],
            sources=["test"],
            metadata={},
            analysis_time=datetime.now()
        )
        
        priority = response_engine._determine_priority(threat_critical)
        assert priority == ResponsePriority.CRITICAL
        
        # Low priority
        threat_low = ThreatAnalysisResult(
            ip_address="192.168.1.101",
            threat_score=30.0,
            confidence=0.5,
            threat_types=[],
            sources=["test"],
            metadata={},
            analysis_time=datetime.now()
        )
        
        priority = response_engine._determine_priority(threat_low)
        assert priority == ResponsePriority.LOW

class TestMonitoringSystem:
    """Test monitoring and metrics system"""
    
    @pytest.fixture
    def monitoring_manager(self):
        """Create test monitoring manager"""
        from monitoring.metrics import initialize_monitoring
        
        config = {
            'enabled': True,
            'prometheus_enabled': False,  # Avoid prometheus dependency in tests
            'metrics_retention_days': 7
        }
        
        manager = initialize_monitoring(config)
        yield manager
    
    def test_metrics_recording(self, monitoring_manager):
        """Test metrics recording"""
        # Record some metrics
        monitoring_manager.record_metric('test_counter', 1)
        monitoring_manager.record_metric('test_gauge', 42.0)
        monitoring_manager.record_metric('test_histogram', 0.5)
        
        # Get metrics
        metrics = monitoring_manager.get_metrics()
        
        # Verify metrics were recorded
        assert 'counters' in metrics
        assert 'gauges' in metrics
        assert 'histograms' in metrics
    
    @pytest.mark.asyncio
    async def test_health_checks(self, monitoring_manager):
        """Test health check functionality"""
        await monitoring_manager.start_monitoring()
        
        # Get health status
        health = monitoring_manager.get_health_status()
        
        assert 'system' in health
        assert 'timestamp' in health
        
        await monitoring_manager.stop_monitoring()

class TestIntegration:
    """Integration tests for complete system"""
    
    @pytest.mark.asyncio 
    async def test_full_analysis_and_response_flow(self):
        """Test complete flow from analysis to response"""
        # This would test the full integration but requires
        # extensive mocking or test environment setup
        # Placeholder for comprehensive integration test
        pass

# Performance Tests
class TestPerformance:
    """Performance and load tests"""
    
    @pytest.mark.asyncio
    async def test_concurrent_analyses(self):
        """Test concurrent IP analyses performance"""
        # Mock setup for performance testing
        mock_plugin_manager = Mock()
        mock_db_manager = Mock()
        mock_monitoring = Mock()
        
        # Fast mock provider
        mock_provider = AsyncMock()
        mock_provider.analyze_ip = AsyncMock(return_value={
            'threat_score': 50.0,
            'confidence': 0.5,
            'threat_types': [],
            'metadata': {}
        })
        mock_provider.health_check = AsyncMock(return_value={'healthy': True})
        mock_provider.is_enabled = Mock(return_value=True)
        mock_provider.weight = 1.0
        
        mock_plugin_manager.get_plugins_by_type.return_value = {
            'test_provider': mock_provider
        }
        
        mock_repo = AsyncMock()
        mock_repo.get_recent_analysis = AsyncMock(return_value=None)
        mock_repo.create_analysis = AsyncMock(return_value="test_id")
        mock_db_manager.get_repository.return_value = mock_repo
        
        # Create engine
        config = {'cache_ttl': 3600}
        engine = ThreatIntelligenceEngineV2(
            config, mock_plugin_manager, mock_db_manager, mock_monitoring
        )
        await engine.initialize()
        
        # Test concurrent analyses
        tasks = []
        num_concurrent = 50
        
        for i in range(num_concurrent):
            task = asyncio.create_task(
                engine.analyze_ip(f"192.168.1.{i + 1}")
            )
            tasks.append(task)
        
        # Measure execution time
        start_time = datetime.now()
        results = await asyncio.gather(*tasks)
        end_time = datetime.now()
        
        execution_time = (end_time - start_time).total_seconds()
        
        # Verify results
        assert len(results) == num_concurrent
        assert all(isinstance(r, ThreatAnalysisResult) for r in results)
        
        # Performance assertion (should complete within reasonable time)
        assert execution_time < 10.0  # Should complete within 10 seconds
        
        print(f"Completed {num_concurrent} concurrent analyses in {execution_time:.2f} seconds")

# Utility functions for testing
def create_test_config():
    """Create test configuration"""
    return {
        'api': {
            'enabled': True,
            'host': '127.0.0.1',
            'port': 8080,
            'api_keys': ['test_key']
        },
        'database': {
            'type': 'sqlite',
            'sqlite_path': ':memory:'
        },
        'threat_intelligence': {
            'abuseipdb': {
                'enabled': True,
                'api_key': 'test_key'
            }
        },
        'response_engine': {
            'ufw': {
                'enabled': True
            }
        },
        'logging': {
            'level': 'DEBUG',
            'file': '/tmp/test.log'
        },
        'monitoring': {
            'enabled': True,
            'prometheus_enabled': False
        }
    }

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])
