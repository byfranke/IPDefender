#!/usr/bin/env python3
"""
IPDefender Pro - Usage Examples
Demonstrates the advanced capabilities of IPDefender Pro

Author: byFranke (https://byfranke.com)
"""

import asyncio
import sys
import os
import json
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Mock the missing dependencies for demonstration
class MockResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self.json_data = json_data or {}
    
    async def json(self):
        return self.json_data
    
    async def text(self):
        return json.dumps(self.json_data)

# Simple mock for aiohttp
class MockSession:
    async def get(self, url, **kwargs):
        # Mock AbuseIPDB response
        if 'abuseipdb.com' in url:
            return MockResponse(200, {
                'data': {
                    'abuseConfidencePercentage': 85,
                    'totalReports': 15,
                    'countryCode': 'US',
                    'isp': 'Example ISP',
                    'usageType': 'hosting',
                    'isPublic': True,
                    'lastReportedAt': '2024-01-15T10:30:00Z'
                }
            })
        # Mock OTX response
        elif 'otx.alienvault.com' in url:
            return MockResponse(200, {
                'reputation': {
                    'threat_score': 4,
                    'activities': ['malware', 'scanning']
                }
            })
        return MockResponse(404)
    
    async def post(self, url, **kwargs):
        return MockResponse(200, {'success': True})
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        pass

# Mock aiohttp module
class MockAiohttp:
    class ClientSession:
        def __init__(self, **kwargs):
            pass
        
        def __call__(self, **kwargs):
            return MockSession()
    
    class ClientTimeout:
        def __init__(self, total=10):
            self.total = total

# Replace imports with mocks
sys.modules['aiohttp'] = MockAiohttp()
sys.modules['fastapi'] = type('MockFastAPI', (), {})()
sys.modules['uvicorn'] = type('MockUvicorn', (), {})()
sys.modules['pydantic'] = type('MockPydantic', (), {
    'BaseModel': object,
    'validator': lambda f: f
})()

# Now import our modules
from core.threat_intel import ThreatIntelligenceEngine, ThreatLevel
from core.response_engine import AutomatedResponseEngine, ResponseAction

async def example_threat_analysis():
    """Demonstrate threat analysis capabilities"""
    print("🔍 IPDefender Pro - Threat Analysis Example")
    print("=" * 50)
    
    # Configure threat intelligence engine
    config = {
        'abuseipdb_api_key': 'demo_key',
        'otx_api_key': 'demo_key',
        'cache_ttl': 3600
    }
    
    engine = ThreatIntelligenceEngine(config)
    
    # Test IPs (using safe examples)
    test_ips = [
        "8.8.8.8",      # Google DNS (safe)
        "1.1.1.1",      # Cloudflare DNS (safe) 
        "192.168.1.100", # Private IP (safe)
        "10.0.0.1"      # Private IP (safe)
    ]
    
    print("Analyzing test IPs for demonstration...")
    print()
    
    for ip in test_ips:
        try:
            analysis = await engine.analyze_ip(ip)
            
            print(f"📊 Analysis for {ip}:")
            print(f"   Threat Score: {analysis.threat_score:.1f}/100")
            print(f"   Confidence: {analysis.confidence:.1f}%")
            print(f"   Threat Level: {analysis.threat_level.name}")
            print(f"   Categories: {[cat.value for cat in analysis.categories]}")
            print(f"   Sources: {analysis.sources_responded}/{analysis.sources_queried}")
            print(f"   Recommendation: {analysis.recommendation}")
            
            if analysis.geolocation:
                print(f"   Location: {analysis.geolocation}")
            
            print()
            
        except Exception as e:
            print(f"❌ Error analyzing {ip}: {e}")
            print()
    
    # Provider status
    status = engine.get_provider_status()
    print("🔧 Threat Intelligence Providers:")
    for provider in status['providers']:
        print(f"   {provider['name']}: {'✅' if provider['enabled'] else '❌'} "
              f"(weight: {provider['weight']})")
    
    print()

async def example_automated_response():
    """Demonstrate automated response capabilities"""
    print("🛡️ IPDefender Pro - Automated Response Example")
    print("=" * 50)
    
    # Configure response engine
    config = {
        'whitelist': ['127.0.0.1', '10.0.0.0/8', '192.168.0.0/16'],
        'providers': {
            'ufw': {'enabled': True},
            'cloudflare': {'enabled': False}  # Disabled for demo
        },
        'response_rules': [
            {
                'name': 'High Threat Block',
                'conditions': {'threat_score': {'min': 80}},
                'action': 'temp_block',
                'priority': 90,
                'duration': 3600,
                'firewall_providers': ['ufw']
            }
        ]
    }
    
    response_engine = AutomatedResponseEngine(config)
    
    # Create mock threat analysis
    from core.threat_intel import ThreatAnalysis, ThreatEvidence, ThreatCategory
    from datetime import datetime, timedelta
    
    # High threat analysis
    high_threat = ThreatAnalysis(
        ip="203.0.113.1",  # TEST-NET-3 (RFC5737)
        threat_score=85.0,
        confidence=90.0,
        threat_level=ThreatLevel.HIGH,
        categories=[ThreatCategory.BOTNET, ThreatCategory.MALWARE],
        evidence=[],
        sources_queried=2,
        sources_responded=2,
        geolocation={'country_code': 'XX', 'isp': 'Example ISP'},
        reputation_history=[],
        recommendation="BLOCK - High threat score from multiple sources",
        expires_at=datetime.now() + timedelta(hours=1),
        analyzed_at=datetime.now()
    )
    
    print("Processing high-threat IP...")
    response = await response_engine.evaluate_and_respond(high_threat)
    
    print(f"🚨 Response for {high_threat.ip}:")
    print(f"   Rule Applied: {response.rule_name}")
    print(f"   Action: {response.action.value}")
    print(f"   Status: {response.status.value}")
    print(f"   Providers: {response.providers_used or ['None (demo mode)']}")
    
    if response.error_message:
        print(f"   Error: {response.error_message}")
    
    print()
    
    # Show response statistics
    stats = response_engine.get_response_statistics()
    print("📈 Response Engine Statistics:")
    print(f"   Total Responses: {stats['total_responses']}")
    print(f"   Active Responses: {stats['active_responses']}")
    
    if stats['response_by_action']:
        print("   Actions Taken:")
        for action, count in stats['response_by_action'].items():
            print(f"     {action}: {count}")
    
    print()

def example_configuration():
    """Show configuration examples"""
    print("⚙️ IPDefender Pro - Configuration Example")
    print("=" * 50)
    
    config_example = {
        "application": {
            "name": "IPDefender Pro",
            "version": "1.0.0",
            "author": "byFranke",
            "website": "https://byfranke.com"
        },
        "threat_intelligence": {
            "abuseipdb_api_key": "YOUR_ABUSEIPDB_KEY",
            "otx_api_key": "YOUR_OTX_KEY", 
            "cache_ttl": 3600
        },
        "response_engine": {
            "whitelist": [
                "127.0.0.1",
                "10.0.0.0/8",
                "192.168.0.0/16"
            ],
            "providers": {
                "ufw": {"enabled": True},
                "cloudflare": {
                    "enabled": True,
                    "api_token": "YOUR_CLOUDFLARE_TOKEN",
                    "zone_id": "YOUR_ZONE_ID"
                }
            }
        },
        "api": {
            "enabled": True,
            "host": "0.0.0.0", 
            "port": 8080,
            "api_keys": ["your-secret-api-key"]
        },
        "wazuh": {
            "enabled": True,
            "url": "https://your-wazuh-server:55000",
            "username": "wazuh",
            "password": "your-password"
        }
    }
    
    print("📝 Example Configuration Structure:")
    print(json.dumps(config_example, indent=2))
    print()
    
    print("🔧 Key Configuration Points:")
    print("1. Add your threat intelligence API keys")
    print("2. Configure firewall providers (UFW, Cloudflare)")
    print("3. Set up Wazuh integration for SIEM")
    print("4. Define custom response rules")
    print("5. Configure notifications (email, Slack, etc.)")
    print()

def example_api_usage():
    """Show API usage examples"""
    print("🌐 IPDefender Pro - API Usage Examples")
    print("=" * 50)
    
    print("🔍 Analyze IP Address:")
    print("curl -X POST http://localhost:8080/api/v1/analyze \\")
    print("  -H 'Authorization: Bearer your-api-key' \\")
    print("  -H 'Content-Type: application/json' \\")
    print("  -d '{\"ip\": \"192.168.1.100\", \"force_refresh\": false}'")
    print()
    
    print("🛡️ Execute Response:")
    print("curl -X POST http://localhost:8080/api/v1/respond \\")
    print("  -H 'Authorization: Bearer your-api-key' \\")
    print("  -H 'Content-Type: application/json' \\")
    print("  -d '{\"ip\": \"192.168.1.100\", \"action\": \"temp_block\"}'")
    print()
    
    print("📊 System Status:")
    print("curl http://localhost:8080/api/v1/status")
    print()
    
    print("📋 List Blocked IPs:")
    print("curl -H 'Authorization: Bearer your-api-key' \\")
    print("  http://localhost:8080/api/v1/blocked-ips")
    print()
    
    print("🔄 Bulk Analysis:")
    print("curl -X POST http://localhost:8080/api/v1/analyze/bulk \\")
    print("  -H 'Authorization: Bearer your-api-key' \\")
    print("  -H 'Content-Type: application/json' \\")
    print("  -d '{\"ips\": [\"8.8.8.8\", \"1.1.1.1\"], \"force_refresh\": false}'")
    print()

def example_wazuh_integration():
    """Show Wazuh integration examples"""
    print("🔍 IPDefender Pro - Wazuh SIEM Integration Example")
    print("=" * 50)
    
    print("📡 Wazuh Integration Features:")
    print("• Automatic alert monitoring")
    print("• Active response triggering")
    print("• Custom rule creation")
    print("• Threat intelligence sharing")
    print()
    
    print("⚠️ Example Alert Processing:")
    print("1. Wazuh detects SSH brute force (Rule 5710)")
    print("2. IPDefender Pro receives alert")
    print("3. Source IP analyzed against threat intelligence")
    print("4. Automated response executed (block IP)")
    print("5. Response reported back to Wazuh")
    print()
    
    print("🎯 Supported Wazuh Rules:")
    print("• 5710: SSH authentication failure")
    print("• 31101: Web application attack")
    print("• 40101: Port scan detection")
    print("• Custom IPDefender Pro rules (999900-999904)")
    print()

async def main():
    """Run all examples"""
    print("🛡️ IPDefender Pro by byFranke")
    print("Advanced Cybersecurity Defense Platform")
    print("https://byfranke.com")
    print("=" * 60)
    print()
    
    try:
        # Run async examples
        await example_threat_analysis()
        await example_automated_response()
        
        # Run sync examples
        example_configuration()
        example_api_usage()
        example_wazuh_integration()
        
        print("✅ All examples completed successfully!")
        print()
        print("🚀 Ready to deploy IPDefender Pro?")
        print("1. Run: sudo ./install.sh")
        print("2. Configure: /etc/ipdefender/config.yaml")
        print("3. Start: sudo systemctl start ipdefender-pro")
        print()
        print("📚 Documentation: https://byfranke.com/ipdefender-pro")
        
    except Exception as e:
        print(f"❌ Example failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
