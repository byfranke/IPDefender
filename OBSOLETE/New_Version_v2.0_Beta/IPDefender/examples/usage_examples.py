#!/usr/bin/env python3
"""
IPDefender 2.0 - Usage Examples
Demonstrates the new unified firewall management capabilities
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.firewall_manager import firewall_manager, FirewallProvider, ThreatValidationLevel
from api.abuseipdb import abuseipdb_manager
import json

def example_basic_blocking():
    """Example: Basic IP blocking across all providers"""
    print("=== Basic IP Blocking ===")
    
    # Block a single IP with threat validation
    result = firewall_manager.block_ip(
        ip="192.168.1.100",
        providers=[FirewallProvider.UFW, FirewallProvider.FAIL2BAN],
        validate_threat=ThreatValidationLevel.MEDIUM,
        comment="Example block from IPDefender 2.0"
    )
    
    print(f"Block result: {json.dumps(result, indent=2)}")
    
    # Unblock the IP
    unblock_result = firewall_manager.unblock_ip(
        ip="192.168.1.100",
        providers=[FirewallProvider.UFW, FirewallProvider.FAIL2BAN]
    )
    
    print(f"Unblock result: {json.dumps(unblock_result, indent=2)}")

def example_bulk_operations():
    """Example: Bulk blocking operations"""
    print("\n=== Bulk Operations ===")
    
    # List of suspicious IPs
    suspicious_ips = [
        "192.168.1.101",
        "192.168.1.102", 
        "192.168.1.103"
    ]
    
    # Bulk block with Cloudflare and UFW
    result = firewall_manager.bulk_block(
        ip_list=suspicious_ips,
        providers=[FirewallProvider.CLOUDFLARE, FirewallProvider.UFW],
        validate_threat=ThreatValidationLevel.LOW,
        comment="Bulk block example"
    )
    
    print(f"Bulk block result: {json.dumps(result, indent=2)}")

def example_threat_intelligence():
    """Example: Using AbuseIPDB threat intelligence"""
    print("\n=== Threat Intelligence ===")
    
    # Check a specific IP against AbuseIPDB
    test_ip = "8.8.8.8"  # Using Google DNS as safe example
    
    threat_result = abuseipdb_manager.check_ip(test_ip, verbose=True)
    print(f"AbuseIPDB check for {test_ip}: {json.dumps(threat_result, indent=2)}")
    
    # Validate threat level
    is_threat, validation = abuseipdb_manager.validate_threat_level(test_ip, threshold=75)
    print(f"Threat validation: {json.dumps(validation, indent=2)}")

def example_auto_sync():
    """Example: Auto-sync with threat intelligence"""
    print("\n=== Threat Intelligence Auto-Sync ===")
    
    # Sync with AbuseIPDB blacklist
    sync_result = firewall_manager.sync_with_threat_intel(
        confidence_threshold=80,
        max_ips=100  # Limit for demo
    )
    
    print(f"Threat intel sync result: {json.dumps(sync_result, indent=2)}")

def example_status_check():
    """Example: Check system status"""
    print("\n=== System Status ===")
    
    status = firewall_manager.get_status()
    print(f"System status: {json.dumps(status, indent=2)}")

def example_advanced_blocking():
    """Example: Advanced blocking with multiple criteria"""
    print("\n=== Advanced Blocking ===")
    
    # Block with specific providers and high threat validation
    result = firewall_manager.block_ip(
        ip="10.0.0.1",  # Example IP
        providers=[FirewallProvider.ALL],  # Use all available providers
        validate_threat=ThreatValidationLevel.HIGH,
        comment="High-confidence threat detected"
    )
    
    print(f"Advanced block result: {json.dumps(result, indent=2)}")

def main():
    """Run all examples"""
    print("IPDefender 2.0 - Usage Examples")
    print("=" * 40)
    
    try:
        # Check if we have providers available
        status = firewall_manager.get_status()
        available_providers = status.get("available_providers", [])
        
        if not available_providers:
            print("⚠️  No firewall providers available. Please configure at least one provider.")
            print("Available providers: Cloudflare, UFW, Fail2ban")
            return
        
        print(f"✅ Available providers: {', '.join(available_providers)}")
        
        # Run examples
        example_status_check()
        example_threat_intelligence()
        
        # Only run blocking examples if we have non-Cloudflare providers
        # (to avoid making actual Cloudflare API calls)
        if "ufw" in available_providers or "fail2ban" in available_providers:
            example_basic_blocking()
            example_bulk_operations()
            example_advanced_blocking()
        else:
            print("\n⚠️  Skipping blocking examples - only Cloudflare available")
        
        # example_auto_sync()  # Commented out to avoid API calls
        
    except Exception as e:
        print(f"❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
