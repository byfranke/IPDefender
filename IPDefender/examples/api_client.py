#!/usr/bin/env python3
"""
IPDefender Pro - API Client Example
Demonstrates how to interact with the IPDefender Pro REST API

Author: byFranke (https://byfranke.com)
"""

import requests
import json
import time
from typing import List, Dict, Optional

class IPDefenderClient:
    """Python client for IPDefender Pro API"""
    
    def __init__(self, base_url: str = "http://localhost:8080", api_key: str = None):
        """
        Initialize IPDefender Pro API client
        
        Args:
            base_url: Base URL of IPDefender Pro API
            api_key: API key for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            })
    
    def analyze_ip(self, ip: str, force_refresh: bool = False) -> Dict:
        """
        Analyze an IP address for threats
        
        Args:
            ip: IP address to analyze
            force_refresh: Skip cache and perform fresh analysis
            
        Returns:
            Analysis results dictionary
        """
        url = f"{self.base_url}/api/v1/analyze"
        data = {
            "ip": ip,
            "force_refresh": force_refresh
        }
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()
    
    def bulk_analyze(self, ips: List[str], force_refresh: bool = False) -> Dict:
        """
        Analyze multiple IP addresses
        
        Args:
            ips: List of IP addresses to analyze
            force_refresh: Skip cache and perform fresh analysis
            
        Returns:
            Bulk analysis results
        """
        url = f"{self.base_url}/api/v1/analyze/bulk"
        data = {
            "ips": ips,
            "force_refresh": force_refresh
        }
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()
    
    def execute_response(self, ip: str, action: str, providers: Optional[List[str]] = None) -> Dict:
        """
        Execute response action against an IP
        
        Args:
            ip: IP address to act upon
            action: Response action (block, temp_block, whitelist, etc.)
            providers: Specific firewall providers to use
            
        Returns:
            Response execution results
        """
        url = f"{self.base_url}/api/v1/respond"
        data = {
            "ip": ip,
            "action": action
        }
        
        if providers:
            data["providers"] = providers
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()
    
    def get_status(self) -> Dict:
        """Get system status and health information"""
        url = f"{self.base_url}/api/v1/status"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def get_blocked_ips(self) -> Dict:
        """Get list of currently blocked IPs"""
        url = f"{self.base_url}/api/v1/blocked-ips"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def unblock_ip(self, ip: str, providers: Optional[List[str]] = None) -> Dict:
        """
        Unblock an IP address
        
        Args:
            ip: IP address to unblock
            providers: Specific firewall providers to use
            
        Returns:
            Unblock results
        """
        url = f"{self.base_url}/api/v1/unblock"
        data = {"ip": ip}
        
        if providers:
            data["providers"] = providers
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()
    
    def get_provider_status(self) -> Dict:
        """Get status of all threat intelligence providers"""
        url = f"{self.base_url}/api/v1/providers/status"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

def demo_basic_usage():
    """Demonstrate basic API usage"""
    print("🔧 Basic IPDefender Pro API Usage")
    print("=" * 40)
    
    # Initialize client (no API key for public endpoints)
    client = IPDefenderClient()
    
    try:
        # Check system status
        print("📊 Checking system status...")
        status = client.get_status()
        print(f"✅ System: {status['status']}")
        print(f"   Uptime: {status.get('uptime', 'Unknown')}")
        print(f"   Version: {status.get('version', 'Unknown')}")
        print()
        
        # Test IP analysis (this will fail without proper setup, but shows the pattern)
        print("🔍 Analyzing test IP...")
        test_ip = "8.8.8.8"
        
        try:
            analysis = client.analyze_ip(test_ip)
            print(f"✅ Analysis for {test_ip}:")
            print(f"   Threat Score: {analysis.get('threat_score', 'N/A')}")
            print(f"   Threat Level: {analysis.get('threat_level', 'N/A')}")
            print(f"   Recommendation: {analysis.get('recommendation', 'N/A')}")
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Analysis failed (expected in demo): {e}")
        
        print()
        
    except requests.exceptions.ConnectionError:
        print("⚠️ Could not connect to IPDefender Pro API")
        print("   Make sure the service is running: systemctl status ipdefender-pro")
        print()

def demo_authenticated_usage():
    """Demonstrate authenticated API usage"""
    print("🔐 Authenticated IPDefender Pro API Usage")
    print("=" * 40)
    
    # This would use a real API key in production
    api_key = "demo-api-key-replace-with-real-key"
    client = IPDefenderClient(api_key=api_key)
    
    print("🔑 Using API Key Authentication")
    print("   (Replace 'demo-api-key' with your real API key)")
    print()
    
    # Example operations that require authentication
    operations = [
        ("Analyze suspicious IP", lambda: client.analyze_ip("192.0.2.1")),
        ("Block malicious IP", lambda: client.execute_response("192.0.2.1", "block")),
        ("Get blocked IPs", lambda: client.get_blocked_ips()),
        ("Unblock IP", lambda: client.unblock_ip("192.0.2.1")),
        ("Bulk analysis", lambda: client.bulk_analyze(["8.8.8.8", "1.1.1.1"])),
    ]
    
    for name, operation in operations:
        try:
            print(f"🔄 {name}...")
            result = operation()
            print(f"✅ Success: {len(str(result))} bytes returned")
        except requests.exceptions.RequestException as e:
            print(f"⚠️ {name} failed (expected in demo): {e}")
        print()

def demo_monitoring_workflow():
    """Demonstrate a real-world monitoring workflow"""
    print("📊 Real-World Monitoring Workflow")
    print("=" * 40)
    
    client = IPDefenderClient()
    
    # Simulated suspicious IPs (using TEST-NET ranges)
    suspicious_ips = [
        "192.0.2.1",    # TEST-NET-1
        "198.51.100.1", # TEST-NET-2  
        "203.0.113.1",  # TEST-NET-3
    ]
    
    print("🎯 Monitoring Workflow Example:")
    print("1. Detect suspicious activity (simulated)")
    print("2. Analyze IP addresses against threat intelligence")
    print("3. Execute appropriate responses")
    print("4. Monitor and report results")
    print()
    
    for i, ip in enumerate(suspicious_ips, 1):
        print(f"🔍 Step {i}: Processing {ip}")
        
        try:
            # Step 1: Analyze the IP
            print(f"   Analyzing threat level...")
            analysis = client.analyze_ip(ip)
            
            threat_score = analysis.get('threat_score', 0)
            threat_level = analysis.get('threat_level', 'UNKNOWN')
            
            print(f"   Threat Score: {threat_score}/100")
            print(f"   Threat Level: {threat_level}")
            
            # Step 2: Decide on action based on threat score
            if threat_score > 80:
                action = "block"
                print(f"   🚫 High threat - executing block")
            elif threat_score > 50:
                action = "temp_block"
                print(f"   ⏰ Medium threat - temporary block")
            else:
                action = None
                print(f"   ✅ Low threat - monitoring only")
            
            # Step 3: Execute response if needed
            if action:
                response = client.execute_response(ip, action)
                print(f"   Response: {response.get('status', 'Unknown')}")
            
        except requests.exceptions.RequestException:
            print(f"   ⚠️ Processing failed (demo mode)")
        
        print()
    
    print("📈 Workflow completed - checking system status...")
    try:
        status = client.get_status()
        print(f"✅ System remains healthy: {status.get('status', 'Unknown')}")
    except requests.exceptions.RequestException:
        print("⚠️ Status check failed (demo mode)")
    
    print()

def demo_curl_examples():
    """Show equivalent curl commands for manual testing"""
    print("🌐 Curl Command Examples")
    print("=" * 30)
    
    base_url = "http://localhost:8080"
    
    examples = [
        {
            'name': 'System Status (No Auth)',
            'command': f'curl {base_url}/api/v1/status'
        },
        {
            'name': 'Analyze IP',
            'command': f"""curl -X POST {base_url}/api/v1/analyze \\
  -H 'Authorization: Bearer YOUR_API_KEY' \\
  -H 'Content-Type: application/json' \\
  -d '{{"ip": "8.8.8.8", "force_refresh": false}}'"""
        },
        {
            'name': 'Block IP',
            'command': f"""curl -X POST {base_url}/api/v1/respond \\
  -H 'Authorization: Bearer YOUR_API_KEY' \\
  -H 'Content-Type: application/json' \\
  -d '{{"ip": "192.0.2.1", "action": "block"}}'"""
        },
        {
            'name': 'Bulk Analysis',
            'command': f"""curl -X POST {base_url}/api/v1/analyze/bulk \\
  -H 'Authorization: Bearer YOUR_API_KEY' \\
  -H 'Content-Type: application/json' \\
  -d '{{"ips": ["8.8.8.8", "1.1.1.1"], "force_refresh": false}}'"""
        },
        {
            'name': 'List Blocked IPs',
            'command': f"""curl -H 'Authorization: Bearer YOUR_API_KEY' \\
  {base_url}/api/v1/blocked-ips"""
        }
    ]
    
    for example in examples:
        print(f"📝 {example['name']}:")
        print(f"   {example['command']}")
        print()

def main():
    """Run all API examples"""
    print("🛡️ IPDefender Pro API Examples by byFranke")
    print("Advanced Cybersecurity Defense Platform")
    print("https://byfranke.com")
    print("=" * 50)
    print()
    
    print("ℹ️ Note: These examples demonstrate API usage patterns.")
    print("   Some operations will fail in demo mode without a running service.")
    print()
    
    # Run demonstrations
    demo_basic_usage()
    demo_authenticated_usage() 
    demo_monitoring_workflow()
    demo_curl_examples()
    
    print("✅ API Examples completed!")
    print()
    print("🚀 To use these examples with a real service:")
    print("1. Install IPDefender Pro: sudo ./install.sh")
    print("2. Start the service: sudo systemctl start ipdefender-pro")
    print("3. Get API key from: /etc/ipdefender/config.yaml")
    print("4. Replace 'demo-api-key' with your real key")
    print()
    print("📚 Full documentation: https://byfranke.com/ipdefender-pro")

if __name__ == "__main__":
    main()
