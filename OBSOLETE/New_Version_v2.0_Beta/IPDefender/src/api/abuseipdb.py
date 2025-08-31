"""
AbuseIPDB integration for IPDefender
Validates IPs against AbuseIPDB threat intelligence
"""
import requests
import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from ..utils.validators import is_valid_ip

logger = logging.getLogger(__name__)

class AbuseIPDBManager:
    """AbuseIPDB API integration class"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        } if api_key else {}
    
    def check_ip(self, ip: str, max_age_in_days: int = 90, verbose: bool = False) -> Dict[str, Any]:
        """Check an IP against AbuseIPDB"""
        if not is_valid_ip(ip):
            return {"error": f"Invalid IP address: {ip}"}
        
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        url = f"{self.base_url}/check"
        params = {
            'ipAddress': ip,
            'maxAgeInDays': max_age_in_days,
            'verbose': verbose
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract key information
            result = {
                "ip": ip,
                "is_public": data.get("data", {}).get("isPublic", False),
                "abuse_confidence": data.get("data", {}).get("abuseConfidencePercentage", 0),
                "country_code": data.get("data", {}).get("countryCode"),
                "usage_type": data.get("data", {}).get("usageType"),
                "isp": data.get("data", {}).get("isp"),
                "total_reports": data.get("data", {}).get("totalReports", 0),
                "last_reported_at": data.get("data", {}).get("lastReportedAt"),
                "is_malicious": data.get("data", {}).get("abuseConfidencePercentage", 0) > 75,
                "raw_response": data
            }
            
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to check IP {ip} with AbuseIPDB: {e}")
            return {"error": f"API request failed: {str(e)}"}
    
    def bulk_check(self, ip_list: List[str], max_age_in_days: int = 90) -> List[Dict[str, Any]]:
        """Check multiple IPs (with rate limiting)"""
        results = []
        
        for i, ip in enumerate(ip_list):
            # Rate limiting - AbuseIPDB allows 1000 requests per day for free
            if i > 0 and i % 10 == 0:  # Pause every 10 requests
                time.sleep(1)
            
            result = self.check_ip(ip, max_age_in_days)
            results.append(result)
        
        return results
    
    def report_ip(self, ip: str, categories: List[int], comment: str = "") -> Dict[str, Any]:
        """Report an IP to AbuseIPDB"""
        if not is_valid_ip(ip):
            return {"error": f"Invalid IP address: {ip}"}
        
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        url = f"{self.base_url}/report"
        data = {
            'ip': ip,
            'categories': ','.join(map(str, categories)),
            'comment': comment
        }
        
        try:
            response = requests.post(url, headers=self.headers, data=data, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to report IP {ip} to AbuseIPDB: {e}")
            return {"error": f"Report failed: {str(e)}"}
    
    def get_blacklist(self, confidence_minimum: int = 75, limit: int = 10000) -> List[str]:
        """Get AbuseIPDB blacklist"""
        if not self.api_key:
            logger.error("AbuseIPDB API key not configured")
            return []
        
        url = f"{self.base_url}/blacklist"
        params = {
            'confidenceMinimum': confidence_minimum,
            'limit': limit
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            blacklisted_ips = []
            
            for item in data.get("data", []):
                ip = item.get("ipAddress")
                if ip and is_valid_ip(ip):
                    blacklisted_ips.append(ip)
            
            return blacklisted_ips
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get AbuseIPDB blacklist: {e}")
            return []
    
    def validate_threat_level(self, ip: str, threshold: int = 75) -> Tuple[bool, Dict[str, Any]]:
        """Validate if an IP should be blocked based on threat level"""
        check_result = self.check_ip(ip)
        
        if "error" in check_result:
            return False, check_result
        
        is_threat = check_result.get("abuse_confidence", 0) >= threshold
        
        return is_threat, {
            "ip": ip,
            "is_threat": is_threat,
            "abuse_confidence": check_result.get("abuse_confidence", 0),
            "threshold": threshold,
            "total_reports": check_result.get("total_reports", 0),
            "recommendation": "block" if is_threat else "allow"
        }
    
    @staticmethod
    def get_abuse_categories() -> Dict[int, str]:
        """Get AbuseIPDB abuse categories"""
        return {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }

# Global instance (will need API key configuration)
abuseipdb_manager = AbuseIPDBManager()
