"""
Unified Firewall Manager for IPDefender
Orchestrates multiple firewall solutions (Cloudflare, UFW, Fail2ban)
with threat intelligence validation (AbuseIPDB)
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum

from ..api.cloudflare import cf_block, cf_unblock, cf_bulk_block, cf_bulk_unblock
from ..api.ufw import ufw_manager
from ..api.fail2ban import fail2ban_manager
from ..api.abuseipdb import abuseipdb_manager
from ..utils.validators import is_valid_ip

logger = logging.getLogger(__name__)

class FirewallProvider(Enum):
    """Supported firewall providers"""
    CLOUDFLARE = "cloudflare"
    UFW = "ufw"
    FAIL2BAN = "fail2ban"
    ALL = "all"

class ThreatValidationLevel(Enum):
    """Threat validation levels"""
    NONE = "none"           # No validation
    LOW = "low"            # AbuseIPDB confidence >= 50
    MEDIUM = "medium"      # AbuseIPDB confidence >= 75
    HIGH = "high"          # AbuseIPDB confidence >= 90
    STRICT = "strict"      # AbuseIPDB confidence >= 95

class UnifiedFirewallManager:
    """Unified firewall management across multiple providers"""
    
    def __init__(self):
        self.providers = {
            FirewallProvider.CLOUDFLARE: self._cloudflare_available(),
            FirewallProvider.UFW: ufw_manager.enabled,
            FirewallProvider.FAIL2BAN: fail2ban_manager.available
        }
        
        self.threat_thresholds = {
            ThreatValidationLevel.LOW: 50,
            ThreatValidationLevel.MEDIUM: 75,
            ThreatValidationLevel.HIGH: 90,
            ThreatValidationLevel.STRICT: 95
        }
    
    def _cloudflare_available(self) -> bool:
        """Check if Cloudflare is properly configured"""
        # This would check API token and Zone ID
        return True  # Placeholder
    
    def block_ip(self, 
                 ip: str, 
                 providers: List[FirewallProvider] = None,
                 validate_threat: ThreatValidationLevel = ThreatValidationLevel.NONE,
                 comment: str = None) -> Dict[str, Any]:
        """Block an IP across specified providers with optional threat validation"""
        
        if not is_valid_ip(ip):
            return {
                "success": False,
                "error": f"Invalid IP address: {ip}",
                "ip": ip
            }
        
        # Default to all available providers
        if providers is None:
            providers = [p for p, available in self.providers.items() if available]
        elif FirewallProvider.ALL in providers:
            providers = [p for p, available in self.providers.items() if available]
        
        result = {
            "ip": ip,
            "success": True,
            "providers": {},
            "threat_validation": None,
            "errors": []
        }
        
        # Threat validation if requested
        if validate_threat != ThreatValidationLevel.NONE:
            threshold = self.threat_thresholds[validate_threat]
            is_threat, validation_result = abuseipdb_manager.validate_threat_level(ip, threshold)
            result["threat_validation"] = validation_result
            
            if not is_threat:
                logger.info(f"IP {ip} does not meet threat threshold {threshold}%, skipping block")
                result["success"] = False
                result["error"] = f"IP does not meet threat threshold ({threshold}%)"
                return result
        
        # Execute blocking across providers
        for provider in providers:
            try:
                if provider == FirewallProvider.CLOUDFLARE:
                    status, response = cf_block(ip)
                    result["providers"][provider.value] = {
                        "status": status,
                        "response": response,
                        "success": 200 <= status < 300
                    }
                
                elif provider == FirewallProvider.UFW:
                    status, response = ufw_manager.block_ip(ip, comment or f"Blocked by IPDefender")
                    result["providers"][provider.value] = {
                        "status": status,
                        "response": response,
                        "success": status == 200
                    }
                
                elif provider == FirewallProvider.FAIL2BAN:
                    status, response = fail2ban_manager.ban_ip(ip)
                    result["providers"][provider.value] = {
                        "status": status,
                        "response": response,
                        "success": status == 200
                    }
                
            except Exception as e:
                error_msg = f"Error blocking IP {ip} on {provider.value}: {str(e)}"
                logger.error(error_msg)
                result["providers"][provider.value] = {
                    "status": 500,
                    "response": error_msg,
                    "success": False
                }
                result["errors"].append(error_msg)
        
        # Overall success if at least one provider succeeded
        provider_successes = [p["success"] for p in result["providers"].values()]
        result["success"] = any(provider_successes) if provider_successes else False
        
        return result
    
    def unblock_ip(self, 
                   ip: str, 
                   providers: List[FirewallProvider] = None) -> Dict[str, Any]:
        """Unblock an IP across specified providers"""
        
        if not is_valid_ip(ip):
            return {
                "success": False,
                "error": f"Invalid IP address: {ip}",
                "ip": ip
            }
        
        # Default to all available providers
        if providers is None:
            providers = [p for p, available in self.providers.items() if available]
        elif FirewallProvider.ALL in providers:
            providers = [p for p, available in self.providers.items() if available]
        
        result = {
            "ip": ip,
            "success": True,
            "providers": {},
            "errors": []
        }
        
        # Execute unblocking across providers
        for provider in providers:
            try:
                if provider == FirewallProvider.CLOUDFLARE:
                    status, response = cf_unblock(ip)
                    result["providers"][provider.value] = {
                        "status": status,
                        "response": response,
                        "success": 200 <= status < 300
                    }
                
                elif provider == FirewallProvider.UFW:
                    status, response = ufw_manager.unblock_ip(ip)
                    result["providers"][provider.value] = {
                        "status": status,
                        "response": response,
                        "success": status == 200
                    }
                
                elif provider == FirewallProvider.FAIL2BAN:
                    status, response = fail2ban_manager.unban_ip(ip)
                    result["providers"][provider.value] = {
                        "status": status,
                        "response": response,
                        "success": status == 200
                    }
                
            except Exception as e:
                error_msg = f"Error unblocking IP {ip} on {provider.value}: {str(e)}"
                logger.error(error_msg)
                result["providers"][provider.value] = {
                    "status": 500,
                    "response": error_msg,
                    "success": False
                }
                result["errors"].append(error_msg)
        
        # Overall success if at least one provider succeeded
        provider_successes = [p["success"] for p in result["providers"].values()]
        result["success"] = any(provider_successes) if provider_successes else False
        
        return result
    
    def bulk_block(self, 
                   ip_list: List[str],
                   providers: List[FirewallProvider] = None,
                   validate_threat: ThreatValidationLevel = ThreatValidationLevel.NONE,
                   comment: str = None) -> Dict[str, Any]:
        """Block multiple IPs across providers"""
        
        results = []
        successful = 0
        failed = 0
        
        for ip in ip_list:
            result = self.block_ip(ip, providers, validate_threat, comment)
            results.append(result)
            
            if result["success"]:
                successful += 1
            else:
                failed += 1
        
        return {
            "total": len(ip_list),
            "successful": successful,
            "failed": failed,
            "results": results
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all firewall providers"""
        status = {
            "providers": {},
            "available_providers": [],
            "blocked_ips": {}
        }
        
        # Provider availability
        for provider, available in self.providers.items():
            status["providers"][provider.value] = {
                "available": available,
                "active": available  # Could add more detailed status checking
            }
            
            if available:
                status["available_providers"].append(provider.value)
        
        # Get blocked IPs from each provider
        try:
            if self.providers[FirewallProvider.UFW]:
                status["blocked_ips"]["ufw"] = ufw_manager.list_blocked_ips()
        except Exception as e:
            logger.error(f"Error getting UFW blocked IPs: {e}")
        
        try:
            if self.providers[FirewallProvider.FAIL2BAN]:
                status["blocked_ips"]["fail2ban"] = fail2ban_manager.get_banned_ips()
        except Exception as e:
            logger.error(f"Error getting Fail2ban blocked IPs: {e}")
        
        return status
    
    def sync_with_threat_intel(self, 
                              confidence_threshold: int = 75,
                              max_ips: int = 1000) -> Dict[str, Any]:
        """Sync with AbuseIPDB blacklist and block high-confidence threats"""
        
        logger.info(f"Syncing with AbuseIPDB blacklist (confidence >= {confidence_threshold}%)")
        
        # Get AbuseIPDB blacklist
        blacklisted_ips = abuseipdb_manager.get_blacklist(
            confidence_minimum=confidence_threshold,
            limit=max_ips
        )
        
        if not blacklisted_ips:
            return {
                "success": False,
                "error": "Failed to retrieve AbuseIPDB blacklist or list is empty",
                "blocked": 0
            }
        
        # Block the IPs
        result = self.bulk_block(
            blacklisted_ips,
            comment=f"AbuseIPDB threat intel sync (confidence >= {confidence_threshold}%)"
        )
        
        logger.info(f"Threat intel sync completed: {result['successful']} IPs blocked")
        
        return {
            "success": True,
            "blacklisted_ips": len(blacklisted_ips),
            "blocked": result["successful"],
            "failed": result["failed"],
            "confidence_threshold": confidence_threshold
        }

# Global instance
firewall_manager = UnifiedFirewallManager()
