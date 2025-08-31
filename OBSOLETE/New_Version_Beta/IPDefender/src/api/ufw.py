"""
UFW (Uncomplicated Firewall) integration for IPDefender
Handles blocking/unblocking IPs using UFW rules
"""
import subprocess
import logging
from typing import Tuple, List, Dict, Any
from ..utils.validators import is_valid_ip

logger = logging.getLogger(__name__)

class UFWManager:
    """UFW firewall management class"""
    
    def __init__(self):
        self.enabled = self._check_ufw_status()
    
    def _check_ufw_status(self) -> bool:
        """Check if UFW is active"""
        try:
            result = subprocess.run(['ufw', 'status'], 
                                  capture_output=True, text=True, check=True)
            return 'Status: active' in result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("UFW not available or not active")
            return False
    
    def block_ip(self, ip: str, comment: str = None) -> Tuple[int, str]:
        """Block an IP using UFW"""
        if not is_valid_ip(ip):
            return 400, f"Invalid IP address: {ip}"
        
        if not self.enabled:
            return 503, "UFW is not active"
        
        try:
            cmd = ['ufw', 'deny', 'from', ip]
            if comment:
                cmd.extend(['comment', comment])
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Blocked IP {ip} via UFW")
            return 200, result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip}: {e.stderr}")
            return 500, e.stderr
    
    def unblock_ip(self, ip: str) -> Tuple[int, str]:
        """Unblock an IP using UFW"""
        if not is_valid_ip(ip):
            return 400, f"Invalid IP address: {ip}"
        
        if not self.enabled:
            return 503, "UFW is not active"
        
        try:
            # First check if rule exists
            if not self._rule_exists(ip):
                return 404, f"No UFW rule found for IP {ip}"
            
            cmd = ['ufw', 'delete', 'deny', 'from', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Unblocked IP {ip} from UFW")
            return 200, result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock IP {ip}: {e.stderr}")
            return 500, e.stderr
    
    def _rule_exists(self, ip: str) -> bool:
        """Check if a UFW rule exists for the given IP"""
        try:
            result = subprocess.run(['ufw', 'status', 'numbered'], 
                                  capture_output=True, text=True, check=True)
            return ip in result.stdout
        except subprocess.CalledProcessError:
            return False
    
    def list_blocked_ips(self) -> List[str]:
        """List all IPs blocked by UFW"""
        blocked_ips = []
        try:
            result = subprocess.run(['ufw', 'status', 'numbered'], 
                                  capture_output=True, text=True, check=True)
            
            # Parse UFW output to extract IPs
            lines = result.stdout.split('\n')
            for line in lines:
                if 'DENY IN' in line and 'from' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'from' and i + 1 < len(parts):
                            ip = parts[i + 1]
                            if is_valid_ip(ip):
                                blocked_ips.append(ip)
            
        except subprocess.CalledProcessError:
            logger.error("Failed to list UFW rules")
        
        return blocked_ips
    
    def bulk_block(self, ip_list: List[str], comment: str = None) -> List[Dict[str, Any]]:
        """Block multiple IPs"""
        results = []
        for ip in ip_list:
            status, response = self.block_ip(ip, comment)
            results.append({"ip": ip, "status": status, "response": response})
        return results
    
    def bulk_unblock(self, ip_list: List[str]) -> List[Dict[str, Any]]:
        """Unblock multiple IPs"""
        results = []
        for ip in ip_list:
            status, response = self.unblock_ip(ip)
            results.append({"ip": ip, "status": status, "response": response})
        return results

# Global instance
ufw_manager = UFWManager()
