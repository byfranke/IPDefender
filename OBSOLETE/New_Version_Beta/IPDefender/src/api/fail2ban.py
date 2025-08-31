"""
Fail2ban integration for IPDefender
Handles banning/unbanning IPs using Fail2ban
"""
import subprocess
import logging
from typing import Tuple, List, Dict, Any
from ..utils.validators import is_valid_ip

logger = logging.getLogger(__name__)

class Fail2banManager:
    """Fail2ban management class"""
    
    def __init__(self):
        self.available = self._check_fail2ban_availability()
        self.default_jail = "ipdefender"
    
    def _check_fail2ban_availability(self) -> bool:
        """Check if fail2ban-client is available"""
        try:
            result = subprocess.run(['fail2ban-client', 'version'], 
                                  capture_output=True, text=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("fail2ban-client not available")
            return False
    
    def ban_ip(self, ip: str, jail: str = None) -> Tuple[int, str]:
        """Ban an IP using fail2ban"""
        if not is_valid_ip(ip):
            return 400, f"Invalid IP address: {ip}"
        
        if not self.available:
            return 503, "Fail2ban is not available"
        
        jail = jail or self.default_jail
        
        try:
            cmd = ['fail2ban-client', 'set', jail, 'banip', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Banned IP {ip} in jail {jail}")
            return 200, result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to ban IP {ip}: {e.stderr}")
            return 500, e.stderr
    
    def unban_ip(self, ip: str, jail: str = None) -> Tuple[int, str]:
        """Unban an IP using fail2ban"""
        if not is_valid_ip(ip):
            return 400, f"Invalid IP address: {ip}"
        
        if not self.available:
            return 503, "Fail2ban is not available"
        
        jail = jail or self.default_jail
        
        try:
            cmd = ['fail2ban-client', 'set', jail, 'unbanip', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Unbanned IP {ip} from jail {jail}")
            return 200, result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unban IP {ip}: {e.stderr}")
            return 500, e.stderr
    
    def get_banned_ips(self, jail: str = None) -> List[str]:
        """Get list of banned IPs from a jail"""
        if not self.available:
            return []
        
        jail = jail or self.default_jail
        
        try:
            cmd = ['fail2ban-client', 'get', jail, 'banip']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse the output to extract IPs
            banned_ips = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if is_valid_ip(line):
                    banned_ips.append(line)
            
            return banned_ips
        except subprocess.CalledProcessError:
            logger.error(f"Failed to get banned IPs from jail {jail}")
            return []
    
    def get_jail_status(self, jail: str = None) -> Dict[str, Any]:
        """Get jail status information"""
        if not self.available:
            return {"error": "Fail2ban not available"}
        
        jail = jail or self.default_jail
        
        try:
            cmd = ['fail2ban-client', 'status', jail]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse status output
            status = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    status[key.strip()] = value.strip()
            
            return status
        except subprocess.CalledProcessError as e:
            return {"error": f"Failed to get jail status: {e.stderr}"}
    
    def create_jail(self, jail_name: str, config: Dict[str, str]) -> Tuple[int, str]:
        """Create a new fail2ban jail"""
        # This would typically involve writing to fail2ban configuration files
        # For now, we'll return a placeholder implementation
        logger.warning("Jail creation not implemented - requires configuration file management")
        return 501, "Jail creation not implemented"
    
    def bulk_ban(self, ip_list: List[str], jail: str = None) -> List[Dict[str, Any]]:
        """Ban multiple IPs"""
        results = []
        for ip in ip_list:
            status, response = self.ban_ip(ip, jail)
            results.append({"ip": ip, "status": status, "response": response})
        return results
    
    def bulk_unban(self, ip_list: List[str], jail: str = None) -> List[Dict[str, Any]]:
        """Unban multiple IPs"""
        results = []
        for ip in ip_list:
            status, response = self.unban_ip(ip, jail)
            results.append({"ip": ip, "status": status, "response": response})
        return results

# Global instance
fail2ban_manager = Fail2banManager()
