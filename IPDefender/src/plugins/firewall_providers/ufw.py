"""
IPDefender Pro - UFW Firewall Provider Plugin
Enhanced UFW integration with non-blocking operations and advanced management

Author: byFranke (https://byfranke.com)
"""

import asyncio
import subprocess
import logging
import re
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
import ipaddress

from plugins import FirewallProvider

logger = logging.getLogger(__name__)

class UFWProvider(FirewallProvider):
    """UFW (Uncomplicated Firewall) provider with enhanced async operations"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.blocked_ips: Set[str] = set()  # Track blocked IPs
        self.temp_blocks: Dict[str, datetime] = {}  # Track temporary blocks
        self.chain_name = config.get('chain_name', 'ipdefender')
        self.rule_prefix = config.get('rule_prefix', 'IPDefender Pro')
        
    async def initialize(self) -> bool:
        """Initialize UFW provider"""
        try:
            # Check if UFW is available
            if not await self._check_ufw_available():
                raise RuntimeError("UFW not available on system")
            
            # Check UFW status
            status = await self._get_ufw_status()
            if not status.get('active', False):
                self.logger.warning("UFW is not active - rules may not be effective")
            
            # Load existing IPDefender rules
            await self._load_existing_rules()
            
            self.logger.info("UFW provider initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"UFW provider initialization failed: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup UFW provider resources"""
        # Remove temporary blocks cleanup task would be here
        # For now, just log cleanup
        self.logger.info("UFW provider cleaned up")
    
    async def health_check(self) -> bool:
        """Check UFW provider health"""
        try:
            return await self._check_ufw_available()
        except Exception:
            return False
    
    async def _check_ufw_available(self) -> bool:
        """Check if UFW is available and accessible"""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ['which', 'ufw'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def _get_ufw_status(self) -> Dict[str, Any]:
        """Get UFW status and configuration"""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ['ufw', 'status', 'numbered'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return {'active': False, 'error': result.stderr}
            
            output = result.stdout.lower()
            active = 'status: active' in output
            
            return {
                'active': active,
                'output': result.stdout,
                'detailed': result.stdout
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get UFW status: {e}")
            return {'active': False, 'error': str(e)}
    
    async def _load_existing_rules(self):
        """Load existing IPDefender rules from UFW"""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ['ufw', 'status', 'numbered'],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode != 0:
                self.logger.warning(f"Could not load existing UFW rules: {result.stderr}")
                return
            
            # Parse UFW output to find our rules
            lines = result.stdout.split('\n')
            for line in lines:
                if self.rule_prefix in line and 'DENY' in line:
                    # Extract IP from rule
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        self.blocked_ips.add(ip)
            
            self.logger.info(f"Loaded {len(self.blocked_ips)} existing blocked IPs from UFW")
            
        except Exception as e:
            self.logger.error(f"Failed to load existing UFW rules: {e}")
    
    async def block_ip(self, ip: str, reason: str = None, duration: int = None) -> bool:
        """Block an IP address using UFW"""
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                self.logger.error(f"Invalid IP address: {ip}")
                return False
            
            # Skip if already blocked
            if ip in self.blocked_ips:
                self.logger.info(f"IP {ip} already blocked")
                return True
            
            # Create UFW rule
            comment = f"{self.rule_prefix}"
            if reason:
                comment += f" - {reason}"
            
            cmd = ['ufw', 'deny', 'from', ip, 'comment', comment]
            
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                
                # Handle temporary blocks
                if duration:
                    expiry = datetime.now() + timedelta(seconds=duration)
                    self.temp_blocks[ip] = expiry
                    # Schedule cleanup (simplified - in production, use proper task scheduling)
                    asyncio.create_task(self._schedule_unblock(ip, duration))
                
                self.update_usage()
                self.logger.info(f"Successfully blocked {ip} with UFW")
                return True
            else:
                self.logger.error(f"UFW block failed for {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"UFW block operation failed for {ip}: {e}")
            return False
    
    async def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address using UFW"""
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                self.logger.error(f"Invalid IP address: {ip}")
                return False
            
            # Skip if not blocked
            if ip not in self.blocked_ips:
                self.logger.info(f"IP {ip} not currently blocked")
                return True
            
            # Remove UFW rule
            # UFW doesn't have a direct "unblock" command, so we delete the rule
            success = await self._delete_ufw_rule_for_ip(ip)
            
            if success:
                self.blocked_ips.discard(ip)
                self.temp_blocks.pop(ip, None)
                self.update_usage()
                self.logger.info(f"Successfully unblocked {ip} with UFW")
                return True
            else:
                self.logger.error(f"Failed to unblock {ip} with UFW")
                return False
                
        except Exception as e:
            self.logger.error(f"UFW unblock operation failed for {ip}: {e}")
            return False
    
    async def _delete_ufw_rule_for_ip(self, ip: str) -> bool:
        """Delete UFW rule for specific IP"""
        try:
            # Get numbered rules
            result = await asyncio.to_thread(
                subprocess.run,
                ['ufw', 'status', 'numbered'],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode != 0:
                return False
            
            # Find rule number for our IP
            lines = result.stdout.split('\n')
            rule_numbers = []
            
            for line in lines:
                if ip in line and self.rule_prefix in line and 'DENY' in line:
                    # Extract rule number
                    rule_match = re.match(r'\s*\[(\d+)\]', line)
                    if rule_match:
                        rule_numbers.append(int(rule_match.group(1)))
            
            # Delete rules (in reverse order to maintain numbering)
            for rule_num in sorted(rule_numbers, reverse=True):
                delete_cmd = ['ufw', 'delete', str(rule_num)]
                
                # Use 'yes' to auto-confirm deletion
                result = await asyncio.to_thread(
                    subprocess.run,
                    delete_cmd,
                    input='y\n',
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    self.logger.error(f"Failed to delete UFW rule {rule_num}: {result.stderr}")
                    return False
            
            return len(rule_numbers) > 0
            
        except Exception as e:
            self.logger.error(f"Failed to delete UFW rule for {ip}: {e}")
            return False
    
    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        return ip in self.blocked_ips
    
    async def list_blocked_ips(self) -> List[str]:
        """List all blocked IP addresses"""
        # Clean up expired temporary blocks
        now = datetime.now()
        expired_ips = [
            ip for ip, expiry in self.temp_blocks.items()
            if expiry <= now
        ]
        
        for ip in expired_ips:
            await self.unblock_ip(ip)
        
        return list(self.blocked_ips)
    
    async def _schedule_unblock(self, ip: str, duration: int):
        """Schedule automatic unblock for temporary blocks"""
        try:
            await asyncio.sleep(duration)
            
            # Check if still should be blocked
            if ip in self.temp_blocks:
                expiry = self.temp_blocks[ip]
                if datetime.now() >= expiry:
                    await self.unblock_ip(ip)
                    self.logger.info(f"Automatically unblocked {ip} after {duration} seconds")
                    
        except Exception as e:
            self.logger.error(f"Failed to auto-unblock {ip}: {e}")
    
    async def get_firewall_stats(self) -> Dict[str, Any]:
        """Get UFW statistics and information"""
        try:
            status = await self._get_ufw_status()
            
            # Count temporary vs permanent blocks
            now = datetime.now()
            active_temp_blocks = len([
                ip for ip, expiry in self.temp_blocks.items()
                if expiry > now
            ])
            permanent_blocks = len(self.blocked_ips) - active_temp_blocks
            
            return {
                'provider': self.name,
                'firewall_active': status.get('active', False),
                'total_blocked_ips': len(self.blocked_ips),
                'permanent_blocks': permanent_blocks,
                'temporary_blocks': active_temp_blocks,
                'usage_count': self.usage_count,
                'last_used': self.last_used.isoformat() if self.last_used else None,
                'status': self.status.value
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get UFW stats: {e}")
            return {
                'provider': self.name,
                'error': str(e),
                'total_blocked_ips': len(self.blocked_ips)
            }
    
    async def cleanup_expired_blocks(self):
        """Clean up expired temporary blocks"""
        now = datetime.now()
        expired_ips = [
            ip for ip, expiry in self.temp_blocks.items()
            if expiry <= now
        ]
        
        for ip in expired_ips:
            success = await self.unblock_ip(ip)
            if success:
                self.logger.info(f"Cleaned up expired block for {ip}")
        
        return len(expired_ips)
    
    async def backup_rules(self) -> Dict[str, Any]:
        """Backup current UFW rules for IPDefender"""
        try:
            blocked_ips_with_meta = {}
            
            for ip in self.blocked_ips:
                meta = {
                    'blocked_at': datetime.now().isoformat(),
                    'provider': self.name
                }
                
                if ip in self.temp_blocks:
                    meta['expires_at'] = self.temp_blocks[ip].isoformat()
                    meta['type'] = 'temporary'
                else:
                    meta['type'] = 'permanent'
                
                blocked_ips_with_meta[ip] = meta
            
            return {
                'provider': self.name,
                'backup_time': datetime.now().isoformat(),
                'blocked_ips': blocked_ips_with_meta
            }
            
        except Exception as e:
            self.logger.error(f"Failed to backup UFW rules: {e}")
            return {'error': str(e)}
    
    async def restore_rules(self, backup_data: Dict[str, Any]) -> bool:
        """Restore UFW rules from backup"""
        try:
            blocked_ips = backup_data.get('blocked_ips', {})
            success_count = 0
            
            for ip, meta in blocked_ips.items():
                if meta.get('type') == 'temporary':
                    # Calculate remaining duration
                    if 'expires_at' in meta:
                        expires_at = datetime.fromisoformat(meta['expires_at'])
                        if expires_at > datetime.now():
                            duration = int((expires_at - datetime.now()).total_seconds())
                            success = await self.block_ip(ip, "Restored from backup", duration)
                        else:
                            continue  # Skip expired blocks
                    else:
                        success = await self.block_ip(ip, "Restored from backup")
                else:
                    success = await self.block_ip(ip, "Restored from backup")
                
                if success:
                    success_count += 1
            
            self.logger.info(f"Restored {success_count}/{len(blocked_ips)} UFW rules from backup")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Failed to restore UFW rules: {e}")
            return False
