"""
IP Defender Module for SecGuard Enterprise
=========================================

Advanced IP management and threat intelligence including:
- UFW and Fail2Ban integration
- CloudFlare API integration
- Geolocation and threat intelligence
- Automated ban/unban operations
- JSON-based ban database with metadata
"""

import asyncio
import json
import logging
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

try:
    import aiohttp
    import ipaddress
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Run: pip install aiohttp")
    raise


@dataclass
class BannedIP:
    """Banned IP information structure"""
    ip: str
    date: datetime
    reason: str
    country: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    score: int = 0
    total_reports: int = 0
    last_reported: Optional[str] = None
    banned_by: List[str] = None  # ufw, fail2ban, cloudflare
    
    def __post_init__(self):
        if self.banned_by is None:
            self.banned_by = []


class IPDefender:
    """Advanced IP defense and threat intelligence system"""
    
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.data_dir = Path(config_manager.get('paths.data_dir'))
        self.ban_db_file = self.data_dir / "banned_ips.json"
        
        # API keys
        self.cloudflare_token = config_manager.get_api_key('cloudflare_token')
        self.cloudflare_zone = config_manager.get_api_key('cloudflare_zone_id')
        self.abuseipdb_key = config_manager.get_api_key('abuseipdb')
        
        # Configuration
        self.use_ufw = config_manager.get('ip_defense.use_ufw', True)
        self.use_fail2ban = config_manager.get('ip_defense.use_fail2ban', True)
        self.use_cloudflare = config_manager.get('ip_defense.use_cloudflare', False)
        self.auto_ban_threshold = config_manager.get('ip_defense.auto_ban_threshold', 80)
        
        # Initialize ban database
        self._initialize_ban_db()
        
        # Reporter reference for notifications (set externally)
        self.reporter = None
    
    def set_reporter(self, reporter):
        """Set reporter instance for notifications"""
        self.reporter = reporter
    
    def _initialize_ban_db(self):
        """Initialize JSON ban database"""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        if not self.ban_db_file.exists():
            with open(self.ban_db_file, 'w') as f:
                json.dump([], f)
    
    def _load_ban_db(self) -> List[Dict]:
        """Load ban database from JSON file"""
        try:
            with open(self.ban_db_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    
    def _save_ban_db(self, bans: List[Dict]):
        """Save ban database to JSON file"""
        # Convert datetime objects to ISO format
        for ban in bans:
            if isinstance(ban.get('date'), datetime):
                ban['date'] = ban['date'].isoformat()
        
        with open(self.ban_db_file, 'w') as f:
            json.dump(bans, f, indent=2, default=str)
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    async def ban_ip(self, ip: str, reason: str = "Manual ban") -> Dict[str, Any]:
        """Ban IP address with comprehensive threat intelligence"""
        if not self._is_valid_ip(ip):
            return {"success": False, "error": "Invalid IP address format"}
        
        if self._is_private_ip(ip):
            return {"success": False, "error": "Cannot ban private IP address"}
        
        # Check if already banned
        if await self._is_ip_banned(ip):
            return {"success": False, "error": "IP already banned"}
        
        self.logger.info(f"Starting ban process for IP: {ip}")
        
        # Gather threat intelligence
        threat_data = await self._get_threat_intelligence(ip)
        
        # Create ban record
        banned_ip = BannedIP(
            ip=ip,
            date=datetime.now(),
            reason=reason,
            country=threat_data.get('country', 'Unknown'),
            city=threat_data.get('city', 'Unknown'),
            isp=threat_data.get('isp', 'Unknown'),
            score=threat_data.get('score', 0),
            total_reports=threat_data.get('total_reports', 0),
            last_reported=threat_data.get('last_reported'),
            banned_by=[]
        )
        
        # Execute bans across different systems
        ban_results = {}
        
        if self.use_ufw:
            ban_results['ufw'] = await self._ban_with_ufw(ip, reason)
            if ban_results['ufw']['success']:
                banned_ip.banned_by.append('ufw')
        
        if self.use_fail2ban:
            ban_results['fail2ban'] = await self._ban_with_fail2ban(ip)
            if ban_results['fail2ban']['success']:
                banned_ip.banned_by.append('fail2ban')
        
        if self.use_cloudflare and self.cloudflare_token:
            ban_results['cloudflare'] = await self._ban_with_cloudflare(ip, reason)
            if ban_results['cloudflare']['success']:
                banned_ip.banned_by.append('cloudflare')
        
                # Save to database if at least one ban was successful
        if banned_ip.banned_by:
            await self._add_to_ban_db(banned_ip)
            self.logger.info(f"Successfully banned {ip} using: {', '.join(banned_ip.banned_by)}")
            
            # Send notifications
            await self._send_ban_notifications(banned_ip)
            
            return {
                "success": True,
                "ip": ip,
                "banned_by": banned_ip.banned_by,
                "threat_data": threat_data
            }
        else:
            return {
                "success": False,
                "error": "Failed to ban IP with any method",
                "results": ban_results
            }
    
    async def unban_ip(self, ip: str) -> Dict[str, Any]:
        """Remove IP ban from all systems"""
        if not self._is_valid_ip(ip):
            return {"success": False, "error": "Invalid IP address format"}
        
        self.logger.info(f"Starting unban process for IP: {ip}")
        
        unban_results = {}
        
        # Remove from UFW
        if self.use_ufw:
            unban_results['ufw'] = await self._unban_with_ufw(ip)
        
        # Remove from Fail2Ban
        if self.use_fail2ban:
            unban_results['fail2ban'] = await self._unban_with_fail2ban(ip)
        
        # Remove from CloudFlare
        if self.use_cloudflare and self.cloudflare_token:
            unban_results['cloudflare'] = await self._unban_with_cloudflare(ip)
        
        # Remove from database
        await self._remove_from_ban_db(ip)
        
        self.logger.info(f"Unban process completed for {ip}")
        
        return {
            "success": True,
            "unban_results": unban_results
        }
    
    async def list_bans(self, include_inactive: bool = True) -> List[Dict]:
        """List all banned IPs with metadata"""
        bans = self._load_ban_db()
        
        # Convert date strings back to datetime for processing
        for ban in bans:
            if isinstance(ban.get('date'), str):
                try:
                    ban['date'] = datetime.fromisoformat(ban['date'])
                except:
                    ban['date'] = datetime.now()
        
        # Verify active bans if requested
        if not include_inactive:
            active_bans = []
            for ban in bans:
                if await self._is_ip_banned(ban['ip']):
                    active_bans.append(ban)
            return active_bans
        
        return bans
    
    async def _get_threat_intelligence(self, ip: str) -> Dict[str, Any]:
        """Gather threat intelligence from multiple sources"""
        threat_data = {}
        
        # Get geolocation data
        geo_data = await self._get_geolocation(ip)
        threat_data.update(geo_data)
        
        # Get AbuseIPDB data if available
        if self.abuseipdb_key:
            abuse_data = await self._query_abuseipdb(ip)
            threat_data.update(abuse_data)
        
        return threat_data
    
    async def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation information"""
        try:
            # Using free ip-api.com service
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,query"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == 'success':
                            return {
                                'country': data.get('country', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'isp': data.get('isp', 'Unknown')
                            }
        except Exception as e:
            self.logger.warning(f"Geolocation lookup failed for {ip}: {e}")
        
        return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
    
    async def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for threat intelligence"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('data'):
                            result = data['data']
                            return {
                                'score': result.get('abuseConfidenceScore', 0),
                                'total_reports': result.get('totalReports', 0),
                                'last_reported': result.get('lastReportedAt')
                            }
        except Exception as e:
            self.logger.warning(f"AbuseIPDB query failed for {ip}: {e}")
        
        return {'score': 0, 'total_reports': 0, 'last_reported': None}
    
    async def _ban_with_ufw(self, ip: str, reason: str) -> Dict[str, Any]:
        """Ban IP using UFW firewall"""
        try:
            cmd = ["ufw", "insert", "1", "deny", "from", ip, "comment", f"SecGuard: {reason}"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {"success": True, "message": "UFW ban successful"}
            else:
                return {"success": False, "error": stderr.decode().strip()}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _unban_with_ufw(self, ip: str) -> Dict[str, Any]:
        """Remove IP ban from UFW"""
        try:
            # Find and remove UFW rules for this IP
            cmd = ["ufw", "status", "numbered"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return {"success": False, "error": "Failed to list UFW rules"}
            
            # Parse output to find rule numbers for this IP
            lines = stdout.decode().split('\n')
            rules_to_delete = []
            
            for line in lines:
                if ip in line and 'DENY' in line:
                    # Extract rule number
                    if '[' in line and ']' in line:
                        rule_num = line.split('[')[1].split(']')[0].strip()
                        rules_to_delete.append(rule_num)
            
            # Delete rules (in reverse order to maintain numbering)
            for rule_num in reversed(rules_to_delete):
                delete_cmd = ["ufw", "--force", "delete", rule_num]
                process = await asyncio.create_subprocess_exec(
                    *delete_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
            
            return {"success": True, "message": f"Removed {len(rules_to_delete)} UFW rules"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _ban_with_fail2ban(self, ip: str) -> Dict[str, Any]:
        """Ban IP using Fail2Ban (add to jail)"""
        try:
            # Get available jails
            cmd = ["fail2ban-client", "status"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return {"success": False, "error": "Fail2ban not available"}
            
            # Try to ban in sshd jail (most common)
            ban_cmd = ["fail2ban-client", "set", "sshd", "banip", ip]
            process = await asyncio.create_subprocess_exec(
                *ban_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {"success": True, "message": "Fail2ban ban successful"}
            else:
                return {"success": False, "error": stderr.decode().strip()}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _unban_with_fail2ban(self, ip: str) -> Dict[str, Any]:
        """Remove IP ban from Fail2Ban"""
        try:
            cmd = ["fail2ban-client", "set", "sshd", "unbanip", ip]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {"success": True, "message": "Fail2ban unban successful"}
            else:
                return {"success": False, "error": stderr.decode().strip()}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _ban_with_cloudflare(self, ip: str, reason: str) -> Dict[str, Any]:
        """Ban IP using CloudFlare API"""
        if not self.cloudflare_token or not self.cloudflare_zone:
            return {"success": False, "error": "CloudFlare credentials not configured"}
        
        try:
            url = f"https://api.cloudflare.com/client/v4/zones/{self.cloudflare_zone}/firewall/access_rules/rules"
            headers = {
                "Authorization": f"Bearer {self.cloudflare_token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "mode": "block",
                "configuration": {
                    "target": "ip",
                    "value": ip
                },
                "notes": f"SecGuard ban: {reason} - {datetime.now().isoformat()}"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload, timeout=10) as response:
                    if response.status in [200, 201]:
                        return {"success": True, "message": "CloudFlare ban successful"}
                    else:
                        error_text = await response.text()
                        return {"success": False, "error": f"CloudFlare API error: {error_text}"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _unban_with_cloudflare(self, ip: str) -> Dict[str, Any]:
        """Remove IP ban from CloudFlare"""
        if not self.cloudflare_token or not self.cloudflare_zone:
            return {"success": False, "error": "CloudFlare credentials not configured"}
        
        try:
            # First, find the rule ID
            search_url = f"https://api.cloudflare.com/client/v4/zones/{self.cloudflare_zone}/firewall/access_rules/rules"
            headers = {
                "Authorization": f"Bearer {self.cloudflare_token}",
                "Content-Type": "application/json"
            }
            
            params = {
                "configuration.target": "ip",
                "configuration.value": ip
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, headers=headers, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('result'):
                            rule_id = data['result'][0]['id']
                            
                            # Delete the rule
                            delete_url = f"{search_url}/{rule_id}"
                            async with session.delete(delete_url, headers=headers, timeout=10) as delete_response:
                                if delete_response.status == 200:
                                    return {"success": True, "message": "CloudFlare unban successful"}
                                else:
                                    error_text = await delete_response.text()
                                    return {"success": False, "error": f"CloudFlare delete error: {error_text}"}
                        else:
                            return {"success": False, "error": "Rule not found in CloudFlare"}
                    else:
                        error_text = await response.text()
                        return {"success": False, "error": f"CloudFlare search error: {error_text}"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _is_ip_banned(self, ip: str) -> bool:
        """Check if IP is currently banned in any system"""
        # Check UFW
        if self.use_ufw:
            try:
                cmd = ["ufw", "status"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if ip in stdout.decode():
                    return True
            except:
                pass
        
        # Check Fail2Ban
        if self.use_fail2ban:
            try:
                cmd = ["fail2ban-client", "status", "sshd"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if ip in stdout.decode():
                    return True
            except:
                pass
        
        return False
    
    async def _add_to_ban_db(self, banned_ip: BannedIP):
        """Add banned IP to database"""
        bans = self._load_ban_db()
        bans.append(asdict(banned_ip))
        self._save_ban_db(bans)
    
    async def _remove_from_ban_db(self, ip: str):
        """Remove IP from ban database"""
        bans = self._load_ban_db()
        bans = [ban for ban in bans if ban['ip'] != ip]
        self._save_ban_db(bans)
    
    async def bulk_ban(self, ip_list: List[str], reason: str = "Bulk ban") -> Dict[str, Any]:
        """Ban multiple IPs in bulk"""
        results = {
            "total": len(ip_list),
            "successful": 0,
            "failed": 0,
            "details": []
        }
        
        for ip in ip_list:
            result = await self.ban_ip(ip.strip(), reason)
            
            if result['success']:
                results['successful'] += 1
            else:
                results['failed'] += 1
            
            results['details'].append({
                'ip': ip,
                'success': result['success'],
                'error': result.get('error')
            })
        
        return results
    
    async def auto_ban_by_score(self, min_score: int = None) -> Dict[str, Any]:
        """Automatically ban IPs based on threat score"""
        if min_score is None:
            min_score = self.auto_ban_threshold
        
        # This would typically be called with a list of IPs to check
        # For now, it's a placeholder for future implementation
        return {"message": "Auto-ban functionality not yet implemented"}
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get ban statistics and metrics"""
        bans = await self.list_bans()
        
        if not bans:
            return {
                "total_bans": 0,
                "by_country": {},
                "by_score_range": {},
                "recent_bans": 0
            }
        
        # Count by country
        country_count = {}
        score_ranges = {"0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0}
        recent_bans = 0
        
        recent_threshold = datetime.now() - timedelta(days=7)
        
        for ban in bans:
            # Country stats
            country = ban.get('country', 'Unknown')
            country_count[country] = country_count.get(country, 0) + 1
            
            # Score range stats
            score = ban.get('score', 0)
            if score <= 25:
                score_ranges["0-25"] += 1
            elif score <= 50:
                score_ranges["26-50"] += 1
            elif score <= 75:
                score_ranges["51-75"] += 1
            else:
                score_ranges["76-100"] += 1
            
            # Recent bans
            ban_date = ban.get('date')
            if isinstance(ban_date, str):
                ban_date = datetime.fromisoformat(ban_date)
            
            if ban_date and ban_date > recent_threshold:
                recent_bans += 1
        
        return {
            "total_bans": len(bans),
            "by_country": country_count,
            "by_score_range": score_ranges,
            "recent_bans": recent_bans
        }
    
    async def _send_ban_notifications(self, banned_ip):
        """Send ban notifications via configured channels"""
        try:
            # Import here to avoid circular imports
            from reporter import SecurityReporter
            
            # Get reporter instance (this is a simplified approach)
            # In production, this should be properly injected
            if hasattr(self, 'reporter'):
                # Prepare notification data
                ip_data = {
                    'ip': banned_ip.ip,
                    'country': banned_ip.country,
                    'city': banned_ip.city,
                    'isp': banned_ip.isp,
                    'score': banned_ip.score,
                    'reason': banned_ip.reason,
                    'banned_by': banned_ip.banned_by,
                    'timestamp': banned_ip.date.isoformat()
                }
                
                # Send webhook notification
                await self.reporter.send_ip_ban_webhook(ip_data)
                
                # Log to Wazuh
                self.reporter.log_ip_ban_to_wazuh(ip_data)
            
        except Exception as e:
            self.logger.warning(f"Failed to send ban notifications: {e}")
