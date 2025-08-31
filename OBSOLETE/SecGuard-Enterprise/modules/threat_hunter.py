"""
Threat Hunter Module for SecGuard Enterprise
==========================================

Advanced threat detection and hunting capabilities including:
- Service analysis with VirusTotal integration
- User account monitoring
- Persistence mechanism detection
- Network connection analysis
- Deep forensic scanning
"""

import asyncio
import hashlib
import json
import logging
import os
import pwd
import grp
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

try:
    import psutil
    import aiohttp
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Run: pip install psutil aiohttp")
    raise
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import aiohttp
import socket
from dataclasses import dataclass, asdict


@dataclass
class ServiceInfo:
    """Service information structure"""
    name: str
    binary_path: str
    pid: int
    status: str
    user: str
    cmdline: str
    sha256: Optional[str] = None
    vt_score: Optional[int] = None
    vt_detection: Optional[str] = None
    suspicious: bool = False
    risk_factors: List[str] = None


@dataclass
class UserInfo:
    """User account information structure"""
    username: str
    uid: int
    gid: int
    home_dir: str
    shell: str
    created_date: Optional[datetime] = None
    last_login: Optional[datetime] = None
    is_new: bool = False
    is_suspicious: bool = False
    risk_factors: List[str] = None


@dataclass
class NetworkConnection:
    """Network connection information"""
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: int
    process_name: str
    suspicious: bool = False
    risk_factors: List[str] = None


@dataclass
class PersistenceItem:
    """Persistence mechanism information"""
    type: str  # systemd, cron, rc.local, etc.
    location: str
    command: str
    user: str
    created_date: Optional[datetime] = None
    suspicious: bool = False
    risk_factors: List[str] = None


class ThreatHunter:
    """Advanced threat hunting engine"""
    
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.vt_api_key = config_manager.get_api_key('virustotal')
        self.vt_cache = {}
        
        # Suspicious patterns
        self.suspicious_paths = [
            '/tmp/', '/var/tmp/', '/dev/shm/', '/home/*/.cache/',
            '/run/user/', '/proc/*/fd/', '/.', '/usr/share/.'
        ]
        
        self.suspicious_commands = [
            'nc', 'netcat', 'ncat', 'socat', 'wget', 'curl', 'python', 
            'python3', 'perl', 'ruby', 'bash', 'sh', 'powershell',
            'base64', 'xxd', 'openssl', 'gpg'
        ]
        
        self.lolbins = [
            'awk', 'sed', 'find', 'xargs', 'ssh', 'scp', 'rsync',
            'tar', 'zip', 'unzip', 'dd', 'mount', 'umount'
        ]
    
    async def full_scan(self, check_services=True, check_users=True, 
                       check_persistence=True, check_network=True, deep_scan=False) -> Dict[str, Any]:
        """Execute comprehensive threat hunting scan"""
        self.logger.info("Starting comprehensive threat hunt")
        scan_start = datetime.now()
        
        results = {
            'scan_info': {
                'start_time': scan_start,
                'scan_types': [],
                'deep_scan': deep_scan
            },
            'services': [],
            'users': [],
            'network': [],
            'persistence': [],
            'summary': {}
        }
        
        tasks = []
        
        if check_services:
            results['scan_info']['scan_types'].append('services')
            tasks.append(self._scan_services(deep_scan))
        
        if check_users:
            results['scan_info']['scan_types'].append('users')
            tasks.append(self._scan_users())
        
        if check_network:
            results['scan_info']['scan_types'].append('network')
            tasks.append(self._scan_network())
        
        if check_persistence:
            results['scan_info']['scan_types'].append('persistence')
            tasks.append(self._scan_persistence())
        
        # Execute all scans concurrently
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        scan_types = results['scan_info']['scan_types']
        for i, result in enumerate(scan_results):
            if isinstance(result, Exception):
                self.logger.error(f"Scan failed for {scan_types[i]}: {result}")
                continue
                
            scan_type = scan_types[i]
            results[scan_type] = result
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        results['scan_info']['end_time'] = datetime.now()
        results['scan_info']['duration'] = (results['scan_info']['end_time'] - scan_start).total_seconds()
        
        self.logger.info(f"Threat hunt completed in {results['scan_info']['duration']:.2f} seconds")
        return results
    
    async def _scan_services(self, deep_scan=False) -> List[ServiceInfo]:
        """Scan running services for threats"""
        self.logger.info("Scanning services...")
        services = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'status']):
            try:
                info = proc.info
                if not info['exe']:
                    continue
                
                service = ServiceInfo(
                    name=info['name'],
                    binary_path=info['exe'],
                    pid=info['pid'],
                    status=info['status'],
                    user=info['username'] or 'unknown',
                    cmdline=' '.join(info['cmdline'] or []),
                    risk_factors=[]
                )
                
                # Basic risk assessment
                self._assess_service_risk(service)
                
                # Deep scan with VirusTotal if enabled
                if deep_scan and self.vt_api_key:
                    await self._check_virustotal(service)
                
                services.append(service)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                continue
        
        return services
    
    def _assess_service_risk(self, service: ServiceInfo):
        """Assess service risk factors"""
        # Check for suspicious paths
        for sus_path in self.suspicious_paths:
            if sus_path.replace('*', '') in service.binary_path:
                service.risk_factors.append(f"Suspicious path: {service.binary_path}")
                service.suspicious = True
        
        # Check for suspicious command patterns
        cmdline_lower = service.cmdline.lower()
        for sus_cmd in self.suspicious_commands:
            if sus_cmd in cmdline_lower:
                service.risk_factors.append(f"Suspicious command: {sus_cmd}")
                service.suspicious = True
        
        # Check for base64 encoded commands
        if 'base64' in cmdline_lower or len([part for part in service.cmdline.split() if len(part) > 50 and part.isalnum()]) > 0:
            service.risk_factors.append("Possible base64 encoded command")
            service.suspicious = True
        
        # Check for network tools
        network_tools = ['nc', 'netcat', 'ncat', 'socat', 'wget', 'curl']
        for tool in network_tools:
            if tool in service.name.lower() or tool in cmdline_lower:
                service.risk_factors.append(f"Network tool detected: {tool}")
                service.suspicious = True
        
        # Check for unusual user context
        if service.user == 'root' and service.name not in ['systemd', 'kernel', 'init']:
            suspicious_root_processes = ['python', 'perl', 'ruby', 'bash', 'sh']
            if any(proc in service.name.lower() for proc in suspicious_root_processes):
                service.risk_factors.append("Suspicious process running as root")
                service.suspicious = True
    
    async def _check_virustotal(self, service: ServiceInfo):
        """Check service binary against VirusTotal"""
        try:
            # Calculate file hash
            if Path(service.binary_path).exists():
                service.sha256 = await self._calculate_file_hash(service.binary_path)
                
                # Check cache first
                if service.sha256 in self.vt_cache:
                    vt_data = self.vt_cache[service.sha256]
                else:
                    vt_data = await self._query_virustotal(service.sha256)
                    self.vt_cache[service.sha256] = vt_data
                
                if vt_data:
                    service.vt_score = vt_data.get('malicious', 0)
                    service.vt_detection = vt_data.get('detection_name')
                    
                    if service.vt_score > 0:
                        service.risk_factors.append(f"VirusTotal detections: {service.vt_score}")
                        service.suspicious = True
        
        except Exception as e:
            self.logger.warning(f"VirusTotal check failed for {service.binary_path}: {e}")
    
    async def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""
    
    async def _query_virustotal(self, file_hash: str) -> Optional[Dict]:
        """Query VirusTotal API for file analysis"""
        if not self.vt_api_key:
            return None
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data['data']['attributes']['last_analysis_stats']
                        return {
                            'malicious': stats.get('malicious', 0),
                            'suspicious': stats.get('suspicious', 0),
                            'total_vendors': sum(stats.values()),
                            'detection_name': self._get_detection_name(data)
                        }
                    elif response.status == 429:  # Rate limited
                        await asyncio.sleep(1)
                        return None
        except Exception as e:
            self.logger.warning(f"VirusTotal query failed: {e}")
        
        return None
    
    def _get_detection_name(self, vt_data: Dict) -> Optional[str]:
        """Extract detection name from VirusTotal response"""
        try:
            scans = vt_data['data']['attributes']['last_analysis_results']
            for vendor, result in scans.items():
                if result.get('category') == 'malicious':
                    return result.get('result')
        except:
            pass
        return None
    
    async def _scan_users(self) -> List[UserInfo]:
        """Scan user accounts for suspicious activity"""
        self.logger.info("Scanning user accounts...")
        users = []
        
        # Get all users
        for user in pwd.getpwall():
            user_info = UserInfo(
                username=user.pw_name,
                uid=user.pw_uid,
                gid=user.pw_gid,
                home_dir=user.pw_dir,
                shell=user.pw_shell,
                risk_factors=[]
            )
            
            # Skip system users (typically UID < 1000)
            if user_info.uid < 1000 and user_info.username not in ['root']:
                continue
            
            # Check for suspicious characteristics
            self._assess_user_risk(user_info)
            
            # Check if user is newly created
            await self._check_user_creation_date(user_info)
            
            users.append(user_info)
        
        return users
    
    def _assess_user_risk(self, user: UserInfo):
        """Assess user account risk factors"""
        # Check for suspicious shells
        suspicious_shells = ['/bin/bash', '/bin/sh', '/bin/zsh']
        if user.shell in suspicious_shells and user.uid > 1000:
            if user.username.startswith('.') or len(user.username) < 3:
                user.risk_factors.append("Suspicious username pattern")
                user.is_suspicious = True
        
        # Check for hidden home directories
        if user.home_dir.startswith('/.') or '/tmp/' in user.home_dir:
            user.risk_factors.append("Suspicious home directory")
            user.is_suspicious = True
        
        # Check for users with unusual UIDs
        if user.uid == 0 and user.username != 'root':
            user.risk_factors.append("UID 0 for non-root user")
            user.is_suspicious = True
    
    async def _check_user_creation_date(self, user: UserInfo):
        """Check when user account was created"""
        try:
            # Check /var/log/auth.log for user creation
            log_files = ['/var/log/auth.log', '/var/log/secure']
            
            for log_file in log_files:
                if Path(log_file).exists():
                    cmd = f"grep -i 'new user.*{user.username}' {log_file} | tail -1"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.stdout:
                        # Extract date from log entry
                        # This is a simplified approach
                        user.is_new = True
                        user.risk_factors.append("Recently created user account")
                        break
        
        except Exception:
            pass
    
    async def _scan_network(self) -> List[NetworkConnection]:
        """Scan network connections for suspicious activity"""
        self.logger.info("Scanning network connections...")
        connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED':
                continue
            
            try:
                process = psutil.Process(conn.pid) if conn.pid else None
                process_name = process.name() if process else 'unknown'
                
                connection = NetworkConnection(
                    local_addr=conn.laddr.ip,
                    local_port=conn.laddr.port,
                    remote_addr=conn.raddr.ip if conn.raddr else '',
                    remote_port=conn.raddr.port if conn.raddr else 0,
                    status=conn.status,
                    pid=conn.pid or 0,
                    process_name=process_name,
                    risk_factors=[]
                )
                
                # Assess connection risk
                self._assess_connection_risk(connection)
                connections.append(connection)
                
            except (psutil.NoSuchProcess, AttributeError):
                continue
        
        return connections
    
    def _assess_connection_risk(self, conn: NetworkConnection):
        """Assess network connection risk factors"""
        # Check for suspicious ports
        suspicious_ports = [4444, 4445, 1234, 9999, 8080, 443]
        if conn.remote_port in suspicious_ports:
            conn.risk_factors.append(f"Suspicious remote port: {conn.remote_port}")
            conn.suspicious = True
        
        # Check for connections to suspicious IPs (simplified check)
        if conn.remote_addr:
            # Private IP ranges that might be suspicious in certain contexts
            if conn.remote_addr.startswith(('192.168.', '10.', '172.')):
                if conn.remote_port in [22, 23, 3389, 4444]:
                    conn.risk_factors.append("Connection to private IP on suspicious port")
                    conn.suspicious = True
    
    async def _scan_persistence(self) -> List[PersistenceItem]:
        """Scan for persistence mechanisms"""
        self.logger.info("Scanning persistence mechanisms...")
        persistence_items = []
        
        # Check systemd services
        await self._check_systemd_services(persistence_items)
        
        # Check cron jobs
        await self._check_cron_jobs(persistence_items)
        
        # Check startup scripts
        await self._check_startup_scripts(persistence_items)
        
        return persistence_items
    
    async def _check_systemd_services(self, persistence_items: List[PersistenceItem]):
        """Check systemd services for suspicious entries"""
        try:
            result = subprocess.run(['systemctl', 'list-unit-files'], 
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if '.service' in line and 'enabled' in line:
                    service_name = line.split()[0]
                    
                    # Get service details
                    try:
                        show_result = subprocess.run(['systemctl', 'show', service_name], 
                                                   capture_output=True, text=True)
                        
                        exec_start = ''
                        for show_line in show_result.stdout.split('\n'):
                            if show_line.startswith('ExecStart='):
                                exec_start = show_line.split('=', 1)[1]
                                break
                        
                        item = PersistenceItem(
                            type='systemd',
                            location=f'/etc/systemd/system/{service_name}',
                            command=exec_start,
                            user='root',
                            risk_factors=[]
                        )
                        
                        self._assess_persistence_risk(item)
                        persistence_items.append(item)
                    
                    except subprocess.CalledProcessError:
                        continue
        
        except subprocess.CalledProcessError:
            pass
    
    async def _check_cron_jobs(self, persistence_items: List[PersistenceItem]):
        """Check cron jobs for suspicious entries"""
        cron_files = ['/etc/crontab', '/var/spool/cron/crontabs/root']
        cron_dirs = ['/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/', 
                     '/etc/cron.monthly/', '/etc/cron.weekly/']
        
        # Check cron files
        for cron_file in cron_files:
            if Path(cron_file).exists():
                try:
                    with open(cron_file, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()
                            if line and not line.startswith('#'):
                                item = PersistenceItem(
                                    type='cron',
                                    location=f'{cron_file}:{line_num}',
                                    command=line,
                                    user='root',
                                    risk_factors=[]
                                )
                                self._assess_persistence_risk(item)
                                persistence_items.append(item)
                except PermissionError:
                    continue
        
        # Check cron directories
        for cron_dir in cron_dirs:
            cron_path = Path(cron_dir)
            if cron_path.exists():
                for cron_script in cron_path.iterdir():
                    if cron_script.is_file():
                        item = PersistenceItem(
                            type='cron',
                            location=str(cron_script),
                            command=str(cron_script),
                            user='root',
                            risk_factors=[]
                        )
                        self._assess_persistence_risk(item)
                        persistence_items.append(item)
    
    async def _check_startup_scripts(self, persistence_items: List[PersistenceItem]):
        """Check startup scripts for suspicious entries"""
        startup_locations = [
            '/etc/rc.local',
            '/etc/init.d/',
            '/etc/rc?.d/'
        ]
        
        for location in startup_locations:
            path = Path(location)
            if path.is_file():
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                        item = PersistenceItem(
                            type='startup_script',
                            location=str(path),
                            command=content[:200] + '...' if len(content) > 200 else content,
                            user='root',
                            risk_factors=[]
                        )
                        self._assess_persistence_risk(item)
                        persistence_items.append(item)
                except PermissionError:
                    continue
    
    def _assess_persistence_risk(self, item: PersistenceItem):
        """Assess persistence mechanism risk factors"""
        command_lower = item.command.lower()
        
        # Check for suspicious commands
        for sus_cmd in self.suspicious_commands:
            if sus_cmd in command_lower:
                item.risk_factors.append(f"Suspicious command: {sus_cmd}")
                item.suspicious = True
        
        # Check for download/network operations
        if any(net_cmd in command_lower for net_cmd in ['wget', 'curl', 'nc', 'netcat']):
            item.risk_factors.append("Network operation in startup")
            item.suspicious = True
        
        # Check for hidden files/directories
        if '/.' in item.command or 'hidden' in command_lower:
            item.risk_factors.append("References hidden files")
            item.suspicious = True
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary statistics"""
        summary = {
            'total_services': len(results.get('services', [])),
            'suspicious_services': len([s for s in results.get('services', []) if s.suspicious]),
            'total_users': len(results.get('users', [])),
            'suspicious_users': len([u for u in results.get('users', []) if u.is_suspicious]),
            'new_users': len([u for u in results.get('users', []) if u.is_new]),
            'total_connections': len(results.get('network', [])),
            'suspicious_connections': len([c for c in results.get('network', []) if c.suspicious]),
            'total_persistence': len(results.get('persistence', [])),
            'suspicious_persistence': len([p for p in results.get('persistence', []) if p.suspicious]),
            'overall_risk': 'Low'
        }
        
        # Calculate overall risk level
        total_suspicious = (summary['suspicious_services'] + summary['suspicious_users'] + 
                          summary['suspicious_connections'] + summary['suspicious_persistence'])
        
        if total_suspicious == 0:
            summary['overall_risk'] = 'Low'
        elif total_suspicious <= 5:
            summary['overall_risk'] = 'Medium'
        else:
            summary['overall_risk'] = 'High'
        
        return summary
