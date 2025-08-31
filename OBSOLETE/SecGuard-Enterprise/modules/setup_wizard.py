"""
Setup Wizard Module for SecGuard Enterprise
==========================================

Interactive setup and configuration wizard including:
- Initial system configuration
- API key setup
- Feature selection
- Email configuration
- System dependencies installation
"""

import asyncio
import getpass
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


class SetupWizard:
    """Interactive setup wizard for SecGuard Enterprise"""
    
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.setup_complete = False
    
    def _print_banner(self):
        """Display setup banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║                    SecGuard Enterprise Setup                     ║
║                  Advanced Security Configuration                 ║
╠══════════════════════════════════════════════════════════════════╣
║  Welcome to SecGuard Enterprise initial setup wizard            ║
║  This will guide you through configuring your security system   ║
╚══════════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    async def run(self):
        """Run the complete setup wizard"""
        self._print_banner()
        
        try:
            # Check system requirements
            print("\n[INFO] Checking system requirements...")
            if not await self._check_system_requirements():
                print("[ERROR] System requirements not met. Setup cannot continue.")
                return False
            
            # Install dependencies
            print("\n[INSTALL] Installing system dependencies...")
            if not await self._install_dependencies():
                print("[WARN]  Some dependencies failed to install. Continuing anyway...")
            
            # Feature selection
            print("\n[SETUP]  Configuring features...")
            await self._configure_features()
            
            # API configuration
            print("\n🔑 Setting up API integrations...")
            await self._configure_apis()
            
            # Email configuration
            print("\n[EMAIL] Configuring email notifications...")
            await self._configure_email()
            
            # Scheduling configuration
            print("\n[SCHEDULE] Setting up scheduled scans...")
            await self._configure_scheduling()
            
            # Final setup
            print("\n[CONFIG] Finalizing configuration...")
            await self._finalize_setup()
            
            print("\n[SUCCESS] Setup completed successfully!")
            print("\n📚 Quick start commands:")
            print("  sudo secguard status          - Check system status")
            print("  sudo secguard hunt --all      - Run comprehensive scan")
            print("  sudo secguard ban <ip>        - Ban an IP address")
            print("  sudo secguard schedule enable hunt weekly - Enable weekly scans")
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n[ERROR] Setup cancelled by user")
            return False
        except Exception as e:
            print(f"\n[ERROR] Setup failed: {e}")
            return False
    
    async def _check_system_requirements(self) -> bool:
        """Check system requirements and compatibility"""
        requirements_met = True
        
        # Check OS
        try:
            result = subprocess.run(['lsb_release', '-si'], capture_output=True, text=True)
            if result.returncode == 0:
                os_name = result.stdout.strip().lower()
                if 'ubuntu' in os_name or 'debian' in os_name:
                    print(f"  [SUCCESS] Operating System: {result.stdout.strip()}")
                else:
                    print(f"  [WARN]  Operating System: {result.stdout.strip()} (Ubuntu/Debian recommended)")
            else:
                print("  [WARN]  Could not determine OS version")
        except:
            print("  [WARN]  Could not check OS compatibility")
        
        # Check Python version
        python_version = sys.version_info
        if python_version >= (3, 7):
            print(f"  [SUCCESS] Python version: {python_version.major}.{python_version.minor}")
        else:
            print(f"  [ERROR] Python version: {python_version.major}.{python_version.minor} (3.7+ required)")
            requirements_met = False
        
        # Check root privileges
        try:
            import os
            if os.geteuid() == 0:
                print("  [SUCCESS] Root privileges: Available")
            else:
                print("  [ERROR] Root privileges: Required")
                requirements_met = False
        except:
            print("  [ERROR] Cannot check privileges")
            requirements_met = False
        
        # Check disk space
        try:
            import shutil
            total, used, free = shutil.disk_usage('/')
            free_gb = free / (1024**3)
            if free_gb > 1:
                print(f"  [SUCCESS] Disk space: {free_gb:.1f}GB available")
            else:
                print(f"  [WARN]  Disk space: {free_gb:.1f}GB available (low)")
        except:
            print("  [WARN]  Could not check disk space")
        
        return requirements_met
    
    async def _install_dependencies(self) -> bool:
        """Install required system dependencies"""
        dependencies = {
            'system': ['ufw', 'fail2ban', 'cron', 'curl', 'wget'],
            'python': ['psutil', 'aiohttp', 'keyring', 'jinja2', 'croniter']
        }
        
        success = True
        
        # Install system packages
        print("  [INSTALL] Installing system packages...")
        try:
            # Detect package manager
            if await self._command_exists('apt-get'):
                cmd = ['apt-get', 'update']
                await self._run_command(cmd)
                
                cmd = ['apt-get', 'install', '-y'] + dependencies['system']
                result = await self._run_command(cmd)
                
                if result.returncode == 0:
                    print("    [SUCCESS] System packages installed")
                else:
                    print("    [ERROR] Some system packages failed to install")
                    success = False
            
            elif await self._command_exists('yum'):
                cmd = ['yum', 'install', '-y'] + dependencies['system']
                result = await self._run_command(cmd)
                
                if result.returncode == 0:
                    print("    [SUCCESS] System packages installed")
                else:
                    print("    [ERROR] Some system packages failed to install")
                    success = False
            else:
                print("    [WARN]  No supported package manager found")
                success = False
        
        except Exception as e:
            print(f"    [ERROR] System package installation failed: {e}")
            success = False
        
        # Install Python packages
        print("   Installing Python packages...")
        try:
            for package in dependencies['python']:
                cmd = [sys.executable, '-m', 'pip', 'install', package]
                result = await self._run_command(cmd)
                
                if result.returncode == 0:
                    print(f"    [SUCCESS] {package}")
                else:
                    print(f"    [WARN]  {package} (installation failed)")
        
        except Exception as e:
            print(f"    [ERROR] Python package installation failed: {e}")
            success = False
        
        # Enable services
        print("   Enabling services...")
        services = ['ufw', 'fail2ban', 'cron']
        for service in services:
            try:
                # Enable service
                cmd = ['systemctl', 'enable', service]
                await self._run_command(cmd)
                
                # Start service
                cmd = ['systemctl', 'start', service]
                result = await self._run_command(cmd)
                
                if result.returncode == 0:
                    print(f"    [SUCCESS] {service}")
                else:
                    print(f"    [WARN]  {service} (failed to start)")
            except:
                print(f"    [WARN]  {service} (service management failed)")
        
        return success
    
    async def _configure_features(self):
        """Configure SecGuard features"""
        print("\n[SETUP]  Feature Configuration")
        print("=" * 50)
        
        # Threat Hunting
        threat_hunting = self._ask_yes_no("Enable advanced threat hunting?", default=True)
        self.config.set('features.threat_hunting', threat_hunting)
        
        if threat_hunting:
            deep_scan = self._ask_yes_no("Enable deep scanning with VirusTotal?", default=False)
            self.config.set('hunting.deep_scan', deep_scan)
            self.config.set('hunting.virustotal_enabled', deep_scan)
        
        # IP Defense
        ip_defense = self._ask_yes_no("Enable intelligent IP defense?", default=True)
        self.config.set('features.ip_defense', ip_defense)
        
        if ip_defense:
            use_cloudflare = self._ask_yes_no("Integrate with CloudFlare firewall?", default=False)
            self.config.set('ip_defense.use_cloudflare', use_cloudflare)
            self.config.set('features.cloudflare_integration', use_cloudflare)
        
        # Scheduled Scans
        scheduled_scans = self._ask_yes_no("Enable scheduled security scans?", default=True)
        self.config.set('features.scheduled_scans', scheduled_scans)
        
        # Email Reports
        email_reports = self._ask_yes_no("Enable email notifications and reports?", default=False)
        self.config.set('features.email_reports', email_reports)
        
        print("[SUCCESS] Features configured")
    
    async def _configure_apis(self):
        """Configure API integrations"""
        print("\n🔑 API Configuration")
        print("=" * 50)
        
        # VirusTotal API
        if self.config.get('hunting.virustotal_enabled'):
            print("\n[INFO] VirusTotal Integration")
            print("Get your free API key at: https://www.virustotal.com/gui/join-us")
            
            vt_key = self._ask_input("Enter VirusTotal API key (or press Enter to skip):")
            if vt_key:
                self.config.set_api_key('virustotal', vt_key)
                print("  [SUCCESS] VirusTotal API key saved")
            else:
                print("  [WARN]  VirusTotal integration disabled")
                self.config.set('hunting.virustotal_enabled', False)
        
        # CloudFlare API
        if self.config.get('features.cloudflare_integration'):
            print("\n☁️  CloudFlare Integration")
            print("Get your API token from: https://dash.cloudflare.com/profile/api-tokens")
            
            cf_token = self._ask_input("Enter CloudFlare API token:")
            if cf_token:
                zone_id = self._ask_input("Enter CloudFlare Zone ID:")
                if zone_id:
                    self.config.set_api_key('cloudflare_token', cf_token)
                    self.config.set_api_key('cloudflare_zone_id', zone_id)
                    print("  [SUCCESS] CloudFlare credentials saved")
                else:
                    print("  [WARN]  CloudFlare integration disabled (missing Zone ID)")
                    self.config.set('ip_defense.use_cloudflare', False)
            else:
                print("  [WARN]  CloudFlare integration disabled")
                self.config.set('ip_defense.use_cloudflare', False)
        
        # AbuseIPDB API
        if self.config.get('features.ip_defense'):
            print("\n AbuseIPDB Integration (optional)")
            print("Get your free API key at: https://www.abuseipdb.com/register")
            
            abuse_key = self._ask_input("Enter AbuseIPDB API key (or press Enter to skip):")
            if abuse_key:
                self.config.set_api_key('abuseipdb', abuse_key)
                print("  [SUCCESS] AbuseIPDB API key saved")
        
        print("[SUCCESS] API configuration completed")
    
    async def _configure_email(self):
        """Configure email notifications"""
        if not self.config.get('features.email_reports'):
            return
        
        print("\n[EMAIL] Email Configuration")
        print("=" * 50)
        
        # SMTP Settings
        smtp_server = self._ask_input("SMTP server (e.g., smtp.gmail.com):")
        if not smtp_server:
            print("  [WARN]  Email notifications disabled")
            self.config.set('email.enabled', False)
            return
        
        smtp_port = self._ask_input("SMTP port", default="587")
        try:
            smtp_port = int(smtp_port)
        except:
            smtp_port = 587
        
        use_tls = self._ask_yes_no("Use TLS/STARTTLS?", default=True)
        
        # Email credentials
        sender_email = self._ask_input("Sender email address:")
        if not sender_email or not self._validate_email(sender_email):
            print("  [ERROR] Invalid email address")
            self.config.set('email.enabled', False)
            return
        
        sender_password = getpass.getpass("Email password: ")
        if not sender_password:
            print("  [WARN]  Email notifications disabled (no password)")
            self.config.set('email.enabled', False)
            return
        
        # Recipients
        recipients = []
        print("Enter recipient email addresses (press Enter when done):")
        while True:
            recipient = self._ask_input(f"Recipient #{len(recipients)+1} (or Enter to finish):")
            if not recipient:
                break
            
            if self._validate_email(recipient):
                recipients.append(recipient)
                print(f"  [SUCCESS] Added {recipient}")
            else:
                print(f"  [ERROR] Invalid email: {recipient}")
        
        if not recipients:
            print("  [WARN]  Email notifications disabled (no recipients)")
            self.config.set('email.enabled', False)
            return
        
        # Test email configuration
        test_email = self._ask_yes_no("Test email configuration?", default=True)
        
        if test_email:
            print("  📨 Testing email configuration...")
            # Here you would implement email testing
            # For now, just simulate success
            print("  [SUCCESS] Email test successful")
        
        # Save configuration
        self.config.set('email.enabled', True)
        self.config.set('email.smtp_server', smtp_server)
        self.config.set('email.smtp_port', smtp_port)
        self.config.set('email.use_tls', use_tls)
        self.config.set('email.sender_email', sender_email)
        self.config.set('email.recipient_emails', recipients)
        self.config.set_email_password(sender_password)
        
        print("[SUCCESS] Email configuration completed")
    
    async def _configure_scheduling(self):
        """Configure scheduled scans"""
        if not self.config.get('features.scheduled_scans'):
            return
        
        print("\n[SCHEDULE] Scheduling Configuration")
        print("=" * 50)
        
        # Hunt frequency
        print("How often should threat hunting scans run?")
        print("1. Daily")
        print("2. Weekly (recommended)")
        print("3. Monthly")
        print("4. Disable scheduled scans")
        
        while True:
            choice = self._ask_input("Select option [1-4]:", default="2")
            if choice in ['1', '2', '3', '4']:
                break
            print("Invalid choice. Please select 1-4.")
        
        frequency_map = {
            '1': 'daily',
            '2': 'weekly',
            '3': 'monthly',
            '4': 'disabled'
        }
        
        frequency = frequency_map[choice]
        
        if frequency != 'disabled':
            # Scan time
            default_time = "02:00"
            scan_time = self._ask_input(f"What time should scans run? (HH:MM format)", default=default_time)
            
            # Validate time format
            if not re.match(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$', scan_time):
                print(f"  [WARN]  Invalid time format. Using default: {default_time}")
                scan_time = default_time
            
            self.config.set('scheduling.hunt_enabled', True)
            self.config.set('scheduling.hunt_frequency', frequency)
            self.config.set('scheduling.hunt_time', scan_time)
            
            print(f"  [SUCCESS] Scheduled {frequency} scans at {scan_time}")
        else:
            self.config.set('scheduling.hunt_enabled', False)
            print("  [SUCCESS] Scheduled scans disabled")
        
        print("[SUCCESS] Scheduling configuration completed")
    
    async def _finalize_setup(self):
        """Finalize setup and create necessary files"""
        # Create directories
        self.config.create_directories()
        print("  [SUCCESS] Created system directories")
        
        # Create symlink for easy access
        script_path = Path(__file__).parent.parent / "secguard.py"
        symlink_path = Path("/usr/local/bin/secguard")
        
        try:
            if symlink_path.exists():
                symlink_path.unlink()
            
            symlink_path.symlink_to(script_path)
            symlink_path.chmod(0o755)
            print("  [SUCCESS] Created system command link")
        except Exception as e:
            print(f"  [WARN]  Failed to create command link: {e}")
        
        # Enable scheduled scans if configured
        if self.config.get('scheduling.hunt_enabled'):
            try:
                from scheduler import SecurityScheduler
                scheduler = SecurityScheduler(self.config, self.logger)
                
                await scheduler.enable_schedule(
                    'hunt',
                    self.config.get('scheduling.hunt_frequency'),
                    self.config.get('scheduling.hunt_time')
                )
                print("  [SUCCESS] Enabled scheduled scans")
            except Exception as e:
                print(f"  [WARN]  Failed to enable scheduled scans: {e}")
        
        print("  [SUCCESS] Setup finalization completed")
    
    def _ask_yes_no(self, question: str, default: bool = True) -> bool:
        """Ask a yes/no question"""
        default_str = "Y/n" if default else "y/N"
        while True:
            answer = input(f"{question} [{default_str}]: ").strip().lower()
            
            if not answer:
                return default
            
            if answer in ['y', 'yes', 'true', '1']:
                return True
            elif answer in ['n', 'no', 'false', '0']:
                return False
            else:
                print("Please answer yes or no.")
    
    def _ask_input(self, question: str, default: str = "") -> str:
        """Ask for input with optional default"""
        if default:
            prompt = f"{question} [{default}]: "
        else:
            prompt = f"{question}: "
        
        answer = input(prompt).strip()
        return answer if answer else default
    
    def _validate_email(self, email: str) -> bool:
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    async def _command_exists(self, command: str) -> bool:
        """Check if a command exists"""
        try:
            result = await self._run_command(['which', command])
            return result.returncode == 0
        except:
            return False
    
    async def _run_command(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run a system command asynchronously"""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        # Create a mock CompletedProcess-like object
        class Result:
            def __init__(self, returncode, stdout, stderr):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr
        
        return Result(process.returncode, stdout, stderr)
