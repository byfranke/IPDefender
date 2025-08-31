#!/usr/bin/env python3
"""
SecGuard Enterprise - Advanced Server Security & Threat Hunting Platform
========================================================================

A comprehensive security solution for Ubuntu servers combining:
- Advanced threat hunting with VirusTotal integration
- Intelligent IP ban management with CloudFlare support
- Automated scheduled security scans
- Professional reporting with email notifications
- Geolocation-based threat intelligence

⚠️  PROJECT ARCHIVED: This project has been discontinued in favor of IPDefender Pro v2.0.0
    Many concepts and features from SecGuard were evolved and integrated into IPDefender Pro.

Author: byFranke (https://byfranke.com)
Version: 1.0.0 (Archived)
License: MIT
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Import custom modules
sys.path.append(str(Path(__file__).parent / "modules"))

from config_manager import ConfigManager
from threat_hunter import ThreatHunter
from ip_defender import IPDefender
from scheduler import SecurityScheduler
from reporter import SecurityReporter
from setup_wizard import SetupWizard
from web_dashboard import SecGuardWebDashboard

VERSION = "1.0.0"
APP_NAME = "SecGuard Enterprise"
CONFIG_DIR = Path("/etc/secguard")
LOG_DIR = Path("/var/log/secguard")
DATA_DIR = Path("/var/lib/secguard")

class SecGuardCLI:
    """Main CLI interface for SecGuard Enterprise"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.logger = self._setup_logging()
        
        # Initialize modules
        self.threat_hunter = ThreatHunter(self.config_manager, self.logger)
        self.ip_defender = IPDefender(self.config_manager, self.logger)
        self.scheduler = SecurityScheduler(self.config_manager, self.logger)
        self.reporter = SecurityReporter(self.config_manager, self.logger)
        self.web_dashboard = SecGuardWebDashboard(
            self.config_manager, self.logger, self.threat_hunter,
            self.ip_defender, self.scheduler, self.reporter
        )
        
        # Set up cross-module dependencies
        self.ip_defender.set_reporter(self.reporter)
        
    def _setup_logging(self):
        """Configure logging system"""
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_DIR / 'secguard.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger('SecGuard')
    
    def _check_root(self):
        """Verify root privileges"""
        if os.geteuid() != 0:
            print("Error: SecGuard requires root privileges")
            print("Please run with: sudo secguard <command>")
            sys.exit(1)
    
    def _print_banner(self):
        """Display application banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    {APP_NAME} v{VERSION}                    ║
║              Advanced Server Security Platform                   ║
╠══════════════════════════════════════════════════════════════════╣
║  Threat Hunting      Professional Reports                       ║
║  IP Defense          Email Notifications                        ║
║  Scheduled Scans     Geo Intelligence                          ║
╚══════════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    async def setup(self):
        """Run initial setup wizard"""
        print("Starting SecGuard Enterprise Setup...")
        wizard = SetupWizard(self.config_manager, self.logger)
        await wizard.run()
    
    async def hunt(self, args):
        """Execute threat hunting scan"""
        print("Starting Threat Hunting Scan...")
        self.logger.info("Threat hunting scan initiated")
        
        try:
            scan_results = await self.threat_hunter.full_scan(
                check_services=args.services or args.all,
                check_users=args.users or args.all,
                check_persistence=args.persistence or args.all,
                check_network=args.network or args.all,
                deep_scan=args.deep
            )
            
            # Display summary
            self._display_scan_summary(scan_results)
            
            # Generate report
            if args.report:
                report_path = await self.reporter.generate_hunt_report(scan_results)
                print(f"Report saved: {report_path}")
                
                # Send email if configured
                if self.config_manager.get('email.enabled'):
                    await self.reporter.send_email_report(
                        report_path, 
                        "SecGuard Threat Hunt Report"
                    )
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Threat hunting scan failed: {e}")
            print(f"Error during threat hunt: {e}")
            return None
    
    def _display_scan_summary(self, scan_results):
        """Display scan results summary"""
        if not scan_results:
            return
            
        summary = scan_results.get('summary', {})
        print(f"\nScan Summary:")
        print(f"  Duration: {summary.get('duration', 0):.2f} seconds")
        print(f"  Services checked: {len(scan_results.get('services', []))}")
        print(f"  Users checked: {len(scan_results.get('users', []))}")
        print(f"  Network connections: {len(scan_results.get('network', []))}")
        print(f"  Persistence items: {len(scan_results.get('persistence', []))}")
        
        # Count suspicious items
        suspicious_services = sum(1 for s in scan_results.get('services', []) if s.get('suspicious', False))
        suspicious_users = sum(1 for u in scan_results.get('users', []) if u.get('is_suspicious', False))
        
        if suspicious_services > 0:
            print(f"  Suspicious services: {suspicious_services}")
        if suspicious_users > 0:
            print(f"  Suspicious users: {suspicious_users}")
        
        if summary.get('risk_level'):
            print(f"  Risk Level: {summary['risk_level']}")
        print()
    
    async def ban_ip(self, ip, reason=None):
        """Ban IP address with threat intelligence"""
        print(f"Analyzing and banning IP: {ip}")
        
        try:
            result = await self.ip_defender.ban_ip(ip, reason)
            
            if result['success']:
                print(f"Successfully banned {ip}")
                if result.get('threat_data'):
                    self._display_threat_info(result['threat_data'])
            else:
                print(f"Failed to ban {ip}: {result['error']}")
                
        except Exception as e:
            self.logger.error(f"IP ban operation failed: {e}")
            print(f"Error during IP ban: {e}")
    
    async def unban_ip(self, ip):
        """Remove IP ban"""
        print(f"Unbanning IP: {ip}")
        
        try:
            result = await self.ip_defender.unban_ip(ip)
            
            if result['success']:
                print(f"Successfully unbanned {ip}")
            else:
                print(f"Failed to unban {ip}: {result['error']}")
                
        except Exception as e:
            self.logger.error(f"IP unban operation failed: {e}")
            print(f"Error during IP unban: {e}")
    
    async def list_bans(self, format_type='table'):
        """List all banned IPs"""
        bans = await self.ip_defender.list_bans()
        
        if format_type == 'json':
            print(json.dumps(bans, indent=2, default=str))
        else:
            self._display_bans_table(bans)
    
    def _display_threat_info(self, threat_data):
        """Display threat intelligence information"""
        print("\nThreat Intelligence:")
        print(f"  Country: {threat_data.get('country', 'Unknown')}")
        print(f"  Risk Score: {threat_data.get('risk_score', 0)}/100")
        print(f"  Total Reports: {threat_data.get('total_reports', 0)}")
        if threat_data.get('isp'):
            print(f"  ISP: {threat_data['isp']}")
        print()
    
    def _display_bans_table(self, bans):
        """Display bans in table format"""
        if not bans:
            print("No banned IPs found.")
            return
        
        print("\nBanned IPs:")
        print("─" * 80)
        print(f"{'IP Address':<15} {'Country':<8} {'Score':<5} {'Date':<12} {'Reason':<20}")
        print("─" * 80)
        
        for ban in bans:
            date_str = ban.get('date', '')[:10] if ban.get('date') else 'Unknown'
            print(f"{ban['ip']:<15} {ban.get('country', 'Unknown'):<8} {ban.get('score', 0):<5} "
                  f"{date_str:<12} {ban.get('reason', '')[:20]:<20}")
    
    async def schedule_enable(self, scan_type, frequency):
        """Enable scheduled scanning"""
        print(f"Enabling scheduled {scan_type} scans ({frequency})")
        try:
            result = await self.scheduler.enable_schedule(scan_type, frequency)
            if result['success']:
                print("Schedule enabled successfully")
            else:
                print(f"Failed to enable schedule: {result.get('error', 'Unknown error')}")
        except Exception as e:
            print(f"Error enabling schedule: {e}")
    
    async def schedule_disable(self, scan_type):
        """Disable scheduled scanning"""
        print(f"Disabling scheduled {scan_type} scans")
        try:
            result = await self.scheduler.disable_schedule(scan_type)
            if result['success']:
                print("Schedule disabled successfully")
            else:
                print(f"Failed to disable schedule: {result.get('error', 'Unknown error')}")
        except Exception as e:
            print(f"Error disabling schedule: {e}")
    
    async def status(self):
        """Display system status"""
        self._print_banner()
        
        status_data = {
            'version': VERSION,
            'config_status': self.config_manager.is_configured(),
            'services': await self._get_service_status(),
            'schedules': await self.scheduler.get_status(),
            'recent_activity': await self._get_recent_activity()
        }
        
        self._display_status(status_data)
    
    async def start_dashboard(self, args):
        """Start web dashboard"""
        print("Starting SecGuard Enterprise Dashboard...")
        
        # Update configuration if provided
        if args.host != '127.0.0.1':
            self.config_manager.set('web_dashboard.host', args.host)
        if args.port != 8888:
            self.config_manager.set('web_dashboard.port', args.port)
        
        # Enable dashboard
        self.config_manager.set('web_dashboard.enabled', True)
        self.config_manager.save_config()
        
        # Start dashboard server
        result = await self.web_dashboard.start_server()
        
        if result['success']:
            print(f"Dashboard started successfully!")
            print(f"URL: {result['url']}")
            print(f"Access restricted to local IPs only")
            
            if result.get('firewall_configured'):
                print(f"Firewall rule configured for port {args.port}")
            
            # Open browser if requested
            if not args.no_browser:
                import webbrowser
                webbrowser.open(result['url'])
            
            print("\nPress Ctrl+C to stop the dashboard")
            
            # Keep running
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping dashboard...")
                await self.web_dashboard.stop_server()
                print("Dashboard stopped")
        else:
            print(f"Failed to start dashboard: {result.get('error', 'Unknown error')}")
            if 'aiohttp' in str(result.get('error', '')):
                print("Install required packages: pip install aiohttp aiohttp-cors")
    
    async def _get_service_status(self):
        """Get status of security services"""
        return {
            'ufw': await self._check_service('ufw'),
            'fail2ban': await self._check_service('fail2ban'),
            'cron': await self._check_service('cron')
        }
    
    async def _check_service(self, service_name):
        """Check if service is running"""
        try:
            process = await asyncio.create_subprocess_exec(
                'systemctl', 'is-active', service_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            return stdout.decode().strip() == 'active'
        except:
            return False
    
    async def _get_recent_activity(self):
        """Get recent security activity"""
        # This would query logs for recent bans, hunts, etc.
        return {
            'recent_bans': 0,
            'recent_hunts': 0,
            'last_hunt': None
        }
    
    def _display_status(self, status_data):
        """Display system status information"""
        print("\nSystem Status:")
        print("─" * 50)
        print(f"Configuration: {'Ready' if status_data['config_status'] else 'Not configured'}")
        
        print("\nServices:")
        for service, status in status_data['services'].items():
            status_text = "Active" if status else "Inactive"
            print(f"  {service.upper()}: {status_text}")
        
        print("\nScheduled Scans:")
        schedules = status_data.get('schedules', [])
        if schedules:
            for schedule in schedules:
                print(f"  {schedule['job_type']}: {'Enabled' if schedule['enabled'] else 'Disabled'} ({schedule.get('frequency', 'N/A')})")
        else:
            print("  No scheduled scans configured")
        
        print("\nRecent Activity:")
        print(f"  Recent Bans: {status_data['recent_activity']['recent_bans']}")
        print(f"  Recent Hunts: {status_data['recent_activity']['recent_hunts']}")
        if status_data['recent_activity']['last_hunt']:
            print(f"  Last Hunt: {status_data['recent_activity']['last_hunt']}")
        print()


def create_parser():
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - Advanced Server Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initial setup
  sudo secguard setup
  
  # Threat hunting
  sudo secguard hunt --deep --report
  sudo secguard hunt --services --users --persistence
  
  # IP management
  sudo secguard ban 192.168.1.100 "Suspicious activity"
  sudo secguard unban 192.168.1.100
  sudo secguard list-bans --format json
  
  # Scheduling
  sudo secguard schedule enable hunt weekly
  sudo secguard schedule disable hunt
  
  # System status
  sudo secguard status
"""
    )
    
    parser.add_argument('--version', action='version', version=f'{APP_NAME} v{VERSION}')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Run initial configuration wizard')
    
    # Hunt command
    hunt_parser = subparsers.add_parser('hunt', help='Execute threat hunting scan')
    hunt_parser.add_argument('--services', action='store_true', help='Check for suspicious services')
    hunt_parser.add_argument('--users', action='store_true', help='Check for new users')
    hunt_parser.add_argument('--persistence', action='store_true', help='Check for persistence mechanisms')
    hunt_parser.add_argument('--network', action='store_true', help='Check network connections')
    hunt_parser.add_argument('--deep', action='store_true', help='Perform deep scan with VirusTotal')
    hunt_parser.add_argument('--report', action='store_true', help='Generate detailed report')
    hunt_parser.add_argument('--all', action='store_true', help='Run all scan types')
    
    # Ban command
    ban_parser = subparsers.add_parser('ban', help='Ban IP address')
    ban_parser.add_argument('ip', help='IP address to ban')
    ban_parser.add_argument('reason', nargs='?', default='Manual ban', help='Reason for ban')
    
    # Unban command
    unban_parser = subparsers.add_parser('unban', help='Remove IP ban')
    unban_parser.add_argument('ip', help='IP address to unban')
    
    # List bans command
    list_parser = subparsers.add_parser('list-bans', help='List all banned IPs')
    list_parser.add_argument('--format', choices=['table', 'json'], default='table', help='Output format')
    
    # Schedule command
    schedule_parser = subparsers.add_parser('schedule', help='Manage scheduled scans')
    schedule_subparsers = schedule_parser.add_subparsers(dest='schedule_action')
    
    enable_parser = schedule_subparsers.add_parser('enable', help='Enable scheduled scan')
    enable_parser.add_argument('type', choices=['hunt'], help='Scan type to schedule')
    enable_parser.add_argument('frequency', choices=['daily', 'weekly', 'monthly'], help='Scan frequency')
    
    disable_parser = schedule_subparsers.add_parser('disable', help='Disable scheduled scan')
    disable_parser.add_argument('type', choices=['hunt'], help='Scan type to disable')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Display system status')
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    dashboard_parser.add_argument('--port', type=int, default=8888, help='Dashboard port')
    dashboard_parser.add_argument('--host', default='127.0.0.1', help='Dashboard host')
    dashboard_parser.add_argument('--no-browser', action='store_true', help='Don\'t open browser automatically')
    
    return parser


async def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cli = SecGuardCLI()
    
    # Most commands require root
    if args.command != 'setup':
        cli._check_root()
    
    try:
        if args.command == 'setup':
            await cli.setup()
        elif args.command == 'hunt':
            # Set all flags if --all is specified
            if args.all:
                args.services = args.users = args.persistence = args.network = args.deep = True
            await cli.hunt(args)
        elif args.command == 'ban':
            await cli.ban_ip(args.ip, args.reason)
        elif args.command == 'unban':
            await cli.unban_ip(args.ip)
        elif args.command == 'list-bans':
            await cli.list_bans(args.format)
        elif args.command == 'schedule':
            if args.schedule_action == 'enable':
                await cli.schedule_enable(args.type, args.frequency)
            elif args.schedule_action == 'disable':
                await cli.schedule_disable(args.type)
        elif args.command == 'status':
            await cli.status()
        elif args.command == 'dashboard':
            await cli.start_dashboard(args)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Ensure proper event loop for asyncio
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(1)
