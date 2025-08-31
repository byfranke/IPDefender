"""
Security Reporter Module for SecGuard Enterprise
==============================================

Professional reporting system with:
- HTML/PDF report generation
- Email notifications
- Webhook integrations (Discord, Slack, Teams)
- Wazuh SIEM integration
- Executive summaries
- Detailed technical findings
- Export capabilities
"""

import asyncio
import json
import logging
import smtplib
import ssl
import platform
import psutil
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import jinja2
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Run: pip install jinja2")
    raise

# Import SecGuard modules
from webhook_notifier import WebhookNotifier
from wazuh_logger import WazuhLogger


class SecurityReporter:
    """Advanced security reporting and notification system"""
    
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.reports_dir = Path(config_manager.get('paths.reports_dir'))
        self.templates_dir = Path(__file__).parent.parent / "templates"
        
        # Email configuration
        self.smtp_server = config_manager.get('email.smtp_server')
        self.smtp_port = config_manager.get('email.smtp_port', 587)
        self.use_tls = config_manager.get('email.use_tls', True)
        self.sender_email = config_manager.get('email.sender_email')
        self.recipient_emails = config_manager.get('email.recipient_emails', [])
        self.email_password = config_manager.get_email_password()
        
        # Initialize integrations
        self.webhook_notifier = WebhookNotifier(config_manager, logger)
        self.wazuh_logger = WazuhLogger(config_manager, logger)
        
        # Initialize reporting
        self._initialize_reporter()
    
    def _initialize_reporter(self):
        """Initialize reporter directories and templates"""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Create archive directory
        (self.reports_dir / "archive").mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.templates_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
    
    async def generate_hunt_report(self, scan_results: Dict[str, Any], 
                                 format_type: str = 'html') -> str:
        """Generate comprehensive threat hunting report"""
        timestamp = datetime.now()
        report_name = f"threat_hunt_report_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        # Prepare report data
        report_data = self._prepare_hunt_data(scan_results, timestamp)
        
        # Log scan summary to Wazuh
        self.wazuh_logger.log_scan_summary(scan_results)
        
        # Send webhook notifications for high-risk findings
        await self._send_threat_webhooks(scan_results)
        
        # Generate report based on format
        if format_type == 'html':
            report_path = await self._generate_html_report(report_data, report_name)
        elif format_type == 'json':
            report_path = await self._generate_json_report(report_data, report_name)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")
        
        self.logger.info(f"Generated threat hunt report: {report_path}")
        return str(report_path)
    
    async def generate_ban_report(self, ban_statistics: Dict[str, Any]) -> str:
        """Generate IP ban statistics report"""
        timestamp = datetime.now()
        report_name = f"ip_ban_report_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        # Prepare report data
        report_data = {
            'report_type': 'IP Ban Statistics',
            'generated_at': timestamp,
            'statistics': ban_statistics,
            'config_info': self._get_system_info()
        }
        
        report_path = await self._generate_html_report(report_data, report_name, 'ban_report.html')
        self.logger.info(f"Generated IP ban report: {report_path}")
        return str(report_path)
    
    def _prepare_hunt_data(self, scan_results: Dict[str, Any], timestamp: datetime) -> Dict[str, Any]:
        """Prepare threat hunting data for reporting"""
        return {
            'report_type': 'Threat Hunting Report',
            'generated_at': timestamp,
            'scan_info': scan_results.get('scan_info', {}),
            'summary': scan_results.get('summary', {}),
            'findings': {
                'services': self._process_service_findings(scan_results.get('services', [])),
                'users': self._process_user_findings(scan_results.get('users', [])),
                'network': self._process_network_findings(scan_results.get('network', [])),
                'persistence': self._process_persistence_findings(scan_results.get('persistence', []))
            },
            'recommendations': self._generate_recommendations(scan_results),
            'system_info': self._get_system_info()
        }
    
    def _process_service_findings(self, services: List) -> Dict[str, Any]:
        """Process service findings for reporting"""
        if not services:
            return {'total': 0, 'suspicious': [], 'clean': 0}
        
        suspicious_services = [s for s in services if getattr(s, 'suspicious', False)]
        
        return {
            'total': len(services),
            'suspicious': [
                {
                    'name': s.name,
                    'path': s.binary_path,
                    'user': s.user,
                    'risk_factors': s.risk_factors or [],
                    'vt_score': getattr(s, 'vt_score', None),
                    'vt_detection': getattr(s, 'vt_detection', None)
                } for s in suspicious_services
            ],
            'clean': len(services) - len(suspicious_services),
            'vt_scanned': len([s for s in services if hasattr(s, 'sha256') and s.sha256])
        }
    
    def _process_user_findings(self, users: List) -> Dict[str, Any]:
        """Process user findings for reporting"""
        if not users:
            return {'total': 0, 'suspicious': [], 'new': []}
        
        suspicious_users = [u for u in users if getattr(u, 'is_suspicious', False)]
        new_users = [u for u in users if getattr(u, 'is_new', False)]
        
        return {
            'total': len(users),
            'suspicious': [
                {
                    'username': u.username,
                    'uid': u.uid,
                    'home_dir': u.home_dir,
                    'shell': u.shell,
                    'risk_factors': u.risk_factors or []
                } for u in suspicious_users
            ],
            'new': [
                {
                    'username': u.username,
                    'uid': u.uid,
                    'created_date': getattr(u, 'created_date', None),
                    'risk_factors': u.risk_factors or []
                } for u in new_users
            ]
        }
    
    def _process_network_findings(self, connections: List) -> Dict[str, Any]:
        """Process network findings for reporting"""
        if not connections:
            return {'total': 0, 'suspicious': []}
        
        suspicious_connections = [c for c in connections if getattr(c, 'suspicious', False)]
        
        return {
            'total': len(connections),
            'suspicious': [
                {
                    'local_addr': c.local_addr,
                    'local_port': c.local_port,
                    'remote_addr': c.remote_addr,
                    'remote_port': c.remote_port,
                    'process_name': c.process_name,
                    'risk_factors': c.risk_factors or []
                } for c in suspicious_connections
            ]
        }
    
    def _process_persistence_findings(self, persistence_items: List) -> Dict[str, Any]:
        """Process persistence findings for reporting"""
        if not persistence_items:
            return {'total': 0, 'suspicious': []}
        
        suspicious_items = [p for p in persistence_items if getattr(p, 'suspicious', False)]
        
        return {
            'total': len(persistence_items),
            'suspicious': [
                {
                    'type': p.type,
                    'location': p.location,
                    'command': p.command[:200] + '...' if len(p.command) > 200 else p.command,
                    'user': p.user,
                    'risk_factors': p.risk_factors or []
                } for p in suspicious_items
            ]
        }
    
    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        summary = scan_results.get('summary', {})
        
        # Service recommendations
        if summary.get('suspicious_services', 0) > 0:
            recommendations.append(
                " Review suspicious services and consider quarantining unknown binaries"
            )
            recommendations.append(
                " Implement application whitelisting for critical systems"
            )
        
        # User recommendations
        if summary.get('new_users', 0) > 0:
            recommendations.append(
                "👥 Verify legitimacy of newly created user accounts"
            )
            recommendations.append(
                "🔐 Implement strong password policies and MFA"
            )
        
        if summary.get('suspicious_users', 0) > 0:
            recommendations.append(
                " Investigate suspicious user accounts immediately"
            )
        
        # Network recommendations
        if summary.get('suspicious_connections', 0) > 0:
            recommendations.append(
                "🌐 Monitor network traffic and implement egress filtering"
            )
            recommendations.append(
                "🔥 Review firewall rules and close unnecessary ports"
            )
        
        # Persistence recommendations
        if summary.get('suspicious_persistence', 0) > 0:
            recommendations.append(
                " Review and validate all startup scripts and scheduled tasks"
            )
            recommendations.append(
                "🔒 Implement file integrity monitoring on system directories"
            )
        
        # General recommendations
        if summary.get('overall_risk') in ['Medium', 'High']:
            recommendations.append(
                " Increase monitoring frequency and implement real-time alerting"
            )
            recommendations.append(
                "🚨 Consider isolating affected systems for forensic analysis"
            )
        
        if not recommendations:
            recommendations.append(" No immediate security concerns detected")
            recommendations.append("🔄 Continue regular security monitoring")
        
        return recommendations
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for reports"""
        try:
            import platform
            import psutil
            
            return {
                'hostname': platform.node(),
                'os': f"{platform.system()} {platform.release()}",
                'architecture': platform.machine(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                'disk_usage': {
                    path: {
                        'total_gb': round(psutil.disk_usage(path).total / (1024**3), 2),
                        'used_percent': round((psutil.disk_usage(path).used / 
                                           psutil.disk_usage(path).total) * 100, 1)
                    } for path in ['/']
                }
            }
        except Exception as e:
            self.logger.warning(f"Failed to gather system info: {e}")
            return {'error': 'System info unavailable'}
    
    async def _generate_html_report(self, report_data: Dict[str, Any], 
                                  report_name: str, template_name: str = 'hunt_report.html') -> Path:
        """Generate HTML report using Jinja2 template"""
        try:
            template = self.jinja_env.get_template(template_name)
            html_content = template.render(**report_data)
            
            report_path = self.reports_dir / f"{report_name}.html"
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return report_path
        
        except jinja2.TemplateNotFound:
            # Fallback to basic HTML generation
            return await self._generate_basic_html_report(report_data, report_name)
    
    async def _generate_basic_html_report(self, report_data: Dict[str, Any], 
                                        report_name: str) -> Path:
        """Generate basic HTML report without template"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{report_data['report_type']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
        .suspicious {{ border-color: #e74c3c; background: #fdf2f2; }}
        .clean {{ border-color: #27ae60; background: #f2fdf2; }}
        .recommendation {{ background: #fff3cd; padding: 10px; margin: 5px 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report_data['report_type']}</h1>
        <p>Generated: {report_data['generated_at'].strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Risk Level:</strong> {report_data.get('summary', {}).get('overall_risk', 'Unknown')}</p>
        <ul>
            <li>Services Scanned: {report_data.get('summary', {}).get('total_services', 0)}</li>
            <li>Suspicious Services: {report_data.get('summary', {}).get('suspicious_services', 0)}</li>
            <li>Users Analyzed: {report_data.get('summary', {}).get('total_users', 0)}</li>
            <li>New Users: {report_data.get('summary', {}).get('new_users', 0)}</li>
        </ul>
    </div>
    
    <div class="finding">
        <h2>Detailed Findings</h2>
        <h3>Suspicious Services</h3>
        {self._generate_services_html(report_data.get('findings', {}).get('services', {}))}
        
        <h3>User Accounts</h3>
        {self._generate_users_html(report_data.get('findings', {}).get('users', {}))}
    </div>
    
    <div class="finding">
        <h2>Recommendations</h2>
        {''.join(f'<div class="recommendation">{rec}</div>' for rec in report_data.get('recommendations', []))}
    </div>
</body>
</html>
"""
        
        report_path = self.reports_dir / f"{report_name}.html"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    def _generate_services_html(self, services_data: Dict) -> str:
        """Generate HTML for services section"""
        if not services_data.get('suspicious'):
            return "<p>No suspicious services detected.</p>"
        
        html = "<table><tr><th>Service</th><th>Path</th><th>User</th><th>Risk Factors</th></tr>"
        
        for service in services_data['suspicious']:
            risk_factors = ', '.join(service.get('risk_factors', []))
            html += f"<tr><td>{service['name']}</td><td>{service['path']}</td><td>{service['user']}</td><td>{risk_factors}</td></tr>"
        
        html += "</table>"
        return html
    
    def _generate_users_html(self, users_data: Dict) -> str:
        """Generate HTML for users section"""
        html = ""
        
        if users_data.get('suspicious'):
            html += "<h4>Suspicious Users</h4><table><tr><th>Username</th><th>UID</th><th>Home</th><th>Risk Factors</th></tr>"
            for user in users_data['suspicious']:
                risk_factors = ', '.join(user.get('risk_factors', []))
                html += f"<tr><td>{user['username']}</td><td>{user['uid']}</td><td>{user['home_dir']}</td><td>{risk_factors}</td></tr>"
            html += "</table>"
        
        if users_data.get('new'):
            html += "<h4>New Users</h4><table><tr><th>Username</th><th>UID</th><th>Created</th></tr>"
            for user in users_data['new']:
                created = user.get('created_date', 'Unknown')
                html += f"<tr><td>{user['username']}</td><td>{user['uid']}</td><td>{created}</td></tr>"
            html += "</table>"
        
        return html if html else "<p>No user account issues detected.</p>"
    
    async def _generate_json_report(self, report_data: Dict[str, Any], report_name: str) -> Path:
        """Generate JSON report"""
        # Convert datetime objects to strings for JSON serialization
        json_data = self._serialize_for_json(report_data)
        
        report_path = self.reports_dir / f"{report_name}.json"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        return report_path
    
    def _serialize_for_json(self, data):
        """Convert data types for JSON serialization"""
        if isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, dict):
            return {k: self._serialize_for_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._serialize_for_json(item) for item in data]
        else:
            return data
    
    async def send_email_report(self, report_path: str, subject: str, 
                              body: str = None) -> Dict[str, Any]:
        """Send report via email"""
        if not self.config.get('email.enabled'):
            return {"success": False, "error": "Email not configured"}
        
        if not self.recipient_emails:
            return {"success": False, "error": "No recipient emails configured"}
        
        try:
            # Create message
            message = MIMEMultipart()
            message["From"] = self.sender_email
            message["To"] = ", ".join(self.recipient_emails)
            message["Subject"] = subject
            
            # Add body
            if not body:
                body = f"Please find attached the security report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."
            
            message.attach(MIMEText(body, "plain"))
            
            # Add attachment
            report_file = Path(report_path)
            if report_file.exists():
                with open(report_file, "rb") as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {report_file.name}'
                )
                message.attach(part)
            
            # Send email
            await self._send_smtp_email(message)
            
            self.logger.info(f"Email report sent to {len(self.recipient_emails)} recipients")
            return {"success": True, "recipients": len(self.recipient_emails)}
        
        except Exception as e:
            self.logger.error(f"Failed to send email report: {e}")
            return {"success": False, "error": str(e)}
    
    async def _send_smtp_email(self, message):
        """Send email via SMTP"""
        context = ssl.create_default_context()
        
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            if self.use_tls:
                server.starttls(context=context)
            
            if self.email_password:
                server.login(self.sender_email, self.email_password)
            
            server.sendmail(
                self.sender_email,
                self.recipient_emails,
                message.as_string()
            )
    
    async def send_notification(self, subject: str, message: str, 
                              priority: str = "normal") -> Dict[str, Any]:
        """Send notification email without attachment"""
        if not self.config.get('email.enabled'):
            return {"success": False, "error": "Email not configured"}
        
        try:
            msg = MIMEMultipart()
            msg["From"] = self.sender_email
            msg["To"] = ", ".join(self.recipient_emails)
            msg["Subject"] = f"[SecGuard {priority.upper()}] {subject}"
            
            # Add priority header
            if priority.lower() == "high":
                msg["X-Priority"] = "1"
                msg["X-MSMail-Priority"] = "High"
            
            msg.attach(MIMEText(message, "plain"))
            
            await self._send_smtp_email(msg)
            
            return {"success": True, "message": "Notification sent"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def archive_old_reports(self, days_old: int = 30) -> Dict[str, Any]:
        """Archive old reports"""
        cutoff_date = datetime.now() - timedelta(days=days_old)
        archive_dir = self.reports_dir / "archive"
        archive_dir.mkdir(exist_ok=True)
        
        archived_count = 0
        
        for report_file in self.reports_dir.glob("*_report_*.html"):
            try:
                file_stat = report_file.stat()
                file_date = datetime.fromtimestamp(file_stat.st_mtime)
                
                if file_date < cutoff_date:
                    archive_path = archive_dir / report_file.name
                    report_file.rename(archive_path)
                    archived_count += 1
            
            except Exception as e:
                self.logger.warning(f"Failed to archive {report_file}: {e}")
        
        return {
            "success": True,
            "archived_count": archived_count
        }
    
    async def _send_threat_webhooks(self, scan_results: Dict[str, Any]):
        """Send webhook notifications for threat findings"""
        summary = scan_results.get('summary', {})
        
        # Check if there are high-risk findings
        high_risk_findings = (
            summary.get('suspicious_services', 0) > 0 or
            summary.get('suspicious_users', 0) > 0 or
            summary.get('suspicious_connections', 0) > 0 or
            summary.get('suspicious_persistence', 0) > 0
        )
        
        if not high_risk_findings:
            return
        
        # Prepare threat alert data
        threat_data = {
            'severity': summary.get('overall_risk_level', 'medium').lower(),
            'threat_type': 'Multiple threats detected',
            'description': self._generate_threat_summary(summary),
            'hostname': scan_results.get('scan_info', {}).get('hostname', 'Unknown'),
            'detection_method': 'SecGuard threat hunting',
            'suspicious_services': summary.get('suspicious_services', 0),
            'suspicious_users': summary.get('suspicious_users', 0),
            'suspicious_connections': summary.get('suspicious_connections', 0),
            'suspicious_persistence': summary.get('suspicious_persistence', 0),
            'scan_duration': scan_results.get('scan_info', {}).get('duration', 0)
        }
        
        # Send webhook notifications
        try:
            result = await self.webhook_notifier.send_threat_alert(threat_data)
            if result['success']:
                self.logger.info("Threat webhook notifications sent successfully")
            else:
                self.logger.warning(f"Webhook notification failed: {result.get('error')}")
        except Exception as e:
            self.logger.error(f"Failed to send threat webhooks: {e}")
    
    def _generate_threat_summary(self, summary: Dict[str, Any]) -> str:
        """Generate threat summary for webhook notifications"""
        findings = []
        
        if summary.get('suspicious_services', 0) > 0:
            findings.append(f"{summary['suspicious_services']} suspicious services")
        
        if summary.get('suspicious_users', 0) > 0:
            findings.append(f"{summary['suspicious_users']} suspicious users")
        
        if summary.get('suspicious_connections', 0) > 0:
            findings.append(f"{summary['suspicious_connections']} suspicious connections")
        
        if summary.get('suspicious_persistence', 0) > 0:
            findings.append(f"{summary['suspicious_persistence']} persistence mechanisms")
        
        return f"Security scan detected: {', '.join(findings)}"
    
    async def send_ip_ban_webhook(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send IP ban notification via webhook"""
        try:
            result = await self.webhook_notifier.send_ip_ban_alert(ip_data)
            if result['success']:
                self.logger.info(f"IP ban webhook sent for {ip_data.get('ip')}")
            return result
        except Exception as e:
            self.logger.error(f"Failed to send IP ban webhook: {e}")
            return {"success": False, "error": str(e)}
    
    async def send_custom_webhook(self, title: str, message: str, 
                                severity: str = "info") -> Dict[str, Any]:
        """Send custom webhook notification"""
        try:
            result = await self.webhook_notifier.send_custom_alert(title, message, severity)
            if result['success']:
                self.logger.info("Custom webhook notification sent")
            return result
        except Exception as e:
            self.logger.error(f"Failed to send custom webhook: {e}")
            return {"success": False, "error": str(e)}
    
    async def test_webhooks(self) -> Dict[str, Any]:
        """Test all configured webhooks"""
        if not hasattr(self.webhook_notifier, 'webhooks') or not self.webhook_notifier.webhooks:
            return {"success": False, "error": "No webhooks configured"}
        
        results = []
        
        for webhook in self.webhook_notifier.webhooks:
            try:
                result = await self.webhook_notifier.test_webhook(webhook.name)
                results.append({
                    "webhook": webhook.name,
                    "success": result["success"],
                    "error": result.get("error")
                })
            except Exception as e:
                results.append({
                    "webhook": webhook.name,
                    "success": False,
                    "error": str(e)
                })
        
        return {
            "success": any(r["success"] for r in results),
            "results": results
        }
    
    def log_threat_to_wazuh(self, threat_data: Dict[str, Any]):
        """Log threat data to Wazuh"""
        self.wazuh_logger.log_threat_detection(threat_data)
    
    def log_ip_ban_to_wazuh(self, ip_data: Dict[str, Any]):
        """Log IP ban to Wazuh"""
        self.wazuh_logger.log_ip_ban(ip_data)
    
    def log_user_discovery_to_wazuh(self, user_data: Dict[str, Any]):
        """Log user discovery to Wazuh"""
        self.wazuh_logger.log_user_discovery(user_data)
    
    async def cleanup_integrations(self):
        """Cleanup integration resources"""
        try:
            await self.webhook_notifier.close()
        except Exception as e:
            self.logger.warning(f"Failed to cleanup webhook notifier: {e}")
