"""
Webhook Integration Module for SecGuard Enterprise
===============================================

Supports webhooks for various platforms:
- Discord
- Slack  
- Microsoft Teams
- Generic webhook endpoints
- Custom webhook formats
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

try:
    import aiohttp
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Run: pip install aiohttp")
    raise


@dataclass
class WebhookConfig:
    """Webhook configuration structure"""
    name: str
    url: str
    webhook_type: str  # discord, slack, teams, generic
    enabled: bool = True
    format_template: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    retry_attempts: int = 3
    timeout: int = 30


class WebhookNotifier:
    """Advanced webhook notification system"""
    
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.session = None
        self.webhooks = []
        self._load_webhooks()
    
    def _load_webhooks(self):
        """Load webhook configurations"""
        webhook_configs = self.config.get('webhooks.configurations', [])
        
        for config in webhook_configs:
            webhook = WebhookConfig(
                name=config.get('name', 'Unnamed'),
                url=config.get('url', ''),
                webhook_type=config.get('type', 'generic'),
                enabled=config.get('enabled', True),
                format_template=config.get('format_template'),
                headers=config.get('headers', {}),
                retry_attempts=config.get('retry_attempts', 3),
                timeout=config.get('timeout', 30)
            )
            self.webhooks.append(webhook)
    
    async def _get_session(self):
        """Get or create aiohttp session"""
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def send_threat_alert(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send threat detection alert via webhooks"""
        if not self.webhooks:
            return {"success": False, "error": "No webhooks configured"}
        
        results = []
        
        for webhook in self.webhooks:
            if not webhook.enabled:
                continue
            
            try:
                payload = self._format_threat_alert(threat_data, webhook)
                result = await self._send_webhook(webhook, payload)
                results.append({
                    "webhook": webhook.name,
                    "success": result["success"],
                    "error": result.get("error")
                })
                
            except Exception as e:
                self.logger.error(f"Failed to send webhook to {webhook.name}: {e}")
                results.append({
                    "webhook": webhook.name,
                    "success": False,
                    "error": str(e)
                })
        
        return {
            "success": any(r["success"] for r in results),
            "results": results
        }
    
    async def send_ip_ban_alert(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send IP ban alert via webhooks"""
        if not self.webhooks:
            return {"success": False, "error": "No webhooks configured"}
        
        results = []
        
        for webhook in self.webhooks:
            if not webhook.enabled:
                continue
            
            try:
                payload = self._format_ip_ban_alert(ip_data, webhook)
                result = await self._send_webhook(webhook, payload)
                results.append({
                    "webhook": webhook.name,
                    "success": result["success"],
                    "error": result.get("error")
                })
                
            except Exception as e:
                self.logger.error(f"Failed to send webhook to {webhook.name}: {e}")
                results.append({
                    "webhook": webhook.name,
                    "success": False,
                    "error": str(e)
                })
        
        return {
            "success": any(r["success"] for r in results),
            "results": results
        }
    
    async def send_custom_alert(self, title: str, message: str, 
                              severity: str = "info") -> Dict[str, Any]:
        """Send custom alert via webhooks"""
        alert_data = {
            "title": title,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "source": "SecGuard Enterprise"
        }
        
        results = []
        
        for webhook in self.webhooks:
            if not webhook.enabled:
                continue
            
            try:
                payload = self._format_custom_alert(alert_data, webhook)
                result = await self._send_webhook(webhook, payload)
                results.append({
                    "webhook": webhook.name,
                    "success": result["success"],
                    "error": result.get("error")
                })
                
            except Exception as e:
                self.logger.error(f"Failed to send webhook to {webhook.name}: {e}")
                results.append({
                    "webhook": webhook.name,
                    "success": False,
                    "error": str(e)
                })
        
        return {
            "success": any(r["success"] for r in results),
            "results": results
        }
    
    def _format_threat_alert(self, threat_data: Dict[str, Any], webhook: WebhookConfig) -> Dict[str, Any]:
        """Format threat alert for specific webhook type"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if webhook.webhook_type == "discord":
            return {
                "embeds": [{
                    "title": "🚨 Threat Detection Alert",
                    "color": 0xFF0000,  # Red
                    "timestamp": datetime.now().isoformat(),
                    "fields": [
                        {
                            "name": "Severity",
                            "value": threat_data.get("severity", "Unknown"),
                            "inline": True
                        },
                        {
                            "name": "Threat Type",
                            "value": threat_data.get("threat_type", "Unknown"),
                            "inline": True
                        },
                        {
                            "name": "Details",
                            "value": threat_data.get("description", "No details available"),
                            "inline": False
                        },
                        {
                            "name": "Host",
                            "value": threat_data.get("hostname", "Unknown"),
                            "inline": True
                        }
                    ],
                    "footer": {
                        "text": "SecGuard Enterprise"
                    }
                }]
            }
        
        elif webhook.webhook_type == "slack":
            severity_colors = {
                "critical": "#FF0000",
                "high": "#FF8800", 
                "medium": "#FFAA00",
                "low": "#00AA00",
                "info": "#0088FF"
            }
            
            return {
                "attachments": [{
                    "color": severity_colors.get(threat_data.get("severity", "info").lower(), "#808080"),
                    "title": "Threat Detection Alert",
                    "text": threat_data.get("description", "No details available"),
                    "fields": [
                        {
                            "title": "Severity",
                            "value": threat_data.get("severity", "Unknown"),
                            "short": True
                        },
                        {
                            "title": "Threat Type",
                            "value": threat_data.get("threat_type", "Unknown"),
                            "short": True
                        },
                        {
                            "title": "Host",
                            "value": threat_data.get("hostname", "Unknown"),
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": timestamp,
                            "short": True
                        }
                    ],
                    "footer": "SecGuard Enterprise",
                    "ts": int(datetime.now().timestamp())
                }]
            }
        
        elif webhook.webhook_type == "teams":
            return {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "FF0000",
                "summary": "SecGuard Threat Alert",
                "sections": [{
                    "activityTitle": "Threat Detection Alert",
                    "activitySubtitle": f"Severity: {threat_data.get('severity', 'Unknown')}",
                    "facts": [
                        {
                            "name": "Threat Type",
                            "value": threat_data.get("threat_type", "Unknown")
                        },
                        {
                            "name": "Host",
                            "value": threat_data.get("hostname", "Unknown")
                        },
                        {
                            "name": "Timestamp",
                            "value": timestamp
                        }
                    ],
                    "text": threat_data.get("description", "No details available")
                }]
            }
        
        else:  # Generic webhook
            return {
                "alert_type": "threat_detection",
                "severity": threat_data.get("severity", "Unknown"),
                "threat_type": threat_data.get("threat_type", "Unknown"),
                "description": threat_data.get("description", "No details available"),
                "hostname": threat_data.get("hostname", "Unknown"),
                "timestamp": timestamp,
                "source": "SecGuard Enterprise",
                "data": threat_data
            }
    
    def _format_ip_ban_alert(self, ip_data: Dict[str, Any], webhook: WebhookConfig) -> Dict[str, Any]:
        """Format IP ban alert for specific webhook type"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if webhook.webhook_type == "discord":
            return {
                "embeds": [{
                    "title": "🚫 IP Address Banned",
                    "color": 0xFFA500,  # Orange
                    "timestamp": datetime.now().isoformat(),
                    "fields": [
                        {
                            "name": "IP Address",
                            "value": ip_data.get("ip", "Unknown"),
                            "inline": True
                        },
                        {
                            "name": "Country",
                            "value": ip_data.get("country", "Unknown"),
                            "inline": True
                        },
                        {
                            "name": "Reason",
                            "value": ip_data.get("reason", "No reason provided"),
                            "inline": False
                        },
                        {
                            "name": "Risk Score",
                            "value": f"{ip_data.get('score', 0)}/100",
                            "inline": True
                        }
                    ],
                    "footer": {
                        "text": "SecGuard Enterprise"
                    }
                }]
            }
        
        elif webhook.webhook_type == "slack":
            return {
                "attachments": [{
                    "color": "#FFA500",
                    "title": "IP Address Banned",
                    "text": f"IP {ip_data.get('ip', 'Unknown')} has been banned",
                    "fields": [
                        {
                            "title": "IP Address",
                            "value": ip_data.get("ip", "Unknown"),
                            "short": True
                        },
                        {
                            "title": "Country", 
                            "value": ip_data.get("country", "Unknown"),
                            "short": True
                        },
                        {
                            "title": "Risk Score",
                            "value": f"{ip_data.get('score', 0)}/100",
                            "short": True
                        },
                        {
                            "title": "Reason",
                            "value": ip_data.get("reason", "No reason provided"),
                            "short": False
                        }
                    ],
                    "footer": "SecGuard Enterprise",
                    "ts": int(datetime.now().timestamp())
                }]
            }
        
        else:  # Generic webhook
            return {
                "alert_type": "ip_ban",
                "ip_address": ip_data.get("ip", "Unknown"),
                "country": ip_data.get("country", "Unknown"),
                "risk_score": ip_data.get("score", 0),
                "reason": ip_data.get("reason", "No reason provided"),
                "timestamp": timestamp,
                "source": "SecGuard Enterprise",
                "data": ip_data
            }
    
    def _format_custom_alert(self, alert_data: Dict[str, Any], webhook: WebhookConfig) -> Dict[str, Any]:
        """Format custom alert for specific webhook type"""
        if webhook.webhook_type == "discord":
            severity_colors = {
                "critical": 0xFF0000,
                "high": 0xFF8800,
                "medium": 0xFFAA00, 
                "low": 0x00AA00,
                "info": 0x0088FF
            }
            
            return {
                "embeds": [{
                    "title": alert_data["title"],
                    "description": alert_data["message"],
                    "color": severity_colors.get(alert_data["severity"].lower(), 0x808080),
                    "timestamp": alert_data["timestamp"],
                    "footer": {
                        "text": alert_data["source"]
                    }
                }]
            }
        
        elif webhook.webhook_type == "slack":
            severity_colors = {
                "critical": "#FF0000",
                "high": "#FF8800",
                "medium": "#FFAA00",
                "low": "#00AA00", 
                "info": "#0088FF"
            }
            
            return {
                "attachments": [{
                    "color": severity_colors.get(alert_data["severity"].lower(), "#808080"),
                    "title": alert_data["title"],
                    "text": alert_data["message"],
                    "footer": alert_data["source"],
                    "ts": int(datetime.fromisoformat(alert_data["timestamp"].replace('Z', '+00:00')).timestamp())
                }]
            }
        
        else:  # Generic webhook
            return alert_data
    
    async def _send_webhook(self, webhook: WebhookConfig, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send webhook with retry logic"""
        session = await self._get_session()
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SecGuard Enterprise/1.0"
        }
        
        if webhook.headers:
            headers.update(webhook.headers)
        
        for attempt in range(webhook.retry_attempts):
            try:
                async with session.post(
                    webhook.url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=webhook.timeout)
                ) as response:
                    
                    if response.status < 400:
                        return {
                            "success": True,
                            "status_code": response.status,
                            "attempt": attempt + 1
                        }
                    else:
                        error_text = await response.text()
                        if attempt == webhook.retry_attempts - 1:  # Last attempt
                            return {
                                "success": False,
                                "error": f"HTTP {response.status}: {error_text}",
                                "status_code": response.status
                            }
                        
                        # Wait before retry
                        await asyncio.sleep(2 ** attempt)
            
            except asyncio.TimeoutError:
                if attempt == webhook.retry_attempts - 1:
                    return {
                        "success": False,
                        "error": "Request timeout"
                    }
                await asyncio.sleep(2 ** attempt)
            
            except Exception as e:
                if attempt == webhook.retry_attempts - 1:
                    return {
                        "success": False,
                        "error": str(e)
                    }
                await asyncio.sleep(2 ** attempt)
        
        return {"success": False, "error": "Max retries exceeded"}
    
    async def test_webhook(self, webhook_name: str) -> Dict[str, Any]:
        """Test a specific webhook"""
        webhook = next((w for w in self.webhooks if w.name == webhook_name), None)
        
        if not webhook:
            return {"success": False, "error": "Webhook not found"}
        
        test_data = {
            "title": "SecGuard Test Alert",
            "message": "This is a test message from SecGuard Enterprise",
            "severity": "info",
            "timestamp": datetime.now().isoformat(),
            "source": "SecGuard Enterprise"
        }
        
        payload = self._format_custom_alert(test_data, webhook)
        return await self._send_webhook(webhook, payload)
    
    async def close(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
