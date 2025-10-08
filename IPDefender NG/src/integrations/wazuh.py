"""
IPDefender Pro - Wazuh SIEM Integration
Advanced integration with Wazuh for automated threat response

Author: byFranke (https://byfranke.com)
"""

import asyncio
import aiohttp
import logging
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import base64

logger = logging.getLogger(__name__)

@dataclass
class WazuhAlert:
    """Wazuh alert structure"""
    id: str
    timestamp: datetime
    rule_id: str
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    decoder: str
    location: str
    data: Dict[str, Any]

@dataclass
class WazuhRule:
    """Wazuh rule configuration"""
    rule_id: str
    description: str
    level: int
    groups: List[str]
    pci_dss: List[str]
    gdpr: List[str]

class WazuhIntegration:
    """Wazuh SIEM integration for IPDefender Pro"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config.get('url', 'https://localhost:55000').rstrip('/')
        self.username = config.get('username', 'wazuh')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl', True)
        
        self.session = None
        self.token = None
        self.token_expires = None
        
        # IPDefender specific rules
        self.ipdefender_rules = self._get_ipdefender_rules()
        
    async def initialize(self) -> bool:
        """Initialize connection to Wazuh"""
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            )
            
            success = await self._authenticate()
            if success:
                logger.info("Successfully connected to Wazuh SIEM")
                return True
            else:
                logger.error("Failed to authenticate with Wazuh")
                return False
                
        except Exception as e:
            logger.error(f"Failed to initialize Wazuh connection: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup connections"""
        if self.session:
            await self.session.close()
    
    async def _authenticate(self) -> bool:
        """Authenticate with Wazuh API"""
        auth_url = f"{self.base_url}/security/user/authenticate"
        
        # Create basic auth header
        credentials = f"{self.username}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json'
        }
        
        try:
            async with self.session.post(auth_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    self.token = data['data']['token']
                    
                    # Set token expiration (Wazuh tokens typically expire in 15 minutes)
                    self.token_expires = datetime.now() + timedelta(minutes=14)  # Refresh 1 min early
                    
                    # Update session headers
                    self.session.headers.update({
                        'Authorization': f'Bearer {self.token}',
                        'Content-Type': 'application/json'
                    })
                    
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Wazuh authentication failed: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Wazuh authentication error: {e}")
            return False
    
    async def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid authentication token"""
        if not self.token or (self.token_expires and datetime.now() >= self.token_expires):
            return await self._authenticate()
        return True
    
    async def get_alerts(self, 
                        hours: int = 24,
                        rule_ids: List[str] = None,
                        level_min: int = None,
                        source_ip: str = None,
                        limit: int = 1000) -> List[WazuhAlert]:
        """Retrieve alerts from Wazuh"""
        if not await self._ensure_authenticated():
            return []
        
        alerts_url = f"{self.base_url}/alerts"
        
        # Build query parameters
        params = {
            'limit': limit,
            'sort': '-timestamp',
            'q': []
        }
        
        # Time filter
        time_filter = datetime.now() - timedelta(hours=hours)
        params['q'].append(f'timestamp>={time_filter.strftime("%Y-%m-%dT%H:%M:%S")}')
        
        # Rule ID filter
        if rule_ids:
            rule_filter = ','.join(rule_ids)
            params['q'].append(f'rule.id=({rule_filter})')
        
        # Level filter
        if level_min:
            params['q'].append(f'rule.level>={level_min}')
        
        # Source IP filter
        if source_ip:
            params['q'].append(f'data.srcip={source_ip}')
        
        # Join all query parts
        if params['q']:
            params['q'] = ';'.join(params['q'])
        else:
            del params['q']
        
        try:
            async with self.session.get(alerts_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    alerts = []
                    
                    for alert_data in data.get('data', {}).get('affected_items', []):
                        alert = self._parse_alert(alert_data)
                        if alert:
                            alerts.append(alert)
                    
                    logger.info(f"Retrieved {len(alerts)} alerts from Wazuh")
                    return alerts
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to get alerts: {response.status} - {error_text}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving Wazuh alerts: {e}")
            return []
    
    def _parse_alert(self, alert_data: Dict[str, Any]) -> Optional[WazuhAlert]:
        """Parse Wazuh alert data"""
        try:
            # Extract source IP from various possible locations
            source_ip = None
            data = alert_data.get('data', {})
            
            # Try different common fields for source IP
            for field in ['srcip', 'src_ip', 'source_ip', 'remote_addr']:
                if field in data and data[field]:
                    source_ip = data[field]
                    break
            
            # Try syscheck data
            if not source_ip and 'syscheck' in data:
                syscheck = data['syscheck']
                if 'path' in syscheck and 'srcip' in syscheck['path']:
                    source_ip = syscheck['srcip']
            
            return WazuhAlert(
                id=alert_data.get('id', ''),
                timestamp=datetime.fromisoformat(alert_data.get('timestamp', '').replace('Z', '+00:00')),
                rule_id=alert_data.get('rule', {}).get('id', ''),
                rule_level=alert_data.get('rule', {}).get('level', 0),
                rule_description=alert_data.get('rule', {}).get('description', ''),
                agent_id=alert_data.get('agent', {}).get('id', ''),
                agent_name=alert_data.get('agent', {}).get('name', ''),
                source_ip=source_ip,
                destination_ip=data.get('dstip'),
                decoder=alert_data.get('decoder', {}).get('name', ''),
                location=alert_data.get('location', ''),
                data=data
            )
            
        except Exception as e:
            logger.error(f"Failed to parse Wazuh alert: {e}")
            return None
    
    async def create_active_response(self, 
                                   agent_id: str,
                                   command: str,
                                   arguments: List[str] = None) -> bool:
        """Trigger active response on Wazuh agent"""
        if not await self._ensure_authenticated():
            return False
        
        ar_url = f"{self.base_url}/active-response"
        
        payload = {
            'command': command,
            'arguments': arguments or [],
            'alert': {
                'data': {
                    'timestamp': datetime.now().isoformat(),
                    'rule': {
                        'id': '999999',
                        'level': 12,
                        'description': 'IPDefender Pro automated response'
                    }
                },
                'agent': {'id': agent_id}
            }
        }
        
        try:
            async with self.session.post(ar_url, json=payload) as response:
                if response.status == 200:
                    logger.info(f"Active response triggered: {command} on agent {agent_id}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Active response failed: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error triggering active response: {e}")
            return False
    
    async def block_ip_on_agent(self, agent_id: str, ip: str, duration: int = 0) -> bool:
        """Block IP on specific Wazuh agent using active response"""
        # Standard Wazuh active response commands for firewall blocking
        command = 'firewall-drop'
        arguments = [ip]
        
        if duration > 0:
            # For temporary blocks, include duration
            arguments.append(str(duration))
            command = 'firewall-drop-temp'
        
        return await self.create_active_response(agent_id, command, arguments)
    
    async def unblock_ip_on_agent(self, agent_id: str, ip: str) -> bool:
        """Unblock IP on specific Wazuh agent"""
        command = 'firewall-allow'
        arguments = [ip]
        
        return await self.create_active_response(agent_id, command, arguments)
    
    async def get_agents(self) -> List[Dict[str, Any]]:
        """Get list of Wazuh agents"""
        if not await self._ensure_authenticated():
            return []
        
        agents_url = f"{self.base_url}/agents"
        
        try:
            async with self.session.get(agents_url) as response:
                if response.status == 200:
                    data = await response.json()
                    agents = data.get('data', {}).get('affected_items', [])
                    logger.info(f"Retrieved {len(agents)} Wazuh agents")
                    return agents
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to get agents: {response.status} - {error_text}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving Wazuh agents: {e}")
            return []
    
    async def submit_custom_alert(self, 
                                 agent_id: str,
                                 rule_id: str,
                                 description: str,
                                 data: Dict[str, Any] = None) -> bool:
        """Submit custom alert to Wazuh"""
        if not await self._ensure_authenticated():
            return False
        
        # Wazuh doesn't have a direct endpoint for custom alerts
        # We'll use the events endpoint to inject custom events
        events_url = f"{self.base_url}/events"
        
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'agent': {'id': agent_id},
            'rule': {
                'id': rule_id,
                'description': description,
                'level': 10,  # Default level for IPDefender events
                'groups': ['ipdefender', 'threat_intel']
            },
            'data': data or {},
            'decoder': {'name': 'ipdefender'},
            'location': 'ipdefender-pro'
        }
        
        try:
            async with self.session.post(events_url, json=event_data) as response:
                if response.status in [200, 201]:
                    logger.info(f"Custom alert submitted: {rule_id}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to submit custom alert: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error submitting custom alert: {e}")
            return False
    
    async def create_ipdefender_rules(self) -> bool:
        """Create custom Wazuh rules for IPDefender Pro"""
        if not await self._ensure_authenticated():
            return False
        
        rules_url = f"{self.base_url}/rules"
        
        for rule in self.ipdefender_rules:
            try:
                # Check if rule already exists
                existing_rules = await self._get_rules_by_id(rule['id'])
                if existing_rules:
                    logger.info(f"Rule {rule['id']} already exists")
                    continue
                
                # Create new rule
                async with self.session.post(rules_url, json=rule) as response:
                    if response.status in [200, 201]:
                        logger.info(f"Created Wazuh rule: {rule['id']}")
                    else:
                        error_text = await response.text()
                        logger.warning(f"Failed to create rule {rule['id']}: {response.status} - {error_text}")
                        
            except Exception as e:
                logger.error(f"Error creating rule {rule['id']}: {e}")
        
        return True
    
    async def _get_rules_by_id(self, rule_id: str) -> List[Dict]:
        """Get Wazuh rules by ID"""
        rules_url = f"{self.base_url}/rules"
        params = {'rule_ids': rule_id}
        
        try:
            async with self.session.get(rules_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {}).get('affected_items', [])
        except Exception:
            pass
        
        return []
    
    def _get_ipdefender_rules(self) -> List[Dict[str, Any]]:
        """Get IPDefender-specific Wazuh rules"""
        return [
            {
                'id': '999900',
                'level': 12,
                'description': 'IPDefender Pro: Critical threat detected',
                'groups': ['ipdefender', 'threat_intel'],
                'rule': '<rule id="999900" level="12"><if_sid>1002</if_sid><regex>IPDefender.*CRITICAL</regex><description>IPDefender Pro: Critical threat detected</description><group>ipdefender,threat_intel</group></rule>'
            },
            {
                'id': '999901',
                'level': 10,
                'description': 'IPDefender Pro: High threat detected',
                'groups': ['ipdefender', 'threat_intel'],
                'rule': '<rule id="999901" level="10"><if_sid>1002</if_sid><regex>IPDefender.*HIGH</regex><description>IPDefender Pro: High threat detected</description><group>ipdefender,threat_intel</group></rule>'
            },
            {
                'id': '999902',
                'level': 7,
                'description': 'IPDefender Pro: Medium threat detected',
                'groups': ['ipdefender', 'threat_intel'],
                'rule': '<rule id="999902" level="7"><if_sid>1002</if_sid><regex>IPDefender.*MEDIUM</regex><description>IPDefender Pro: Medium threat detected</description><group>ipdefender,threat_intel</group></rule>'
            },
            {
                'id': '999903',
                'level': 12,
                'description': 'IPDefender Pro: Automated IP block',
                'groups': ['ipdefender', 'response'],
                'rule': '<rule id="999903" level="12"><if_sid>1002</if_sid><regex>IPDefender.*BLOCKED</regex><description>IPDefender Pro: Automated IP block</description><group>ipdefender,response</group></rule>'
            },
            {
                'id': '999904',
                'level': 5,
                'description': 'IPDefender Pro: Threat intelligence update',
                'groups': ['ipdefender', 'intel'],
                'rule': '<rule id="999904" level="5"><if_sid>1002</if_sid><regex>IPDefender.*INTEL</regex><description>IPDefender Pro: Threat intelligence update</description><group>ipdefender,intel</group></rule>'
            }
        ]
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get Wazuh system status"""
        if not await self._ensure_authenticated():
            return {'status': 'disconnected'}
        
        status_url = f"{self.base_url}/cluster/status"
        
        try:
            async with self.session.get(status_url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'status': 'connected',
                        'cluster': data.get('data', {}),
                        'token_expires': self.token_expires.isoformat() if self.token_expires else None
                    }
                else:
                    return {'status': 'error', 'code': response.status}
                    
        except Exception as e:
            logger.error(f"Error getting Wazuh status: {e}")
            return {'status': 'error', 'message': str(e)}
    
    async def send_threat_intelligence(self, ip: str, threat_data: Dict[str, Any]) -> bool:
        """Send threat intelligence data to Wazuh"""
        # Find agents to send the intelligence to
        agents = await self.get_agents()
        
        if not agents:
            logger.warning("No Wazuh agents found for threat intelligence distribution")
            return False
        
        success_count = 0
        
        for agent in agents:
            agent_id = agent.get('id')
            if agent_id == '000':  # Skip manager
                continue
            
            # Create custom alert for this threat intelligence
            alert_data = {
                'srcip': ip,
                'threat_score': threat_data.get('threat_score', 0),
                'threat_level': threat_data.get('threat_level', 'UNKNOWN'),
                'sources': threat_data.get('sources_responded', 0),
                'recommendation': threat_data.get('recommendation', ''),
                'ipdefender_action': 'THREAT_INTEL_UPDATE'
            }
            
            success = await self.submit_custom_alert(
                agent_id=agent_id,
                rule_id='999904',
                description=f'IPDefender Pro threat intel update for {ip}',
                data=alert_data
            )
            
            if success:
                success_count += 1
        
        logger.info(f"Sent threat intelligence for {ip} to {success_count}/{len(agents)-1} agents")
        return success_count > 0
