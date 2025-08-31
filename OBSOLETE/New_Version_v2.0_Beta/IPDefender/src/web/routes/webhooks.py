from flask import Blueprint, request, jsonify
from src.api.cloudflare import cf_block, cf_unblock
from src.api.wazuh import get_wazuh_alerts
from src.core.ip_manager import add_ip_record
from src.utils.logger import logger

webhook_bp = Blueprint('webhook', __name__)

@webhook_bp.route('/webhook/otx', methods=['POST'])
def otx_webhook():
    data = request.json
    if not data or 'ip' not in data:
        return jsonify({'error': 'Invalid data'}), 400

    ip = data['ip']
    status, response = cf_block(ip)
    if status == 200:
        add_ip_record(ip)
        return jsonify({'status': 'blocked', 'ip': ip}), 200
    return jsonify({'status': 'error', 'response': response}), status

@webhook_bp.route('/webhook/misp', methods=['POST'])
def misp_webhook():
    data = request.json
    if not data or 'ip' not in data:
        return jsonify({'error': 'Invalid data'}), 400

    ip = data['ip']
    status, response = cf_block(ip)
    if status == 200:
        add_ip_record(ip)
        return jsonify({'status': 'blocked', 'ip': ip}), 200
    return jsonify({'status': 'error', 'response': response}), status

@webhook_bp.route('/webhook/wazuh', methods=['POST'])
def wazuh_webhook():
    data = request.json
    alerts = get_wazuh_alerts()
    for alert in alerts:
        ip = alert.get('ip')
        if ip:
            status, response = cf_block(ip)
            if status == 200:
                add_ip_record(ip)
    return jsonify({'status': 'processed', 'alerts': len(alerts)}), 200