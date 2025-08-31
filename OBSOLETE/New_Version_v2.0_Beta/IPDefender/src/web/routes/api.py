from flask import Blueprint, request, jsonify
from src.api.cloudflare import cf_block, cf_unblock
from src.api.otx import fetch_threats as fetch_otx_threats
from src.api.misp import fetch_threats as fetch_misp_threats
from src.api.wazuh import fetch_wazuh_alerts
from src.core.ip_manager import add_ip, remove_ip

api_bp = Blueprint('api', __name__)

@api_bp.route('/block_ip', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    status, response = cf_block(ip)
    if status == 200:
        add_ip(ip)  # Add IP to local management
        return jsonify({"status": "success", "response": response}), 200
    return jsonify({"status": "error", "response": response}), status

@api_bp.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    status, response = cf_unblock(ip)
    if status == 200:
        remove_ip(ip)  # Remove IP from local management
        return jsonify({"status": "success", "response": response}), 200
    return jsonify({"status": "error", "response": response}), status

@api_bp.route('/fetch_otx_threats', methods=['GET'])
def fetch_otx_threats_route():
    threats = fetch_otx_threats()
    return jsonify(threats), 200

@api_bp.route('/fetch_misp_threats', methods=['GET'])
def fetch_misp_threats_route():
    threats = fetch_misp_threats()
    return jsonify(threats), 200

@api_bp.route('/fetch_wazuh_alerts', methods=['GET'])
def fetch_wazuh_alerts_route():
    alerts = fetch_wazuh_alerts()
    return jsonify(alerts), 200