from flask import Blueprint, render_template, request, redirect, url_for, flash
from src.core.ip_manager import IPManager
from src.core.threat_intel import ThreatIntel

dashboard_bp = Blueprint('dashboard', __name__)

ip_manager = IPManager()
threat_intel = ThreatIntel()

@dashboard_bp.route('/dashboard', methods=['GET'])
def dashboard():
    blocked_ips = ip_manager.get_blocked_ips()
    threat_data = threat_intel.get_recent_threats()
    return render_template('dashboard.html', blocked_ips=blocked_ips, threat_data=threat_data)

@dashboard_bp.route('/dashboard/block_ip', methods=['POST'])
def block_ip():
    ip = request.form.get('ip')
    if ip_manager.block_ip(ip):
        flash(f'IP {ip} has been blocked successfully.', 'success')
    else:
        flash(f'Failed to block IP {ip}.', 'error')
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/dashboard/unblock_ip', methods=['POST'])
def unblock_ip():
    ip = request.form.get('ip')
    if ip_manager.unblock_ip(ip):
        flash(f'IP {ip} has been unblocked successfully.', 'success')
    else:
        flash(f'Failed to unblock IP {ip}.', 'error')
    return redirect(url_for('dashboard.dashboard'))