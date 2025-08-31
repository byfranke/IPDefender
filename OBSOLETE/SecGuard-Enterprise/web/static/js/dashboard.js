// SecGuard Enterprise Dashboard JavaScript
class SecGuardDashboard {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.updateInterval = null;
        this.isConnected = false;
        
        this.init();
    }
    
    init() {
        this.connectWebSocket();
        this.initCharts();
        this.startDataRefresh();
        this.bindEvents();
    }
    
    connectWebSocket() {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.updateConnectionStatus(true);
        };
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.isConnected = false;
            this.updateConnectionStatus(false);
            
            // Reconnect after 5 seconds
            setTimeout(() => this.connectWebSocket(), 5000);
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    handleWebSocketMessage(data) {
        if (data.type === 'update') {
            this.updateDashboard(data.data);
        }
    }
    
    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connection-status');
        const lastUpdateElement = document.getElementById('last-update');
        
        if (connected) {
            statusElement.textContent = '●';
            statusElement.style.color = '#27ae60';
            lastUpdateElement.textContent = 'Conectado';
        } else {
            statusElement.textContent = '●';
            statusElement.style.color = '#e74c3c';
            lastUpdateElement.textContent = 'Desconectado';
        }
    }
    
    async fetchData(endpoint) {
        try {
            const response = await fetch(`/api/${endpoint}`);
            if (!response.ok) throw new Error('Network response was not ok');
            return await response.json();
        } catch (error) {
            console.error(`Error fetching ${endpoint}:`, error);
            return null;
        }
    }
    
    async updateDashboard(data = null) {
        // Update system health
        await this.updateSystemHealth();
        
        // Update security status
        await this.updateSecurityStatus();
        
        // Update threat information
        await this.updateThreatInfo();
        
        // Update IP bans
        await this.updateIPBans();
        
        // Update scheduled jobs
        await this.updateScheduledJobs();
        
        // Update activity log
        await this.updateActivityLog();
        
        // Update last refresh time
        document.getElementById('last-update').textContent = 
            'Atualizado: ' + new Date().toLocaleTimeString('pt-BR');
    }
    
    async updateSystemHealth() {
        const healthData = await this.fetchData('health');
        if (!healthData) return;
        
        const { system } = healthData;
        
        // Update CPU
        document.getElementById('cpu-usage').textContent = `${system.cpu_percent.toFixed(1)}%`;
        this.updateChart('cpu-chart', [system.cpu_percent]);
        
        // Update Memory
        document.getElementById('memory-usage').textContent = `${system.memory_percent.toFixed(1)}%`;
        this.updateChart('memory-chart', [system.memory_percent]);
        
        // Update Disk
        document.getElementById('disk-usage').textContent = `${system.disk_percent.toFixed(1)}%`;
        this.updateChart('disk-chart', [system.disk_percent]);
    }
    
    async updateSecurityStatus() {
        const securityData = await this.fetchData('security-status');
        if (!securityData) return;
        
        // Update UFW status
        const ufwElement = document.getElementById('ufw-status');
        ufwElement.textContent = securityData.ufw_status ? 'Ativo' : 'Inativo';
        ufwElement.className = `indicator-status ${securityData.ufw_status ? 'active' : 'inactive'}`;
        
        // Update Fail2Ban status
        const fail2banElement = document.getElementById('fail2ban-status');
        fail2banElement.textContent = securityData.fail2ban_status ? 'Ativo' : 'Inativo';
        fail2banElement.className = `indicator-status ${securityData.fail2ban_status ? 'active' : 'inactive'}`;
        
        // Update overall security status
        const overallSecure = securityData.ufw_status && securityData.fail2ban_status;
        document.getElementById('security-status').textContent = overallSecure ? 'Seguro' : 'Atenção';
    }
    
    async updateThreatInfo() {
        const threatData = await this.fetchData('threat-summary');
        if (!threatData) return;
        
        document.getElementById('total-scans').textContent = threatData.total_scans || 0;
        document.getElementById('threats-detected').textContent = threatData.threats_detected || 0;
        
        // Update threat types chart
        if (threatData.threats_by_type) {
            this.updateThreatTypesChart(threatData.threats_by_type);
        }
    }
    
    async updateIPBans() {
        const banData = await this.fetchData('ip-bans');
        if (!banData) return;
        
        document.getElementById('banned-ips').textContent = banData.total_bans || 0;
        
        // Update banned countries chart
        if (banData.ban_countries) {
            this.updateBannedCountriesChart(banData.ban_countries);
        }
    }
    
    async updateScheduledJobs() {
        const jobsData = await this.fetchData('scheduled-jobs');
        if (!jobsData) return;
        
        document.getElementById('scheduled-jobs').textContent = jobsData.active_jobs || 0;
        
        // Update jobs table
        const tableBody = document.getElementById('jobs-table-body');
        tableBody.innerHTML = '';
        
        if (jobsData.jobs && jobsData.jobs.length > 0) {
            jobsData.jobs.forEach(job => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${job.type || 'N/A'}</td>
                    <td>${job.frequency || 'N/A'}</td>
                    <td><span class="status-${job.status === 'Enabled' ? 'enabled' : 'disabled'}">${job.status}</span></td>
                    <td>${job.next_run ? new Date(job.next_run).toLocaleString('pt-BR') : 'N/A'}</td>
                    <td>${job.last_run ? new Date(job.last_run).toLocaleString('pt-BR') : 'Nunca'}</td>
                `;
                tableBody.appendChild(row);
            });
        } else {
            tableBody.innerHTML = '<tr><td colspan="5">Nenhum job agendado</td></tr>';
        }
    }
    
    async updateActivityLog() {
        // Simulate activity log entries
        const logEntries = [
            { time: new Date(), message: 'Sistema funcionando normalmente', type: 'info' },
            { time: new Date(Date.now() - 300000), message: 'Verificação de ameaças concluída', type: 'info' },
            { time: new Date(Date.now() - 600000), message: 'Novo IP banido: 192.168.1.100', type: 'warning' }
        ];
        
        const logContainer = document.getElementById('activity-log');
        logContainer.innerHTML = '';
        
        logEntries.forEach(entry => {
            const logElement = document.createElement('div');
            logElement.className = `log-entry ${entry.type}`;
            logElement.textContent = `[${entry.time.toLocaleTimeString('pt-BR')}] ${entry.message}`;
            logContainer.appendChild(logElement);
        });
    }
    
    initCharts() {
        // Initialize CPU chart
        this.charts.cpu = this.createGaugeChart('cpu-chart', 'CPU Usage', '#3498db');
        
        // Initialize Memory chart
        this.charts.memory = this.createGaugeChart('memory-chart', 'Memory Usage', '#e74c3c');
        
        // Initialize Disk chart
        this.charts.disk = this.createGaugeChart('disk-chart', 'Disk Usage', '#f39c12');
        
        // Initialize threat types chart
        this.charts.threatTypes = this.createDoughnutChart('threats-type-chart', 'Tipos de Ameaças');
        
        // Initialize banned countries chart
        this.charts.bannedCountries = this.createDoughnutChart('banned-countries-chart', 'Países Banidos');
    }
    
    createGaugeChart(canvasId, label, color) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [color, '#ecf0f1'],
                    borderWidth: 0,
                    cutout: '70%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });
    }
    
    createDoughnutChart(canvasId, label) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#3498db', '#e74c3c', '#f39c12', '#27ae60', '#9b59b6'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 10,
                            font: { size: 10 }
                        }
                    }
                }
            }
        });
    }
    
    updateChart(chartName, values) {
        const chart = this.charts[chartName.replace('-chart', '')];
        if (chart && values.length > 0) {
            chart.data.datasets[0].data = [values[0], 100 - values[0]];
            chart.update('none');
        }
    }
    
    updateThreatTypesChart(data) {
        const chart = this.charts.threatTypes;
        if (chart && data) {
            const labels = Object.keys(data);
            const values = Object.values(data);
            
            chart.data.labels = labels;
            chart.data.datasets[0].data = values;
            chart.update();
        }
    }
    
    updateBannedCountriesChart(data) {
        const chart = this.charts.bannedCountries;
        if (chart && data) {
            const labels = Object.keys(data).slice(0, 5); // Top 5 countries
            const values = Object.values(data).slice(0, 5);
            
            chart.data.labels = labels;
            chart.data.datasets[0].data = values;
            chart.update();
        }
    }
    
    startDataRefresh() {
        // Initial load
        this.updateDashboard();
        
        // Refresh every 30 seconds
        this.updateInterval = setInterval(() => {
            this.updateDashboard();
        }, 30000);
    }
    
    bindEvents() {
        // Global refresh function
        window.refreshData = () => {
            this.updateDashboard();
        };
        
        // Handle visibility change to pause/resume updates
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                if (this.updateInterval) {
                    clearInterval(this.updateInterval);
                    this.updateInterval = null;
                }
            } else {
                this.startDataRefresh();
            }
        });
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SecGuardDashboard();
});