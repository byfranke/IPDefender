# IPDefender 2.0 🛡️

**Uma solução robusta e unificada de defesa cibernética para a comunidade**

IPDefender é uma plataforma de segurança que integra múltiplas soluções de firewall (Cloudflare, UFW, Fail2ban) com feeds de threat intelligence (AbuseIPDB, OTX, MISP) e sistemas SIEM (Wazuh) para fornecer proteção automatizada contra ameaças.

## 🚀 Novidades da Versão 2.0

### Múltiplos Provedores de Firewall
- **Cloudflare WAF**: Proteção na borda da rede
- **UFW (Uncomplicated Firewall)**: Firewall local do servidor
- **Fail2ban**: Proteção baseada em logs e padrões

### Integração com Threat Intelligence
- **AbuseIPDB**: Validação de IPs maliciosos com níveis de confiança
- **AlienVault OTX**: Feed de indicadores de ameaças
- **MISP**: Plataforma de compartilhamento de threat intelligence

### SIEM Integration
- **Wazuh**: Integração completa para resposta automática a eventos
- **Regras customizáveis**: Resposta baseada em diferentes tipos de ataques

## 📋 Funcionalidades

### 🔒 Proteção Multi-Camada
- Bloqueio unificado em múltiplos firewalls
- Validação automática de ameaças
- Whitelist inteligente para IPs confiáveis

### 🤖 Automação Inteligente
- Sync automático com feeds de threat intelligence
- Resposta automática a eventos do SIEM
- Regras customizáveis por tipo de ataque

### 📊 Dashboard Web
- Interface web para monitoramento
- API REST completa
- Métricas em tempo real

### 🔔 Notificações
- Email, Slack, Discord
- Alertas em tempo real
- Relatórios periódicos

## 🛠️ Instalação

### Pré-requisitos

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip ufw fail2ban

# CentOS/RHEL
sudo yum install python3 python3-pip
# UFW e Fail2ban podem precisar de instalação manual
```

### Instalação do IPDefender

```bash
# Clone o repositório
git clone https://github.com/byfranke/IPDefender.git
cd IPDefender/New_Version_Beta/IPDefender

# Instale as dependências
pip3 install -r requirements.txt

# Execute o script de setup
sudo ./scripts/setup.sh
```

### Configuração

1. **Copie o arquivo de configuração**:
```bash
cp config/config.yaml.example config/config.yaml
```

2. **Configure suas credenciais**:
```yaml
# config/config.yaml
firewall:
  cloudflare:
    enabled: true
    api_token: "seu_token_cloudflare"
    zone_id: "seu_zone_id"

threat_intel:
  abuseipdb:
    enabled: true
    api_key: "sua_chave_abuseipdb"

siem:
  wazuh:
    enabled: true
    api_url: "https://seu-wazuh-server:55000"
    api_user: "wazuh_user"
    api_password: "wazuh_password"
```

3. **Inicie o serviço**:
```bash
python3 src/main.py
```

## 🎯 Uso Básico

### Via Linha de Comando

```bash
# Bloquear um IP em todos os firewalls
python3 -m ipdefender block 192.168.1.100

# Bloquear com validação de ameaça
python3 -m ipdefender block 192.168.1.100 --validate-threat medium

# Bloquear apenas em provedores específicos
python3 -m ipdefender block 192.168.1.100 --providers cloudflare,ufw

# Desbloquear IP
python3 -m ipdefender unblock 192.168.1.100

# Sync com threat intelligence
python3 -m ipdefender sync-threats --confidence 80

# Status do sistema
python3 -m ipdefender status
```

### Via API REST

```bash
# Bloquear IP
curl -X POST http://localhost:8080/api/v2/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "providers": ["ufw", "fail2ban"], "validate_threat": "medium"}'

# Status do sistema
curl http://localhost:8080/api/v2/status

# Listar IPs bloqueados
curl http://localhost:8080/api/v2/blocked-ips
```

### Via Python

```python
from ipdefender.core.firewall_manager import firewall_manager, FirewallProvider, ThreatValidationLevel

# Bloquear IP com validação
result = firewall_manager.block_ip(
    ip="192.168.1.100",
    providers=[FirewallProvider.UFW, FirewallProvider.FAIL2BAN],
    validate_threat=ThreatValidationLevel.MEDIUM
)

# Sync com threat intelligence
sync_result = firewall_manager.sync_with_threat_intel(confidence_threshold=80)
```

## 🔧 Configuração Avançada

### Regras de Detecção

Customize as regras em `config/rules.yaml`:

```yaml
detection_rules:
  ssh_brute_force:
    name: "SSH Brute Force Attack"
    enabled: true
    severity: "high"
    wazuh_rules: ["5710", "5712"]
    threshold: 5
    time_window: 300
    action: "block"
    firewall_providers: ["ufw", "fail2ban", "cloudflare"]
    threat_validation: "low"
    block_duration: 3600
```

### Automação

Configure tarefas automáticas:

```yaml
automation:
  scheduled_tasks:
    - name: "threat_intel_sync"
      enabled: true
      schedule: "0 */6 * * *"  # A cada 6 horas
      action: "sync_with_threat_intel"
      params:
        confidence_threshold: 80
```

## 🚀 Ideias de Expansão

### 1. Machine Learning Integration
- Detecção de anomalias com ML
- Classificação automática de ameaças
- Predição de ataques

```python
# Exemplo de integração ML
from ipdefender.ml.anomaly_detector import AnomalyDetector

detector = AnomalyDetector()
is_anomaly = detector.predict_threat(ip_features)
```

### 2. Integração com Mais Firewalls
- **pfSense**: Firewall empresarial
- **FortiGate**: Integração via API
- **Cisco ASA**: Suporte empresarial
- **OPNsense**: Alternativa open source

### 3. Threat Hunting Avançado
- **VirusTotal**: Análise de arquivos e URLs
- **Shodan**: Intel sobre dispositivos expostos
- **URLVoid**: Verificação de URLs maliciosas

### 4. Orquestração SOAR
- **TheHive**: Gestão de casos
- **Cortex**: Análise automatizada
- **Phantom/Splunk SOAR**: Orquestração empresarial

### 5. Integração com Clouds
- **AWS WAF**: Proteção na AWS
- **Azure Firewall**: Integração Azure
- **GCP Cloud Armor**: Proteção no Google Cloud

### 6. Análise Comportamental
- Perfis de usuário baseados em comportamento
- Detecção de insider threats
- Análise de padrões de tráfego

### 7. Compliance e Relatórios
- Relatórios SOC/CSIRT
- Compliance LGPD/GDPR
- Auditoria automática

## 📊 Arquitetura da Solução

```
┌─────────────────────────────────────────────────────────────┐
│                    IPDefender 2.0                          │
├─────────────────────────────────────────────────────────────┤
│  Web Dashboard  │  API REST  │  CLI  │  Webhooks          │
├─────────────────────────────────────────────────────────────┤
│              Unified Firewall Manager                      │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│  Cloudflare │     UFW     │  Fail2ban   │   Future...     │
├─────────────────────────────────────────────────────────────┤
│              Threat Intelligence Engine                    │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│  AbuseIPDB  │     OTX     │    MISP     │   Future...     │
├─────────────────────────────────────────────────────────────┤
│                  SIEM Integration                          │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│    Wazuh    │   Elastic   │   Splunk    │   Future...     │
├─────────────────────────────────────────────────────────────┤
│              Database & Configuration                      │
└─────────────────────────────────────────────────────────────┘
```

## 🤝 Contribuindo

### Como Contribuir

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/amazing-feature`)
3. Commit suas mudanças (`git commit -m 'Add amazing feature'`)
4. Push para a branch (`git push origin feature/amazing-feature`)
5. Abra um Pull Request

### Roadmap

- [ ] **v2.1**: Machine Learning integration
- [ ] **v2.2**: Multi-cloud firewall support
- [ ] **v2.3**: Advanced threat hunting
- [ ] **v2.4**: SOAR integration
- [ ] **v3.0**: Enterprise features

### Issues e Sugestões

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/byfranke/IPDefender/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/byfranke/IPDefender/discussions)
- 💬 **Chat**: [Discord Community](https://discord.gg/ipdefender)

## 📝 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🙏 Agradecimentos

- Comunidade de segurança cibernética
- Contribuidores open source
- Provedores de threat intelligence

---

**IPDefender 2.0** - Transformando a defesa cibernética para a comunidade 🛡️

Made with ❤️ by [@byfranke](https://github.com/byfranke)
