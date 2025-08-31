# 🔧 IPDefender Pro v2.0.0 - Requisitos do Sistema

> **⚙️ ESPECIFICAÇÕES TÉCNICAS COMPLETAS**
>
> Este documento detalha TODOS os requisitos necessários para executar o IPDefender Pro v2.0.0 em diferentes ambientes.

## 📋 **ÍNDICE**
1. [Requisitos Mínimos](#-requisitos-mínimos)
2. [Requisitos Recomendados](#-requisitos-recomendados)
3. [Requisitos de Produção](#-requisitos-de-produção)
4. [Sistemas Operacionais Suportados](#-sistemas-operacionais-suportados)
5. [Dependências de Software](#-dependências-de-software)
6. [Requisitos de Rede](#-requisitos-de-rede)
7. [Considerações de Segurança](#-considerações-de-segurança)
8. [Planejamento de Capacidade](#-planejamento-de-capacidade)

---

## 💻 **REQUISITOS MÍNIMOS**

### **🖥️ HARDWARE MÍNIMO**

#### **CPU**
- **Arquitetura**: x86_64 (AMD64) ou ARM64
- **Cores**: 2 vCPUs mínimo
- **Frequência**: 1.8 GHz mínimo
- **Features Requeridas**: SSE4.2, AVX (recomendado)

#### **MEMÓRIA RAM**
- **Mínimo**: 2 GB RAM
- **Recomendado**: 4 GB RAM
- **Swap**: 1 GB mínimo (se RAM < 4GB)

```bash
# Verificar RAM disponível
free -h

# Output esperado (mínimo):
#               total        used        free      shared  buff/cache   available
# Mem:           2.0G        1.2G        300M         50M        500M        700M
# Swap:          1.0G          0B        1.0G
```

#### **ARMAZENAMENTO**
- **Mínimo**: 10 GB espaço livre
- **Recomendado**: 50 GB para logs e dados
- **Tipo**: SSD recomendado para performance
- **IOPS**: Mínimo 100 IOPS (500+ recomendado)

```bash
# Verificar espaço em disco
df -h

# Verificar tipo de disco
lsblk -f
```

#### **REDE**
- **Interface**: Ethernet 100 Mbps mínimo
- **Largura de banda**: 10 Mbps downstream mínimo
- **Latência**: < 100ms para APIs externas

### **🐧 SISTEMA OPERACIONAL MÍNIMO**

#### **Linux (Recomendado)**
```yaml
Distribuições Suportadas:
  Ubuntu: 
    - "20.04 LTS (Focal)" # Mínimo
    - "22.04 LTS (Jammy)" # Recomendado
    - "24.04 LTS (Noble)" # Mais recente
  
  Debian:
    - "11 (Bullseye)" # Mínimo  
    - "12 (Bookworm)" # Recomendado
  
  CentOS/RHEL:
    - "8.x" # Mínimo
    - "9.x" # Recomendado
  
  Rocky Linux:
    - "8.x" # Mínimo
    - "9.x" # Recomendado
    
  Alpine Linux:
    - "3.17+" # Para containers
```

#### **Kernel Requirements**
```bash
# Versão mínima do kernel
uname -r  # Deve ser >= 5.4.0

# Features necessárias do kernel
grep CONFIG_NETFILTER /boot/config-$(uname -r)
# Deve retornar: CONFIG_NETFILTER=y

# Para funcionalidades avançadas de firewall
modprobe iptables_filter
modprobe ip6tables_filter
```

---

## 🚀 **REQUISITOS RECOMENDADOS**

### **🖥️ HARDWARE RECOMENDADO**

#### **CPU**
- **Cores**: 4+ vCPUs
- **Frequência**: 2.4+ GHz
- **Cache**: L3 8MB+
- **Arquitetura**: x86_64 com AVX2

```bash
# Verificar CPU
lscpu | grep -E "(Model name|CPU\(s\)|Thread|Core|MHz)"

# Verificar features de CPU
grep -o '\bavx2\b' /proc/cpuinfo | head -1  # Deve retornar 'avx2'
```

#### **MEMÓRIA**
- **RAM**: 8+ GB
- **Swap**: 2 GB (mesmo com RAM alta)
- **Huge Pages**: Configuradas (opcional, para alta performance)

```bash
# Configurar huge pages (opcional)
echo 'vm.nr_hugepages=512' >> /etc/sysctl.conf
sysctl -p
```

#### **ARMAZENAMENTO**
- **Tipo**: NVMe SSD
- **Espaço**: 100+ GB
- **IOPS**: 1000+ IOPS
- **Latência**: < 1ms

```bash
# Testar performance do disco
sudo hdparm -Tt /dev/sda

# Testar IOPS (requer fio)
fio --name=random-write --ioengine=posixaio --rw=randwrite --bs=64k --size=256m --numjobs=16 --iodepth=16 --runtime=60 --time_based --end_fsync=1
```

### **🌐 REDE RECOMENDADA**
- **Interface**: Gigabit Ethernet
- **Largura de banda**: 100+ Mbps
- **Latência**: < 50ms para APIs
- **DNS**: Múltiplos servidores DNS configurados

---

## 🏭 **REQUISITOS DE PRODUÇÃO**

### **🖥️ HARDWARE DE PRODUÇÃO**

#### **CPU**
```yaml
Configuração Mínima de Produção:
  Cores: 8+ vCPUs
  Frequência: 3.0+ GHz
  Cache: L3 16MB+
  Arquitetura: x86_64 com todas as extensions modernas
  
Configuração Recomendada:
  Cores: 16+ vCPUs  
  Frequência: 3.2+ GHz
  Arquitetura: Intel Xeon ou AMD EPYC
  Features: AVX-512 (se disponível)
```

#### **MEMÓRIA**
```yaml
Configuração Mínima:
  RAM: 16 GB
  Swap: 4 GB
  
Configuração Recomendada:
  RAM: 32+ GB
  Swap: 8 GB
  ECC: Recomendado
  
Configuração Enterprise:
  RAM: 64+ GB
  Swap: 16 GB  
  ECC: Obrigatório
  NUMA: Otimizado
```

#### **ARMAZENAMENTO**
```yaml
Sistema Operacional:
  Tipo: SSD NVMe
  Espaço: 100 GB
  RAID: RAID 1 (mirror)
  
Base de Dados:
  Tipo: SSD NVMe Enterprise
  Espaço: 500+ GB
  RAID: RAID 10 (recomendado)
  IOPS: 5000+ IOPS
  
Logs:
  Tipo: SSD SATA (aceitável)
  Espaço: 1+ TB
  Rotação: Configurada
  Backup: Diário
```

### **🌐 INFRAESTRUTURA DE PRODUÇÃO**

#### **REDE**
```yaml
Conectividade:
  Interface: 10 Gbps (recomendado)
  Redundância: Dual-homed
  Largura de Banda: 1 Gbps+ dedicado
  
Segurança:
  Firewall: Dedicado
  IDS/IPS: Recomendado
  VPN: Para acesso administrativo
  SSL/TLS: Obrigatório para todas as conexões
```

#### **ALTA DISPONIBILIDADE**
```yaml
Load Balancer:
  Tipo: Layer 7 (Application)
  Health Checks: Configurados
  SSL Termination: Sim
  
Clustering:
  Nós: Mínimo 3 nós
  Replicação: Master-slave
  Failover: Automático
  
Backup:
  Frequência: Diário (mínimo)
  Retenção: 30 dias (mínimo)
  Localização: Off-site
  Teste: Mensal
```

---

## 🐧 **SISTEMAS OPERACIONAIS SUPORTADOS**

### **🟢 LINUX (TOTALMENTE SUPORTADO)**

#### **Ubuntu LTS**
```yaml
Ubuntu 20.04 LTS (Focal Fossa):
  Status: ✅ Suportado
  Python: 3.8.x (padrão)
  Kernel: 5.4+
  EOL: Abril 2025
  Notas: Versão mínima estável
  
Ubuntu 22.04 LTS (Jammy Jellyfish):
  Status: ✅ Recomendado  
  Python: 3.10.x (padrão)
  Kernel: 5.15+
  EOL: Abril 2027
  Notas: Versão recomendada para produção
  
Ubuntu 24.04 LTS (Noble Numbat):
  Status: ✅ Mais recente
  Python: 3.12.x (padrão)  
  Kernel: 6.8+
  EOL: Abril 2029
  Notas: Versão mais moderna, com features mais recentes
```

**Script de verificação Ubuntu:**
```bash
#!/bin/bash
# Verificar compatibilidade Ubuntu

echo "=== Verificação de Compatibilidade Ubuntu ==="

# Versão do Ubuntu
lsb_release -a

# Kernel version
echo "Kernel: $(uname -r)"

# Python version
python3 --version

# Verificar systemd
systemctl --version | head -1

# Verificar iptables
iptables --version

# Verificar recursos necessários
echo "Verificando dependências..."
dpkg -l | grep -E "(python3|python3-pip|git|curl)" || echo "⚠️  Dependências faltando"
```

#### **Debian**
```yaml
Debian 11 (Bullseye):
  Status: ✅ Suportado
  Python: 3.9.x
  Kernel: 5.10+
  EOL: 2026
  Notas: Estável, adequado para produção
  
Debian 12 (Bookworm):
  Status: ✅ Recomendado
  Python: 3.11.x
  Kernel: 6.1+
  EOL: 2028
  Notas: Versão atual, features modernas
```

#### **CentOS/RHEL/Rocky Linux**
```yaml
CentOS 8 Stream:
  Status: ✅ Suportado
  Python: 3.8+
  Kernel: 4.18+
  Notas: Stream release
  
Rocky Linux 9:
  Status: ✅ Recomendado
  Python: 3.9+
  Kernel: 5.14+
  Notas: Substituto estável do CentOS
  
RHEL 9:
  Status: ✅ Enterprise
  Python: 3.9+
  Kernel: 5.14+
  Support: Suporte comercial Red Hat
```

#### **Alpine Linux**
```yaml
Alpine 3.18+:
  Status: ✅ Container apenas
  Python: 3.11+
  Kernel: 6.1+
  Uso: Containers e deployments leves
  Notas: Imagem mínima, ideal para Docker
```

### **🟨 OUTROS SISTEMAS (SUPORTE LIMITADO)**

#### **macOS**
```yaml
Status: 🟨 Desenvolvimento apenas
Versões: macOS 12+ (Monterey)
Python: 3.9+ (via Homebrew)
Limitações:
  - Sem integração nativa de firewall
  - Plugins limitados
  - Performance reduzida
  - Não recomendado para produção
```

#### **Windows**
```yaml
Status: 🟨 Experimental
Versões: Windows 10/11, Windows Server 2019+
Python: 3.9+ (Microsoft Store ou Python.org)
WSL: Recomendado usar WSL2 com Ubuntu
Limitações:
  - Integração limitada de firewall
  - Performance inferior
  - Plugins específicos de Linux não funcionam
```

---

## 📦 **DEPENDÊNCIAS DE SOFTWARE**

### **🐍 PYTHON RUNTIME**

#### **Versão Python**
```yaml
Mínimo Suportado: Python 3.8.0
Recomendado: Python 3.11.x
Mais Recente: Python 3.12.x

Considerações por Versão:
  Python 3.8:
    - Funcional mas sem otimizações recentes
    - Suporte até outubro 2024
    - Performance 10-15% menor
    
  Python 3.9:
    - Bom balance estabilidade/performance
    - Suporte até outubro 2025
    - Algumas features modernas disponíveis
    
  Python 3.10:
    - Versão recomendada para produção
    - Pattern matching disponível
    - Mensagens de erro melhoradas
    
  Python 3.11:
    - Performance 10-60% melhor
    - Error messages mais claras
    - Versão recomendada atual
    
  Python 3.12:
    - Performance ainda melhor
    - Novas features de typing
    - Pode ter algumas dependências instáveis
```

**Verificação de Python:**
```bash
#!/bin/bash
# Verificar instalação Python

echo "=== Verificação Python ==="

# Versão do Python
python3 --version
python3 -c "import sys; print(f'Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"

# Verificar pip
python3 -m pip --version

# Verificar virtualenv
python3 -m venv --help > /dev/null 2>&1 && echo "✅ venv disponível" || echo "❌ venv não disponível"

# Verificar compilação com otimizações
python3 -c "import sys; print('✅ Optimized build' if sys.flags.optimize else '⚠️  Debug build')"

# Verificar features importantes
python3 -c "
import asyncio
import ssl
import sqlite3
import json
import hashlib
print('✅ Todas as bibliotecas padrão necessárias estão disponíveis')
"
```

### **🗄️ BANCO DE DADOS**

#### **SQLite (Desenvolvimento)**
```yaml
Versão: 3.35+ (recomendado 3.40+)
Uso: Desenvolvimento local, testes
Configuração: Automática
Performance: Adequada para desenvolvimento

Verificação:
  - sqlite3 --version
  - Deve ser >= 3.35.0
```

#### **PostgreSQL (Produção)**
```yaml
Versões Suportadas:
  - PostgreSQL 12.x (mínimo)
  - PostgreSQL 13.x (suportado)
  - PostgreSQL 14.x (recomendado)
  - PostgreSQL 15.x (mais recente)

Extensões Necessárias:
  - uuid-ossp (para UUIDs)
  - pg_stat_statements (para monitoring)
  - pg_trgm (para busca de texto)

Configuração Mínima:
  max_connections: 100
  shared_buffers: 256MB
  effective_cache_size: 1GB
  work_mem: 4MB
  maintenance_work_mem: 64MB
```

**Instalação PostgreSQL (Ubuntu):**
```bash
# Instalar PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Configurar usuário
sudo -u postgres createuser --interactive ipdefender
sudo -u postgres createdb ipdefender_pro

# Verificar instalação
sudo -u postgres psql -c "SELECT version();"
```

### **🔧 FERRAMENTAS SISTEMA**

#### **Git**
```bash
# Versão mínima: 2.25+
# Recomendado: 2.40+
git --version

# Instalação Ubuntu/Debian
sudo apt install git

# Instalação CentOS/RHEL
sudo yum install git  # ou dnf install git
```

#### **Curl/Wget**
```bash
# Para downloads e verificações de API
curl --version  # >= 7.68
wget --version  # >= 1.20

# Instalação
sudo apt install curl wget  # Ubuntu/Debian
sudo yum install curl wget  # CentOS/RHEL
```

#### **Ferramentas de Desenvolvimento (Opcional)**
```bash
# Build tools para compilar algumas dependências
sudo apt install build-essential python3-dev libffi-dev libssl-dev

# Para CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install python3-devel libffi-devel openssl-devel
```

---

## 🌐 **REQUISITOS DE REDE**

### **🔗 CONECTIVIDADE EXTERNA**

#### **APIs de Threat Intelligence**
```yaml
AbuseIPDB:
  URL: https://api.abuseipdb.com/api/v2/
  Protocolo: HTTPS (TCP 443)
  Rate Limit: 1000 requests/day (free)
  Timeout: 30 segundos
  
VirusTotal:
  URL: https://www.virustotal.com/vtapi/v2/
  Protocolo: HTTPS (TCP 443)
  Rate Limit: 4 requests/minute (free)
  Timeout: 45 segundos
  
Shodan:
  URL: https://api.shodan.io/
  Protocolo: HTTPS (TCP 443)
  Rate Limit: 100 queries/month (free)
  Timeout: 30 segundos
```

#### **Requisitos de DNS**
```yaml
Servidores DNS:
  Primário: 8.8.8.8 (Google)
  Secundário: 1.1.1.1 (Cloudflare)
  Terciário: 208.67.222.222 (OpenDNS)
  
Configuração:
  Timeout: 5 segundos
  Tentativas: 3
  Cache TTL: 300 segundos
```

**Teste de conectividade:**
```bash
#!/bin/bash
# Testar conectividade externa

echo "=== Teste de Conectividade ==="

# Testar DNS
nslookup api.abuseipdb.com
nslookup www.virustotal.com

# Testar conectividade HTTPS
curl -I https://api.abuseipdb.com/api/v2/ --connect-timeout 10
curl -I https://www.virustotal.com/vtapi/v2/ --connect-timeout 10

# Testar latência
ping -c 3 api.abuseipdb.com
ping -c 3 www.virustotal.com
```

### **🔥 CONFIGURAÇÃO DE FIREWALL**

#### **Portas Necessárias**

**Entrada (Inbound):**
```yaml
API Server:
  Porta: 8000 (padrão, configurável)
  Protocolo: TCP
  Origem: Clientes autorizados
  Descrição: API REST do IPDefender
  
SSH (Administração):
  Porta: 22
  Protocolo: TCP  
  Origem: IPs administrativos
  Descrição: Acesso de administração
  
SNMP (Opcional):
  Porta: 161
  Protocolo: UDP
  Origem: Sistema de monitoring
  Descrição: Monitoramento SNMP
```

**Saída (Outbound):**
```yaml
HTTPS (APIs Externas):
  Porta: 443
  Protocolo: TCP
  Destino: Internet
  Descrição: APIs de threat intelligence
  
DNS:
  Porta: 53
  Protocolo: UDP/TCP
  Destino: Servidores DNS
  Descrição: Resolução DNS
  
NTP:
  Porta: 123
  Protocolo: UDP
  Destino: Servidores NTP
  Descrição: Sincronização de tempo
  
SMTP (Opcional):
  Porta: 587/465
  Protocolo: TCP
  Destino: Servidor SMTP
  Descrição: Envio de notificações
```

**Configuração UFW (Ubuntu):**
```bash
# Configurar firewall básico
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permitir SSH
sudo ufw allow ssh

# Permitir API do IPDefender
sudo ufw allow 8000/tcp

# Permitir HTTPS para APIs externas
sudo ufw allow out 443/tcp

# Permitir DNS
sudo ufw allow out 53

# Ativar firewall
sudo ufw --force enable
sudo ufw status
```

---

## 🛡️ **CONSIDERAÇÕES DE SEGURANÇA**

### **🔐 HARDENING DO SISTEMA**

#### **Sistema Operacional**
```bash
# Atualizações de segurança
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y

# Configurar automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Desabilitar serviços desnecessários
sudo systemctl disable apache2 2>/dev/null || true
sudo systemctl disable nginx 2>/dev/null || true
sudo systemctl disable mysql 2>/dev/null || true

# Configurar limites do sistema
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf
```

#### **Usuários e Permissões**
```bash
# Criar usuário dedicado
sudo useradd -r -m -s /bin/bash ipdefender
sudo usermod -aG sudo ipdefender  # Se acesso administrativo necessário

# Configurar SSH key-based authentication
sudo -u ipdefender mkdir -p /home/ipdefender/.ssh
sudo -u ipdefender chmod 700 /home/ipdefender/.ssh

# Desabilitar login por senha (após configurar SSH keys)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

#### **Monitoramento de Segurança**
```yaml
Logs de Segurança:
  Localização: /var/log/
  Arquivos:
    - auth.log (autenticação)
    - syslog (sistema)
    - ufw.log (firewall)
    - ipdefender.log (aplicação)
  
Rotação:
  Frequência: Diária
  Retenção: 30 dias
  Compressão: Sim
  
Monitoramento:
  Failed logins: Alertar após 5 tentativas
  Disk usage: Alertar > 85%
  Memory usage: Alertar > 90%
  CPU usage: Alertar > 95% por 5 min
```

### **🔒 CERTIFICADOS SSL/TLS**

#### **Certificados para Produção**
```yaml
Opções Recomendadas:
  Let's Encrypt:
    Custo: Gratuito
    Validade: 90 dias (renovação automática)
    Domínio: Validação de domínio
    
  Certificado Comercial:
    Custo: Pago
    Validade: 1-3 anos
    Validação: DV/OV/EV disponível
    
Configuração TLS:
  Versão Mínima: TLS 1.2
  Ciphers: Modern cipher suites apenas
  HSTS: Habilitado
  OCSP Stapling: Habilitado
```

**Configuração Let's Encrypt:**
```bash
# Instalar certbot
sudo apt install certbot

# Obter certificado (DNS challenge)
sudo certbot certonly --manual --preferred-challenges dns -d api.yourdomain.com

# Configurar renovação automática
sudo crontab -e
# Adicionar linha: 0 3 * * * certbot renew --quiet
```

---

## 📊 **PLANEJAMENTO DE CAPACIDADE**

### **📈 CÁLCULO DE RECURSOS POR CARGA**

#### **Ambiente de Desenvolvimento**
```yaml
Carga Esperada:
  Requests/dia: < 1.000
  Requests/hora: < 100
  IPs únicos/dia: < 500
  
Recursos Necessários:
  CPU: 2 vCPUs
  RAM: 4 GB
  Disco: 50 GB
  Rede: 10 Mbps
  
Configuração Sugerida:
  Instância: t3.small (AWS) / B1s (Azure) / e2-small (GCP)
  Database: SQLite local
  Cache: Memória local
  Monitoring: Básico
```

#### **Ambiente de Teste**
```yaml
Carga Esperada:
  Requests/dia: < 10.000
  Requests/hora: < 1.000
  IPs únicos/dia: < 5.000
  
Recursos Necessários:
  CPU: 4 vCPUs
  RAM: 8 GB
  Disco: 100 GB
  Rede: 50 Mbps
  
Configuração Sugerida:
  Instância: t3.medium (AWS) / B2s (Azure) / e2-medium (GCP)
  Database: PostgreSQL local
  Cache: Redis local
  Monitoring: Intermediário
```

#### **Ambiente de Produção (Pequeno)**
```yaml
Carga Esperada:
  Requests/dia: 10.000-100.000
  Requests/hora: 1.000-10.000  
  IPs únicos/dia: 5.000-50.000
  
Recursos Necessários:
  CPU: 8 vCPUs
  RAM: 16 GB
  Disco: 500 GB SSD
  Rede: 100 Mbps
  
Configuração Sugerida:
  Instância: t3.large (AWS) / B4ms (Azure) / e2-standard-8 (GCP)
  Database: PostgreSQL dedicado
  Cache: Redis dedicado
  Load Balancer: Sim
  Monitoring: Completo
```

#### **Ambiente de Produção (Médio)**
```yaml
Carga Esperada:
  Requests/dia: 100.000-1.000.000
  Requests/hora: 10.000-100.000
  IPs únicos/dia: 50.000-500.000
  
Recursos Necessários:
  CPU: 16 vCPUs
  RAM: 32 GB
  Disco: 1 TB SSD
  Rede: 500 Mbps
  
Configuração Sugerida:
  Instâncias: 2x c5.2xlarge (AWS) / F8s_v2 (Azure)
  Database: RDS/CloudSQL Multi-AZ
  Cache: ElastiCache/Redis cluster
  Load Balancer: Application LB
  Monitoring: Enterprise
  CDN: CloudFront/CloudFlare
```

#### **Ambiente de Produção (Grande)**
```yaml
Carga Esperada:
  Requests/dia: > 1.000.000
  Requests/hora: > 100.000
  IPs únicos/dia: > 500.000
  
Recursos Necessários:
  CPU: 32+ vCPUs (por nó)
  RAM: 64+ GB (por nó)
  Disco: 2+ TB NVMe
  Rede: 1+ Gbps
  
Configuração Sugerida:
  Instâncias: 3+ c5.4xlarge (AWS) / F16s_v2 (Azure)
  Database: RDS/CloudSQL com read replicas
  Cache: Redis cluster com sharding
  Load Balancer: Global LB
  Monitoring: Enterprise + APM
  CDN: Multi-região
  Auto Scaling: Habilitado
```

### **🔄 SCALING GUIDELINES**

#### **Indicadores para Scaling Up**
```yaml
CPU:
  Warning: > 70% por 5 minutos
  Critical: > 85% por 2 minutos
  Action: Adicionar vCPUs ou scale out
  
Memory:
  Warning: > 80% utilização
  Critical: > 95% utilização
  Action: Adicionar RAM ou scale out
  
Disk I/O:
  Warning: > 80% IOPS utilizados
  Critical: > 95% IOPS utilizados
  Action: Migrar para SSD mais rápido
  
Network:
  Warning: > 70% bandwidth utilizado
  Critical: > 90% bandwidth utilizado  
  Action: Upgrade de rede ou CDN
  
Response Time:
  Warning: > 500ms P95
  Critical: > 1000ms P95
  Action: Scaling horizontal
```

#### **Estratégias de Scaling**

**Scaling Vertical (Scale Up):**
```yaml
Quando usar:
  - Carga crescendo gradualmente
  - Aplicação com estado
  - Recursos específicos limitados
  
Limitações:
  - Limite físico do hardware
  - Downtime para upgrade
  - Single point of failure
  
Implementação:
  1. Monitorar métricas
  2. Agendar maintenance window
  3. Upgrade de recursos
  4. Validar performance
```

**Scaling Horizontal (Scale Out):**
```yaml
Quando usar:
  - Carga variável/sazonal
  - Necessidade de alta disponibilidade
  - Crescimento rápido esperado
  
Vantagens:
  - Sem single point of failure
  - Scaling automático possível
  - Melhor cost-efficiency
  
Implementação:
  1. Configurar load balancer
  2. Preparar imagens/containers
  3. Implementar health checks
  4. Configurar auto scaling
```

---

## ✅ **CHECKLIST DE VERIFICAÇÃO**

### **📋 PRÉ-INSTALAÇÃO**

```bash
#!/bin/bash
# Script de verificação de requisitos

echo "=== IPDefender Pro v2.0.0 - Verificação de Requisitos ==="

# 1. Sistema Operacional
echo "1. Verificando Sistema Operacional..."
lsb_release -a 2>/dev/null || cat /etc/os-release
uname -a

# 2. Hardware
echo -e "\n2. Verificando Hardware..."
echo "CPU: $(nproc) cores - $(cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2)"
echo "RAM: $(free -h | grep '^Mem:' | awk '{print $2}') total, $(free -h | grep '^Mem:' | awk '{print $7}') available"
echo "Disk: $(df -h / | tail -1 | awk '{print $4}') available in /"

# 3. Python
echo -e "\n3. Verificando Python..."
python3 --version
python3 -m pip --version

# 4. Rede
echo -e "\n4. Verificando Conectividade..."
curl -I https://api.abuseipdb.com/api/v2/ --connect-timeout 5 --max-time 10 2>/dev/null && echo "✅ AbuseIPDB acessível" || echo "❌ AbuseIPDB inacessível"
curl -I https://www.virustotal.com/vtapi/v2/ --connect-timeout 5 --max-time 10 2>/dev/null && echo "✅ VirusTotal acessível" || echo "❌ VirusTotal inacessível"

# 5. Ferramentas
echo -e "\n5. Verificando Ferramentas..."
git --version && echo "✅ Git disponível" || echo "❌ Git não encontrado"
curl --version | head -1 && echo "✅ Curl disponível" || echo "❌ Curl não encontrado"

# 6. Portas
echo -e "\n6. Verificando Portas..."
ss -tlnp | grep :8000 && echo "⚠️  Porta 8000 já em uso" || echo "✅ Porta 8000 disponível"

echo -e "\n=== Verificação Concluída ==="
```

### **🔍 PÓS-INSTALAÇÃO**

```bash
#!/bin/bash
# Verificação pós-instalação

echo "=== Verificação Pós-Instalação ==="

# 1. Serviços
echo "1. Verificando Serviços..."
systemctl is-active ipdefender && echo "✅ IPDefender ativo" || echo "❌ IPDefender inativo"

# 2. Database
echo -e "\n2. Verificando Database..."
python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('/opt/ipdefender/data/ipdefender.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM sqlite_master WHERE type=\"table\"')
    tables = cursor.fetchall()
    print(f'✅ Database OK - {len(tables)} tabelas encontradas')
    conn.close()
except Exception as e:
    print(f'❌ Database Error: {e}')
"

# 3. API
echo -e "\n3. Verificando API..."
curl -I http://localhost:8000/health --connect-timeout 5 2>/dev/null && echo "✅ API respondendo" || echo "❌ API não responde"

# 4. Logs
echo -e "\n4. Verificando Logs..."
[ -f /var/log/ipdefender.log ] && echo "✅ Log file existe" || echo "❌ Log file não encontrado"

# 5. Performance inicial
echo -e "\n5. Teste de Performance..."
curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" -d '{"ip":"8.8.8.8"}' --connect-timeout 10 2>/dev/null && echo "✅ Análise de IP funcionando" || echo "❌ Análise de IP com problema"

echo -e "\n=== Verificação Pós-Instalação Concluída ==="
```

---

<div align="center">

**⚙️ REQUISITOS ENTERPRISE-GRADE ⚙️**

*Especificações detalhadas para implantação robusta*

*Testado e validado em ambientes de produção*

*Built with ❤️ by byFranke*

</div>
