# 🚀 IPDefender Pro v2.0.0 - Guia Completo de Instalação

> **🎯 INSTALAÇÃO PASSO A PASSO DETALHADA**
>
> Este guia cobre TODOS os métodos de instalação do IPDefender Pro v2.0.0, desde desenvolvimento até produção enterprise.

## 📋 **ÍNDICE**
1. [Visão Geral de Instalação](#-visão-geral-de-instalação)
2. [Instalação Rápida (Desenvolvimento)](#-instalação-rápida-desenvolvimento)
3. [Instalação Manual Detalhada](#-instalação-manual-detalhada)
4. [Instalação com Docker](#-instalação-com-docker)
5. [Instalação de Produção](#-instalação-de-produção)
6. [Configuração Inicial](#-configuração-inicial)
7. [Verificação da Instalação](#-verificação-da-instalação)
8. [Troubleshooting](#-troubleshooting)

---

## 🎯 **VISÃO GERAL DE INSTALAÇÃO**

### **📊 MÉTODOS DE INSTALAÇÃO DISPONÍVEIS**

```yaml
🔧 Desenvolvimento Local:
  Método: Script de instalação automático
  Tempo: 5-10 minutos
  Dificuldade: ⭐ Fácil
  Database: SQLite
  Uso: Desenvolvimento e testes
  
🐳 Container Docker:
  Método: Docker Compose
  Tempo: 2-5 minutos
  Dificuldade: ⭐ Fácil
  Database: PostgreSQL em container
  Uso: Desenvolvimento isolado
  
🏗️ Manual Completa:
  Método: Passo a passo detalhado
  Tempo: 20-30 minutos
  Dificuldade: ⭐⭐ Médio
  Database: Configurável
  Uso: Customização avançada
  
🏭 Produção Enterprise:
  Método: Scripts de produção + configuração manual
  Tempo: 1-2 horas
  Dificuldade: ⭐⭐⭐ Avançado
  Database: PostgreSQL dedicado
  Uso: Ambientes de produção
```

### **🔍 PRÉ-REQUISITOS RÁPIDOS**

**Verificação Express:**
```bash
#!/bin/bash
# Verificação rápida de pré-requisitos

echo "🔍 Verificação Express de Pré-requisitos"
echo "========================================"

# Python 3.8+
python3_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
if (( $(echo "$python3_version >= 3.8" | bc -l) )); then
    echo "✅ Python $python3_version - OK"
else
    echo "❌ Python $python3_version - Requer 3.8+"
    exit 1
fi

# Git
git --version >/dev/null 2>&1 && echo "✅ Git - OK" || { echo "❌ Git não encontrado"; exit 1; }

# Curl
curl --version >/dev/null 2>&1 && echo "✅ Curl - OK" || { echo "❌ Curl não encontrado"; exit 1; }

# Espaço em disco (mínimo 5GB)
available_space=$(df / | tail -1 | awk '{print $4}')
if (( available_space > 5000000 )); then
    echo "✅ Espaço em disco - OK"
else
    echo "❌ Espaço insuficiente (${available_space}KB disponível, mínimo 5GB)"
    exit 1
fi

echo "🎉 Todos os pré-requisitos atendidos!"
```

---

## ⚡ **INSTALAÇÃO RÁPIDA (DESENVOLVIMENTO)**

### **🚀 INSTALAÇÃO EM UM COMANDO**

**Para Ubuntu/Debian:**
```bash
curl -fsSL https://raw.githubusercontent.com/byfranke/IPDefender/main/install.sh | bash
```

**Para CentOS/RHEL/Rocky:**
```bash
curl -fsSL https://raw.githubusercontent.com/byfranke/IPDefender/main/install.sh | bash -s -- --rhel
```

### **🔧 INSTALAÇÃO MANUAL RÁPIDA**

```bash
#!/bin/bash
# Instalação rápida do IPDefender Pro v2.0.0

set -e  # Exit on any error

echo "🚀 IPDefender Pro v2.0.0 - Instalação Rápida"
echo "============================================="

# 1. Criar diretório de instalação
INSTALL_DIR="/opt/ipdefender"
echo "📁 Criando diretório de instalação: $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 2. Clonar repositório
echo "📥 Clonando repositório..."
git clone https://github.com/byfranke/IPDefender.git .
cd IPDefender

# 3. Criar ambiente virtual
echo "🐍 Criando ambiente virtual Python..."
python3 -m venv venv
source venv/bin/activate

# 4. Instalar dependências
echo "📦 Instalando dependências..."
pip install --upgrade pip
pip install -r requirements.txt

# 5. Configurar database inicial
echo "🗄️ Configurando database..."
mkdir -p data logs
python3 -c "
from src.database.manager import DatabaseManager
import asyncio

async def setup_db():
    db = DatabaseManager('sqlite:///data/ipdefender.db')
    await db.initialize()
    print('Database inicializada com sucesso')

asyncio.run(setup_db())
"

# 6. Configurar arquivo de configuração
echo "⚙️ Criando configuração inicial..."
cp config/config.yaml config/config.local.yaml
sed -i 's/database_url:.*/database_url: "sqlite:\/\/\/opt\/ipdefender\/IPDefender\/data\/ipdefender.db"/' config/config.local.yaml

# 7. Criar service systemd (opcional)
if command -v systemctl >/dev/null 2>&1; then
    echo "🔧 Criando serviço systemd..."
    sudo tee /etc/systemd/system/ipdefender.service > /dev/null << EOF
[Unit]
Description=IPDefender Pro v2.0.0
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR/IPDefender
Environment=PATH=$INSTALL_DIR/IPDefender/venv/bin
ExecStart=$INSTALL_DIR/IPDefender/venv/bin/python src/main_v2.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable ipdefender
fi

echo "🎉 Instalação concluída com sucesso!"
echo ""
echo "📋 Próximos passos:"
echo "   1. Editar configuração: nano config/config.local.yaml"
echo "   2. Iniciar serviço: sudo systemctl start ipdefender"
echo "   3. Verificar logs: sudo journalctl -u ipdefender -f"
echo "   4. Testar API: curl http://localhost:8000/health"
echo ""
echo "📖 Documentação completa: $INSTALL_DIR/IPDefender/Documentation/"
```

---

## 🔧 **INSTALAÇÃO MANUAL DETALHADA**

### **🎯 PREPARAÇÃO DO AMBIENTE**

#### **1. Atualizar Sistema**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git python3 python3-pip python3-venv build-essential

# CentOS/RHEL/Rocky
sudo yum update -y
sudo yum install -y curl wget git python3 python3-pip python3-devel gcc openssl-devel libffi-devel

# Verificar instalação
python3 --version
git --version
curl --version
```

#### **2. Configurar Usuário Dedicado (Recomendado para Produção)**
```bash
# Criar usuário ipdefender
sudo useradd -r -m -s /bin/bash ipdefender

# Adicionar ao grupo sudo se necessário acesso administrativo
sudo usermod -aG sudo ipdefender

# Alternar para o usuário
sudo su - ipdefender
```

#### **3. Configurar Diretórios**
```bash
# Estrutura de diretórios recomendada
sudo mkdir -p /opt/ipdefender/{app,data,logs,config,backup}
sudo mkdir -p /var/log/ipdefender
sudo chown -R ipdefender:ipdefender /opt/ipdefender
sudo chown -R ipdefender:ipdefender /var/log/ipdefender

# Criar links simbólicos para facilitar navegação
ln -sf /opt/ipdefender /home/ipdefender/ipdefender
ln -sf /var/log/ipdefender /home/ipdefender/logs
```

### **📥 DOWNLOAD E CONFIGURAÇÃO**

#### **1. Clonar Repositório**
```bash
# Navegar para diretório de instalação
cd /opt/ipdefender

# Clonar repositório principal
git clone https://github.com/byfranke/IPDefender.git app
cd app

# Verificar versão
git describe --tags
git log --oneline -5

# Alternativamente, download direto de release
# wget https://github.com/byfranke/IPDefender/archive/refs/tags/v2.0.0.tar.gz
# tar -xzf v2.0.0.tar.gz
# mv IPDefender-2.0.0/* .
```

#### **2. Configurar Ambiente Virtual Python**
```bash
# Criar ambiente virtual
python3 -m venv venv

# Ativar ambiente virtual
source venv/bin/activate

# Atualizar pip
pip install --upgrade pip setuptools wheel

# Verificar ambiente
which python
which pip
python --version
```

#### **3. Instalar Dependências**
```bash
# Instalar dependências principais
pip install -r requirements.txt

# Verificar instalação das dependências críticas
python -c "
import fastapi
import sqlalchemy
import pydantic
import asyncio
import aiohttp
print('✅ Todas as dependências principais instaladas')
"

# Instalar dependências opcionais de produção
pip install uvicorn[standard] gunicorn redis psycopg2-binary

# Salvar versões instaladas
pip freeze > requirements-installed.txt
```

### **🗄️ CONFIGURAÇÃO DA DATABASE**

#### **Option A: SQLite (Desenvolvimento)**
```bash
# Criar diretório da database
mkdir -p /opt/ipdefender/data

# Configurar database SQLite
cd /opt/ipdefender/app
python3 -c "
import asyncio
from src.database.manager import DatabaseManager

async def setup_sqlite():
    db_url = 'sqlite:///opt/ipdefender/data/ipdefender.db'
    db = DatabaseManager(db_url)
    await db.initialize()
    
    # Criar tabelas
    await db.create_tables()
    
    # Inserir dados iniciais se necessário
    # await db.create_initial_data()
    
    print('✅ SQLite database configurada')

if __name__ == '__main__':
    asyncio.run(setup_sqlite())
"
```

#### **Option B: PostgreSQL (Produção)**

**Instalar PostgreSQL:**
```bash
# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib

# CentOS/RHEL
sudo yum install postgresql-server postgresql-contrib
sudo postgresql-setup initdb
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Verificar status
sudo systemctl status postgresql
```

**Configurar Database:**
```bash
# Conectar como usuário postgres
sudo -u postgres psql

-- Criar usuário e database
CREATE USER ipdefender WITH PASSWORD 'super_secure_password_here';
CREATE DATABASE ipdefender_prod OWNER ipdefender;
GRANT ALL PRIVILEGES ON DATABASE ipdefender_prod TO ipdefender;

-- Criar extensões necessárias
\c ipdefender_prod
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Sair do psql
\q
```

**Inicializar Schema:**
```bash
# Configurar URL da database
export DATABASE_URL="postgresql://ipdefender:super_secure_password_here@localhost/ipdefender_prod"

# Executar migrações
cd /opt/ipdefender/app
python3 -c "
import asyncio
import os
from src.database.manager import DatabaseManager

async def setup_postgresql():
    db_url = os.getenv('DATABASE_URL')
    db = DatabaseManager(db_url)
    await db.initialize()
    await db.create_tables()
    print('✅ PostgreSQL database configurada')

asyncio.run(setup_postgresql())
"
```

### **⚙️ CONFIGURAÇÃO DO SISTEMA**

#### **1. Arquivo de Configuração Principal**
```bash
# Criar configuração personalizada
cd /opt/ipdefender/app
cp config/config.yaml config/config.local.yaml

# Editar configuração
nano config/config.local.yaml
```

**Exemplo de configuração local:**
```yaml
# config/config.local.yaml
app:
  name: "IPDefender Pro"
  version: "2.0.0"
  debug: false
  log_level: "INFO"

server:
  host: "0.0.0.0"
  port: 8000
  workers: 4
  
database:
  # Para SQLite
  url: "sqlite:///opt/ipdefender/data/ipdefender.db"
  # Para PostgreSQL
  # url: "postgresql://ipdefender:password@localhost/ipdefender_prod"
  pool_size: 10
  max_overflow: 20
  
cache:
  enabled: true
  url: "redis://localhost:6379/0"  # Se Redis disponível
  default_ttl: 3600
  
threat_intelligence:
  providers:
    abuseipdb:
      enabled: true
      api_key: "YOUR_API_KEY_HERE"
      max_requests_per_day: 1000
    virustotal:
      enabled: false  # Configurar quando necessário
      api_key: "YOUR_VT_API_KEY"

firewall:
  providers:
    ufw:
      enabled: true
      default_action: "deny"

monitoring:
  metrics:
    enabled: true
    port: 9090
  health_check:
    enabled: true
    interval: 60

logging:
  level: "INFO"
  file: "/var/log/ipdefender/ipdefender.log"
  max_size: "50MB"
  backup_count: 5
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

security:
  api_keys:
    master: "generate-secure-api-key-here"
  rate_limiting:
    enabled: true
    requests_per_minute: 100
  cors:
    allowed_origins: ["http://localhost:3000"]
```

#### **2. Configurar Logging**
```bash
# Criar configuração de logging
mkdir -p /opt/ipdefender/config
cat > /opt/ipdefender/config/logging.yaml << 'EOF'
version: 1
disable_existing_loggers: false

formatters:
  standard:
    format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
  detailed:
    format: "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
  json:
    format: '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: standard
    stream: ext://sys.stdout
    
  file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: detailed
    filename: /var/log/ipdefender/ipdefender.log
    maxBytes: 52428800  # 50MB
    backupCount: 5
    
  error_file:
    class: logging.handlers.RotatingFileHandler
    level: ERROR
    formatter: detailed
    filename: /var/log/ipdefender/error.log
    maxBytes: 52428800
    backupCount: 5

loggers:
  ipdefender:
    level: INFO
    handlers: [console, file, error_file]
    propagate: false
    
  uvicorn:
    level: INFO
    handlers: [console, file]
    propagate: false
    
  sqlalchemy.engine:
    level: WARNING
    handlers: [file]
    propagate: false

root:
  level: INFO
  handlers: [console]
EOF
```

#### **3. Configurar Serviço Systemd**
```bash
# Criar arquivo de serviço
sudo tee /etc/systemd/system/ipdefender.service > /dev/null << EOF
[Unit]
Description=IPDefender Pro v2.0.0 - Advanced IP Defense System
Documentation=https://github.com/byfranke/IPDefender
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/opt/ipdefender

[Service]
Type=simple
User=ipdefender
Group=ipdefender
WorkingDirectory=/opt/ipdefender/app
Environment=PATH=/opt/ipdefender/app/venv/bin
Environment=PYTHONPATH=/opt/ipdefender/app
Environment=CONFIG_FILE=/opt/ipdefender/app/config/config.local.yaml
ExecStart=/opt/ipdefender/app/venv/bin/python src/main_v2.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
RestartForceExitStatus=1

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ipdefender /var/log/ipdefender

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Health monitoring
WatchdogSec=30
StartLimitInterval=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF

# Recarregar systemd e ativar serviço
sudo systemctl daemon-reload
sudo systemctl enable ipdefender

# Verificar arquivo de serviço
sudo systemctl cat ipdefender
```

#### **4. Configurar Firewall**
```bash
# Configurar UFW (Ubuntu/Debian)
if command -v ufw >/dev/null 2>&1; then
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Permitir SSH
    sudo ufw allow ssh
    
    # Permitir API do IPDefender
    sudo ufw allow 8000/tcp comment "IPDefender API"
    
    # Permitir métricas (se necessário)
    sudo ufw allow 9090/tcp comment "IPDefender Metrics"
    
    # Ativar firewall
    sudo ufw --force enable
    sudo ufw status verbose
fi

# Configurar iptables (CentOS/RHEL)
if command -v firewall-cmd >/dev/null 2>&1; then
    sudo firewall-cmd --permanent --add-port=8000/tcp
    sudo firewall-cmd --permanent --add-port=9090/tcp
    sudo firewall-cmd --reload
    sudo firewall-cmd --list-all
fi
```

---

## 🐳 **INSTALAÇÃO COM DOCKER**

### **🚀 Docker Compose (Recomendado)**

#### **1. Criar Docker Compose**
```bash
# Criar diretório para Docker
mkdir -p /opt/ipdefender-docker
cd /opt/ipdefender-docker

# Criar docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  ipdefender:
    image: byfranke/ipdefender:v2.0.0
    container_name: ipdefender-app
    restart: unless-stopped
    ports:
      - "8000:8000"
      - "9090:9090"
    environment:
      - CONFIG_FILE=/app/config/config.docker.yaml
      - DATABASE_URL=postgresql://ipdefender:secure_password@postgres:5432/ipdefender
      - REDIS_URL=redis://redis:6379/0
    volumes:
      - ./config:/app/config
      - ./logs:/var/log/ipdefender
      - ./data:/app/data
    depends_on:
      - postgres
      - redis
    networks:
      - ipdefender-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgres:
    image: postgres:15-alpine
    container_name: ipdefender-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: ipdefender
      POSTGRES_USER: ipdefender
      POSTGRES_PASSWORD: secure_password
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --lc-collate=C --lc-ctype=C"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./postgres-init:/docker-entrypoint-initdb.d
    networks:
      - ipdefender-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ipdefender -d ipdefender"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: ipdefender-redis
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass secure_redis_password
    volumes:
      - redis_data:/data
    networks:
      - ipdefender-net
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  nginx:
    image: nginx:alpine
    container_name: ipdefender-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx:/etc/nginx/conf.d
      - ./ssl:/etc/ssl/certs
    depends_on:
      - ipdefender
    networks:
      - ipdefender-net

volumes:
  postgres_data:
  redis_data:

networks:
  ipdefender-net:
    driver: bridge
EOF
```

#### **2. Configurar Arquivos Adicionais**

**Configuração Docker:**
```bash
mkdir -p config
cat > config/config.docker.yaml << 'EOF'
app:
  name: "IPDefender Pro Docker"
  version: "2.0.0"
  debug: false

server:
  host: "0.0.0.0"
  port: 8000
  workers: 4

database:
  url: "postgresql://ipdefender:secure_password@postgres:5432/ipdefender"
  pool_size: 20
  max_overflow: 40

cache:
  enabled: true
  url: "redis://:secure_redis_password@redis:6379/0"
  default_ttl: 3600

threat_intelligence:
  providers:
    abuseipdb:
      enabled: true
      api_key: "${ABUSEIPDB_API_KEY}"

monitoring:
  metrics:
    enabled: true
    port: 9090

logging:
  level: "INFO"
  file: "/var/log/ipdefender/ipdefender.log"
EOF
```

**Configuração Nginx:**
```bash
mkdir -p nginx
cat > nginx/default.conf << 'EOF'
upstream ipdefender_backend {
    server ipdefender:8000;
}

server {
    listen 80;
    server_name localhost;

    location /health {
        access_log off;
        proxy_pass http://ipdefender_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        proxy_pass http://ipdefender_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Rate limiting
        limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
        limit_req zone=api burst=20 nodelay;
    }
    
    location /metrics {
        proxy_pass http://ipdefender:9090;
        # Restringir acesso às métricas se necessário
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }
}
EOF
```

#### **3. Executar Docker Compose**
```bash
# Criar diretórios necessários
mkdir -p logs data postgres-init ssl

# Definir variáveis de ambiente
cat > .env << 'EOF'
ABUSEIPDB_API_KEY=your_api_key_here
COMPOSE_PROJECT_NAME=ipdefender
EOF

# Inicializar banco de dados
cat > postgres-init/01-init.sql << 'EOF'
-- Criar extensões necessárias
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Configurações de performance
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET max_connections = 100;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
EOF

# Subir os containers
docker-compose up -d

# Verificar status
docker-compose ps
docker-compose logs -f ipdefender
```

### **🐋 Docker Standalone**

#### **Executar Container Único:**
```bash
# Executar com SQLite
docker run -d \
  --name ipdefender \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /opt/ipdefender/data:/app/data \
  -v /opt/ipdefender/logs:/var/log/ipdefender \
  -e CONFIG_FILE=/app/config/config.yaml \
  byfranke/ipdefender:v2.0.0

# Verificar logs
docker logs -f ipdefender

# Executar comandos no container
docker exec -it ipdefender bash
```

#### **Build Personalizado:**
```bash
# Clonar repositório
git clone https://github.com/byfranke/IPDefender.git
cd IPDefender

# Build da imagem
docker build -t ipdefender:local .

# Executar imagem local
docker run -d \
  --name ipdefender-local \
  -p 8000:8000 \
  ipdefender:local
```

---

## 🏭 **INSTALAÇÃO DE PRODUÇÃO**

### **🎯 ARQUITETURA DE PRODUÇÃO**

#### **1. Load Balancer + Multi-Instance**
```bash
# Configurar múltiplas instâncias
for i in {1..3}; do
    sudo mkdir -p /opt/ipdefender-node${i}
    sudo cp -r /opt/ipdefender/app /opt/ipdefender-node${i}/
    
    # Configurar porta específica para cada instância
    sudo sed -i "s/port: 8000/port: 800${i}/" /opt/ipdefender-node${i}/app/config/config.local.yaml
    
    # Criar serviço específico
    sudo cp /etc/systemd/system/ipdefender.service /etc/systemd/system/ipdefender-node${i}.service
    sudo sed -i "s|WorkingDirectory=.*|WorkingDirectory=/opt/ipdefender-node${i}/app|" /etc/systemd/system/ipdefender-node${i}.service
    sudo sed -i "s|ExecStart=.*|ExecStart=/opt/ipdefender-node${i}/app/venv/bin/python src/main_v2.py|" /etc/systemd/system/ipdefender-node${i}.service
done

sudo systemctl daemon-reload

for i in {1..3}; do
    sudo systemctl enable ipdefender-node${i}
    sudo systemctl start ipdefender-node${i}
done
```

#### **2. Configurar HAProxy**
```bash
# Instalar HAProxy
sudo apt install haproxy

# Configurar HAProxy
sudo tee /etc/haproxy/haproxy.cfg > /dev/null << 'EOF'
global
    daemon
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    option dontlognull

frontend ipdefender_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/ipdefender.pem
    redirect scheme https if !{ ssl_fc }
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request reject if { sc_http_req_rate(0) gt 20 }
    
    default_backend ipdefender_backend

backend ipdefender_backend
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    
    server node1 127.0.0.1:8001 check
    server node2 127.0.0.1:8002 check
    server node3 127.0.0.1:8003 check

listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
EOF

# Reiniciar HAProxy
sudo systemctl restart haproxy
sudo systemctl enable haproxy
```

#### **3. Configurar PostgreSQL Master-Slave**

**Master Configuration:**
```bash
# Configurar PostgreSQL Master
sudo -u postgres psql << 'EOF'
-- Criar usuário de replicação
CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'replica_password';

-- Configurar archive mode
ALTER SYSTEM SET wal_level = replica;
ALTER SYSTEM SET max_wal_senders = 3;
ALTER SYSTEM SET wal_keep_segments = 64;
ALTER SYSTEM SET archive_mode = on;
ALTER SYSTEM SET archive_command = 'cp %p /var/lib/postgresql/15/main/archive/%f';

SELECT pg_reload_conf();
EOF

# Configurar pg_hba.conf para replicação
echo "host replication replicator 192.168.1.0/24 md5" | sudo tee -a /etc/postgresql/15/main/pg_hba.conf

sudo systemctl restart postgresql
```

#### **4. Monitoramento com Prometheus + Grafana**

**Configurar Prometheus:**
```bash
# Instalar Prometheus
sudo useradd --no-create-home --shell /bin/false prometheus
sudo mkdir /etc/prometheus /var/lib/prometheus
sudo chown prometheus:prometheus /etc/prometheus /var/lib/prometheus

# Download e instalação
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/v2.40.0/prometheus-2.40.0.linux-amd64.tar.gz
tar xzf prometheus-2.40.0.linux-amd64.tar.gz
sudo cp prometheus-2.40.0.linux-amd64/prometheus /usr/local/bin/
sudo cp prometheus-2.40.0.linux-amd64/promtool /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool

# Configurar Prometheus
sudo tee /etc/prometheus/prometheus.yml > /dev/null << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "ipdefender_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'ipdefender'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: /metrics
    scrape_interval: 15s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']
EOF

# Criar regras de alertas
sudo tee /etc/prometheus/ipdefender_rules.yml > /dev/null << 'EOF'
groups:
- name: ipdefender_alerts
  rules:
  - alert: IPDefenderDown
    expr: up{job="ipdefender"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "IPDefender instance is down"
      description: "IPDefender instance {{ $labels.instance }} has been down for more than 1 minute."

  - alert: HighRequestRate
    expr: rate(http_requests_total[5m]) > 100
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High request rate detected"
      description: "Request rate is {{ $value }} per second."

  - alert: DatabaseConnectionHigh
    expr: database_connections_active / database_connections_max > 0.8
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High database connection usage"
      description: "Database connections are at {{ $value }}% of maximum."
EOF

# Criar serviço systemd
sudo tee /etc/systemd/system/prometheus.service > /dev/null << 'EOF'
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries \
    --web.listen-address=0.0.0.0:9091 \
    --web.enable-lifecycle

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable prometheus
sudo systemctl start prometheus
```

---

## ⚙️ **CONFIGURAÇÃO INICIAL**

### **🔐 CONFIGURAÇÃO DE SEGURANÇA**

#### **1. Gerar Chaves API**
```bash
# Gerar chave API master
API_KEY=$(openssl rand -hex 32)
echo "Master API Key: $API_KEY"

# Atualizar configuração
cd /opt/ipdefender/app
sed -i "s/master: \".*\"/master: \"$API_KEY\"/" config/config.local.yaml

# Criar arquivo .env para desenvolvimento
echo "IPDEFENDER_API_KEY=$API_KEY" > .env
```

#### **2. Configurar SSL/TLS**
```bash
# Gerar certificado self-signed para desenvolvimento
sudo mkdir -p /etc/ssl/ipdefender
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/ipdefender/ipdefender.key \
    -out /etc/ssl/ipdefender/ipdefender.crt \
    -subj "/C=BR/ST=SP/L=SaoPaulo/O=IPDefender/CN=localhost"

# Para produção, usar Let's Encrypt
# sudo certbot --nginx -d api.yourdomain.com
```

#### **3. Configurar Backup Automático**
```bash
# Criar script de backup
sudo tee /usr/local/bin/ipdefender-backup.sh > /dev/null << 'EOF'
#!/bin/bash
# IPDefender Backup Script

BACKUP_DIR="/opt/ipdefender/backup"
DATE=$(date +%Y%m%d_%H%M%S)
DATABASE_URL=$(grep "url:" /opt/ipdefender/app/config/config.local.yaml | cut -d'"' -f2)

# Criar diretório de backup
mkdir -p "$BACKUP_DIR/$DATE"

# Backup configuração
cp -r /opt/ipdefender/app/config "$BACKUP_DIR/$DATE/"

# Backup database
if [[ $DATABASE_URL == *"sqlite"* ]]; then
    cp /opt/ipdefender/data/ipdefender.db "$BACKUP_DIR/$DATE/"
else
    pg_dump "$DATABASE_URL" > "$BACKUP_DIR/$DATE/database.sql"
fi

# Backup logs (últimos 7 dias)
find /var/log/ipdefender -name "*.log" -mtime -7 -exec cp {} "$BACKUP_DIR/$DATE/" \;

# Comprimir backup
tar -czf "$BACKUP_DIR/ipdefender_backup_$DATE.tar.gz" -C "$BACKUP_DIR" "$DATE"
rm -rf "$BACKUP_DIR/$DATE"

# Manter apenas backups dos últimos 30 dias
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete

echo "Backup concluído: $BACKUP_DIR/ipdefender_backup_$DATE.tar.gz"
EOF

sudo chmod +x /usr/local/bin/ipdefender-backup.sh

# Agendar backup diário
echo "0 2 * * * root /usr/local/bin/ipdefender-backup.sh" | sudo tee -a /etc/crontab
```

---

## ✅ **VERIFICAÇÃO DA INSTALAÇÃO**

### **🔍 TESTES BÁSICOS**

#### **1. Verificar Serviços**
```bash
#!/bin/bash
# Script de verificação completa

echo "🔍 Verificação da Instalação do IPDefender Pro v2.0.0"
echo "=================================================="

# 1. Verificar serviço systemd
if systemctl is-active --quiet ipdefender; then
    echo "✅ Serviço IPDefender: Ativo"
    systemctl status ipdefender --no-pager -l
else
    echo "❌ Serviço IPDefender: Inativo"
    systemctl status ipdefender --no-pager -l
fi

# 2. Verificar processos
pgrep -f "main_v2.py" > /dev/null && echo "✅ Processo Python: Rodando" || echo "❌ Processo Python: Não encontrado"

# 3. Verificar portas
ss -tlnp | grep ":8000" > /dev/null && echo "✅ Porta 8000: Escutando" || echo "❌ Porta 8000: Não disponível"

# 4. Verificar API Health
echo ""
echo "🏥 Teste de Health Check:"
curl -s -f http://localhost:8000/health | python3 -m json.tool 2>/dev/null && echo "✅ API Health: OK" || echo "❌ API Health: Falhou"

# 5. Verificar database
echo ""
echo "🗄️ Teste de Database:"
response=$(curl -s -X POST http://localhost:8000/analyze \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $(grep 'master:' /opt/ipdefender/app/config/config.local.yaml | cut -d'"' -f2)" \
    -d '{"ip":"8.8.8.8","source":"test"}')

if echo "$response" | grep -q '"status"'; then
    echo "✅ Database: Conectado e funcional"
    echo "Response: $response"
else
    echo "❌ Database: Problema de conexão"
    echo "Response: $response"
fi

# 6. Verificar logs
echo ""
echo "📋 Últimas linhas do log:"
tail -10 /var/log/ipdefender/ipdefender.log 2>/dev/null || echo "⚠️  Log file não encontrado"

# 7. Verificar recursos
echo ""
echo "📊 Uso de Recursos:"
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)% uso"
echo "RAM: $(free | grep Mem | awk '{printf "%.1f%% uso", $3/$2 * 100.0}')"
echo "Disk: $(df /opt/ipdefender | tail -1 | awk '{print $5}') uso"
```

#### **2. Testes de Funcionalidade**
```bash
#!/bin/bash
# Testes funcionais completos

API_KEY=$(grep 'master:' /opt/ipdefender/app/config/config.local.yaml | cut -d'"' -f2)
BASE_URL="http://localhost:8000"

echo "🧪 Testes Funcionais do IPDefender"
echo "================================="

# Test 1: Health Check
echo "1. Teste Health Check:"
curl -s -f "$BASE_URL/health" > /dev/null && echo "✅ PASS" || echo "❌ FAIL"

# Test 2: API Documentation
echo "2. Teste Documentação API:"
curl -s -f "$BASE_URL/docs" > /dev/null && echo "✅ PASS" || echo "❌ FAIL"

# Test 3: IP Analysis
echo "3. Teste Análise de IP:"
response=$(curl -s -X POST "$BASE_URL/analyze" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{"ip":"8.8.8.8","source":"test"}')
    
if echo "$response" | grep -q '"ip"'; then
    echo "✅ PASS - Análise funcionando"
else
    echo "❌ FAIL - Resposta: $response"
fi

# Test 4: Batch Analysis
echo "4. Teste Análise em Lote:"
response=$(curl -s -X POST "$BASE_URL/analyze/batch" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{"ips":["8.8.8.8","1.1.1.1"],"source":"test"}')
    
if echo "$response" | grep -q '"results"'; then
    echo "✅ PASS - Análise em lote funcionando"
else
    echo "❌ FAIL - Resposta: $response"
fi

# Test 5: Rate Limiting
echo "5. Teste Rate Limiting:"
for i in {1..5}; do
    curl -s -X POST "$BASE_URL/analyze" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d '{"ip":"1.2.3.4","source":"test"}' > /dev/null
done

# Deve falhar na sexta tentativa se rate limiting estiver ativo
response=$(curl -s -X POST "$BASE_URL/analyze" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{"ip":"1.2.3.4","source":"test"}')
    
if echo "$response" | grep -q "rate limit"; then
    echo "✅ PASS - Rate limiting ativo"
else
    echo "⚠️  WARNING - Rate limiting pode não estar funcionando"
fi

echo ""
echo "🎉 Testes concluídos!"
```

#### **3. Teste de Performance**
```bash
#!/bin/bash
# Teste de performance básico

echo "⚡ Teste de Performance"
echo "====================="

API_KEY=$(grep 'master:' /opt/ipdefender/app/config/config.local.yaml | cut -d'"' -f2)

# Teste de latência
echo "1. Teste de Latência (10 requests):"
for i in {1..10}; do
    time_ms=$(curl -w "%{time_total}" -s -o /dev/null -X POST http://localhost:8000/analyze \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "{\"ip\":\"8.8.8.$i\",\"source\":\"perf_test\"}")
    
    time_ms_formatted=$(echo "$time_ms * 1000" | bc | cut -d. -f1)
    echo "Request $i: ${time_ms_formatted}ms"
done

# Teste de throughput com Apache Bench (se disponível)
if command -v ab > /dev/null; then
    echo ""
    echo "2. Teste de Throughput (Apache Bench):"
    echo '{"ip":"8.8.8.8","source":"load_test"}' > /tmp/ipdefender_test.json
    ab -n 100 -c 10 -T 'application/json' -H "X-API-Key: $API_KEY" -p /tmp/ipdefender_test.json http://localhost:8000/analyze
    rm /tmp/ipdefender_test.json
else
    echo "2. Apache Bench não disponível - instalar com: sudo apt install apache2-utils"
fi
```

---

## 🔧 **TROUBLESHOOTING**

### **❌ PROBLEMAS COMUNS**

#### **1. Serviço não inicia**

**Problema**: `systemctl start ipdefender` falha

**Diagnóstico**:
```bash
# Verificar status detalhado
systemctl status ipdefender -l

# Verificar logs do systemd
journalctl -u ipdefender -f

# Verificar logs da aplicação
tail -f /var/log/ipdefender/ipdefender.log
```

**Soluções**:
```bash
# 1. Verificar permissões
sudo chown -R ipdefender:ipdefender /opt/ipdefender
sudo chmod +x /opt/ipdefender/app/venv/bin/python

# 2. Verificar dependências Python
cd /opt/ipdefender/app
source venv/bin/activate
pip check

# 3. Verificar configuração
python3 -c "
import yaml
with open('config/config.local.yaml', 'r') as f:
    config = yaml.safe_load(f)
    print('Configuração carregada com sucesso')
"

# 4. Testar execução manual
cd /opt/ipdefender/app
source venv/bin/activate
python3 src/main_v2.py
```

#### **2. Database connection error**

**Problema**: Erro ao conectar com database

**Diagnóstico**:
```bash
# Para PostgreSQL
pg_isready -h localhost -p 5432 -U ipdefender

# Testar conexão manual
psql -h localhost -U ipdefender -d ipdefender_prod -c "SELECT version();"

# Para SQLite
ls -la /opt/ipdefender/data/ipdefender.db
sqlite3 /opt/ipdefender/data/ipdefender.db ".tables"
```

**Soluções**:
```bash
# 1. Verificar se PostgreSQL está rodando
sudo systemctl status postgresql
sudo systemctl start postgresql

# 2. Verificar usuário e database
sudo -u postgres psql -c "\du"  # Listar usuários
sudo -u postgres psql -c "\l"   # Listar databases

# 3. Recriar database se necessário
sudo -u postgres dropdb ipdefender_prod
sudo -u postgres createdb ipdefender_prod -O ipdefender

# 4. Para SQLite, verificar permissões
sudo chown ipdefender:ipdefender /opt/ipdefender/data/
sudo chmod 755 /opt/ipdefender/data/
```

#### **3. Port already in use**

**Problema**: Porta 8000 já está em uso

**Diagnóstico**:
```bash
# Verificar que processo está usando a porta
sudo lsof -i :8000
sudo netstat -tlnp | grep :8000

# Verificar processos Python
ps aux | grep python3
```

**Soluções**:
```bash
# 1. Matar processo que está usando a porta
sudo kill $(sudo lsof -t -i:8000)

# 2. Ou alterar porta na configuração
sed -i 's/port: 8000/port: 8001/' /opt/ipdefender/app/config/config.local.yaml

# 3. Reiniciar serviço
sudo systemctl restart ipdefender
```

#### **4. API Keys não funcionando**

**Problema**: Authentication failed

**Diagnóstico**:
```bash
# Verificar configuração da API key
grep -A 5 "api_keys:" /opt/ipdefender/app/config/config.local.yaml

# Testar com curl
API_KEY="your_api_key_here"
curl -v -H "X-API-Key: $API_KEY" http://localhost:8000/health
```

**Soluções**:
```bash
# 1. Gerar nova API key
NEW_KEY=$(openssl rand -hex 32)
echo "Nova API Key: $NEW_KEY"

# 2. Atualizar configuração
sed -i "s/master: \".*\"/master: \"$NEW_KEY\"/" /opt/ipdefender/app/config/config.local.yaml

# 3. Reiniciar serviço
sudo systemctl restart ipdefender

# 4. Testar nova key
curl -H "X-API-Key: $NEW_KEY" http://localhost:8000/health
```

#### **5. Performance Issues**

**Problema**: Resposta lenta da API

**Diagnóstico**:
```bash
# Verificar uso de recursos
htop
iostat 1 5
free -h

# Verificar logs de performance
grep -i "slow\|timeout\|error" /var/log/ipdefender/ipdefender.log

# Testar conectividade externa
curl -w "time_total: %{time_total}s\n" -o /dev/null -s https://api.abuseipdb.com/api/v2/
```

**Soluções**:
```bash
# 1. Otimizar database
sudo -u postgres psql ipdefender_prod -c "
VACUUM ANALYZE;
REINDEX DATABASE ipdefender_prod;
"

# 2. Verificar cache
redis-cli ping  # Se usando Redis
redis-cli info memory

# 3. Ajustar configuração de workers
sed -i 's/workers: .*/workers: 8/' /opt/ipdefender/app/config/config.local.yaml

# 4. Verificar logs detalhados
tail -f /var/log/ipdefender/ipdefender.log | grep -E "(ERROR|WARNING|SLOW)"
```

### **🔍 LOGS E DEBUGGING**

#### **Estrutura de Logs**
```bash
/var/log/ipdefender/
├── ipdefender.log       # Log principal da aplicação
├── error.log           # Apenas erros
├── access.log          # Logs de acesso da API
└── audit.log           # Logs de auditoria de segurança
```

#### **Comandos Úteis de Debugging**
```bash
# Ver logs em tempo real
tail -f /var/log/ipdefender/ipdefender.log

# Filtrar por nível de log
grep "ERROR" /var/log/ipdefender/ipdefender.log
grep "WARNING" /var/log/ipdefender/ipdefender.log

# Ver logs por período
grep "2024-01-15" /var/log/ipdefender/ipdefender.log

# Analisar performance
grep "slow\|timeout" /var/log/ipdefender/ipdefender.log

# Ver estatísticas de requests
grep "POST /analyze" /var/log/ipdefender/access.log | wc -l

# Debug de específico IP
grep "8.8.8.8" /var/log/ipdefender/ipdefender.log
```

---

<div align="center">

**🚀 INSTALAÇÃO ENTERPRISE-GRADE COMPLETA 🚀**

*Guia detalhado para todas as situações de deploy*

*Do desenvolvimento à produção de alta disponibilidade*

*Built with ❤️ by byFranke*

</div>
