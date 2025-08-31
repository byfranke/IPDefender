# ⚙️ IPDefender Pro v2.0.0 - Visão Geral da Configuração

> **🎯 CONFIGURAÇÃO COMPLETA E DETALHADA**
>
> Este documento explica TODOS os aspectos de configuração do IPDefender Pro v2.0.0, desde configurações básicas até ajustes avançados de produção.

## 📋 **ÍNDICE**
1. [Filosofia de Configuração](#-filosofia-de-configuração)
2. [Estrutura de Configuração](#-estrutura-de-configuração)
3. [Hierarquia de Configurações](#-hierarquia-de-configurações)
4. [Configuração por Ambiente](#-configuração-por-ambiente)
5. [Validação de Configuração](#-validação-de-configuração)
6. [Configurações Dinâmicas](#-configurações-dinâmicas)
7. [Backup e Versionamento](#-backup-e-versionamento)
8. [Best Practices](#-best-practices)

---

## 🎯 **FILOSOFIA DE CONFIGURAÇÃO**

### **🏗️ PRINCIPLES OF CONFIGURATION**

O IPDefender Pro v2.0.0 segue os princípios de **configuração como código** com foco em:

#### **1. CONFIGURAÇÃO DECLARATIVA**
```yaml
# Exemplo de configuração declarativa
app:
  name: "IPDefender Pro"
  version: "2.0.0"
  environment: "production"  # Define comportamento completo
  
security:
  encryption: true           # Estado desejado, não como fazer
  audit_level: "full"       # O que queremos, não como implementar
  
database:
  type: "postgresql"        # Declara o tipo desejado
  high_availability: true   # Sistema configura automaticamente
```

**Benefícios**:
- ✅ **Previsibilidade**: Estado sempre conhecido
- ✅ **Reprodutibilidade**: Mesmo resultado em qualquer ambiente
- ✅ **Versionabilidade**: Configuração tratada como código
- ✅ **Validação**: Verificação automática de consistência

#### **2. IMMUTABLE CONFIGURATION**
```yaml
# Configurações imutáveis durante execução
core:
  instance_id: "ipd-prod-001"    # Nunca muda durante runtime
  cluster_name: "production"     # Identificação fixa
  
# Configurações mutáveis em runtime
runtime:
  log_level: "INFO"              # Pode ser alterada via API
  rate_limits:                   # Ajustável em tempo real
    api: 1000
    analysis: 100
```

#### **3. ENVIRONMENT-AWARE**
```yaml
# Configuração baseada em ambiente
environments:
  development:
    database:
      url: "sqlite:///data/dev.db"
      debug: true
    cache:
      enabled: false
      
  production:
    database:
      url: "postgresql://user:pass@db-cluster/prod"
      pool_size: 20
    cache:
      enabled: true
      cluster: "redis-cluster"
```

### **🔄 CONFIGURAÇÃO COMO INFRAESTRUTURA**

#### **Configuration as Infrastructure (CaI)**
```yaml
# Infraestrutura definida por configuração
infrastructure:
  load_balancer:
    enabled: true
    algorithm: "round_robin"
    health_check:
      endpoint: "/health"
      interval: 30
      
  auto_scaling:
    min_instances: 2
    max_instances: 10
    metrics:
      cpu_threshold: 70
      memory_threshold: 80
      
  monitoring:
    metrics: true
    tracing: true
    alerting:
      channels: ["slack", "email"]
      escalation: "on-call"
```

---

## 🏢 **ESTRUTURA DE CONFIGURAÇÃO**

### **📁 ESTRUTURA DE ARQUIVOS**

```
config/
├── config.yaml                 # Configuração base/template
├── config.local.yaml          # Configuração local (gitignored)
├── environments/
│   ├── development.yaml        # Configurações específicas de dev
│   ├── staging.yaml           # Configurações de staging
│   ├── production.yaml        # Configurações de produção
│   └── testing.yaml           # Configurações para testes
├── plugins/
│   ├── threat-providers.yaml  # Configuração de provedores TI
│   ├── firewall-providers.yaml # Configuração de firewalls
│   └── monitoring.yaml        # Configuração de monitoramento
├── schemas/
│   ├── config.schema.json     # Schema JSON para validação
│   └── plugin.schema.json     # Schema para plugins
└── templates/
    ├── minimal.yaml           # Template configuração mínima
    ├── standard.yaml          # Template configuração padrão
    └── enterprise.yaml        # Template configuração enterprise
```

### **🎯 ARQUIVO DE CONFIGURAÇÃO PRINCIPAL**

#### **config/config.yaml (Template Base)**
```yaml
# IPDefender Pro v2.0.0 - Configuração Base
# Este arquivo serve como template - não editar diretamente
# Usar config.local.yaml para customizações

metadata:
  version: "2.0.0"
  schema_version: "1.0"
  last_updated: "2024-01-15T10:00:00Z"
  description: "IPDefender Pro Configuration Template"

# =============================================================================
# APPLICATION SETTINGS
# =============================================================================
app:
  name: "IPDefender Pro"
  version: "2.0.0"
  description: "Advanced IP Defense System"
  
  # Environment: development, staging, production
  environment: "development"
  
  # Debug mode - NEVER enable in production
  debug: false
  
  # Timezone for all operations
  timezone: "UTC"
  
  # Language and locale
  locale: "en_US.UTF-8"
  
  # Instance identifier (unique per deployment)
  instance_id: null  # Auto-generated if null
  
  # Cluster configuration
  cluster:
    name: "default"
    node_id: null    # Auto-generated if null
    discovery:
      method: "static"  # static, consul, etcd
      endpoints: []

# =============================================================================
# SERVER CONFIGURATION
# =============================================================================
server:
  # Bind configuration
  host: "0.0.0.0"        # Listen on all interfaces
  port: 8000             # Primary API port
  
  # Worker configuration
  workers: 4             # Number of worker processes
  threads: 2             # Threads per worker
  
  # Connection limits
  max_connections: 1000
  keepalive_timeout: 75
  client_timeout: 30
  
  # SSL/TLS configuration
  ssl:
    enabled: false
    cert_file: null
    key_file: null
    ca_file: null
    verify_mode: "CERT_REQUIRED"
  
  # Proxy configuration
  proxy:
    enabled: false
    trust_ips: ["127.0.0.1", "::1"]
    headers:
      real_ip: "X-Real-IP"
      forwarded_for: "X-Forwarded-For"
      forwarded_proto: "X-Forwarded-Proto"

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
database:
  # Database URL - override in environment-specific config
  url: "sqlite:///data/ipdefender.db"
  
  # Connection pool settings
  pool:
    size: 10           # Base pool size
    max_overflow: 20   # Additional connections under load
    timeout: 30        # Connection timeout
    recycle: 3600      # Connection recycle time
    pre_ping: true     # Verify connections before use
  
  # Query configuration
  query:
    timeout: 30        # Query timeout in seconds
    slow_query_threshold: 1.0  # Log slow queries > 1 second
    
  # Migration settings
  migrations:
    auto_upgrade: false  # Auto-run migrations on startup
    backup_before: true  # Backup before migrations
    
  # Maintenance settings
  maintenance:
    vacuum_interval: 86400    # SQLite VACUUM interval
    analyze_interval: 3600    # ANALYZE statistics interval

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================
cache:
  enabled: true
  
  # Cache backend: memory, redis, memcached
  backend: "memory"
  
  # Connection settings (for Redis/Memcached)
  url: null              # e.g., "redis://localhost:6379/0"
  
  # Default TTL in seconds
  default_ttl: 3600
  
  # Cache sizes (for memory backend)
  max_size: 10000        # Maximum number of items
  max_memory: "100MB"    # Maximum memory usage
  
  # Cache strategies
  strategies:
    threat_analysis: 
      ttl: 3600          # 1 hour for threat analysis
      max_entries: 50000
    ip_reputation:
      ttl: 7200          # 2 hours for IP reputation
      max_entries: 100000
    dns_resolution:
      ttl: 1800          # 30 minutes for DNS
      max_entries: 10000

# =============================================================================
# THREAT INTELLIGENCE CONFIGURATION
# =============================================================================
threat_intelligence:
  # Global settings
  enabled: true
  timeout: 30            # Global timeout for all providers
  max_concurrent: 10     # Max concurrent provider calls
  
  # Scoring configuration
  scoring:
    algorithm: "weighted_average"  # weighted_average, max_score, consensus
    confidence_threshold: 0.7      # Minimum confidence for actions
    
  # Provider configuration
  providers:
    # AbuseIPDB Configuration
    abuseipdb:
      enabled: false     # Enable when API key available
      api_key: null      # Set in environment-specific config
      base_url: "https://api.abuseipdb.com/api/v2"
      timeout: 15
      rate_limit:
        requests_per_day: 1000
        requests_per_hour: 100
      confidence_multiplier: 1.0
      
    # VirusTotal Configuration
    virustotal:
      enabled: false     # Enable when API key available
      api_key: null      # Set in environment-specific config
      base_url: "https://www.virustotal.com/vtapi/v2"
      timeout: 20
      rate_limit:
        requests_per_minute: 4
      confidence_multiplier: 0.9
      
    # Shodan Configuration
    shodan:
      enabled: false     # Enable when API key available
      api_key: null      # Set in environment-specific config
      base_url: "https://api.shodan.io"
      timeout: 15
      confidence_multiplier: 0.8

# =============================================================================
# FIREWALL CONFIGURATION
# =============================================================================
firewall:
  # Global firewall settings
  enabled: true
  default_action: "log"  # log, block, allow
  
  # Provider configuration
  providers:
    # UFW (Uncomplicated Firewall)
    ufw:
      enabled: true      # Enable on Ubuntu/Debian systems
      chain: "INPUT"
      default_policy: "DENY"
      logging: true
      
    # iptables direct
    iptables:
      enabled: false     # Manual iptables management
      chain: "INPUT"
      target: "DROP"
      
    # Cloud provider firewalls
    aws_security_groups:
      enabled: false     # Enable for AWS deployments
      region: null
      vpc_id: null
      
    azure_nsg:
      enabled: false     # Enable for Azure deployments
      resource_group: null
      
    gcp_firewall:
      enabled: false     # Enable for GCP deployments
      project_id: null

# =============================================================================
# MONITORING CONFIGURATION
# =============================================================================
monitoring:
  # Global monitoring settings
  enabled: true
  
  # Metrics configuration
  metrics:
    enabled: true
    port: 9090         # Prometheus metrics port
    path: "/metrics"
    
    # Custom metrics
    custom_metrics:
      - name: "threat_detections_total"
        type: "counter"
        description: "Total number of threats detected"
        
      - name: "response_time_seconds"
        type: "histogram"
        description: "API response time in seconds"
        buckets: [0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
  
  # Health check configuration
  health:
    enabled: true
    endpoint: "/health"
    checks:
      database: true     # Check database connectivity
      cache: true        # Check cache connectivity
      external_apis: true # Check threat intel APIs
      disk_space: true   # Check available disk space
      memory: true       # Check memory usage
    
    # Health thresholds
    thresholds:
      response_time: 5.0    # Max response time in seconds
      disk_usage: 0.9       # Max disk usage (90%)
      memory_usage: 0.9     # Max memory usage (90%)
  
  # Alerting configuration
  alerting:
    enabled: false       # Enable when configured
    channels: []         # slack, email, webhook, pagerduty
    
    # Alert rules
    rules:
      - name: "high_threat_volume"
        condition: "threats_per_minute > 100"
        severity: "warning"
        duration: "5m"
        
      - name: "api_error_rate"
        condition: "error_rate > 0.05"  # 5% error rate
        severity: "critical"
        duration: "2m"

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
logging:
  # Global logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  level: "INFO"
  
  # Log format: text, json
  format: "text"
  
  # Console logging
  console:
    enabled: true
    level: "INFO"
    format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
  
  # File logging
  file:
    enabled: true
    level: "INFO"
    path: "/var/log/ipdefender/ipdefender.log"
    max_size: "50MB"
    backup_count: 5
    rotation: "time"     # size, time
    interval: "midnight"
    
  # Structured logging
  structured:
    enabled: false       # Enable for production
    format: "json"
    
  # Log rotation
  rotation:
    max_size: "100MB"
    max_files: 10
    compress: true
    
  # Component-specific logging levels
  loggers:
    "ipdefender.core": "INFO"
    "ipdefender.api": "INFO"
    "ipdefender.database": "WARNING"
    "ipdefender.plugins": "INFO"
    "uvicorn": "WARNING"
    "sqlalchemy": "WARNING"

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
security:
  # API authentication
  authentication:
    enabled: true
    method: "api_key"    # api_key, jwt, oauth2
    
    # API keys configuration
    api_keys:
      master: null       # Set in environment-specific config
      readonly: null     # Read-only access key
      
    # JWT configuration (if using JWT)
    jwt:
      secret_key: null
      algorithm: "HS256"
      expiration: 3600   # 1 hour
      
  # Rate limiting
  rate_limiting:
    enabled: true
    
    # Global rate limits
    global:
      requests_per_minute: 1000
      burst: 100
      
    # Per-endpoint limits
    endpoints:
      "/analyze": 100        # requests per minute
      "/analyze/batch": 10   # requests per minute
      "/health": 1000        # requests per minute
      
    # Per-client limits
    per_client:
      requests_per_minute: 100
      burst: 20
      
  # CORS configuration
  cors:
    enabled: true
    allowed_origins: ["*"]   # Restrict in production
    allowed_methods: ["GET", "POST", "OPTIONS"]
    allowed_headers: ["*"]
    allow_credentials: false
    
  # Security headers
  security_headers:
    enabled: true
    headers:
      "X-Content-Type-Options": "nosniff"
      "X-Frame-Options": "DENY"
      "X-XSS-Protection": "1; mode=block"
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
      "Content-Security-Policy": "default-src 'self'"
      
  # Input validation
  input_validation:
    strict_mode: true
    max_request_size: "10MB"
    allowed_ip_formats: ["ipv4", "ipv6"]
    
  # Audit logging
  audit:
    enabled: true
    level: "INFO"        # DEBUG, INFO, WARNING, ERROR
    file: "/var/log/ipdefender/audit.log"
    format: "json"
    
    # Events to audit
    events:
      authentication: true
      authorization: true
      ip_analysis: true
      configuration_changes: true
      admin_actions: true

# =============================================================================
# PERFORMANCE CONFIGURATION
# =============================================================================
performance:
  # Async configuration
  async_settings:
    max_workers: 100        # Max async workers
    timeout: 30             # Default async timeout
    
  # Connection pooling
  connection_pooling:
    enabled: true
    max_connections: 100
    idle_timeout: 300
    
  # Batch processing
  batch:
    max_size: 1000         # Max items per batch
    timeout: 60            # Batch processing timeout
    
  # Background tasks
  background_tasks:
    enabled: true
    max_workers: 10
    queue_size: 10000
    
  # Caching strategies
  caching:
    aggressive_caching: false  # Enable for read-heavy workloads
    cache_warming: false       # Pre-populate cache
    cache_compression: false   # Compress cached data

# =============================================================================
# PLUGIN SYSTEM CONFIGURATION
# =============================================================================
plugins:
  # Plugin system settings
  enabled: true
  auto_discovery: true
  hot_reload: false        # Enable for development only
  
  # Plugin directories
  directories:
    - "src/plugins"
    - "/opt/ipdefender/plugins"
    
  # Plugin loading
  loading:
    timeout: 30
    retry_attempts: 3
    fail_fast: false       # Continue if some plugins fail
    
  # Plugin health monitoring
  health_monitoring:
    enabled: true
    check_interval: 60     # seconds
    unhealthy_threshold: 3 # consecutive failures
    
  # Plugin configuration
  configurations:
    threat_providers:
      config_file: "plugins/threat-providers.yaml"
    firewall_providers:
      config_file: "plugins/firewall-providers.yaml"
    monitoring_providers:
      config_file: "plugins/monitoring.yaml"

# =============================================================================
# INTEGRATION CONFIGURATION
# =============================================================================
integrations:
  # SIEM integration
  siem:
    enabled: false
    type: null             # splunk, qradar, sentinel
    
  # Webhook notifications
  webhooks:
    enabled: false
    endpoints: []
    timeout: 10
    retry_attempts: 3
    
  # Message queue integration
  message_queue:
    enabled: false
    type: null             # rabbitmq, kafka, redis
    
  # External databases
  external_databases:
    enabled: false
    connections: {}

# =============================================================================
# MAINTENANCE CONFIGURATION
# =============================================================================
maintenance:
  # Automated maintenance
  auto_maintenance:
    enabled: true
    schedule: "0 2 * * *"  # Daily at 2 AM
    
  # Maintenance tasks
  tasks:
    database_cleanup:
      enabled: true
      retention_days: 90
      
    log_rotation:
      enabled: true
      retention_days: 30
      
    cache_cleanup:
      enabled: true
      max_age: 86400       # 24 hours
      
    health_checks:
      enabled: true
      
  # Backup configuration
  backup:
    enabled: false         # Configure for production
    schedule: "0 1 * * *"  # Daily at 1 AM
    retention: 30          # days
    compression: true

# =============================================================================
# DEVELOPMENT CONFIGURATION
# =============================================================================
development:
  # Development-only features
  hot_reload: false
  debug_toolbar: false
  profiling: false
  
  # Test data
  test_data:
    enabled: false
    seed_data: false
    
  # Mock services
  mock_services:
    threat_intelligence: false
    firewall: false
    
  # Development server
  dev_server:
    auto_restart: true
    watch_files: true
```

---

## 🏗️ **HIERARQUIA DE CONFIGURAÇÕES**

### **📊 ORDEM DE PRECEDÊNCIA**

O IPDefender Pro usa uma hierarquia clara de configurações, onde configurações mais específicas sobrescrevem as gerais:

```yaml
# 1. Padrões do código (mais baixa precedência)
DEFAULT_CONFIG = {
    "server": {"port": 8000, "host": "localhost"},
    "database": {"url": "sqlite:///data/default.db"}
}

# 2. config.yaml (configuração base)
server:
  port: 8000
  host: "0.0.0.0"      # Sobrescreve padrão

# 3. Configuração específica do ambiente
# config/environments/production.yaml
server:
  port: 80             # Sobrescreve config.yaml
  workers: 8           # Adiciona nova configuração

# 4. config.local.yaml (configurações locais)
server:
  port: 8080           # Sobrescreve ambiente
  
# 5. Variáveis de ambiente (mais alta precedência)
export IPDEFENDER_SERVER_PORT=9000  # Sobrescreve tudo
```

### **🔄 MERGE STRATEGY**

#### **Deep Merge de Configurações**
```python
# Exemplo de como as configurações são merged
base_config = {
    "database": {
        "url": "sqlite:///default.db",
        "pool": {"size": 10, "timeout": 30}
    },
    "cache": {"enabled": True}
}

environment_config = {
    "database": {
        "url": "postgresql://user:pass@db/prod",
        "pool": {"size": 20}  # Mantém timeout: 30
    }
}

# Resultado final após merge:
final_config = {
    "database": {
        "url": "postgresql://user:pass@db/prod",  # Sobrescrito
        "pool": {"size": 20, "timeout": 30}      # Merged
    },
    "cache": {"enabled": True}                   # Mantido
}
```

### **🌍 VARIÁVEIS DE AMBIENTE**

#### **Mapeamento de Variáveis**
```bash
# Todas as configurações podem ser sobrescritas por variáveis de ambiente
# Formato: IPDEFENDER_<SEÇÃO>_<SUBSEÇÃO>_<CHAVE>

# Configuração do servidor
export IPDEFENDER_SERVER_HOST="0.0.0.0"
export IPDEFENDER_SERVER_PORT="8000"
export IPDEFENDER_SERVER_WORKERS="4"

# Configuração do banco de dados
export IPDEFENDER_DATABASE_URL="postgresql://user:pass@localhost/ipdefender"
export IPDEFENDER_DATABASE_POOL_SIZE="20"

# Configuração de cache
export IPDEFENDER_CACHE_ENABLED="true"
export IPDEFENDER_CACHE_URL="redis://localhost:6379/0"

# Configuração de threat intelligence
export IPDEFENDER_THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY="your-api-key"
export IPDEFENDER_THREAT_INTELLIGENCE_ABUSEIPDB_ENABLED="true"

# Configuração de segurança
export IPDEFENDER_SECURITY_API_KEYS_MASTER="your-secret-api-key"

# Configuração de logging
export IPDEFENDER_LOGGING_LEVEL="INFO"
export IPDEFENDER_LOGGING_FILE_PATH="/var/log/ipdefender/app.log"
```

#### **Auto-Discovery de Variáveis**
```python
# Sistema automaticamente mapeia variáveis de ambiente
# Suporta diferentes tipos de dados

# Boolean
export IPDEFENDER_CACHE_ENABLED="true"     # → cache.enabled = True
export IPDEFENDER_DEBUG="false"           # → debug = False

# Integer  
export IPDEFENDER_SERVER_PORT="8080"      # → server.port = 8080
export IPDEFENDER_WORKERS="4"             # → workers = 4

# Float
export IPDEFENDER_THRESHOLD="0.85"        # → threshold = 0.85

# List (separado por vírgula)
export IPDEFENDER_ALLOWED_IPS="127.0.0.1,192.168.1.0/24"  # → ["127.0.0.1", "192.168.1.0/24"]

# JSON (para estruturas complexas)
export IPDEFENDER_COMPLEX_CONFIG='{"key": "value", "nested": {"num": 42}}'
```

---

## 🏢 **CONFIGURAÇÃO POR AMBIENTE**

### **🔧 DESENVOLVIMENTO**

#### **config/environments/development.yaml**
```yaml
# Configuração otimizada para desenvolvimento
metadata:
  environment: "development"
  description: "Configuração para ambiente de desenvolvimento"

# Aplicação em modo debug
app:
  debug: true
  log_level: "DEBUG"
  environment: "development"

# Servidor de desenvolvimento
server:
  host: "127.0.0.1"    # Apenas localhost
  port: 8000
  workers: 1           # Single worker para debugging
  auto_reload: true    # Auto-restart em mudanças

# Database local SQLite
database:
  url: "sqlite:///data/development.db"
  echo: true          # Log todas as queries SQL
  
# Cache em memória (simples)
cache:
  backend: "memory"
  enabled: true
  max_size: 1000

# Threat Intelligence com mocks
threat_intelligence:
  providers:
    abuseipdb:
      enabled: false   # Não usar APIs reais em dev
    mock_provider:
      enabled: true    # Usar provider mock
      
# Firewall desabilitado
firewall:
  providers:
    ufw:
      enabled: false   # Não modificar firewall em dev
    mock_firewall:
      enabled: true    # Usar mock

# Logging verboso
logging:
  level: "DEBUG"
  console:
    enabled: true
    level: "DEBUG"
  file:
    enabled: true
    level: "DEBUG"
    path: "logs/development.log"

# Segurança relaxada para desenvolvimento
security:
  api_keys:
    master: "dev-master-key-not-secure"
  rate_limiting:
    enabled: false     # Sem rate limiting em dev
  cors:
    allowed_origins: ["*"]  # Permite qualquer origem
    
# Performance para desenvolvimento
performance:
  async_settings:
    max_workers: 10    # Menos workers
  connection_pooling:
    max_connections: 10

# Plugins com hot reload
plugins:
  hot_reload: true     # Recarregar plugins automaticamente
  fail_fast: false    # Continuar mesmo com plugins com erro

# Features de desenvolvimento
development:
  hot_reload: true
  debug_toolbar: true
  profiling: true
  test_data:
    enabled: true
    seed_data: true
  mock_services:
    threat_intelligence: true
    firewall: true
```

### **🧪 TESTES**

#### **config/environments/testing.yaml**
```yaml
# Configuração para execução de testes
metadata:
  environment: "testing"
  description: "Configuração para ambiente de testes automatizados"

app:
  debug: false
  environment: "testing"

# Servidor de testes
server:
  host: "127.0.0.1"
  port: 8001          # Porta diferente para evitar conflitos
  workers: 1

# Database em memória para testes
database:
  url: "sqlite:///:memory:"  # Database temporária em RAM
  echo: false         # Não logar queries em testes
  
# Cache desabilitado para testes determinísticos
cache:
  enabled: false

# Mocks para todos os providers externos
threat_intelligence:
  providers:
    mock_provider:
      enabled: true
      test_responses: true

firewall:
  providers:
    mock_firewall:
      enabled: true
      test_mode: true

# Logging mínimo para testes
logging:
  level: "ERROR"      # Apenas erros durante testes
  console:
    enabled: false
  file:
    enabled: false

# Sem autenticação para testes
security:
  authentication:
    enabled: false
  rate_limiting:
    enabled: false

# Performance otimizada para testes rápidos
performance:
  async_settings:
    max_workers: 2
    timeout: 5
  batch:
    max_size: 100
    timeout: 10

# Plugins em modo de teste
plugins:
  hot_reload: false
  fail_fast: true     # Falhar rápido em testes
  test_mode: true

# Configurações específicas de teste
testing:
  fast_mode: true
  mock_external_calls: true
  deterministic_responses: true
```

### **🏗️ STAGING**

#### **config/environments/staging.yaml**
```yaml
# Configuração para ambiente de staging/homologação
metadata:
  environment: "staging"
  description: "Ambiente de staging - replica produção com dados de teste"

app:
  debug: false
  environment: "staging"
  
# Servidor similar à produção
server:
  host: "0.0.0.0"
  port: 8000
  workers: 2          # Menos workers que produção

# Database dedicado de staging
database:
  url: "postgresql://ipdefender:staging_pass@staging-db:5432/ipdefender_staging"
  pool:
    size: 10          # Pool menor que produção
    max_overflow: 20

# Cache Redis dedicado
cache:
  enabled: true
  backend: "redis"
  url: "redis://staging-redis:6379/0"

# APIs reais mas com rate limits mais baixos
threat_intelligence:
  providers:
    abuseipdb:
      enabled: true
      api_key: "${STAGING_ABUSEIPDB_KEY}"
      rate_limit:
        requests_per_day: 500  # Menor que produção

# Firewall real mas não crítico
firewall:
  providers:
    ufw:
      enabled: true
      test_mode: true   # Modo de teste - não bloquear realmente

# Logging intermediário
logging:
  level: "INFO"
  console:
    enabled: true
  file:
    enabled: true
    path: "/var/log/ipdefender/staging.log"

# Segurança similar à produção
security:
  api_keys:
    master: "${STAGING_API_KEY}"
  rate_limiting:
    enabled: true
    global:
      requests_per_minute: 500  # Menor que produção

# Monitoramento habilitado
monitoring:
  enabled: true
  metrics:
    enabled: true
  health:
    enabled: true
  alerting:
    enabled: false    # Sem alertas em staging

# Performance moderada
performance:
  async_settings:
    max_workers: 50
  connection_pooling:
    max_connections: 50

# Staging específico
staging:
  reset_data_daily: true      # Reset dados diário
  synthetic_load: false       # Carga sintética para testes
  feature_flags:
    new_features: true        # Testar features novas
```

### **🏭 PRODUÇÃO**

#### **config/environments/production.yaml**
```yaml
# Configuração para ambiente de produção
metadata:
  environment: "production"
  description: "Configuração otimizada para produção"

app:
  debug: false
  environment: "production"
  
# Servidor de produção otimizado
server:
  host: "0.0.0.0"
  port: 8000
  workers: 8          # Baseado em CPU cores
  max_connections: 2000
  keepalive_timeout: 120

# Database de produção com alta disponibilidade
database:
  url: "postgresql://ipdefender:${PROD_DB_PASSWORD}@prod-db-cluster:5432/ipdefender_prod"
  pool:
    size: 20
    max_overflow: 40
    timeout: 30
    recycle: 3600
    pre_ping: true

# Cache Redis em cluster
cache:
  enabled: true
  backend: "redis"
  url: "redis://prod-redis-cluster:6379/0"
  default_ttl: 7200   # TTL maior em produção

# APIs de produção com rate limits completos
threat_intelligence:
  enabled: true
  timeout: 45
  max_concurrent: 20
  providers:
    abuseipdb:
      enabled: true
      api_key: "${PROD_ABUSEIPDB_KEY}"
      rate_limit:
        requests_per_day: 10000
        requests_per_hour: 1000
    virustotal:
      enabled: true
      api_key: "${PROD_VIRUSTOTAL_KEY}"
      rate_limit:
        requests_per_minute: 4

# Firewall de produção
firewall:
  enabled: true
  default_action: "block"
  providers:
    ufw:
      enabled: true
      default_policy: "DENY"
      logging: true
    aws_security_groups:
      enabled: true
      region: "${AWS_REGION}"
      vpc_id: "${AWS_VPC_ID}"

# Logging de produção
logging:
  level: "INFO"
  format: "json"      # Structured logging
  console:
    enabled: false    # Sem console em produção
  file:
    enabled: true
    path: "/var/log/ipdefender/production.log"
    max_size: "100MB"
    backup_count: 10
    rotation: "time"

# Segurança máxima
security:
  api_keys:
    master: "${PROD_MASTER_API_KEY}"
    readonly: "${PROD_READONLY_API_KEY}"
  rate_limiting:
    enabled: true
    global:
      requests_per_minute: 5000
      burst: 200
    per_client:
      requests_per_minute: 100
      burst: 20
  cors:
    enabled: true
    allowed_origins: [
      "https://dashboard.yourdomain.com",
      "https://admin.yourdomain.com"
    ]
  security_headers:
    enabled: true
  audit:
    enabled: true
    level: "INFO"

# Monitoramento completo de produção
monitoring:
  enabled: true
  metrics:
    enabled: true
    port: 9090
    custom_metrics: true
  health:
    enabled: true
    thresholds:
      response_time: 2.0
      disk_usage: 0.85
      memory_usage: 0.85
  alerting:
    enabled: true
    channels: ["slack", "pagerduty"]
    rules:
      - name: "high_error_rate"
        condition: "error_rate > 0.01"
        severity: "critical"
        duration: "2m"
      - name: "high_latency"
        condition: "p95_latency > 5000"
        severity: "warning"
        duration: "5m"

# Performance otimizada para produção
performance:
  async_settings:
    max_workers: 200
    timeout: 60
  connection_pooling:
    enabled: true
    max_connections: 200
    idle_timeout: 600
  batch:
    max_size: 5000
    timeout: 300
  background_tasks:
    enabled: true
    max_workers: 20
    queue_size: 50000
  caching:
    aggressive_caching: true
    cache_warming: true
    cache_compression: true

# Plugins de produção
plugins:
  enabled: true
  hot_reload: false   # Nunca em produção
  fail_fast: true
  health_monitoring:
    enabled: true
    check_interval: 30
    unhealthy_threshold: 2

# Integrações de produção
integrations:
  siem:
    enabled: true
    type: "splunk"
    endpoint: "${SPLUNK_ENDPOINT}"
  webhooks:
    enabled: true
    endpoints: ["${WEBHOOK_ENDPOINT}"]
    timeout: 15
    retry_attempts: 5

# Maintenance de produção
maintenance:
  auto_maintenance:
    enabled: true
    schedule: "0 3 * * *"  # 3 AM daily
  backup:
    enabled: true
    schedule: "0 1 * * *"  # 1 AM daily
    retention: 90
    compression: true
    
# SSL/TLS obrigatório
server:
  ssl:
    enabled: true
    cert_file: "/etc/ssl/certs/ipdefender.crt"
    key_file: "/etc/ssl/private/ipdefender.key"
    verify_mode: "CERT_REQUIRED"
```

---

## ✅ **VALIDAÇÃO DE CONFIGURAÇÃO**

### **🔍 SCHEMA VALIDATION**

#### **config/schemas/config.schema.json**
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "IPDefender Pro Configuration Schema",
  "type": "object",
  "required": ["app", "server", "database"],
  
  "properties": {
    "app": {
      "type": "object",
      "required": ["name", "version", "environment"],
      "properties": {
        "name": {
          "type": "string",
          "minLength": 1
        },
        "version": {
          "type": "string",
          "pattern": "^\\d+\\.\\d+\\.\\d+$"
        },
        "environment": {
          "type": "string",
          "enum": ["development", "testing", "staging", "production"]
        },
        "debug": {
          "type": "boolean"
        }
      },
      "additionalProperties": true
    },
    
    "server": {
      "type": "object",
      "required": ["host", "port"],
      "properties": {
        "host": {
          "type": "string",
          "anyOf": [
            {"format": "ipv4"},
            {"format": "ipv6"},
            {"format": "hostname"}
          ]
        },
        "port": {
          "type": "integer",
          "minimum": 1,
          "maximum": 65535
        },
        "workers": {
          "type": "integer",
          "minimum": 1,
          "maximum": 32
        }
      },
      "additionalProperties": true
    },
    
    "database": {
      "type": "object",
      "required": ["url"],
      "properties": {
        "url": {
          "type": "string",
          "pattern": "^(sqlite|postgresql|mysql)://"
        },
        "pool": {
          "type": "object",
          "properties": {
            "size": {
              "type": "integer",
              "minimum": 1,
              "maximum": 100
            },
            "max_overflow": {
              "type": "integer",
              "minimum": 0,
              "maximum": 200
            }
          }
        }
      },
      "additionalProperties": true
    },
    
    "security": {
      "type": "object",
      "properties": {
        "api_keys": {
          "type": "object",
          "properties": {
            "master": {
              "type": ["string", "null"],
              "minLength": 16
            }
          }
        },
        "rate_limiting": {
          "type": "object",
          "properties": {
            "enabled": {
              "type": "boolean"
            },
            "global": {
              "type": "object",
              "properties": {
                "requests_per_minute": {
                  "type": "integer",
                  "minimum": 1
                }
              }
            }
          }
        }
      }
    }
  },
  
  "additionalProperties": true
}
```

#### **Script de Validação**
```python
#!/usr/bin/env python3
"""
IPDefender Configuration Validator
Valida configurações usando JSON Schema
"""

import json
import yaml
import jsonschema
import sys
from pathlib import Path
from typing import Dict, Any, List

class ConfigValidator:
    def __init__(self, schema_file: str = "config/schemas/config.schema.json"):
        self.schema_file = Path(schema_file)
        self.schema = self._load_schema()
        
    def _load_schema(self) -> Dict[str, Any]:
        """Carrega schema de validação"""
        try:
            with open(self.schema_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ Schema file not found: {self.schema_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in schema: {e}")
            sys.exit(1)
    
    def validate_config(self, config_file: str) -> bool:
        """Valida arquivo de configuração"""
        config_path = Path(config_file)
        
        if not config_path.exists():
            print(f"❌ Config file not found: {config_file}")
            return False
            
        try:
            # Carregar configuração
            with open(config_path, 'r') as f:
                if config_path.suffix in ['.yaml', '.yml']:
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
            
            # Validar contra schema
            jsonschema.validate(config, self.schema)
            print(f"✅ Configuration valid: {config_file}")
            return True
            
        except yaml.YAMLError as e:
            print(f"❌ YAML parsing error in {config_file}: {e}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ JSON parsing error in {config_file}: {e}")
            return False
        except jsonschema.ValidationError as e:
            print(f"❌ Validation error in {config_file}:")
            print(f"   Path: {'.'.join(str(p) for p in e.path)}")
            print(f"   Error: {e.message}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error validating {config_file}: {e}")
            return False
    
    def validate_all_configs(self) -> bool:
        """Valida todos os arquivos de configuração"""
        config_files = [
            "config/config.yaml",
            "config/environments/development.yaml",
            "config/environments/testing.yaml", 
            "config/environments/staging.yaml",
            "config/environments/production.yaml"
        ]
        
        all_valid = True
        
        print("🔍 Validating IPDefender Configuration Files")
        print("=" * 50)
        
        for config_file in config_files:
            if not self.validate_config(config_file):
                all_valid = False
                
        print("=" * 50)
        
        if all_valid:
            print("🎉 All configuration files are valid!")
        else:
            print("💥 Some configuration files have errors!")
            
        return all_valid
    
    def check_environment_consistency(self) -> bool:
        """Verifica consistência entre ambientes"""
        environments = ["development", "testing", "staging", "production"]
        configs = {}
        
        # Carregar todas as configurações de ambiente
        for env in environments:
            config_file = f"config/environments/{env}.yaml"
            try:
                with open(config_file, 'r') as f:
                    configs[env] = yaml.safe_load(f)
            except FileNotFoundError:
                print(f"⚠️  Environment config not found: {env}")
                continue
                
        # Verificar consistências
        issues = []
        
        # Verificar se todas têm a mesma estrutura básica
        required_sections = ["app", "server", "database", "security"]
        
        for env, config in configs.items():
            for section in required_sections:
                if section not in config:
                    issues.append(f"{env}: Missing required section '{section}'")
        
        # Verificar se versões são consistentes
        versions = {env: config.get("app", {}).get("version") for env, config in configs.items()}
        unique_versions = set(v for v in versions.values() if v is not None)
        
        if len(unique_versions) > 1:
            issues.append(f"Inconsistent versions across environments: {versions}")
            
        if issues:
            print("⚠️  Environment consistency issues found:")
            for issue in issues:
                print(f"   - {issue}")
            return False
        else:
            print("✅ Environment configurations are consistent")
            return True

if __name__ == "__main__":
    validator = ConfigValidator()
    
    # Validar todos os arquivos
    configs_valid = validator.validate_all_configs()
    
    # Verificar consistência
    consistency_ok = validator.check_environment_consistency()
    
    # Exit code baseado nos resultados
    if configs_valid and consistency_ok:
        sys.exit(0)
    else:
        sys.exit(1)
```

---

<div align="center">

**⚙️ CONFIGURAÇÃO ENTERPRISE-GRADE ⚙️**

*Sistema de configuração flexível e robusto*

*Suporte completo para todos os ambientes*

*Built with ❤️ by byFranke*

</div>
