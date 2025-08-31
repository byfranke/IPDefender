# SecGuard Enterprise - Dashboard Web

## 🎯 Visão Geral

O **Dashboard Web** do SecGuard Enterprise é uma interface de monitoramento em tempo real que permite visualizar o status de segurança do sistema através de um navegador web. Desenvolvido com foco na **segurança e acesso local**, o dashboard oferece uma experiência profissional para administradores de sistema.

## 🔒 Recursos de Segurança

### **Acesso Restrito Local**
- ✅ **Bind apenas localhost**: Servidor escuta apenas em `127.0.0.1`
- ✅ **Firewall UFW**: Configuração automática para permitir apenas acesso local
- ✅ **Lista de IPs permitidos**: Controle granular de acesso por IP
- ✅ **API Key opcional**: Autenticação adicional para endpoints da API

### **Configuração de Firewall Automática**
```bash
# Regra UFW criada automaticamente:
ufw allow from 127.0.0.1 to any port 8888 comment 'SecGuard Dashboard 8888'
```

## 🚀 Como Usar

### **1. Iniciar o Dashboard**
```bash
# Comando básico
sudo secguard dashboard

# Com configurações customizadas
sudo secguard dashboard --port 9000 --host 127.0.0.1 --no-browser
```

### **2. Acessar o Dashboard**
- **URL Padrão**: `http://127.0.0.1:8888`
- **Acesso Automático**: O browser abre automaticamente (pode ser desabilitado)
- **Atualização em Tempo Real**: WebSocket para updates automáticos

### **3. Parar o Dashboard**
```bash
# Pressione Ctrl+C no terminal onde o dashboard está executando
```

## 📊 Interface do Dashboard

### **Cartões de Saúde do Sistema**
- **CPU**: Uso atual com gráfico em tempo real
- **Memória**: Consumo de RAM com indicadores visuais
- **Disco**: Espaço utilizado em armazenamento
- **Status de Segurança**: UFW, Fail2Ban e serviços críticos

### **Seção de Detecção de Ameaças**
- **Resumo Estatístico**: Total de scans, ameaças detectadas, IPs banidos
- **Gráficos Interativos**: Tipos de ameaças e países dos IPs banidos
- **Atividades Recentes**: Log em tempo real das ações de segurança

### **Gerenciamento de Jobs**
- **Tabela de Jobs Agendados**: Status, frequência e próximas execuções
- **Controle Visual**: Status enabled/disabled com cores intuitivas

## ⚙️ Configuração

### **Arquivo de Configuração**
```json
{
  "web_dashboard": {
    "enabled": false,
    "host": "127.0.0.1",
    "port": 8888,
    "allowed_ips": ["127.0.0.1", "::1"],
    "api_key": null,
    "auto_open": true
  }
}
```

### **Variáveis de Configuração**
| Parâmetro | Padrão | Descrição |
|-----------|---------|-----------|
| `enabled` | `false` | Habilita/desabilita o dashboard |
| `host` | `127.0.0.1` | IP de bind do servidor |
| `port` | `8888` | Porta do servidor web |
| `allowed_ips` | `["127.0.0.1", "::1"]` | IPs permitidos |
| `api_key` | `null` | Chave de API opcional |
| `auto_open` | `true` | Abrir browser automaticamente |

## 🔧 API REST Endpoints

### **Endpoints Disponíveis**

#### **System Health**
```bash
GET /api/health
# Retorna: CPU, memória, disco, rede, processos
```

#### **Security Status**
```bash
GET /api/security-status
# Retorna: UFW, Fail2Ban, serviços críticos, último scan
```

#### **Threat Summary**
```bash
GET /api/threat-summary
# Retorna: Total de scans, ameaças detectadas, tipos
```

#### **IP Bans**
```bash
GET /api/ip-bans
# Retorna: Lista de IPs banidos, estatísticas por país
```

#### **Scheduled Jobs**
```bash
GET /api/scheduled-jobs
# Retorna: Jobs agendados, status, próximas execuções
```

#### **System Metrics**
```bash
GET /api/system-metrics
# Retorna: Métricas detalhadas do sistema
```

### **Exemplo de Resposta da API**
```json
{
  "timestamp": "2025-07-21T15:30:00Z",
  "status": "healthy",
  "system": {
    "cpu_percent": 25.4,
    "memory_percent": 68.2,
    "disk_percent": 45.1,
    "processes": 287
  }
}
```

## 🌐 WebSocket para Tempo Real

### **Conexão WebSocket**
- **Endpoint**: `ws://127.0.0.1:8888/ws`
- **Auto-reconexão**: Reconecta automaticamente em caso de queda
- **Updates Automáticos**: Dados atualizados a cada 30 segundos

### **Mensagens WebSocket**
```json
{
  "type": "update",
  "data": {
    "cpu": 25.4,
    "memory": 68.2,
    "new_threats": 0
  },
  "timestamp": "2025-07-21T15:30:00Z"
}
```

## 📁 Estrutura de Arquivos

```
web/
├── templates/
│   └── dashboard.html          # Template principal
├── static/
│   ├── css/
│   │   └── dashboard.css       # Estilos responsivos
│   └── js/
│       └── dashboard.js        # Funcionalidade JavaScript
```

### **Assets Gerados Automaticamente**
- **HTML**: Interface responsiva com design profissional
- **CSS**: Estilos com tema escuro/claro, animações suaves
- **JavaScript**: Gráficos Chart.js, WebSocket, updates em tempo real

## 🎨 Design e UX

### **Características Visuais**
- ✅ **Design Profissional**: Interface limpa sem emojis
- ✅ **Responsivo**: Funciona em desktop e mobile
- ✅ **Gráficos Interativos**: Chart.js para visualizações
- ✅ **Cores Intuitivas**: Verde (ok), Vermelho (problema), Azul (info)
- ✅ **Animações Suaves**: Transições profissionais

### **Acessibilidade**
- **Contraste Alto**: Legibilidade em diferentes condições
- **Navegação por Teclado**: Suporte completo
- **Indicadores Visuais**: Status claros com cores e texto

## 🛡️ Medidas de Segurança Implementadas

### **1. Isolamento de Rede**
```python
# Servidor bind apenas local
self.host = '127.0.0.1'  # Nunca 0.0.0.0

# Middleware de segurança
@web.middleware
async def _security_middleware(self, request, handler):
    client_ip = request.remote
    if client_ip not in self.allowed_ips:
        raise web.HTTPForbidden(text="Access denied: IP not allowed")
```

### **2. Validação de Entrada**
- **Sanitização**: Todos os inputs são validados
- **Rate Limiting**: Proteção contra spam de requests
- **CORS Restrito**: Apenas origin local permitido

### **3. Logs de Segurança**
```python
# Log de tentativas de acesso negado
self.logger.warning(f"Blocked access attempt from {client_ip}")
```

## 🔍 Monitoramento e Debugging

### **Logs do Dashboard**
```bash
# Logs do servidor web
tail -f /var/log/secguard/secguard.log | grep "Dashboard"

# Status da porta
sudo netstat -tlnp | grep :8888
```

### **Troubleshooting Comum**

#### **Dashboard não inicia**
```bash
# Verificar se a porta está em uso
sudo lsof -i :8888

# Verificar permissões
sudo chown -R root:root /var/lib/secguard
```

#### **Acesso negado**
```bash
# Verificar configuração UFW
sudo ufw status numbered

# Verificar IPs permitidos na configuração
cat /etc/secguard/config.json | jq '.web_dashboard.allowed_ips'
```

## 📈 Performance e Recursos

### **Recursos do Sistema**
- **RAM**: ~50MB para servidor web
- **CPU**: <5% durante operação normal
- **Rede**: Apenas tráfego local

### **Otimizações**
- **Assets Estáticos**: Servidos diretamente pelo aiohttp
- **WebSocket Eficiente**: Apenas clients conectados recebem updates
- **Lazy Loading**: Gráficos carregados sob demanda

## 🚀 Comando de Produção

### **Inicialização Completa**
```bash
# 1. Iniciar dashboard
sudo secguard dashboard --port 8888

# 2. Verificar acesso
curl http://127.0.0.1:8888/api/health

# 3. Verificar firewall
sudo ufw status | grep 8888
```

### **Dashboard como Serviço** (Futuro)
```bash
# Exemplo de systemd service (futuro)
sudo systemctl enable secguard-dashboard
sudo systemctl start secguard-dashboard
```

## 🎯 Exemplo de Uso Completo

```bash
# 1. Configurar sistema
sudo secguard setup

# 2. Habilitar monitoramento
sudo secguard schedule enable hunt weekly

# 3. Iniciar dashboard
sudo secguard dashboard

# 4. Acessar dashboard
# http://127.0.0.1:8888 (abre automaticamente)

# 5. Monitorar em tempo real
# - Ver saúde do sistema
# - Acompanhar ameaças detectadas
# - Verificar jobs agendados
# - Analisar IPs banidos
```

---

## 📋 Resumo dos Benefícios

✅ **Segurança**: Acesso apenas local, firewall configurado automaticamente  
✅ **Profissional**: Interface limpa sem emojis, design empresarial  
✅ **Tempo Real**: Updates automáticos via WebSocket  
✅ **Completo**: Todos os dados do SecGuard em uma interface  
✅ **Responsivo**: Funciona em qualquer dispositivo  
✅ **Fácil**: Um comando para iniciar, zero configuração manual  

**O Dashboard Web do SecGuard Enterprise oferece uma experiência de monitoramento profissional, segura e em tempo real para administradores de sistema.**
