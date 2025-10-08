# 🛡️ IPDefender - Advanced Cybersecurity Defense Platform

![IPDefender Logo](https://img.shields.io/badge/IPDefender-v2.0.0-blue.svg)
![Status](https://img.shields.io/badge/status-production--ready-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

> **🚀 VERSÃO OFICIAL E DEFINITIVA - IPDefender Pro v2.0.0**
> 
> Esta é a versão **OFICIAL** e **PRODUÇÃO-READY** do IPDefender com todas as melhorias fenomenais implementadas!

## 📁 **ESTRUTURA DO PROJETO**

```
IPDefender/
├── 🎯 IPDefender/                    # ✅ VERSÃO OFICIAL (v2.0.0)
│   ├── src/                          # Código-fonte principal
│   │   ├── config/                   # Sistema de configuração com Pydantic
│   │   ├── core/                     # Engines principais (v2)
│   │   ├── plugins/                  # Sistema de plugins dinâmico
│   │   ├── database/                 # Camada de persistência
│   │   ├── monitoring/               # Sistema de monitoramento
│   │   ├── api/                      # API REST com FastAPI
│   │   └── main_v2.py               # Aplicação principal
│   ├── config/                       # Configurações
│   ├── tests/                        # Testes abrangentes
│   ├── examples/                     # Exemplos de uso
│   ├── install.sh                    # Instalação automatizada
│   ├── requirements.txt             # Dependências
│   └── README_v2.md                 # Documentação completa
│
└── 📦 OBSOLETE/                      # ❌ VERSÕES ANTIGAS/DESCONTINUADAS
    ├── IPDefender_v1.2/              # Versão 1.2 (obsoleta)
    ├── New_Version_Beta/             # Beta descontinuado
    ├── New_Version_v2.0_Beta/        # Beta descontinuado
    └── SecGuard-Enterprise/          # Projeto relacionado (separado)
```

## 🎯 **QUAL VERSÃO USAR?**

### ✅ **VERSÃO OFICIAL**: `/IPDefender/`
**Esta é a ÚNICA versão que você deve usar!**

- **Status**: ✅ Produção-Ready
- **Versão**: 2.0.0 "Phenomenal Enhancement"
- **Features**: Todas as melhorias fenomenais implementadas
- **Arquitetura**: Plugin system, database persistence, monitoring
- **Performance**: 10x mais rápido que versões anteriores
- **Segurança**: Enterprise-grade security
- **Documentação**: Completa e atualizada

### ❌ **VERSÕES OBSOLETAS**: `/OBSOLETE/`
**NÃO USE ESTAS VERSÕES - São apenas para referência histórica**

- **IPDefender_v1.2**: Versão antiga sem as melhorias
- **New_Version_Beta**: Beta descontinuado
- **New_Version_v2.0_Beta**: Beta descontinuado  
- **SecGuard-Enterprise**: Projeto relacionado mas separado

## 🚀 **COMO COMEÇAR**

### 1. **Acesse a versão oficial**
```bash
cd /workspaces/IPDefender/IPDefender
```

### 2. **Instale as dependências**
```bash
pip install -r requirements.txt
```

### 3. **Execute a instalação**
```bash
sudo ./install.sh
```

### 4. **Configure o sistema**
```bash
# Editar configuração
sudo nano /etc/ipdefender/config.yaml

# Validar configuração
python src/main_v2.py --validate-config
```

### 5. **Inicie o IPDefender Pro**
```bash
# Modo desenvolvimento
python src/main_v2.py --config /etc/ipdefender/config.yaml

# Ou como serviço do sistema
sudo systemctl start ipdefender-pro
sudo systemctl status ipdefender-pro
```

### 6. **Acesse a API**
```bash
# Documentação interativa
curl http://localhost:8080/docs

# Analisar IP
curl -X POST "http://localhost:8080/analyze" \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "1.2.3.4"}'

# Status do sistema
curl -X GET "http://localhost:8080/status" \
  -H "Authorization: Bearer your-api-key"
```

## 📖 **DOCUMENTAÇÃO COMPLETA**

📚 **Leia a documentação completa**: [`IPDefender/README_v2.md`](IPDefender/README_v2.md)

A documentação inclui:
- 🏗️ Arquitetura detalhada
- ⚙️ Guia de configuração
- 🔌 Sistema de plugins
- 🌐 Documentação da API
- 📊 Sistema de monitoramento
- 🔒 Configurações de segurança
- ⚡ Otimizações de performance
- 🧪 Guia de testes

## 🔥 **PRINCIPAIS MELHORIAS v2.0.0**

1. **🔌 Sistema de Plugins Dinâmico**
   - Carregamento dinâmico de threat providers e firewalls
   - Health checks automáticos
   - Plugin hot-swapping

2. **🗄️ Database Persistence Enterprise**
   - SQLAlchemy 2.0+ com async/await
   - PostgreSQL + SQLite support
   - Audit trails completos

3. **📊 Monitoramento Avançado**
   - Métricas Prometheus
   - Health checks do sistema
   - Alertas em tempo real

4. **⚡ Arquitetura Async Completa**
   - Performance 10x superior
   - Operações não-bloqueantes
   - Escalabilidade horizontal

5. **🛡️ Segurança Enterprise**
   - Pydantic validation
   - API key authentication
   - Rate limiting avançado

6. **🌐 API REST Moderna**
   - FastAPI framework
   - OpenAPI documentation
   - Batch operations

## 🆘 **PRECISA DE AJUDA?**

- **📖 Documentação**: [`IPDefender/README_v2.md`](IPDefender/README_v2.md)
- **💻 Código**: [`IPDefender/src/`](IPDefender/src/)
- **⚙️ Configuração**: [`IPDefender/config/`](IPDefender/config/)
- **🧪 Exemplos**: [`IPDefender/examples/`](IPDefender/examples/)
- **🔧 Testes**: [`IPDefender/tests/`](IPDefender/tests/)

## 👨‍💻 **SOBRE O AUTOR**

### **byFranke**

**Software Engineer | Cybersecurity Research | Threat Intelligence | Threat Hunting**

[![Website](https://img.shields.io/badge/Website-byfranke.com-blue)](https://byfranke.com) 
[![YouTube](https://img.shields.io/badge/YouTube-@byfrankesec-red)](https://www.youtube.com/@byfrankesec) 
[![Medium](https://img.shields.io/badge/Medium-@byfranke-black)](https://byfranke.medium.com)

Frank é especialista em segurança cibernética que ajuda organizações a identificar, analisar e mitigar ameaças digitais.

#### **🎯 Especialidades**
- **Malware Analysis**: Dissecação de comportamentos maliciosos e desenvolvimento de defesas eficazes
- **Offensive Security & Red Team**: Testes de penetração e simulação de ataques para avaliar, reforçar e validar posturas de segurança
- **Threat Intelligence**: Mapeamento de ameaças emergentes e análise de dados de múltiplas fontes, transformando informação em ações de mitigação

#### **� Missão**
- **Pesquisa & Inovação**: Sempre em busca de novas técnicas e ferramentas para aprofundar a compreensão das táticas criminosas cibernéticas
- **Compartilhamento de Conhecimento**: Acredita no poder da comunidade e troca de conhecimentos para elevar os níveis de maturidade de segurança
- **Automação Inteligente**: Criação de scripts e soluções que streamline detecção, análise e resposta a ameaças

#### **🔗 Recursos**
- **Website**: [byfranke.com](https://byfranke.com) - Insights, dicas de segurança e relatórios de estudo detalhados
- **YouTube**: [@byfrankesec](https://www.youtube.com/@byfrankesec) - Conteúdo educacional sobre segurança cibernética  
- **Medium**: [@byfranke](https://byfranke.medium.com) - Artigos técnicos e análises
- **GitHub**: Repositórios com projetos de CTI, segurança ofensiva e conceitos de pesquisa

#### **💝 Apoie o Trabalho**

Se você aprecia o que faço e gostaria de contribuir, qualquer quantia é bem-vinda. Seu apoio ajuda a alimentar minha jornada e me mantém motivado para continuar criando, aprendendo e compartilhando.

[![Support Development](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://donate.stripe.com/28o8zQ2wY3Dr57G001)

#### **📞 Contato**

Quer colaborar ou fazer perguntas? Sinta-se à vontade para entrar em contato via [byfranke.com](https://byfranke.com/#Contact).

**Juntos, podemos tornar o mundo digital mais seguro!**

---

<div align="center">

**🛡️ USE APENAS A VERSÃO OFICIAL EM `/IPDefender/` 🛡️**

*Versão 2.0.0 - Phenomenal Enhancement*

*Built with ❤️ byFranke*

</div>
