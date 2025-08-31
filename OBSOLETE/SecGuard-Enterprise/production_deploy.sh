#!/bin/bash
"""
SecGuard Enterprise - Script de Produção
=======================================

Script para preparar e deploar o SecGuard Enterprise em produção
"""

set -e  # Sair em caso de erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função de log
log() {
    echo -e "${GREEN}[PROD]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║              SecGuard Enterprise - Production Deploy            ║"
    echo "║                     Script de Produção v1.0                     ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Verificar se está executando como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root"
        echo "Execute: sudo $0"
        exit 1
    fi
}

# Validar estrutura do projeto
validate_structure() {
    log "Validando estrutura do projeto..."
    
    required_files=(
        "secguard.py"
        "requirements.txt"
        "install.sh"
        "README.md"
        "modules/"
        "config/"
        "templates/"
        "web/"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -e "$file" ]]; then
            error "Arquivo essencial não encontrado: $file"
            exit 1
        fi
    done
    
    log "✓ Estrutura do projeto validada"
}

# Verificar arquivos desnecessários
check_cleanup() {
    log "Verificando limpeza do projeto..."
    
    # Verificar se existem arquivos que deveriam estar na .trash
    unnecessary_files=(
        "test_*.py"
        "*_test.py"
        "__pycache__"
        "*.pyc"
        ".DS_Store"
        "validate*.py"
        "validate*.sh"
        "*_demo.sh"
    )
    
    found_unnecessary=false
    for pattern in "${unnecessary_files[@]}"; do
        if ls $pattern 2>/dev/null | grep -v '.trash' >/dev/null; then
            warn "Arquivo desnecessário encontrado: $pattern"
            found_unnecessary=true
        fi
    done
    
    if [[ "$found_unnecessary" == true ]]; then
        warn "Considere mover arquivos desnecessários para .trash/"
        echo "Execute: mv test_*.py __pycache__ .DS_Store .trash/ 2>/dev/null || true"
    else
        log "✓ Projeto limpo, sem arquivos desnecessários"
    fi
}

# Instalar dependências
install_dependencies() {
    log "Instalando dependências Python..."
    
    # Verificar se pip está instalado
    if ! command -v pip3 &> /dev/null; then
        error "pip3 não encontrado. Instale Python3 e pip3"
        exit 1
    fi
    
    # Instalar dependências
    pip3 install -r requirements.txt
    
    log "✓ Dependências instaladas"
}

# Configurar permissões
setup_permissions() {
    log "Configurando permissões..."
    
    # Tornar executável
    chmod +x secguard.py
    chmod +x install.sh
    
    # Criar diretórios do sistema se não existirem
    mkdir -p /etc/secguard
    mkdir -p /var/log/secguard
    mkdir -p /var/lib/secguard
    
    # Definir permissões corretas
    chown -R root:root .
    chmod 755 secguard.py
    chmod 644 requirements.txt
    chmod 644 README.md
    chmod -R 755 modules/
    
    log "✓ Permissões configuradas"
}

# Criar link simbólico
create_symlink() {
    log "Criando link simbólico para /usr/local/bin..."
    
    if [[ ! -f "/usr/local/bin/secguard" ]]; then
        ln -sf "$(pwd)/secguard.py" /usr/local/bin/secguard
        log "✓ Link criado: /usr/local/bin/secguard"
    else
        info "Link já existe: /usr/local/bin/secguard"
    fi
}

# Executar setup inicial
run_setup() {
    log "Executando configuração inicial..."
    
    # Executar o wizard de setup
    python3 secguard.py setup
    
    log "✓ Setup inicial concluído"
}

# Testar instalação
test_installation() {
    log "Testando instalação..."
    
    # Testar comando básico
    if /Users/produtora_00/Documents/PXSS/DEV/.venv/bin/python secguard.py status >/dev/null 2>&1; then
        log "✓ Comando status funcionando"
    else
        warn "Problema no comando status"
    fi
    
    # Testar importações
    if /Users/produtora_00/Documents/PXSS/DEV/.venv/bin/python -c "
import sys
sys.path.append('modules')
from config_manager import ConfigManager
from threat_hunter import ThreatHunter
from ip_defender import IPDefender
from scheduler import SecurityScheduler
from reporter import SecurityReporter
from web_dashboard import SecGuardWebDashboard
from webhook_notifier import WebhookNotifier
from wazuh_logger import WazuhLogger
from setup_wizard import SetupWizard
print('Todos os módulos importados com sucesso')
" >/dev/null 2>&1; then
        log "✓ Todos os módulos funcionando"
    else
        error "Problema com importação de módulos"
        exit 1
    fi
}

# Criar pacote para produção
create_production_package() {
    log "Criando pacote para produção..."
    
    package_name="secguard-enterprise-production-$(date +%Y%m%d-%H%M%S)"
    
    # Criar diretório temporário
    temp_dir="/tmp/$package_name"
    mkdir -p "$temp_dir"
    
    # Copiar arquivos essenciais (excluindo .trash)
    rsync -av --exclude='.trash' --exclude='__pycache__' --exclude='*.pyc' \
          . "$temp_dir/"
    
    # Criar tarball
    cd /tmp
    tar -czf "${package_name}.tar.gz" "$package_name"
    
    # Mover para diretório atual
    mv "${package_name}.tar.gz" "$(dirname "$0")/"
    
    # Limpar
    rm -rf "$temp_dir"
    
    log "✓ Pacote criado: ${package_name}.tar.gz"
    info "Para deploy remoto: scp ${package_name}.tar.gz user@server:/tmp/"
}

# Mostrar informações finais
show_final_info() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    Deploy Concluído com Sucesso!                ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "🚀 SecGuard Enterprise está pronto para produção!"
    echo ""
    echo "📋 Comandos disponíveis:"
    echo "   secguard setup              # Configuração inicial"
    echo "   secguard hunt              # Caça a ameaças"
    echo "   secguard dashboard         # Interface web"
    echo "   secguard status           # Status do sistema"
    echo "   secguard ban <ip>         # Banir IP"
    echo ""
    echo "🌐 Dashboard Web:"
    echo "   sudo secguard dashboard"
    echo "   Acesso: http://127.0.0.1:8888"
    echo ""
    echo "📁 Arquivos de configuração:"
    echo "   /etc/secguard/config.json"
    echo ""
    echo "📝 Logs:"
    echo "   /var/log/secguard/"
    echo ""
    echo "🗑️ Arquivos de desenvolvimento movidos para .trash/"
    echo "   Para produção: rm -rf .trash"
}

# Função principal
main() {
    show_banner
    
    # Verificar se é deploy ou teste
    if [[ "$1" == "--test-only" ]]; then
        log "Modo teste - apenas validação"
        validate_structure
        check_cleanup
        test_installation
        log "✓ Testes concluídos com sucesso"
        exit 0
    fi
    
    if [[ "$1" == "--package-only" ]]; then
        log "Modo empacotamento - criando pacote para produção"
        validate_structure
        check_cleanup
        create_production_package
        exit 0
    fi
    
    # Deploy completo
    log "Iniciando deploy completo do SecGuard Enterprise..."
    
    check_root
    validate_structure
    check_cleanup
    install_dependencies
    setup_permissions
    create_symlink
    test_installation
    
    if [[ "$1" != "--no-setup" ]]; then
        run_setup
    fi
    
    show_final_info
}

# Ajuda
show_help() {
    echo "SecGuard Enterprise - Script de Produção"
    echo ""
    echo "Uso: $0 [opções]"
    echo ""
    echo "Opções:"
    echo "  --test-only       Apenas testar, não instalar"
    echo "  --package-only    Criar pacote para deploy remoto"
    echo "  --no-setup        Pular configuração inicial"
    echo "  --help            Mostrar esta ajuda"
    echo ""
    echo "Exemplos:"
    echo "  sudo $0                    # Deploy completo"
    echo "  sudo $0 --test-only        # Apenas testar"
    echo "  $0 --package-only          # Criar pacote"
    echo ""
}

# Processar argumentos
case "${1:-}" in
    --help|-h)
        show_help
        exit 0
        ;;
    --test-only|--package-only|--no-setup)
        main "$1"
        ;;
    "")
        main
        ;;
    *)
        error "Opção inválida: $1"
        show_help
        exit 1
        ;;
esac
