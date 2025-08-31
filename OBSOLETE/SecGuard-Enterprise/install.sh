#!/bin/bash

# SecGuard Enterprise Installation Script
# =====================================

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/secguard"
BIN_LINK="/usr/local/bin/secguard"
SERVICE_NAME="secguard"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                    SecGuard Enterprise                          ║
║              Advanced Server Security Platform                  ║
║                        Installation                             ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine operating system"
        exit 1
    fi
    
    source /etc/os-release
    
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        log_warn "This installer is designed for Ubuntu/Debian. Your OS: $PRETTY_NAME"
        read -p "Continue anyway? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log_info "Operating System: $PRETTY_NAME"
    fi
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log_info "Python version: $PYTHON_VERSION"
    
    # Check if version is >= 3.7
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 7) else 1)'; then
        log_info "Python version check passed"
    else
        log_error "Python 3.7 or higher is required"
        exit 1
    fi
}

install_system_packages() {
    log_info "Installing system packages..."
    
    # Update package list
    apt-get update -qq
    
    # Install required packages
    PACKAGES=(
        "ufw"
        "fail2ban"
        "cron"
        "curl"
        "wget"
        "python3-pip"
        "python3-venv"
        "git"
        "systemd"
    )
    
    for package in "${PACKAGES[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            log_info "$package is already installed"
        else
            log_info "Installing $package..."
            apt-get install -y "$package" || {
                log_error "Failed to install $package"
                exit 1
            }
        fi
    done
}

install_python_packages() {
    log_info "Installing Python packages..."
    
    # Create virtual environment
    python3 -m venv "$INSTALL_DIR/venv"
    source "$INSTALL_DIR/venv/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install required packages
    pip install \
        psutil \
        aiohttp \
        keyring \
        jinja2 \
        croniter \
        ipaddress \
        || {
        log_error "Failed to install Python packages"
        exit 1
    }
    
    log_info "Python packages installed successfully"
}

create_install_directory() {
    log_info "Creating installation directory..."
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    
    # Copy application files
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    
    # Set permissions
    chmod -R 755 "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR/secguard.py"
    
    log_info "Files copied to $INSTALL_DIR"
}

create_wrapper_script() {
    log_info "Creating wrapper script..."
    
    cat > "$BIN_LINK" << EOF
#!/bin/bash
# SecGuard Enterprise Wrapper Script

INSTALL_DIR="$INSTALL_DIR"
PYTHON_ENV="\$INSTALL_DIR/venv/bin/python"

# Check if virtual environment exists
if [[ ! -f "\$PYTHON_ENV" ]]; then
    echo "Error: SecGuard installation not found at \$INSTALL_DIR"
    exit 1
fi

# Check if running as root for most commands
if [[ \$EUID -ne 0 && "\$1" != "setup" && "\$1" != "--version" && "\$1" != "--help" ]]; then
    echo "Error: Most SecGuard commands require root privileges"
    echo "Please run: sudo secguard \$*"
    exit 1
fi

# Execute SecGuard with virtual environment
exec "\$PYTHON_ENV" "\$INSTALL_DIR/secguard.py" "\$@"
EOF
    
    chmod +x "$BIN_LINK"
    log_info "Wrapper script created at $BIN_LINK"
}

enable_services() {
    log_info "Enabling system services..."
    
    # Enable and start UFW
    systemctl enable ufw 2>/dev/null || true
    ufw --force enable 2>/dev/null || log_warn "Failed to enable UFW"
    
    # Enable and start Fail2Ban
    systemctl enable fail2ban 2>/dev/null || true
    systemctl start fail2ban 2>/dev/null || log_warn "Failed to start Fail2Ban"
    
    # Enable and start Cron
    systemctl enable cron 2>/dev/null || true
    systemctl start cron 2>/dev/null || log_warn "Failed to start Cron"
    
    log_info "System services configured"
}

create_config_directories() {
    log_info "Creating configuration directories..."
    
    # Create system directories
    mkdir -p /etc/secguard
    mkdir -p /var/log/secguard
    mkdir -p /var/lib/secguard/{reports,quarantine}
    
    # Set proper permissions
    chmod 700 /etc/secguard
    chmod 755 /var/log/secguard
    chmod 755 /var/lib/secguard
    chmod 755 /var/lib/secguard/reports
    chmod 755 /var/lib/secguard/quarantine
    
    log_info "Configuration directories created"
}

setup_logrotate() {
    log_info "Setting up log rotation..."
    
    cat > /etc/logrotate.d/secguard << EOF
/var/log/secguard/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log_info "Log rotation configured"
}

run_initial_setup() {
    log_info "SecGuard installed successfully!"
    echo
    echo "Next steps:"
    echo "1. Run the setup wizard: sudo secguard setup"
    echo "2. Check system status: sudo secguard status"
    echo "3. Run a security scan: sudo secguard hunt --all"
    echo
    echo "For help: secguard --help"
    echo
    
    read -p "Would you like to run the setup wizard now? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Starting setup wizard..."
        "$BIN_LINK" setup
    fi
}

cleanup() {
    log_info "Cleaning up temporary files..."
    # Add cleanup logic if needed
}

main() {
    print_banner
    
    log_info "Starting SecGuard Enterprise installation..."
    
    # Pre-installation checks
    check_root
    check_os
    check_python
    
    # Installation steps
    install_system_packages
    create_install_directory
    install_python_packages
    create_wrapper_script
    enable_services
    create_config_directories
    setup_logrotate
    
    # Post-installation
    cleanup
    run_initial_setup
    
    log_info "Installation completed successfully!"
}

# Handle script interruption
trap cleanup EXIT

# Run main installation
main "$@"
