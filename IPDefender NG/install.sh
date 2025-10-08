#!/bin/bash

# IPDefender Pro Installation Script
# Advanced Cybersecurity Defense Platform
# Author: byFranke (https://byfranke.com)

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ipdefender-pro"
BIN_LINK="/usr/local/bin/ipdefender-pro"
SERVICE_NAME="ipdefender-pro"
CONFIG_DIR="/etc/ipdefender"
LOG_DIR="/var/log/ipdefender"
DATA_DIR="/var/lib/ipdefender"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                      IPDefender Pro                              ║
║            Advanced Cybersecurity Defense Platform               ║
║                                                                  ║
║                        by byFranke                               ║
║                    https://byfranke.com                          ║
║                                                                  ║
║                Installation & Setup Script                       ║
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

log_debug() {
    echo -e "${CYAN}[DEBUG]${NC} $1"
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
    
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "$ID" != "centos" && "$ID" != "rhel" ]]; then
        log_warn "This installer is designed for Ubuntu/Debian/CentOS/RHEL. Your OS: $PRETTY_NAME"
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
        log_info "Installing Python 3..."
        
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y python3 python3-pip python3-venv
        elif command -v yum &> /dev/null; then
            yum install -y python3 python3-pip
        elif command -v dnf &> /dev/null; then
            dnf install -y python3 python3-pip
        else
            log_error "Cannot install Python 3 automatically"
            exit 1
        fi
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log_info "Python version: $PYTHON_VERSION"
    
    # Check if version is >= 3.8
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        log_info "Python version check passed"
    else
        log_error "Python 3.8 or higher is required"
        exit 1
    fi
}

install_system_packages() {
    log_info "Installing system packages..."
    
    # Update package list
    if command -v apt-get &> /dev/null; then
        apt-get update -qq
        
        PACKAGES=(
            "ufw"
            "fail2ban"
            "cron"
            "curl"
            "wget"
            "git"
            "systemd"
            "python3-dev"
            "build-essential"
            "libffi-dev"
            "libssl-dev"
            "sqlite3"
            "nmap"
            "whois"
            "dnsutils"
            "net-tools"
        )
        
        for package in "${PACKAGES[@]}"; do
            if dpkg -l | grep -q "^ii  $package "; then
                log_debug "$package is already installed"
            else
                log_info "Installing $package..."
                apt-get install -y "$package" || {
                    log_warn "Failed to install $package (non-critical)"
                }
            fi
        done
        
    elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
        PKG_MANAGER="yum"
        command -v dnf &> /dev/null && PKG_MANAGER="dnf"
        
        PACKAGES=(
            "firewalld"
            "fail2ban"
            "cronie"
            "curl"
            "wget"
            "git"
            "python3-devel"
            "gcc"
            "openssl-devel"
            "libffi-devel"
            "sqlite"
            "nmap"
            "whois"
            "bind-utils"
            "net-tools"
        )
        
        for package in "${PACKAGES[@]}"; do
            log_info "Installing $package..."
            $PKG_MANAGER install -y "$package" || {
                log_warn "Failed to install $package (non-critical)"
            }
        done
    fi
}

create_directories() {
    log_info "Creating system directories..."
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    
    # Create configuration directory
    mkdir -p "$CONFIG_DIR"
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    # Create data directory
    mkdir -p "$DATA_DIR"/{reports,quarantine,backup}
    
    # Set proper permissions
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"  # Sensitive configuration
    chmod 755 "$LOG_DIR"
    chmod 755 "$DATA_DIR"
    
    log_info "Directories created successfully"
}

create_user() {
    log_info "Creating ipdefender user..."
    
    # Create system user for IPDefender Pro
    if ! id "ipdefender" &> /dev/null; then
        useradd -r -s /bin/false -d "$DATA_DIR" -c "IPDefender Pro Service" ipdefender
        log_info "User 'ipdefender' created"
    else
        log_debug "User 'ipdefender' already exists"
    fi
    
    # Set ownership
    chown -R ipdefender:ipdefender "$DATA_DIR"
    chown -R ipdefender:ipdefender "$LOG_DIR"
    chown -R root:ipdefender "$CONFIG_DIR"
    
    log_info "User configuration completed"
}

install_python_packages() {
    log_info "Setting up Python virtual environment..."
    
    # Create virtual environment
    python3 -m venv "$INSTALL_DIR/venv"
    source "$INSTALL_DIR/venv/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip wheel setuptools
    
    log_info "Installing Python packages..."
    
    # Install requirements
    if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
        pip install -r "$SCRIPT_DIR/requirements.txt" || {
            log_error "Failed to install Python packages"
            exit 1
        }
    else
        log_warn "requirements.txt not found, installing core packages only"
        pip install \
            aiohttp \
            fastapi \
            uvicorn \
            pyyaml \
            click \
            rich \
            structlog \
            cryptography
    fi
    
    log_info "Python packages installed successfully"
}

install_application() {
    log_info "Installing IPDefender Pro application..."
    
    # Copy application files
    cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"
    
    # Copy configuration files
    if [[ -f "$SCRIPT_DIR/config/config.yaml" ]]; then
        cp "$SCRIPT_DIR/config/config.yaml" "$CONFIG_DIR/config.yaml.example"
        if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
            cp "$SCRIPT_DIR/config/config.yaml" "$CONFIG_DIR/config.yaml"
            log_info "Default configuration installed"
        else
            log_warn "Configuration file exists, not overwriting"
        fi
    fi
    
    # Set permissions
    chmod -R 755 "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR/src/main.py"
    
    log_info "Application files installed"
}

create_wrapper_script() {
    log_info "Creating wrapper script..."
    
    cat > "$BIN_LINK" << EOF
#!/bin/bash
# IPDefender Pro Wrapper Script
# by byFranke (https://byfranke.com)

INSTALL_DIR="$INSTALL_DIR"
PYTHON_ENV="\$INSTALL_DIR/venv/bin/python"
MAIN_SCRIPT="\$INSTALL_DIR/src/main.py"
CONFIG_FILE="$CONFIG_DIR/config.yaml"

# Check if installation exists
if [[ ! -f "\$PYTHON_ENV" ]]; then
    echo "Error: IPDefender Pro installation not found at \$INSTALL_DIR"
    exit 1
fi

if [[ ! -f "\$MAIN_SCRIPT" ]]; then
    echo "Error: IPDefender Pro main script not found"
    exit 1
fi

# Check for configuration
if [[ ! -f "\$CONFIG_FILE" ]]; then
    echo "Error: Configuration file not found at \$CONFIG_FILE"
    echo "Please run: ipdefender-pro setup"
    exit 1
fi

# Handle setup command without requiring root
if [[ "\$1" == "setup" || "\$1" == "--help" || "\$1" == "--version" ]]; then
    exec "\$PYTHON_ENV" "\$MAIN_SCRIPT" --config "\$CONFIG_FILE" "\$@"
fi

# Check if running as root for most commands
if [[ \$EUID -ne 0 ]]; then
    echo "Error: Most IPDefender Pro commands require root privileges"
    echo "Please run: sudo ipdefender-pro \$*"
    exit 1
fi

# Execute IPDefender Pro with virtual environment
exec "\$PYTHON_ENV" "\$MAIN_SCRIPT" --config "\$CONFIG_FILE" "\$@"
EOF
    
    chmod +x "$BIN_LINK"
    log_info "Wrapper script created at $BIN_LINK"
}

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=IPDefender Pro - Advanced Cybersecurity Defense Platform
Documentation=https://byfranke.com
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ipdefender
Group=ipdefender
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/src/main.py --config $CONFIG_DIR/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
KillMode=process
TimeoutStopSec=30

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR $LOG_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE

# Environment
Environment=PYTHONPATH=$INSTALL_DIR/src
WorkingDirectory=$INSTALL_DIR

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ipdefender-pro

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    log_info "Systemd service created and enabled"
}

configure_firewall() {
    log_info "Configuring firewall settings..."
    
    # Configure UFW if available
    if command -v ufw &> /dev/null; then
        # Enable UFW if not already enabled
        ufw --force enable 2>/dev/null || log_warn "Failed to enable UFW"
        
        # Allow SSH (be careful not to lock ourselves out)
        ufw allow ssh 2>/dev/null || log_warn "Failed to configure SSH rule"
        
        # Allow API port if configured
        ufw allow 8080/tcp comment "IPDefender Pro API" 2>/dev/null || log_warn "Failed to configure API port"
        
        log_info "UFW configured"
    fi
    
    # Configure fail2ban if available
    if command -v fail2ban-client &> /dev/null; then
        systemctl enable fail2ban 2>/dev/null || log_warn "Failed to enable fail2ban"
        systemctl start fail2ban 2>/dev/null || log_warn "Failed to start fail2ban"
        log_info "Fail2ban configured"
    fi
}

setup_logrotate() {
    log_info "Setting up log rotation..."
    
    cat > /etc/logrotate.d/ipdefender-pro << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 ipdefender ipdefender
    sharedscripts
    postrotate
        systemctl reload ipdefender-pro > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log_info "Log rotation configured"
}

run_initial_setup() {
    log_info "Installation completed successfully!"
    echo
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                    IPDefender Pro                               ║${NC}"
    echo -e "${PURPLE}║                     by byFranke                                 ║${NC}"
    echo -e "${PURPLE}║                 https://byfranke.com                            ║${NC}"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${PURPLE}║                 Installation Complete!                          ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${GREEN}Next steps:${NC}"
    echo "  1. Configure your API keys: sudo nano $CONFIG_DIR/config.yaml"
    echo "  2. Start the service: sudo systemctl start $SERVICE_NAME"
    echo "  3. Check status: sudo systemctl status $SERVICE_NAME"
    echo "  4. View logs: sudo journalctl -u $SERVICE_NAME -f"
    echo "  5. Access API docs: http://localhost:8080/docs"
    echo
    echo -e "${GREEN}Command examples:${NC}"
    echo "  ipdefender-pro --help          # Show help"
    echo "  ipdefender-pro --version       # Show version"
    echo "  sudo ipdefender-pro status     # System status"
    echo
    echo -e "${YELLOW}Important:${NC}"
    echo "  - Configure threat intelligence API keys in config.yaml"
    echo "  - Review firewall provider settings"
    echo "  - Set up notifications if desired"
    echo
    
    read -p "Would you like to start the service now? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Starting IPDefender Pro service..."
        systemctl start "$SERVICE_NAME"
        
        sleep 3
        
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_info "Service started successfully!"
            echo
            echo "API is available at: http://localhost:8080"
            echo "API documentation: http://localhost:8080/docs"
        else
            log_error "Service failed to start. Check logs with:"
            echo "sudo journalctl -u $SERVICE_NAME -f"
        fi
    fi
    
    echo
    echo -e "${CYAN}Thank you for using IPDefender Pro!${NC}"
    echo -e "${CYAN}Visit https://byfranke.com for updates and support${NC}"
}

cleanup() {
    log_debug "Cleaning up temporary files..."
    # Add cleanup logic if needed
}

main() {
    print_banner
    
    log_info "Starting IPDefender Pro installation..."
    
    # Pre-installation checks
    check_root
    check_os
    check_python
    
    # Installation steps
    install_system_packages
    create_directories
    create_user
    install_python_packages
    install_application
    create_wrapper_script
    create_systemd_service
    configure_firewall
    setup_logrotate
    
    # Post-installation
    cleanup
    run_initial_setup
    
    log_info "Installation script completed!"
}

# Handle script interruption
trap cleanup EXIT

# Run main installation
main "$@"
