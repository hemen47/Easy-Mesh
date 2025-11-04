#!/bin/bash

#############################################################################
# EasyMesh - Professional EasyTier VPN Management Script
# Version: 1.0.0 Stable
# Author: Musixal
# Telegram: @Gozar_Xray
# GitHub: github.com/Musixal/easy-mesh
# License: MIT
#############################################################################

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

#############################################################################
# CONFIGURATION CONSTANTS
#############################################################################

readonly SCRIPT_VERSION="1.0.0"
readonly EASYTIER_VERSION="v1.2.0"
readonly INSTALL_DIR="/opt/easytier"
readonly CONFIG_DIR="/etc/easytier"
readonly SERVICE_NAME="easymesh.service"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
readonly WATCHDOG_SERVICE="easymesh-watchdog.service"
readonly WATCHDOG_FILE="/etc/systemd/system/${WATCHDOG_SERVICE}"
readonly LOG_FILE="/var/log/easymesh.log"
readonly LOCK_FILE="/var/lock/easymesh.lock"

# Binary paths
readonly EASYTIER_CORE="${INSTALL_DIR}/easytier-core"
readonly EASYTIER_CLI="${INSTALL_DIR}/easytier-cli"

# Download URLs
readonly BASE_URL="https://github.com/Musixal/Easy-Mesh/raw/main/core/${EASYTIER_VERSION}"
readonly URL_X86="${BASE_URL}/easytier-linux-x86_64/"
readonly URL_ARM="${BASE_URL}/easytier-linux-armv7/"
readonly URL_ARM_HF="${BASE_URL}/easytier-linux-armv7hf/"

#############################################################################
# COLOR CODES
#############################################################################

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly RESET='\033[0m'
readonly BOLD='\033[1m'

#############################################################################
# UTILITY FUNCTIONS
#############################################################################

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}" 2>/dev/null || true
}

# Print colored output
print_color() {
    local color="$1"
    local message="$2"
    local style="${3:-}"

    case "$color" in
        red) echo -e "${style}${RED}${message}${RESET}" ;;
        green) echo -e "${style}${GREEN}${message}${RESET}" ;;
        yellow) echo -e "${style}${YELLOW}${message}${RESET}" ;;
        blue) echo -e "${style}${BLUE}${message}${RESET}" ;;
        magenta) echo -e "${style}${MAGENTA}${message}${RESET}" ;;
        cyan) echo -e "${style}${CYAN}${message}${RESET}" ;;
        white) echo -e "${style}${WHITE}${message}${RESET}" ;;
        *) echo -e "${message}" ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_color red "❌ This script must be run as root (use sudo)" "${BOLD}"
        exit 1
    fi
}

# Press any key to continue
press_key() {
    echo ""
    read -rp "Press Enter to continue..."
}

# Validate IP address
validate_ip() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ $ip =~ $regex ]]; then
        for octet in $(echo "$ip" | tr '.' ' '); do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Validate port number
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0
    fi
    return 1
}

# Generate random network secret
generate_secret() {
    openssl rand -hex 12 2>/dev/null || head -c 12 /dev/urandom | xxd -p
}

# Detect system architecture
detect_architecture() {
    local arch=$(uname -m)

    case "$arch" in
        x86_64)
            echo "$URL_X86"
            ;;
        armv7l|aarch64)
            if ldd /bin/ls 2>/dev/null | grep -q 'armhf'; then
                echo "$URL_ARM_HF"
            else
                echo "$URL_ARM"
            fi
            ;;
        *)
            print_color red "❌ Unsupported architecture: $arch" "${BOLD}"
            exit 1
            ;;
    esac
}

# Check if service exists
service_exists() {
    [[ -f "$SERVICE_FILE" ]]
}

# Check if core is installed
core_installed() {
    [[ -f "$EASYTIER_CORE" ]] && [[ -f "$EASYTIER_CLI" ]]
}

#############################################################################
# INSTALLATION FUNCTIONS
#############################################################################

# Install required dependencies
install_dependencies() {
    log "INFO" "Checking and installing dependencies..."

    local packages=("curl" "wget" "openssl" "systemd")
    local missing_packages=()

    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            missing_packages+=("$pkg")
        fi
    done

    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        print_color yellow "📦 Installing missing packages: ${missing_packages[*]}"

        if command -v apt-get &>/dev/null; then
            apt-get update -qq
            apt-get install -y -qq "${missing_packages[@]}"
        elif command -v yum &>/dev/null; then
            yum install -y -q "${missing_packages[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y -q "${missing_packages[@]}"
        else
            print_color red "❌ Unsupported package manager"
            exit 1
        fi
    fi
}

# Install EasyTier core
install_core() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   📥 EasyTier Core Installation" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if core_installed; then
        print_color green "✅ EasyTier core is already installed" "${BOLD}"
        echo ""
        read -rp "Do you want to reinstall? (y/N): " reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi

    log "INFO" "Starting EasyTier core installation..."

    # Detect architecture
    local download_url=$(detect_architecture)
    print_color blue "🔍 Detected architecture: $(uname -m)"
    print_color blue "📡 Download URL: $download_url"
    echo ""

    # Create installation directory
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

    # Download binaries
    print_color yellow "⬇️  Downloading easytier-core..."
    if ! curl -fsSL "${download_url}easytier-core" -o "${EASYTIER_CORE}"; then
        print_color red "❌ Failed to download easytier-core"
        log "ERROR" "Failed to download easytier-core from $download_url"
        exit 1
    fi

    print_color yellow "⬇️  Downloading easytier-cli..."
    if ! curl -fsSL "${download_url}easytier-cli" -o "${EASYTIER_CLI}"; then
        print_color red "❌ Failed to download easytier-cli"
        log "ERROR" "Failed to download easytier-cli from $download_url"
        exit 1
    fi

    # Set permissions
    chmod +x "$EASYTIER_CORE" "$EASYTIER_CLI"

    # Verify installation
    if core_installed; then
        print_color green "✅ EasyTier core installed successfully!" "${BOLD}"
        log "INFO" "EasyTier core installed successfully"

        # Display version
        local version=$("$EASYTIER_CORE" --version 2>/dev/null || echo "Unknown")
        print_color cyan "📌 Version: $version"
    else
        print_color red "❌ Installation failed"
        log "ERROR" "Installation verification failed"
        exit 1
    fi

    echo ""
    press_key
}

# Remove EasyTier core
remove_core() {
    clear
    print_color red "═══════════════════════════════════════" "${BOLD}"
    print_color red "   🗑️  Remove EasyTier Core" "${BOLD}"
    print_color red "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if service_exists; then
        print_color red "❌ Service is still active. Please remove the service first."
        log "WARN" "Attempted to remove core while service exists"
        press_key
        return 1
    fi

    if ! core_installed; then
        print_color yellow "⚠️  EasyTier core is not installed"
        press_key
        return 0
    fi

    print_color yellow "⚠️  This will permanently delete EasyTier core files"
    read -rp "Are you sure? (y/N): " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
        print_color green "✅ EasyTier core removed successfully"
        log "INFO" "EasyTier core removed"
    else
        print_color blue "ℹ️  Operation cancelled"
    fi

    echo ""
    press_key
}

#############################################################################
# NETWORK CONFIGURATION
#############################################################################

# Configure and start EasyMesh network
configure_network() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🌐 EasyMesh Network Configuration" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! core_installed; then
        print_color red "❌ EasyTier core is not installed. Please install it first."
        press_key
        return 1
    fi

    if service_exists; then
        print_color yellow "⚠️  A service configuration already exists"
        read -rp "Do you want to reconfigure? (y/N): " reconfig
        if [[ ! "$reconfig" =~ ^[Yy]$ ]]; then
            return 0
        fi
        stop_service
    fi

    log "INFO" "Starting network configuration..."

    # Configuration variables
    local ipv4_address hostname network_name network_secret
    local peer_addresses port protocol
    local enable_encryption="yes"
    local enable_ipv6="no"
    local enable_multi_thread="no"

    # Display configuration guide
    print_color yellow "📖 Configuration Guide:" "${BOLD}"
    echo ""
    echo "  • Leave peer addresses empty for reverse connection mode"
    echo "  • UDP protocol is recommended for better stability"
    echo "  • Use strong network secrets (min 12 characters)"
    echo "  • Disable encryption only for testing purposes"
    echo ""
    print_color cyan "─────────────────────────────────────────"
    echo ""

    # Get peer addresses
    read -rp "🔗 Peer addresses (comma-separated, or empty): " peer_addresses

    # Get local IPv4 address
    while true; do
        read -rp "🏠 Local IPv4 address (e.g., 10.144.144.1): " ipv4_address
        if [[ -z "$ipv4_address" ]]; then
            print_color red "❌ IPv4 address cannot be empty"
            continue
        fi
        if validate_ip "$ipv4_address"; then
            break
        else
            print_color red "❌ Invalid IPv4 address format"
        fi
    done

    # Get hostname
    while true; do
        read -rp "💻 Hostname (e.g., Server-Iran-1): " hostname
        if [[ -n "$hostname" ]]; then
            break
        fi
        print_color red "❌ Hostname cannot be empty"
    done

    # Get network name
    while true; do
        read -rp "🌐 Network name (e.g., my-vpn-network): " network_name
        if [[ -n "$network_name" ]]; then
            break
        fi
        print_color red "❌ Network name cannot be empty"
    done

    # Get port
    while true; do
        read -rp "🔌 Listen port (default: 11010): " port
        port=${port:-11010}
        if validate_port "$port"; then
            break
        fi
        print_color red "❌ Invalid port number (1-65535)"
    done

    # Generate and confirm network secret
    local generated_secret=$(generate_secret)
    echo ""
    print_color cyan "🔐 Generated network secret: ${BOLD}$generated_secret"
    read -rp "Enter network secret (press Enter to use generated): " network_secret
    network_secret=${network_secret:-$generated_secret}

    # Select protocol
    echo ""
    print_color green "📡 Select Protocol:" "${BOLD}"
    echo "  1) TCP"
    echo "  2) UDP (Recommended)"
    echo "  3) WebSocket (WS)"
    echo "  4) WebSocket Secure (WSS)"
    echo ""
    read -rp "Select protocol [1-4] (default: 2): " protocol_choice
    protocol_choice=${protocol_choice:-2}

    case "$protocol_choice" in
        1) protocol="tcp" ;;
        2) protocol="udp" ;;
        3) protocol="ws" ;;
        4) protocol="wss" ;;
        *) protocol="udp" ;;
    esac

    # Encryption option
    echo ""
    read -rp "🔒 Enable encryption? (Y/n): " enable_encryption
    enable_encryption=${enable_encryption:-yes}

    # IPv6 option
    read -rp "🌍 Enable IPv6? (y/N): " enable_ipv6
    enable_ipv6=${enable_ipv6:-no}

    # Multi-thread option
    read -rp "⚡ Enable multi-thread? (y/N): " enable_multi_thread
    enable_multi_thread=${enable_multi_thread:-no}

    # Build command options
    local cmd_options="--ipv4 $ipv4_address"
    cmd_options+=" --hostname $hostname"
    cmd_options+=" --network-name $network_name"
    cmd_options+=" --network-secret $network_secret"
    cmd_options+=" --default-protocol $protocol"

    # Add listeners
    cmd_options+=" --listeners ${protocol}://0.0.0.0:${port}"
if [[ "$enable_ipv6" =~ ^[Yy]$ ]]; then
    cmd_options+=" --listeners ${protocol}://[::]:${port} ${protocol}://0.0.0.0:${port}"
else
    cmd_options+=" --listeners ${protocol}://0.0.0.0:${port}"
    cmd_options+=" --disable-ipv6"
fi

    # Add peer addresses
    if [[ -n "$peer_addresses" ]]; then
        IFS=',' read -ra peers <<< "$peer_addresses"
        for peer in "${peers[@]}"; do
            peer=$(echo "$peer" | xargs)  # Trim whitespace
            if [[ -n "$peer" ]]; then
                # Handle IPv6 addresses
                if [[ "$peer" == *:*:* ]] && [[ "$peer" != \[*\] ]]; then
                    peer="[$peer]"
                fi
                cmd_options+=" --peers ${protocol}://${peer}:${port}"
            fi
        done
    fi

    # Add encryption option
    if [[ ! "$enable_encryption" =~ ^[Yy]$ ]]; then
        cmd_options+=" --disable-encryption"
    fi

    # Add multi-thread option
    if [[ "$enable_multi_thread" =~ ^[Yy]$ ]]; then
        cmd_options+=" --multi-thread"
    fi

    # Create systemd service
    create_service "$cmd_options"

    # Start service
    start_service

    # Display configuration summary
    echo ""
    print_color green "═══════════════════════════════════════" "${BOLD}"
    print_color green "   ✅ Configuration Summary" "${BOLD}"
    print_color green "═══════════════════════════════════════" "${BOLD}"
    echo ""
    print_color cyan "  IPv4 Address: $ipv4_address"
    print_color cyan "  Hostname: $hostname"
    print_color cyan "  Network Name: $network_name"
    print_color cyan "  Network Secret: $network_secret"
    print_color cyan "  Protocol: $protocol"
    print_color cyan "  Port: $port"
    print_color cyan "  Encryption: $([ "$enable_encryption" =~ ^[Yy]$ ] && echo 'Enabled' || echo 'Disabled')"
    print_color cyan "  IPv6: $([ "$enable_ipv6" =~ ^[Yy]$ ] && echo 'Enabled' || echo 'Disabled')"
    print_color cyan "  Multi-thread: $([ "$enable_multi_thread" =~ ^[Yy]$ ] && echo 'Enabled' || echo 'Disabled')"
    echo ""

    log "INFO" "Network configured: $hostname ($ipv4_address)"

    press_key
}

#############################################################################
# SERVICE MANAGEMENT
#############################################################################

# Create systemd service
create_service() {
    local cmd_options="$1"

    log "INFO" "Creating systemd service..."

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EasyMesh Network Service ${EASYTIER_VERSION}
Documentation=https://easytier.cn
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${EASYTIER_CORE} ${cmd_options}
Restart=always
RestartSec=5
StartLimitInterval=0
StartLimitBurst=0

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=easymesh

# Process management
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=10
TimeoutStartSec=30

# Security hardening
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR} ${CONFIG_DIR} /var/log

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "INFO" "Service file created successfully"
}

# Start service
start_service() {
    print_color yellow "🚀 Starting EasyMesh service..."

    if systemctl enable --now "$SERVICE_NAME" &>/dev/null; then
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_color green "✅ Service started successfully" "${BOLD}"
            log "INFO" "Service started successfully"
        else
            print_color red "❌ Service failed to start"
            print_color yellow "📋 Checking logs..."
            journalctl -u "$SERVICE_NAME" -n 20 --no-pager
            log "ERROR" "Service failed to start"
        fi
    else
        print_color red "❌ Failed to enable service"
        log "ERROR" "Failed to enable service"
    fi
}

# Stop service
stop_service() {
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_color yellow "⏸️  Stopping EasyMesh service..."
        systemctl stop "$SERVICE_NAME"
        print_color green "✅ Service stopped"
        log "INFO" "Service stopped"
    fi
}

# Restart service
restart_service() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🔄 Restart EasyMesh Service" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ Service does not exist"
        press_key
        return 1
    fi

    print_color yellow "🔄 Restarting service..."

    if systemctl restart "$SERVICE_NAME" &>/dev/null; then
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_color green "✅ Service restarted successfully" "${BOLD}"
            log "INFO" "Service restarted"
        else
            print_color red "❌ Service failed to restart"
            log "ERROR" "Service failed to restart"
        fi
    else
        print_color red "❌ Failed to restart service"
        log "ERROR" "Failed to restart service"
    fi

    echo ""
    press_key
}

# Remove service
remove_service() {
    clear
    print_color red "═══════════════════════════════════════" "${BOLD}"
    print_color red "   🗑️  Remove EasyMesh Service" "${BOLD}"
    print_color red "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color yellow "⚠️  Service does not exist"
        press_key
        return 0
    fi

    print_color yellow "⚠️  This will stop and remove the EasyMesh service"
    read -rp "Are you sure? (y/N): " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_color blue "ℹ️  Operation cancelled"
        press_key
        return 0
    fi

    # Stop service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_color yellow "⏸️  Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi

    # Disable service
    print_color yellow "🔓 Disabling service..."
    systemctl disable "$SERVICE_NAME" &>/dev/null

    # Remove service file
    print_color yellow "🗑️  Removing service file..."
    rm -f "$SERVICE_FILE"

    # Reload systemd
    systemctl daemon-reload

    print_color green "✅ Service removed successfully" "${BOLD}"
    log "INFO" "Service removed"

    echo ""
    press_key
}

# View service status
view_status() {
    clear

    if ! service_exists; then
        print_color red "❌ Service does not exist"
        press_key
        return 1
    fi

    systemctl status "$SERVICE_NAME" --no-pager -l
    echo ""
    press_key
}

#############################################################################
# NETWORK MONITORING
#############################################################################

# Display peers
display_peers() {
    clear

    if ! core_installed; then
        print_color red "❌ EasyTier core is not installed"
        press_key
        return 1
    fi

    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   👥 Network Peers (Auto-refresh)" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""
    print_color yellow "Press Ctrl+C to exit"
    echo ""

    watch -n 1 -c "$EASYTIER_CLI peer"
}

# Display routes
display_routes() {
    clear

    if ! core_installed; then
        print_color red "❌ EasyTier core is not installed"
        press_key
        return 1
    fi

    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🛣️  Network Routes (Auto-refresh)" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""
    print_color yellow "Press Ctrl+C to exit"
    echo ""

    watch -n 1 -c "$EASYTIER_CLI route"
}

# Display peer center
display_peer_center() {
    clear

    if ! core_installed; then
        print_color red "❌ EasyTier core is not installed"
        press_key
        return 1
    fi

    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🎯 Peer Center (Auto-refresh)" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""
    print_color yellow "Press Ctrl+C to exit"
    echo ""

    watch -n 1 -c "$EASYTIER_CLI peer-center"
}

# Show network secret
show_secret() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🔐 Network Secret Key" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ Service does not exist"
        press_key
        return 1
    fi

    local secret=$(grep -oP '(?<=--network-secret )[^ ]+' "$SERVICE_FILE" 2>/dev/null)

    if [[ -n "$secret" ]]; then
        print_color green "🔑 Network Secret: ${BOLD}$secret"
        echo ""
        print_color yellow "⚠️  Keep this secret safe and share only with trusted nodes"
    else
        print_color red "❌ Network secret not found in configuration"
    fi

    echo ""
    press_key
}

#############################################################################
# WATCHDOG FUNCTIONS
#############################################################################

# Configure watchdog
configure_watchdog() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🐕 Watchdog Configuration" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    # Check watchdog status
    if systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
        print_color green "✅ Watchdog is currently running" "${BOLD}"
    else
        print_color red "❌ Watchdog is not running" "${BOLD}"
    fi

    echo ""
    print_color cyan "─────────────────────────────────────────"
    echo ""
    print_color green "1) Start/Configure Watchdog"
    print_color red "2) Stop Watchdog"
    print_color yellow "3) View Watchdog Logs"
    print_color white "4) Back to Main Menu"
    echo ""

    read -rp "Select option [1-4]: " choice

    case "$choice" in
        1) start_watchdog ;;
        2) stop_watchdog ;;
        3) view_watchdog_logs ;;
        4) return 0 ;;
        *) print_color red "❌ Invalid option" && sleep 1 ;;
    esac
}

# Start watchdog
start_watchdog() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🐕 Start Watchdog Service" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ EasyMesh service does not exist"
        press_key
        return 1
    fi

    print_color yellow "📖 Watchdog monitors network latency and restarts the service if needed"
    print_color yellow "⚠️  Recommended to run on external (Kharej) servers only"
    echo ""

    # Get configuration
    local monitor_ip latency_threshold check_interval

    read -rp "🎯 IP address to monitor: " monitor_ip
    if ! validate_ip "$monitor_ip"; then
        print_color red "❌ Invalid IP address"
        press_key
        return 1
    fi

    read -rp "⏱️  Latency threshold in ms (default: 200): " latency_threshold
    latency_threshold=${latency_threshold:-200}

    read -rp "🔄 Check interval in seconds (default: 10): " check_interval
    check_interval=${check_interval:-10}

    # Stop existing watchdog
    if systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
        systemctl stop "$WATCHDOG_SERVICE"
    fi

    # Create watchdog script
    local watchdog_script="/opt/easytier/watchdog.sh"

    cat > "$watchdog_script" <<'WATCHDOG_EOF'
#!/bin/bash

# Watchdog Configuration
MONITOR_IP="REPLACE_IP"
LATENCY_THRESHOLD=REPLACE_THRESHOLD
CHECK_INTERVAL=REPLACE_INTERVAL
SERVICE_NAME="easymesh.service"
LOG_FILE="/var/log/easymesh-watchdog.log"

# Maximum log file size (10MB)
MAX_LOG_SIZE=$((10 * 1024 * 1024))

# Rotate log if too large
rotate_log() {
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE") -gt $MAX_LOG_SIZE ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Log rotated" > "$LOG_FILE"
    fi
}

# Log function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Restart service
restart_service() {
    log_message "Restarting $SERVICE_NAME..."
    if systemctl restart "$SERVICE_NAME"; then
        log_message "Service restarted successfully"
    else
        log_message "ERROR: Failed to restart service"
    fi
}

# Calculate average latency
get_average_latency() {
    local latencies=$(ping -c 3 -W 2 -i 0.2 "$MONITOR_IP" 2>/dev/null | grep 'time=' | sed -n 's/.*time=\([0-9.]*\).*/\1/p')

    if [[ -z "$latencies" ]]; then
        echo "0"
        return
    fi

    local total=0
    local count=0

    while IFS= read -r latency; do
        total=$(echo "$total + $latency" | bc)
        ((count++))
    done <<< "$latencies"

    if [[ $count -gt 0 ]]; then
        echo "scale=2; $total / $count" | bc
    else
        echo "0"
    fi
}

# Main loop
log_message "Watchdog started - Monitoring $MONITOR_IP (threshold: ${LATENCY_THRESHOLD}ms, interval: ${CHECK_INTERVAL}s)"

while true; do
    rotate_log

    avg_latency=$(get_average_latency)

    if [[ "$avg_latency" == "0" ]]; then
        log_message "ALERT: Cannot ping $MONITOR_IP - Restarting service"
        restart_service
    else
        latency_int=${avg_latency%.*}

        if [[ $latency_int -gt $LATENCY_THRESHOLD ]]; then
            log_message "ALERT: High latency detected (${avg_latency}ms > ${LATENCY_THRESHOLD}ms) - Restarting service"
            restart_service
        else
            log_message "OK: Latency ${avg_latency}ms (threshold: ${LATENCY_THRESHOLD}ms)"
        fi
    fi

    sleep "$CHECK_INTERVAL"
done
WATCHDOG_EOF

    # Replace placeholders
    sed -i "s/REPLACE_IP/$monitor_ip/g" "$watchdog_script"
    sed -i "s/REPLACE_THRESHOLD/$latency_threshold/g" "$watchdog_script"
    sed -i "s/REPLACE_INTERVAL/$check_interval/g" "$watchdog_script"

    chmod +x "$watchdog_script"

    # Create watchdog service
    cat > "$WATCHDOG_FILE" <<EOF
[Unit]
Description=EasyMesh Watchdog Service
Documentation=https://github.com/Musixal/easy-mesh
After=network-online.target ${SERVICE_NAME}
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash ${watchdog_script}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=easymesh-watchdog

[Install]
WantedBy=multi-user.target
EOF

    # Start watchdog
    systemctl daemon-reload

    if systemctl enable --now "$WATCHDOG_SERVICE" &>/dev/null; then
        print_color green "✅ Watchdog started successfully" "${BOLD}"
        echo ""
        print_color cyan "  Monitor IP: $monitor_ip"
        print_color cyan "  Latency Threshold: ${latency_threshold}ms"
        print_color cyan "  Check Interval: ${check_interval}s"
        log "INFO" "Watchdog started: monitoring $monitor_ip"
    else
        print_color red "❌ Failed to start watchdog"
        log "ERROR" "Failed to start watchdog"
    fi

    echo ""
    press_key
}

# Stop watchdog
stop_watchdog() {
    echo ""

    if ! systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
        print_color yellow "⚠️  Watchdog is not running"
        sleep 2
        return 0
    fi

    print_color yellow "⏸️  Stopping watchdog..."

    systemctl stop "$WATCHDOG_SERVICE"
    systemctl disable "$WATCHDOG_SERVICE" &>/dev/null
    rm -f "$WATCHDOG_FILE" /opt/easytier/watchdog.sh
    systemctl daemon-reload

    print_color green "✅ Watchdog stopped and removed" "${BOLD}"
    log "INFO" "Watchdog stopped"

    sleep 2
}

# View watchdog logs
view_watchdog_logs() {
    clear

    if [[ -f /var/log/easymesh-watchdog.log ]]; then
        print_color cyan "═══════════════════════════════════════" "${BOLD}"
        print_color cyan "   📋 Watchdog Logs" "${BOLD}"
        print_color cyan "═══════════════════════════════════════" "${BOLD}"
        echo ""
        tail -f /var/log/easymesh-watchdog.log
    else
        print_color yellow "⚠️  No watchdog logs found"
        press_key
    fi
}

#############################################################################
# CRON JOB MANAGEMENT
#############################################################################

# Configure cron job
configure_cronjob() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   ⏰ Cron Job Configuration" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    print_color green "1) Add Cron Job"
    print_color red "2) Remove Cron Job"
    print_color white "3) Back to Main Menu"
    echo ""

    read -rp "Select option [1-3]: " choice

    case "$choice" in
        1) add_cronjob ;;
        2) remove_cronjob ;;
        3) return 0 ;;
        *) print_color red "❌ Invalid option" && sleep 1 ;;
    esac
}

# Add cron job
add_cronjob() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   ⏰ Add Cron Job" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ EasyMesh service does not exist"
        press_key
        return 1
    fi

    print_color yellow "Select restart interval:"
    echo ""
    echo "  1) Every 30 minutes"
    echo "  2) Every 1 hour"
    echo "  3) Every 2 hours"
    echo "  4) Every 4 hours"
    echo "  5) Every 6 hours"
    echo "  6) Every 12 hours"
    echo "  7) Every 24 hours"
    echo ""

    read -rp "Select option [1-7]: " interval_choice

    local cron_schedule
    case "$interval_choice" in
        1) cron_schedule="*/30 * * * *" ;;
        2) cron_schedule="0 * * * *" ;;
        3) cron_schedule="0 */2 * * *" ;;
        4) cron_schedule="0 */4 * * *" ;;
        5) cron_schedule="0 */6 * * *" ;;
        6) cron_schedule="0 */12 * * *" ;;
        7) cron_schedule="0 0 * * *" ;;
        *)
            print_color red "❌ Invalid option"
            press_key
            return 1
            ;;
    esac

    # Remove existing cron job
    remove_cronjob &>/dev/null

    # Create restart script
    local restart_script="/opt/easytier/restart.sh"

    cat > "$restart_script" <<'EOF'
#!/bin/bash
# EasyMesh Auto-Restart Script
LOG_FILE="/var/log/easymesh-cron.log"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Scheduled restart initiated" >> "$LOG_FILE"

# Kill any hanging processes
pkill -9 easytier-core 2>/dev/null

# Restart service
systemctl daemon-reload
systemctl restart easymesh.service

if systemctl is-active --quiet easymesh.service; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Service restarted successfully" >> "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Service failed to restart" >> "$LOG_FILE"
fi
EOF

    chmod +x "$restart_script"

    # Add to crontab
    (crontab -l 2>/dev/null | grep -v "#easymesh-restart"; echo "$cron_schedule $restart_script #easymesh-restart") | crontab -

    print_color green "✅ Cron job added successfully" "${BOLD}"
    echo ""
    print_color cyan "  Schedule: $cron_schedule"
    print_color cyan "  Script: $restart_script"
    log "INFO" "Cron job added: $cron_schedule"

    echo ""
    press_key
}

# Remove cron job
remove_cronjob() {
    echo ""

    if ! crontab -l 2>/dev/null | grep -q "#easymesh-restart"; then
        print_color yellow "⚠️  No cron job found"
        sleep 2
        return 0
    fi

    crontab -l 2>/dev/null | grep -v "#easymesh-restart" | crontab -
    rm -f /opt/easytier/restart.sh

    print_color green "✅ Cron job removed successfully" "${BOLD}"
    log "INFO" "Cron job removed"

    sleep 2
}

#############################################################################
# MAIN MENU
#############################################################################

# Display header
display_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${WHITE}              🌐 EasyMesh Manager              ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}        Professional VPN Network Solution      ${CYAN}║${RESET}"
    echo -e "${CYAN}╠════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║${WHITE}  Version: ${SCRIPT_VERSION}                                 ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}  EasyTier: ${EASYTIER_VERSION}                              ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}  Telegram: @Gozar_Xray                         ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}  GitHub: github.com/Musixal/easy-mesh         ${CYAN}║${RESET}"
    echo -e "${CYAN}╠════════════════════════════════════════════════╣${RESET}"

    # Status indicators
    if core_installed; then
        echo -e "${CYAN}║${GREEN}  ✅ Core: Installed                             ${CYAN}║${RESET}"
    else
        echo -e "${CYAN}║${RED}  ❌ Core: Not Installed                         ${CYAN}║${RESET}"
    fi

    if service_exists; then
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${CYAN}║${GREEN}  ✅ Service: Running                            ${CYAN}║${RESET}"
        else
            echo -e "${CYAN}║${YELLOW}  ⚠️  Service: Stopped                            ${CYAN}║${RESET}"
        fi
    else
        echo -e "${CYAN}║${RED}  ❌ Service: Not Configured                     ${CYAN}║${RESET}"
    fi

    if systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
        echo -e "${CYAN}║${GREEN}  ✅ Watchdog: Active                            ${CYAN}║${RESET}"
    else
        echo -e "${CYAN}║${WHITE}  ⚪ Watchdog: Inactive                           ${CYAN}║${RESET}"
    fi

    echo -e "${CYAN}╚════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Display menu
display_menu() {
    display_header

    print_color green "  ${BOLD}📦 Installation & Setup${RESET}"
    echo "    [1] Install/Update EasyTier Core"
    echo "    [2] Configure Network"
    echo ""

    print_color yellow "  ${BOLD}📊 Monitoring${RESET}"
    echo "    [3] Display Peers"
    echo "    [4] Display Routes"
    echo "    [5] Display Peer Center"
    echo "    [6] Show Network Secret"
    echo ""

    print_color cyan "  ${BOLD}⚙️  Service Management${RESET}"
    echo "    [7] View Service Status"
    echo "    [8] Restart Service"
    echo "    [9] Remove Service"
    echo ""

    print_color magenta "  ${BOLD}🔧 Advanced${RESET}"
    echo "    [10] Configure Watchdog"
    echo "    [11] Configure Cron Job"
    echo "    [12] View System Logs"
    echo ""

    print_color red "  ${BOLD}🗑️  Removal${RESET}"
    echo "    [13] Remove Core"
    echo ""

    echo "    [0] Exit"
    echo ""
}

# View system logs
view_system_logs() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   📋 System Logs" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ Service does not exist"
        press_key
        return 1
    fi

    print_color yellow "Showing last 50 log entries (Press Ctrl+C to exit)..."
    echo ""

    journalctl -u "$SERVICE_NAME" -f -n 50
}

# Main loop
main() {
    # Initialize
    check_root
    install_dependencies

    # Create log file
    touch "$LOG_FILE" 2>/dev/null || true

    log "INFO" "EasyMesh Manager started (v${SCRIPT_VERSION})"

    while true; do
        display_menu

        echo -ne "  ${MAGENTA}${BOLD}Enter your choice [0-13]: ${RESET}"
        read -r choice

        case "$choice" in
            1) install_core ;;
            2) configure_network ;;
            3) display_peers ;;
            4) display_routes ;;
            5) display_peer_center ;;
            6) show_secret ;;
            7) view_status ;;
            8) restart_service ;;
            9) remove_service ;;
            10) configure_watchdog ;;
            11) configure_cronjob ;;
            12) view_system_logs ;;
            13) remove_core ;;
            0)
                clear
                print_color green "👋 Thank you for using EasyMesh Manager!" "${BOLD}"
                log "INFO" "EasyMesh Manager exited"
                exit 0
                ;;
            *)
                print_color red "❌ Invalid option. Please select 0-13" "${BOLD}"
                sleep 2
                ;;
        esac
    done
}

# Run main function
main "$@"
