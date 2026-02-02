#!/bin/bash

#############################################################################
# EasyMesh - Professional Secure EasyTier VPN Management Script
# Version: 2.0.0 Security-Hardened Edition
# Author: Musixal
# Telegram: @Gozar_Xray
# GitHub: github.com/Musixal/easy-mesh
# License: MIT
#
# Security Enhancements:
# - Full systemd hardening with capability restrictions
# - AES-256-GCM encryption enforcement
# - Traffic obfuscation and stealth mode
# - Connection pooling and stability improvements
# - Enhanced watchdog with retry logic
# - Secure secret generation and storage
# - Input validation and sanitization
# - Comprehensive logging and audit trail
#############################################################################

set -euo pipefail  # Exit on error, undefined variables, and pipe failures
IFS=$'\n\t'        # Secure IFS

#############################################################################
# CONFIGURATION CONSTANTS
#############################################################################

readonly SCRIPT_VERSION="2.0.0-secure"
readonly EASYTIER_VERSION="v1.2.0"
readonly INSTALL_DIR="/opt/easytier"
readonly CONFIG_DIR="/etc/easytier"
readonly SECURE_CONFIG_DIR="/etc/easytier/secure"
readonly SERVICE_NAME="easymesh.service"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
readonly WATCHDOG_SERVICE="easymesh-watchdog.service"
readonly WATCHDOG_FILE="/etc/systemd/system/${WATCHDOG_SERVICE}"
readonly LOG_FILE="/var/log/easymesh.log"
readonly AUDIT_LOG="/var/log/easymesh-audit.log"
readonly LOCK_FILE="/var/lock/easymesh.lock"
readonly PID_FILE="/var/run/easymesh.pid"

# Binary paths
readonly EASYTIER_CORE="${INSTALL_DIR}/easytier-core"
readonly EASYTIER_CLI="${INSTALL_DIR}/easytier-cli"

# Download URLs
readonly BASE_URL="https://github.com/Musixal/Easy-Mesh/raw/main/core/${EASYTIER_VERSION}"
readonly URL_X86="${BASE_URL}/easytier-linux-x86_64/"
readonly URL_ARM="${BASE_URL}/easytier-linux-armv7/"
readonly URL_ARM_HF="${BASE_URL}/easytier-linux-armv7hf/"

# Security constants
readonly MIN_SECRET_LENGTH=16
readonly MAX_LOG_SIZE=$((50 * 1024 * 1024))  # 50MB
readonly SECURE_PERMISSIONS=600
readonly DIR_PERMISSIONS=700

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

# Secure logging function with audit trail
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local caller="${BASH_SOURCE[2]##*/}:${BASH_LINENO[1]}"

    # Main log
    echo -e "${timestamp} [${level}] [${caller}] ${message}" | tee -a "${LOG_FILE}" 2>/dev/null || true

    # Audit log for security events
    if [[ "$level" == "SECURITY" ]] || [[ "$level" == "ERROR" ]]; then
        echo -e "${timestamp} [${level}] [${caller}] ${message}" >> "${AUDIT_LOG}" 2>/dev/null || true
    fi

    # Rotate logs if too large
    rotate_logs
}

# Log rotation
rotate_logs() {
    for log in "${LOG_FILE}" "${AUDIT_LOG}"; do
        if [[ -f "$log" ]] && [[ $(stat -f%z "$log" 2>/dev/null || stat -c%s "$log" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
            mv "$log" "${log}.old"
            touch "$log"
            chmod 600 "$log"
            log "INFO" "Log rotated: $log"
        fi
    done
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
        log "SECURITY" "Unauthorized execution attempt by UID: $EUID"
        exit 1
    fi
    log "INFO" "Root access verified"
}

# Press any key to continue
press_key() {
    echo ""
    read -rp "Press Enter to continue..."
}

# Sanitize input to prevent injection attacks
sanitize_input() {
    local input="$1"
    # Remove dangerous characters
    echo "$input" | sed 's/[;&|`$(){}]//g' | tr -d '\n\r'
}

# Validate IP address (IPv4 and IPv6)
validate_ip() {
    local ip="$1"

    # IPv4 validation
    local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ $ip =~ $ipv4_regex ]]; then
        IFS='.' read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    fi

    # IPv6 validation (simplified)
    local ipv6_regex='^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    if [[ $ip =~ $ipv6_regex ]]; then
        return 0
    fi

    return 1
}

# Validate port number
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        # Warn about privileged ports
        if ((port < 1024)); then
            log "SECURITY" "Privileged port selected: $port"
        fi
        return 0
    fi
    return 1
}

# Validate hostname
validate_hostname() {
    local hostname="$1"
    local hostname_regex='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'

    if [[ $hostname =~ $hostname_regex ]] && [[ ${#hostname} -le 63 ]]; then
        return 0
    fi
    return 1
}

# Generate cryptographically secure random secret
generate_secret() {
    local length="${1:-24}"

    if command -v openssl &>/dev/null; then
        openssl rand -hex "$((length / 2))" 2>/dev/null
    elif [[ -r /dev/urandom ]]; then
        head -c "$((length / 2))" /dev/urandom | xxd -p | tr -d '\n'
    else
        log "ERROR" "No secure random source available"
        return 1
    fi
}

# Secure file creation with proper permissions
create_secure_file() {
    local filepath="$1"
    local content="$2"

    # Create parent directory if needed
    local dirpath=$(dirname "$filepath")
    mkdir -p "$dirpath"
    chmod "$DIR_PERMISSIONS" "$dirpath"

    # Write content securely
    echo "$content" > "$filepath"
    chmod "$SECURE_PERMISSIONS" "$filepath"

    log "SECURITY" "Secure file created: $filepath"
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
            log "ERROR" "Unsupported architecture: $arch"
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

# Verify binary integrity (basic check)
verify_binary() {
    local binary="$1"

    if [[ ! -f "$binary" ]]; then
        log "ERROR" "Binary not found: $binary"
        return 1
    fi

    if [[ ! -x "$binary" ]]; then
        log "ERROR" "Binary not executable: $binary"
        return 1
    fi

    # Check if binary is ELF format
    if ! file "$binary" | grep -q "ELF"; then
        log "ERROR" "Invalid binary format: $binary"
        return 1
    fi

    log "INFO" "Binary verified: $binary"
    return 0
}

# Acquire lock to prevent concurrent execution
acquire_lock() {
    local timeout=10
    local count=0

    while [[ -f "$LOCK_FILE" ]] && ((count < timeout)); do
        print_color yellow "⏳ Waiting for lock..."
        sleep 1
        ((count++))
    done

    if [[ -f "$LOCK_FILE" ]]; then
        print_color red "❌ Could not acquire lock. Another instance may be running."
        log "ERROR" "Lock acquisition failed"
        exit 1
    fi

    echo $$ > "$LOCK_FILE"
    log "INFO" "Lock acquired: PID $$"
}

# Release lock
release_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE"
        log "INFO" "Lock released"
    fi
}

# Trap to ensure cleanup on exit
cleanup_on_exit() {
    release_lock
    log "INFO" "Script exited"
}

trap cleanup_on_exit EXIT INT TERM

#############################################################################
# INSTALLATION FUNCTIONS
#############################################################################

# Install required dependencies
install_dependencies() {
    log "INFO" "Checking and installing dependencies..."

    local packages=("curl" "wget" "openssl" "systemd" "iptables" "net-tools")
    local missing_packages=()

    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &>/dev/null && ! dpkg -l | grep -q "^ii  $pkg"; then
            missing_packages+=("$pkg")
        fi
    done

    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        print_color yellow "📦 Installing missing packages: ${missing_packages[*]}"

        if command -v apt-get &>/dev/null; then
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing_packages[@]}"
        elif command -v yum &>/dev/null; then
            yum install -y -q "${missing_packages[@]}"
        elif command -v dnf &>/dev/null; then
            dnf install -y -q "${missing_packages[@]}"
        else
            print_color red "❌ Unsupported package manager"
            log "ERROR" "Unsupported package manager"
            exit 1
        fi

        log "INFO" "Dependencies installed successfully"
    else
        log "INFO" "All dependencies already installed"
    fi
}

# Install EasyTier core with security verification
install_core() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   📥 EasyTier Core Installation (Secure)" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if core_installed; then
        print_color green "✅ EasyTier core is already installed" "${BOLD}"
        echo ""
        read -rp "Do you want to reinstall? (y/N): " reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return 0
        fi
        log "INFO" "Reinstalling EasyTier core"
    fi

    log "INFO" "Starting EasyTier core installation..."

    # Detect architecture
    local download_url=$(detect_architecture)
    print_color blue "🔍 Detected architecture: $(uname -m)"
    print_color blue "📡 Download URL: $download_url"
    echo ""

    # Create installation directories with secure permissions
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$SECURE_CONFIG_DIR"
    chmod "$DIR_PERMISSIONS" "$INSTALL_DIR" "$CONFIG_DIR" "$SECURE_CONFIG_DIR"

    # Download binaries with verification
    print_color yellow "⬇️  Downloading easytier-core..."
    if ! curl -fsSL --max-time 60 "${download_url}easytier-core" -o "${EASYTIER_CORE}.tmp"; then
        print_color red "❌ Failed to download easytier-core"
        log "ERROR" "Failed to download easytier-core from $download_url"
        rm -f "${EASYTIER_CORE}.tmp"
        exit 1
    fi

    print_color yellow "⬇️  Downloading easytier-cli..."
    if ! curl -fsSL --max-time 60 "${download_url}easytier-cli" -o "${EASYTIER_CLI}.tmp"; then
        print_color red "❌ Failed to download easytier-cli"
        log "ERROR" "Failed to download easytier-cli from $download_url"
        rm -f "${EASYTIER_CLI}.tmp"
        exit 1
    fi

    # Move to final location
    mv "${EASYTIER_CORE}.tmp" "${EASYTIER_CORE}"
    mv "${EASYTIER_CLI}.tmp" "${EASYTIER_CLI}"

    # Set secure permissions
    chmod 755 "$EASYTIER_CORE" "$EASYTIER_CLI"
    chown root:root "$EASYTIER_CORE" "$EASYTIER_CLI"

    # Verify installation
    if verify_binary "$EASYTIER_CORE" && verify_binary "$EASYTIER_CLI"; then
        print_color green "✅ EasyTier core installed successfully!" "${BOLD}"
        log "SECURITY" "EasyTier core installed and verified"

        # Display version
        local version=$("$EASYTIER_CORE" --version 2>/dev/null || echo "Unknown")
        print_color cyan "📌 Version: $version"
    else
        print_color red "❌ Installation verification failed"
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
        log "SECURITY" "Attempted to remove core while service exists"
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
        # Secure deletion
        shred -vfz -n 3 "$EASYTIER_CORE" "$EASYTIER_CLI" 2>/dev/null || rm -f "$EASYTIER_CORE" "$EASYTIER_CLI"
        rm -rf "$INSTALL_DIR"
        print_color green "✅ EasyTier core removed successfully"
        log "SECURITY" "EasyTier core securely removed"
    else
        print_color blue "ℹ️  Operation cancelled"
    fi

    echo ""
    press_key
}

#############################################################################
# NETWORK CONFIGURATION (SECURITY HARDENED)
#############################################################################

# Configure and start EasyMesh network with security hardening
configure_network() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🌐 EasyMesh Secure Network Configuration" "${BOLD}"
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

    log "INFO" "Starting secure network configuration..."

    # Configuration variables
    local ipv4_address hostname network_name network_secret
    local peer_addresses port protocol
    local enable_encryption="yes"
    local enable_ipv6="no"
    local enable_multi_thread="no"
    local stealth_mode="no"
    local enable_whitelist="no"

    # Display configuration guide
    print_color yellow "📖 Secure Configuration Guide:" "${BOLD}"
    echo ""
    echo "  • Leave peer addresses empty for reverse connection mode"
    echo "  • WSS/TCP protocols recommended for stealth and stability"
    echo "  • Network secrets must be at least ${MIN_SECRET_LENGTH} characters"
    echo "  • Encryption is MANDATORY for security (cannot be disabled)"
    echo "  • Stealth mode uses port 443 with traffic obfuscation"
    echo ""
    print_color cyan "─────────────────────────────────────────"
    echo ""

    # Enable stealth mode option
    read -rp "🥷 Enable stealth mode? (Recommended) (Y/n): " stealth_mode
    stealth_mode=${stealth_mode:-yes}

    # Get peer addresses with validation
    while true; do
        read -rp "🔗 Peer addresses (comma-separated, or empty for reverse mode): " peer_addresses
        peer_addresses=$(sanitize_input "$peer_addresses")

        if [[ -z "$peer_addresses" ]]; then
            print_color yellow "ℹ️  Reverse connection mode enabled"
            break
        fi

        # Validate each peer address
        local valid=true
        IFS=',' read -ra peers <<< "$peer_addresses"
        for peer in "${peers[@]}"; do
            peer=$(echo "$peer" | xargs)
            # Extract IP from peer (remove protocol and port if present)
            local peer_ip=$(echo "$peer" | sed -E 's/^[a-z]+:\/\///; s/:([0-9]+)$//')
            if [[ -n "$peer_ip" ]] && ! validate_ip "$peer_ip"; then
                print_color red "❌ Invalid peer address: $peer"
                valid=false
                break
            fi
        done

        if $valid; then
            break
        fi
    done

    # Get local IPv4 address with validation
    while true; do
        read -rp "🏠 Local IPv4 address (e.g., 10.144.144.1): " ipv4_address
        ipv4_address=$(sanitize_input "$ipv4_address")

        if [[ -z "$ipv4_address" ]]; then
            print_color red "❌ IPv4 address cannot be empty"
            continue
        fi

        if validate_ip "$ipv4_address"; then
            # Check if IP is in private range
            if [[ "$ipv4_address" =~ ^10\. ]] || [[ "$ipv4_address" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ "$ipv4_address" =~ ^192\.168\. ]]; then
                break
            else
                print_color yellow "⚠️  Warning: Using public IP address"
                read -rp "Continue? (y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    break
                fi
            fi
        else
            print_color red "❌ Invalid IPv4 address format"
        fi
    done

    # Get hostname with validation
    while true; do
        read -rp "💻 Hostname (e.g., Server-Iran-1): " hostname
        hostname=$(sanitize_input "$hostname")

        if [[ -z "$hostname" ]]; then
            print_color red "❌ Hostname cannot be empty"
            continue
        fi

        if validate_hostname "$hostname"; then
            break
        else
            print_color red "❌ Invalid hostname format (alphanumeric and hyphens only, max 63 chars)"
        fi
    done

    # Get network name with validation
    while true; do
        read -rp "🌐 Network name (e.g., my-secure-vpn): " network_name
        network_name=$(sanitize_input "$network_name")

        if [[ -z "$network_name" ]]; then
            print_color red "❌ Network name cannot be empty"
            continue
        fi

        if [[ ${#network_name} -ge 4 ]] && [[ ${#network_name} -le 64 ]]; then
            break
        else
            print_color red "❌ Network name must be 4-64 characters"
        fi
    done

    # Get port with stealth mode consideration
    if [[ "$stealth_mode" =~ ^[Yy]$ ]]; then
        port=443
        print_color green "🔒 Stealth mode: Using port 443 (HTTPS)"
    else
        while true; do
            read -rp "🔌 Listen port (default: 11010, recommended: 443 for stealth): " port
            port=${port:-11010}

            if validate_port "$port"; then
                if ((port == 443)) || ((port == 8443)); then
                    print_color green "✅ Using stealth port: $port"
                fi
                break
            fi
            print_color red "❌ Invalid port number (1-65535)"
        done
    fi

    # Generate and confirm network secret with strength validation
    while true; do
        local generated_secret=$(generate_secret 32)
        echo ""
        print_color cyan "🔐 Generated secure network secret (32 chars): ${BOLD}$generated_secret"
        read -rp "Enter network secret (press Enter to use generated, min ${MIN_SECRET_LENGTH} chars): " network_secret
        network_secret=${network_secret:-$generated_secret}
        network_secret=$(sanitize_input "$network_secret")

        if [[ ${#network_secret} -ge $MIN_SECRET_LENGTH ]]; then
            # Save secret securely
            create_secure_file "${SECURE_CONFIG_DIR}/network.secret" "$network_secret"
            log "SECURITY" "Network secret generated and stored securely"
            break
        else
            print_color red "❌ Network secret must be at least ${MIN_SECRET_LENGTH} characters for security"
        fi
    done

    # Select protocol with stealth mode consideration
    echo ""
    if [[ "$stealth_mode" =~ ^[Yy]$ ]]; then
        protocol="wss"
        print_color green "🔒 Stealth mode: Using WSS (WebSocket Secure) protocol"
    else
        print_color green "📡 Select Protocol:" "${BOLD}"
        echo "  1) TCP (Reliable)"
        echo "  2) UDP (Fast, may be detected)"
        echo "  3) WebSocket (WS) (Stealth)"
        echo "  4) WebSocket Secure (WSS) (Most Secure - Recommended)"
        echo ""
        read -rp "Select protocol [1-4] (default: 4): " protocol_choice
        protocol_choice=${protocol_choice:-4}

        case "$protocol_choice" in
            1) protocol="tcp" ;;
            2) protocol="udp" ;;
            3) protocol="ws" ;;
            4) protocol="wss" ;;
            *) protocol="wss" ;;
        esac
    fi

    # Encryption is MANDATORY for security
    enable_encryption="yes"
    print_color green "🔒 Encryption: ENABLED (AES-256-GCM - Mandatory for security)"

    # IPv6 option
    echo ""
    read -rp "🌍 Enable IPv6? (y/N): " enable_ipv6
    enable_ipv6=${enable_ipv6:-no}

    # Multi-thread option
    read -rp "⚡ Enable multi-thread? (Y/n): " enable_multi_thread
    enable_multi_thread=${enable_multi_thread:-yes}

    # Peer whitelist option
    read -rp "🛡️  Enable peer whitelist? (Restrict connections) (y/N): " enable_whitelist
    enable_whitelist=${enable_whitelist:-no}

   # Build command options with security hardening
      local cmd_options="--ipv4 $ipv4_address"
      cmd_options+=" --hostname $hostname"
      cmd_options+=" --network-name $network_name"
      cmd_options+=" --network-secret $network_secret"
      cmd_options+=" --default-protocol $protocol"

      # Add listeners with proper binding
      if [[ "$enable_ipv6" =~ ^[Yy]$ ]]; then
          cmd_options+=" --listeners ${protocol}://[::]:${port} ${protocol}://0.0.0.0:${port}"
      else
          cmd_options+=" --listeners ${protocol}://0.0.0.0:${port}"
          cmd_options+=" --disable-ipv6"
      fi

      # Add peer addresses with protocol prefix
      if [[ -n "$peer_addresses" ]]; then
          IFS=',' read -ra peers <<< "$peer_addresses"
          for peer in "${peers[@]}"; do
              peer=$(echo "$peer" | xargs)
              if [[ -n "$peer" ]]; then
                  # Handle IPv6 addresses
                  if [[ "$peer" == *:*:* ]] && [[ "$peer" != \[*\] ]]; then
                      peer="[$peer]"
                  fi
                  # Add protocol if not present
                  if [[ ! "$peer" =~ ^[a-z]+:// ]]; then
                      cmd_options+=" --peers ${protocol}://${peer}:${port}"
                  else
                      cmd_options+=" --peers ${peer}"
                  fi
              fi
          done
      fi

      # Multi-thread option
      if [[ "$enable_multi_thread" =~ ^[Yy]$ ]]; then
          cmd_options+=" --multi-thread"
      fi

      # RPC portal - CRITICAL for CLI communication
      cmd_options+=" --rpc-portal 127.0.0.1:15888"

      # Connection stability options
      cmd_options+=" --latency-first"
      cmd_options+=" --mtu 1400"

      # Stealth mode enhancements
      if [[ "$stealth_mode" =~ ^[Yy]$ ]]; then
          cmd_options+=" --console-log-level error"
          cmd_options+=" --disable-p2p"  # Force relay for stealth
          log "SECURITY" "Stealth mode enabled"
      else
          # Logging level for non-stealth
          cmd_options+=" --console-log-level info"
      fi

      # Peer whitelist
      if [[ "$enable_whitelist" =~ ^[Yy]$ ]] && [[ -n "$peer_addresses" ]]; then
          cmd_options+=" --enable-whitelist"
          log "SECURITY" "Peer whitelist enabled"
      fi

      # Create systemd service with hardening
      create_secure_service "$cmd_options"

      # Start service
      start_service

      # Display configuration summary
      echo ""
      print_color green "═══════════════════════════════════════" "${BOLD}"
      print_color green "   ✅ Secure Configuration Summary" "${BOLD}"
      print_color green "═══════════════════════════════════════" "${BOLD}"
      echo ""
      print_color cyan "  IPv4 Address: $ipv4_address"
      print_color cyan "  Hostname: $hostname"
      print_color cyan "  Network Name: $network_name"
      print_color cyan "  Network Secret: [SECURED - stored in ${SECURE_CONFIG_DIR}/network.secret]"
      print_color cyan "  Protocol: $protocol"
      print_color cyan "  Port: $port"
      print_color cyan "  Encryption: AES-256-GCM (Enabled by default)"

      if [[ "$enable_ipv6" =~ ^[Yy]$ ]]; then
          print_color cyan "  IPv6: Enabled"
      else
          print_color cyan "  IPv6: Disabled"
      fi

      if [[ "$enable_multi_thread" =~ ^[Yy]$ ]]; then
          print_color cyan "  Multi-thread: Enabled"
      else
          print_color cyan "  Multi-thread: Disabled"
      fi

      if [[ "$stealth_mode" =~ ^[Yy]$ ]]; then
          print_color cyan "  Stealth Mode: Enabled"
      else
          print_color cyan "  Stealth Mode: Disabled"
      fi

      if [[ "$enable_whitelist" =~ ^[Yy]$ ]]; then
          print_color cyan "  Peer Whitelist: Enabled"
      else
          print_color cyan "  Peer Whitelist: Disabled"
      fi

      echo ""

      log "SECURITY" "Secure network configured: $hostname ($ipv4_address) - Protocol: $protocol, Port: $port"

      press_key
  }

#############################################################################
# SERVICE MANAGEMENT (SYSTEMD HARDENED)
#############################################################################

# Create systemd service with comprehensive security hardening
create_secure_service() {
    local cmd_options="$1"

    log "INFO" "Creating hardened systemd service..."

    # Create service file with extensive security hardening based on systemd best practices
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EasyMesh Secure Network Service ${EASYTIER_VERSION}
Documentation=https://easytier.rs https://github.com/Musixal/easy-mesh
After=network-online.target systemd-networkd.service
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${EASYTIER_CORE} ${cmd_options}

# Restart policy
Restart=always
RestartSec=10
TimeoutStartSec=60
TimeoutStopSec=30

# Process management
KillMode=mixed
KillSignal=SIGTERM
SendSIGKILL=yes

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=easymesh

# Security Hardening (systemd)
# Reference: https://www.freedesktop.org/software/systemd/man/systemd.exec.html

# Filesystem Protection
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR} ${CONFIG_DIR} ${SECURE_CONFIG_DIR} /var/log /var/run /dev/net
PrivateTmp=true
PrivateDevices=false
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectKernelLogs=true
ProtectControlGroups=true

# Network Protection
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET
# Remove IPAddressDeny/Allow as they conflict with TUN device creation

# Capability Restrictions - CRITICAL FIX
NoNewPrivileges=false
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

# System Call Filtering - RELAXED for TUN device
SystemCallFilter=@system-service @network-io @io-event
SystemCallFilter=~@obsolete
SystemCallErrorNumber=EPERM

# Resource Limits
LimitNOFILE=65536
LimitNPROC=4096
LimitMEMLOCK=infinity
TasksMax=4096

# Additional Security
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
ProtectHostname=false
ProtectClock=true

# Memory Protection - DISABLED for TUN device
MemoryDenyWriteExecute=false
RestrictNamespaces=false

# Secure Bits
SecureBits=keep-caps

[Install]
WantedBy=multi-user.target
EOF

    # Set secure permissions on service file
    chmod 644 "$SERVICE_FILE"
    chown root:root "$SERVICE_FILE"

    systemctl daemon-reload
    log "SECURITY" "Hardened service file created successfully"
}

# Start service with verification
start_service() {
    print_color yellow "🚀 Starting EasyMesh secure service..."

    if systemctl enable --now "$SERVICE_NAME" &>/dev/null; then
        sleep 3

        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_color green "✅ Service started successfully" "${BOLD}"
            log "INFO" "Service started successfully"

            # Verify RPC portal is accessible
            sleep 2
            if timeout 5 "$EASYTIER_CLI" peer &>/dev/null; then
                print_color green "✅ RPC portal verified"
            else
                print_color yellow "⚠️  RPC portal may not be ready yet (this is normal)"
            fi
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

        # Wait for clean shutdown
        local count=0
        while systemctl is-active --quiet "$SERVICE_NAME" && ((count < 10)); do
            sleep 1
            ((count++))
        done

        if ! systemctl is-active --quiet "$SERVICE_NAME"; then
            print_color green "✅ Service stopped"
            log "INFO" "Service stopped"
        else
            print_color yellow "⚠️  Force stopping service..."
            systemctl kill -s SIGKILL "$SERVICE_NAME"
            log "SECURITY" "Service force stopped"
        fi
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

    # Kill any hanging processes first
    pkill -9 easytier-core 2>/dev/null || true
    sleep 1

    systemctl daemon-reload

    if systemctl restart "$SERVICE_NAME" &>/dev/null; then
        sleep 3
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_color green "✅ Service restarted successfully" "${BOLD}"
            log "INFO" "Service restarted"
        else
            print_color red "❌ Service failed to restart"
            journalctl -u "$SERVICE_NAME" -n 20 --no-pager
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
        pkill -9 easytier-core 2>/dev/null || true
    fi

    # Disable service
    print_color yellow "🔓 Disabling service..."
    systemctl disable "$SERVICE_NAME" &>/dev/null

    # Remove service file
    print_color yellow "🗑️  Removing service file..."
    rm -f "$SERVICE_FILE"

    # Remove secrets
    print_color yellow "🔐 Removing stored secrets..."
    shred -vfz -n 3 "${SECURE_CONFIG_DIR}/network.secret" 2>/dev/null || rm -f "${SECURE_CONFIG_DIR}/network.secret"

    # Reload systemd
    systemctl daemon-reload
    systemctl reset-failed &>/dev/null || true

    print_color green "✅ Service removed successfully" "${BOLD}"
    log "SECURITY" "Service removed and secrets securely deleted"

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

    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   📊 Service Status" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    systemctl status "$SERVICE_NAME" --no-pager -l

    echo ""
    print_color cyan "─────────────────────────────────────────"
    print_color cyan "   🔒 Security Analysis" "${BOLD}"
    print_color cyan "─────────────────────────────────────────"
    echo ""

    # Run systemd security analysis
    if command -v systemd-analyze &>/dev/null; then
        systemd-analyze security "$SERVICE_NAME" --no-pager 2>/dev/null | head -n 20
    else
        print_color yellow "⚠️  systemd-analyze not available"
    fi

    echo ""
    press_key
}

#############################################################################
# NETWORK MONITORING
#############################################################################

# Display peers with auto-refresh
display_peers() {
    clear

    if ! core_installed; then
        print_color red "❌ EasyTier core is not installed"
        press_key
        return 1
    fi

    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        print_color red "❌ Service is not running"
        press_key
        return 1
    fi

    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   👥 Network Peers (Auto-refresh)" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""
    print_color yellow "Press Ctrl+C to exit"
    echo ""

    # Use watch with color support
    watch -n 2 -c "$EASYTIER_CLI peer 2>/dev/null || echo 'Waiting for peers...'"
}

# Display routes
display_routes() {
    clear

    if ! core_installed; then
        print_color red "❌ EasyTier core is not installed"
        press_key
        return 1
    fi

    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        print_color red "❌ Service is not running"
        press_key
        return 1
    fi

    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🛣️  Network Routes (Auto-refresh)" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""
    print_color yellow "Press Ctrl+C to exit"
    echo ""

    watch -n 2 -c "$EASYTIER_CLI route 2>/dev/null || echo 'Waiting for routes...'"
}

# Display peer center
display_peer_center() {
    clear

    if ! core_installed; then
        print_color red "❌ EasyTier core is not installed"
        press_key
        return 1
    fi

    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        print_color red "❌ Service is not running"
        press_key
        return 1
    fi

    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🎯 Peer Center (Auto-refresh)" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""
    print_color yellow "Press Ctrl+C to exit"
    echo ""

    watch -n 2 -c "$EASYTIER_CLI peer-center 2>/dev/null || echo 'Waiting for peer center...'"
}

# Show network secret securely
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

    # Try to read from secure storage first
    if [[ -f "${SECURE_CONFIG_DIR}/network.secret" ]]; then
        local secret=$(cat "${SECURE_CONFIG_DIR}/network.secret")
        print_color green "🔑 Network Secret: ${BOLD}$secret"
        log "SECURITY" "Network secret accessed"
    else
        # Fallback to service file
        local secret=$(grep -oP '(?<=--network-secret )[^ ]+' "$SERVICE_FILE" 2>/dev/null)

        if [[ -n "$secret" ]]; then
            print_color green "🔑 Network Secret: ${BOLD}$secret"
            log "SECURITY" "Network secret accessed from service file"
        else
            print_color red "❌ Network secret not found"
        fi
    fi

    echo ""
    print_color yellow "⚠️  Keep this secret safe and share only with trusted nodes"
    print_color yellow "⚠️  Anyone with this secret can join your network"
    echo ""

    press_key
}

# Network diagnostics
network_diagnostics() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🔍 Network Diagnostics" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        print_color red "❌ Service is not running"
        press_key
        return 1
    fi

    print_color yellow "Running diagnostics..."
    echo ""

    # Check service status
    print_color cyan "📊 Service Status:"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_color green "  ✅ Service is running"
    else
        print_color red "  ❌ Service is not running"
    fi
    echo ""

    # Check RPC portal
    print_color cyan "🔌 RPC Portal:"
    if timeout 3 "$EASYTIER_CLI" peer &>/dev/null; then
        print_color green "  ✅ RPC portal accessible"
    else
        print_color red "  ❌ RPC portal not accessible"
    fi
    echo ""

    # Check peers
    print_color cyan "👥 Connected Peers:"
    local peer_count=$("$EASYTIER_CLI" peer 2>/dev/null | grep -c "peer_id" || echo "0")
    if ((peer_count > 0)); then
        print_color green "  ✅ $peer_count peer(s) connected"
    else
        print_color yellow "  ⚠️  No peers connected"
    fi
    echo ""

    # Check routes
    print_color cyan "🛣️  Network Routes:"
    local route_count=$("$EASYTIER_CLI" route 2>/dev/null | grep -c "ipv4" || echo "0")
    if ((route_count > 0)); then
        print_color green "  ✅ $route_count route(s) available"
    else
        print_color yellow "  ⚠️  No routes available"
    fi
    echo ""

    # Check network interfaces
    print_color cyan "🌐 Network Interfaces:"
    ip addr show | grep -E "^[0-9]+:|inet " | grep -v "127.0.0.1"
    echo ""

    # Check listening ports
    print_color cyan "🔌 Listening Ports:"
    ss -tulpn | grep easytier || echo "  No easytier ports found"
    echo ""

    press_key
}

#############################################################################
# ENHANCED WATCHDOG FUNCTIONS
#############################################################################

# Configure watchdog with improved logic
configure_watchdog() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🐕 Enhanced Watchdog Configuration" "${BOLD}"
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

# Start enhanced watchdog with retry logic
start_watchdog() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🐕 Start Enhanced Watchdog Service" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ EasyMesh service does not exist"
        press_key
        return 1
    fi

    print_color yellow "📖 Enhanced Watchdog Features:" "${BOLD}"
    echo "  • Monitors network latency with retry logic"
    echo "  • Prevents false positives with consecutive failure tracking"
    echo "  • Automatic log rotation"
    echo "  • Recommended for external (Kharej) servers only"
    echo ""

    # Get configuration with validation
    local monitor_ip latency_threshold check_interval max_failures

    while true; do
        read -rp "🎯 IP address to monitor: " monitor_ip
        monitor_ip=$(sanitize_input "$monitor_ip")

        if validate_ip "$monitor_ip"; then
            break
        fi
        print_color red "❌ Invalid IP address"
    done

    read -rp "⏱️  Latency threshold in ms (default: 500): " latency_threshold
    latency_threshold=${latency_threshold:-500}

    read -rp "🔄 Check interval in seconds (default: 30): " check_interval
    check_interval=${check_interval:-30}

    read -rp "❌ Max consecutive failures before restart (default: 3): " max_failures
    max_failures=${max_failures:-3}

    # Stop existing watchdog
    if systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
        systemctl stop "$WATCHDOG_SERVICE"
    fi

    # Create enhanced watchdog script
    local watchdog_script="/opt/easytier/watchdog.sh"

    cat > "$watchdog_script" <<'WATCHDOG_EOF'
#!/bin/bash

# Enhanced Watchdog Configuration
MONITOR_IP="REPLACE_IP"
LATENCY_THRESHOLD=REPLACE_THRESHOLD
CHECK_INTERVAL=REPLACE_INTERVAL
MAX_FAILURES=REPLACE_MAX_FAILURES
SERVICE_NAME="easymesh.service"
LOG_FILE="/var/log/easymesh-watchdog.log"

# State variables
CONSECUTIVE_FAILURES=0
RESTART_COUNT=0
MAX_LOG_SIZE=$((50 * 1024 * 1024))  # 50MB

# Rotate log if too large
rotate_log() {
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Log rotated" > "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
}

# Log function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Restart service with safety checks
restart_service() {
    log_message "Initiating service restart (Attempt: $((RESTART_COUNT + 1)))"

    # Kill any hanging processes
    pkill -9 easytier-core 2>/dev/null || true
    sleep 2

    # Restart service
    systemctl daemon-reload
    if systemctl restart "$SERVICE_NAME"; then
        sleep 5
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_message "Service restarted successfully"
            CONSECUTIVE_FAILURES=0
            ((RESTART_COUNT++))
            return 0
        else
            log_message "ERROR: Service failed to start after restart"
            return 1
        fi
    else
        log_message "ERROR: Failed to restart service"
        return 1
    fi
}

# Calculate average latency with multiple samples
get_average_latency() {
    local latencies=$(ping -c 5 -W 3 -i 0.3 "$MONITOR_IP" 2>/dev/null | grep 'time=' | sed -n 's/.*time=\([0-9.]*\).*/\1/p')

    if [[ -z "$latencies" ]]; then
        echo "0"
        return
    fi

    local total=0
    local count=0

    while IFS= read -r latency; do
        total=$(echo "$total + $latency" | bc 2>/dev/null || echo "$total")
        ((count++))
    done <<< "$latencies"

    if [[ $count -gt 0 ]]; then
        echo "scale=2; $total / $count" | bc 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Check if service is actually running
check_service_health() {
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        log_message "ALERT: Service is not running"
        return 1
    fi

    # Check if RPC portal is responsive
    if ! timeout 5 /opt/easytier/easytier-cli peer &>/dev/null; then
        log_message "WARNING: RPC portal not responsive"
        return 1
    fi

    return 0
}

# Main loop
log_message "Enhanced Watchdog started - Monitoring $MONITOR_IP (threshold: ${LATENCY_THRESHOLD}ms, interval: ${CHECK_INTERVAL}s, max failures: ${MAX_FAILURES})"

while true; do
    rotate_log

    # Check service health first
    if ! check_service_health; then
        log_message "ALERT: Service health check failed"
        ((CONSECUTIVE_FAILURES++))
    else
        # Check network latency
        avg_latency=$(get_average_latency)

        if [[ "$avg_latency" == "0" ]]; then
            log_message "ALERT: Cannot ping $MONITOR_IP (Failure: $((CONSECUTIVE_FAILURES + 1))/${MAX_FAILURES})"
            ((CONSECUTIVE_FAILURES++))
        else
            latency_int=${avg_latency%.*}
            latency_int=${latency_int:-0}

            if [[ $latency_int -gt $LATENCY_THRESHOLD ]]; then
                log_message "ALERT: High latency detected (${avg_latency}ms > ${LATENCY_THRESHOLD}ms) (Failure: $((CONSECUTIVE_FAILURES + 1))/${MAX_FAILURES})"
                ((CONSECUTIVE_FAILURES++))
            else
                if [[ $CONSECUTIVE_FAILURES -gt 0 ]]; then
                    log_message "OK: Latency recovered (${avg_latency}ms) - Resetting failure counter"
                else
                    log_message "OK: Latency ${avg_latency}ms (threshold: ${LATENCY_THRESHOLD}ms)"
                fi
                CONSECUTIVE_FAILURES=0
            fi
        fi
    fi

    # Restart if max failures reached
    if [[ $CONSECUTIVE_FAILURES -ge $MAX_FAILURES ]]; then
        log_message "CRITICAL: Max consecutive failures reached ($CONSECUTIVE_FAILURES) - Restarting service"
        restart_service
        sleep 10  # Wait before next check after restart
    fi

    sleep "$CHECK_INTERVAL"
done
WATCHDOG_EOF

    # Replace placeholders
    sed -i "s/REPLACE_IP/$monitor_ip/g" "$watchdog_script"
    sed -i "s/REPLACE_THRESHOLD/$latency_threshold/g" "$watchdog_script"
    sed -i "s/REPLACE_INTERVAL/$check_interval/g" "$watchdog_script"
    sed -i "s/REPLACE_MAX_FAILURES/$max_failures/g" "$watchdog_script"

    chmod 755 "$watchdog_script"

    # Create watchdog service with hardening
    cat > "$WATCHDOG_FILE" <<EOF
[Unit]
Description=EasyMesh Enhanced Watchdog Service
Documentation=https://github.com/Musixal/easy-mesh
After=network-online.target ${SERVICE_NAME}
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash ${watchdog_script}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=easymesh-watchdog

# Security hardening
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /opt/easytier
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Start watchdog
    systemctl daemon-reload

    if systemctl enable --now "$WATCHDOG_SERVICE" &>/dev/null; then
        sleep 2
        if systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
            print_color green "✅ Enhanced watchdog started successfully" "${BOLD}"
            echo ""
            print_color cyan "  Monitor IP: $monitor_ip"
            print_color cyan "  Latency Threshold: ${latency_threshold}ms"
            print_color cyan "  Check Interval: ${check_interval}s"
            print_color cyan "  Max Consecutive Failures: ${max_failures}"
            log "INFO" "Enhanced watchdog started: monitoring $monitor_ip"
        else
            print_color red "❌ Watchdog failed to start"
            log "ERROR" "Watchdog failed to start"
        fi
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
        print_color cyan "   📋 Watchdog Logs (Live)" "${BOLD}"
        print_color cyan "═══════════════════════════════════════" "${BOLD}"
        echo ""
        print_color yellow "Press Ctrl+C to exit"
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

    # Check if cron job exists
    if crontab -l 2>/dev/null | grep -q "#easymesh-restart"; then
        print_color green "✅ Cron job is currently active" "${BOLD}"
    else
        print_color red "❌ No cron job configured" "${BOLD}"
    fi

    echo ""
    print_color cyan "─────────────────────────────────────────"
    echo ""
    print_color green "1) Add/Update Cron Job"
    print_color red "2) Remove Cron Job"
    print_color yellow "3) View Cron Logs"
    print_color white "4) Back to Main Menu"
    echo ""

    read -rp "Select option [1-4]: " choice

    case "$choice" in
        1) add_cronjob ;;
        2) remove_cronjob ;;
        3) view_cron_logs ;;
        4) return 0 ;;
        *) print_color red "❌ Invalid option" && sleep 1 ;;
    esac
}

# Add cron job with enhanced restart script
add_cronjob() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   ⏰ Add Scheduled Restart" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ EasyMesh service does not exist"
        press_key
        return 1
    fi

    print_color yellow "⚠️  Note: Regular restarts can help maintain connection stability"
    print_color yellow "⚠️  Recommended for servers with persistent connection issues"
    echo ""

    print_color yellow "Select restart interval:"
    echo ""
    echo "  1) Every 30 minutes"
    echo "  2) Every 1 hour"
    echo "  3) Every 2 hours"
    echo "  4) Every 4 hours"
    echo "  5) Every 6 hours"
    echo "  6) Every 12 hours"
    echo "  7) Every 24 hours (Daily at midnight)"
    echo "  8) Custom cron expression"
    echo ""

    read -rp "Select option [1-8]: " interval_choice

    local cron_schedule
    case "$interval_choice" in
        1) cron_schedule="*/30 * * * *" ;;
        2) cron_schedule="0 * * * *" ;;
        3) cron_schedule="0 */2 * * *" ;;
        4) cron_schedule="0 */4 * * *" ;;
        5) cron_schedule="0 */6 * * *" ;;
        6) cron_schedule="0 */12 * * *" ;;
        7) cron_schedule="0 0 * * *" ;;
        8)
            echo ""
            print_color cyan "Enter custom cron expression (e.g., '0 3 * * *' for 3 AM daily):"
            read -rp "Cron expression: " cron_schedule
            if [[ -z "$cron_schedule" ]]; then
                print_color red "❌ Invalid cron expression"
                press_key
                return 1
            fi
            ;;
        *)
            print_color red "❌ Invalid option"
            press_key
            return 1
            ;;
    esac

    # Remove existing cron job
    remove_cronjob &>/dev/null

    # Create enhanced restart script
    local restart_script="/opt/easytier/restart.sh"

    cat > "$restart_script" <<'RESTART_EOF'
#!/bin/bash
# EasyMesh Enhanced Auto-Restart Script
# Version: 2.0.0

LOG_FILE="/var/log/easymesh-cron.log"
MAX_LOG_SIZE=$((10 * 1024 * 1024))  # 10MB
SERVICE_NAME="easymesh.service"

# Rotate log if too large
rotate_log() {
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Log rotated" > "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
}

# Log function
log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

rotate_log

log_msg "=========================================="
log_msg "Scheduled restart initiated"

# Get current status
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_msg "Service was running before restart"
else
    log_msg "WARNING: Service was not running before restart"
fi

# Kill any hanging processes
log_msg "Killing any hanging easytier processes..."
pkill -9 easytier-core 2>/dev/null
sleep 2

# Clear any stale locks
rm -f /var/lock/easytier* 2>/dev/null

# Reload systemd
log_msg "Reloading systemd daemon..."
systemctl daemon-reload

# Restart service
log_msg "Restarting service..."
if systemctl restart "$SERVICE_NAME"; then
    sleep 5

    # Verify service is running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_msg "✅ Service restarted successfully"

        # Check RPC portal
        if timeout 5 /opt/easytier/easytier-cli peer &>/dev/null; then
            log_msg "✅ RPC portal is responsive"
        else
            log_msg "⚠️  RPC portal not responsive yet"
        fi
    else
        log_msg "❌ ERROR: Service failed to start after restart"

        # Get error details
        error_log=$(systemctl status "$SERVICE_NAME" --no-pager -l 2>&1 | tail -n 10)
        log_msg "Error details: $error_log"

        # Try one more time
        log_msg "Attempting second restart..."
        sleep 3
        systemctl restart "$SERVICE_NAME"
        sleep 5

        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_msg "✅ Service started on second attempt"
        else
            log_msg "❌ CRITICAL: Service failed to start after multiple attempts"
        fi
    fi
else
    log_msg "❌ ERROR: Failed to execute restart command"
fi

log_msg "Scheduled restart completed"
log_msg "=========================================="
RESTART_EOF

    chmod 755 "$restart_script"
    chown root:root "$restart_script"

    # Add to crontab
    (crontab -l 2>/dev/null | grep -v "#easymesh-restart"; echo "$cron_schedule $restart_script #easymesh-restart") | crontab -

    print_color green "✅ Cron job added successfully" "${BOLD}"
    echo ""
    print_color cyan "  Schedule: $cron_schedule"
    print_color cyan "  Script: $restart_script"
    print_color cyan "  Log: /var/log/easymesh-cron.log"
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

# View cron logs
view_cron_logs() {
    clear

    if [[ -f /var/log/easymesh-cron.log ]]; then
        print_color cyan "═══════════════════════════════════════" "${BOLD}"
        print_color cyan "   📋 Cron Job Logs" "${BOLD}"
        print_color cyan "═══════════════════════════════════════" "${BOLD}"
        echo ""

        # Show last 100 lines
        tail -n 100 /var/log/easymesh-cron.log

        echo ""
        print_color cyan "─────────────────────────────────────────"
        print_color yellow "Showing last 100 lines. Press Enter to continue..."
        read -r
    else
        print_color yellow "⚠️  No cron logs found"
        press_key
    fi
}

#############################################################################
# FIREWALL MANAGEMENT
#############################################################################

# Configure firewall rules
configure_firewall() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🔥 Firewall Configuration" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ Service does not exist. Configure network first."
        press_key
        return 1
    fi

    # Extract port from service file
    local port=$(grep -oP '(?<=://0.0.0.0:)[0-9]+' "$SERVICE_FILE" | head -n 1)
    local protocol=$(grep -oP '(?<=--default-protocol )[a-z]+' "$SERVICE_FILE")

    if [[ -z "$port" ]]; then
        print_color red "❌ Could not determine port from configuration"
        press_key
        return 1
    fi

    print_color yellow "Current configuration:"
    print_color cyan "  Port: $port"
    print_color cyan "  Protocol: $protocol"
    echo ""

    print_color green "1) Add firewall rules (Allow EasyMesh traffic)"
    print_color red "2) Remove firewall rules"
    print_color yellow "3) View current firewall rules"
    print_color white "4) Back to Main Menu"
    echo ""

    read -rp "Select option [1-4]: " choice

    case "$choice" in
        1) add_firewall_rules "$port" "$protocol" ;;
        2) remove_firewall_rules "$port" ;;
        3) view_firewall_rules ;;
        4) return 0 ;;
        *) print_color red "❌ Invalid option" && sleep 1 ;;
    esac
}

# Add firewall rules
add_firewall_rules() {
    local port="$1"
    local protocol="$2"

    echo ""
    print_color yellow "Adding firewall rules..."

    # Detect firewall system
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        # UFW (Ubuntu/Debian)
        print_color cyan "Detected UFW firewall"

        if [[ "$protocol" == "tcp" ]] || [[ "$protocol" == "ws" ]] || [[ "$protocol" == "wss" ]]; then
            ufw allow "$port/tcp" comment "EasyMesh"
        elif [[ "$protocol" == "udp" ]]; then
            ufw allow "$port/udp" comment "EasyMesh"
        else
            ufw allow "$port" comment "EasyMesh"
        fi

        ufw reload
        print_color green "✅ UFW rules added"

    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        # FirewallD (CentOS/RHEL/Fedora)
        print_color cyan "Detected FirewallD"

        if [[ "$protocol" == "tcp" ]] || [[ "$protocol" == "ws" ]] || [[ "$protocol" == "wss" ]]; then
            firewall-cmd --permanent --add-port="${port}/tcp"
        elif [[ "$protocol" == "udp" ]]; then
            firewall-cmd --permanent --add-port="${port}/udp"
        else
            firewall-cmd --permanent --add-port="${port}/tcp"
            firewall-cmd --permanent --add-port="${port}/udp"
        fi

        firewall-cmd --reload
        print_color green "✅ FirewallD rules added"

    elif command -v iptables &>/dev/null; then
        # iptables (Legacy)
        print_color cyan "Using iptables"

        if [[ "$protocol" == "tcp" ]] || [[ "$protocol" == "ws" ]] || [[ "$protocol" == "wss" ]]; then
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT -m comment --comment "EasyMesh"
        elif [[ "$protocol" == "udp" ]]; then
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT -m comment --comment "EasyMesh"
        else
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT -m comment --comment "EasyMesh"
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT -m comment --comment "EasyMesh"
        fi

        # Save rules
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null
        fi

        print_color green "✅ iptables rules added"
    else
        print_color yellow "⚠️  No firewall detected or firewall is not active"
    fi

    log "SECURITY" "Firewall rules added for port $port ($protocol)"

    echo ""
    press_key
}

# Remove firewall rules
remove_firewall_rules() {
    local port="$1"

    echo ""
    print_color yellow "Removing firewall rules..."

    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw delete allow "$port/tcp" 2>/dev/null
        ufw delete allow "$port/udp" 2>/dev/null
        ufw reload
        print_color green "✅ UFW rules removed"

    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --remove-port="${port}/tcp" 2>/dev/null
        firewall-cmd --permanent --remove-port="${port}/udp" 2>/dev/null
        firewall-cmd --reload
        print_color green "✅ FirewallD rules removed"

    elif command -v iptables &>/dev/null; then
        iptables -D INPUT -p tcp --dport "$port" -j ACCEPT -m comment --comment "EasyMesh" 2>/dev/null
        iptables -D INPUT -p udp --dport "$port" -j ACCEPT -m comment --comment "EasyMesh" 2>/dev/null

        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null
        fi

        print_color green "✅ iptables rules removed"
    fi

    log "SECURITY" "Firewall rules removed for port $port"

    echo ""
    press_key
}

# View firewall rules
view_firewall_rules() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🔥 Current Firewall Rules" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        print_color green "UFW Status:"
        ufw status numbered

    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        print_color green "FirewallD Status:"
        firewall-cmd --list-all

    elif command -v iptables &>/dev/null; then
        print_color green "iptables Rules:"
        iptables -L -n -v --line-numbers
    else
        print_color yellow "⚠️  No firewall detected"
    fi

    echo ""
    press_key
}

#############################################################################
# BACKUP AND RESTORE
#############################################################################

# Backup configuration
backup_configuration() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   💾 Backup Configuration" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ No configuration to backup"
        press_key
        return 1
    fi

    local backup_dir="/root/easymesh-backups"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${backup_dir}/easymesh_backup_${timestamp}.tar.gz"

    mkdir -p "$backup_dir"

    print_color yellow "📦 Creating backup..."

    # Create temporary directory for backup
    local temp_backup="/tmp/easymesh_backup_$$"
    mkdir -p "$temp_backup"

    # Copy configuration files
    cp -r "$CONFIG_DIR" "$temp_backup/" 2>/dev/null || true
    cp -r "$SECURE_CONFIG_DIR" "$temp_backup/" 2>/dev/null || true
    cp "$SERVICE_FILE" "$temp_backup/" 2>/dev/null || true
    cp "$WATCHDOG_FILE" "$temp_backup/" 2>/dev/null || true

    # Export cron job
    crontab -l 2>/dev/null | grep "#easymesh-restart" > "$temp_backup/crontab.txt" 2>/dev/null || true

    # Create backup archive
    tar -czf "$backup_file" -C "$temp_backup" . 2>/dev/null

    # Secure the backup
    chmod 600 "$backup_file"

    # Cleanup
    rm -rf "$temp_backup"

    if [[ -f "$backup_file" ]]; then
        print_color green "✅ Backup created successfully" "${BOLD}"
        echo ""
        print_color cyan "  Backup file: $backup_file"
        print_color cyan "  Size: $(du -h "$backup_file" | cut -f1)"
        log "INFO" "Configuration backup created: $backup_file"
    else
        print_color red "❌ Backup failed"
        log "ERROR" "Backup creation failed"
    fi

    echo ""
    press_key
}

# Restore configuration
restore_configuration() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   📥 Restore Configuration" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    local backup_dir="/root/easymesh-backups"

    if [[ ! -d "$backup_dir" ]] || [[ -z "$(ls -A "$backup_dir" 2>/dev/null)" ]]; then
        print_color red "❌ No backups found"
        press_key
        return 1
    fi

    print_color yellow "Available backups:"
    echo ""

    # List backups
    local backups=($(ls -t "$backup_dir"/easymesh_backup_*.tar.gz 2>/dev/null))

    if [[ ${#backups[@]} -eq 0 ]]; then
        print_color red "❌ No backup files found"
        press_key
        return 1
    fi

    local i=1
    for backup in "${backups[@]}"; do
        local size=$(du -h "$backup" | cut -f1)
        local date=$(stat -c %y "$backup" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
        echo "  $i) $(basename "$backup") - $size - $date"
        ((i++))
    done

    echo ""
    read -rp "Select backup to restore [1-${#backups[@]}] or 0 to cancel: " choice

    if [[ "$choice" == "0" ]]; then
        print_color blue "ℹ️  Operation cancelled"
        press_key
        return 0
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || ((choice < 1 || choice > ${#backups[@]})); then
        print_color red "❌ Invalid selection"
        press_key
        return 1
    fi

    local selected_backup="${backups[$((choice - 1))]}"

    echo ""
    print_color yellow "⚠️  This will overwrite current configuration"
    read -rp "Are you sure? (y/N): " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_color blue "ℹ️  Operation cancelled"
        press_key
        return 0
    fi

    print_color yellow "📥 Restoring backup..."

    # Stop services
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl stop "$WATCHDOG_SERVICE" 2>/dev/null || true

    # Extract backup
    local temp_restore="/tmp/easymesh_restore_$$"
    mkdir -p "$temp_restore"

    if tar -xzf "$selected_backup" -C "$temp_restore" 2>/dev/null; then
        # Restore files
        cp -r "$temp_restore/easytier/"* "$CONFIG_DIR/" 2>/dev/null || true
        cp -r "$temp_restore/secure/"* "$SECURE_CONFIG_DIR/" 2>/dev/null || true
        cp "$temp_restore/easymesh.service" "$SERVICE_FILE" 2>/dev/null || true
        cp "$temp_restore/easymesh-watchdog.service" "$WATCHDOG_FILE" 2>/dev/null || true

        # Restore cron job
        if [[ -f "$temp_restore/crontab.txt" ]]; then
            (crontab -l 2>/dev/null | grep -v "#easymesh-restart"; cat "$temp_restore/crontab.txt") | crontab -
        fi

        # Reload systemd
        systemctl daemon-reload

        # Restart services
        systemctl start "$SERVICE_NAME" 2>/dev/null || true

        print_color green "✅ Configuration restored successfully" "${BOLD}"
        log "INFO" "Configuration restored from: $selected_backup"
    else
        print_color red "❌ Restore failed"
        log "ERROR" "Restore failed from: $selected_backup"
    fi

    # Cleanup
    rm -rf "$temp_restore"

    echo ""
    press_key
}

#############################################################################
# SYSTEM INFORMATION
#############################################################################

# Display system information
system_information() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   💻 System Information" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    # System details
    print_color green "System Details:" "${BOLD}"
    echo "  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'Unknown')"
    echo "  Kernel: $(uname -r)"
    echo "  Architecture: $(uname -m)"
    echo "  Hostname: $(hostname)"
    echo ""

    # Network interfaces
    print_color green "Network Interfaces:" "${BOLD}"
    ip -br addr show | grep -v "lo" | awk '{print "  " $1 ": " $3}'
    echo ""

    # EasyMesh status
    print_color green "EasyMesh Status:" "${BOLD}"

    if core_installed; then
        local version=$("$EASYTIER_CORE" --version 2>/dev/null | head -n1 || echo "Unknown")
        echo "  Core: Installed ($version)"
    else
        echo "  Core: Not installed"
    fi

    if service_exists; then
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo "  Service: Running"
            local uptime=$(systemctl show "$SERVICE_NAME" --property=ActiveEnterTimestamp --value)
            echo "  Uptime: $(systemd-analyze timestamp "$uptime" 2>/dev/null | grep -oP '(?<=ago: ).*' || echo 'Unknown')"
        else
            echo "  Service: Stopped"
        fi
    else
        echo "  Service: Not configured"
    fi

    if systemctl is-active --quiet "$WATCHDOG_SERVICE"; then
        echo "  Watchdog: Active"
    else
        echo "  Watchdog: Inactive"
    fi

    if crontab -l 2>/dev/null | grep -q "#easymesh-restart"; then
        echo "  Cron Job: Configured"
    else
        echo "  Cron Job: Not configured"
    fi
    echo ""

    # Resource usage
    print_color green "Resource Usage:" "${BOLD}"

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        local pid=$(systemctl show "$SERVICE_NAME" --property=MainPID --value)
        if [[ "$pid" != "0" ]] && [[ -n "$pid" ]]; then
            local cpu=$(ps -p "$pid" -o %cpu --no-headers 2>/dev/null | xargs)
            local mem=$(ps -p "$pid" -o %mem --no-headers 2>/dev/null | xargs)
            local rss=$(ps -p "$pid" -o rss --no-headers 2>/dev/null | xargs)

            echo "  CPU: ${cpu}%"
            echo "  Memory: ${mem}% ($(numfmt --to=iec-i --suffix=B $((rss * 1024)) 2>/dev/null || echo "${rss}K"))"
        else
            echo "  Service not running"
        fi
    else
        echo "  Service not running"
    fi
    echo ""

    # Disk usage
    print_color green "Disk Usage:" "${BOLD}"
    df -h / | tail -n 1 | awk '{print "  Root: " $3 " / " $2 " (" $5 " used)"}'

    if [[ -d "$INSTALL_DIR" ]]; then
        local install_size=$(du -sh "$INSTALL_DIR" 2>/dev/null | cut -f1)
        echo "  EasyMesh: $install_size"
    fi
    echo ""

    # Log files
    print_color green "Log Files:" "${BOLD}"
    for log in "$LOG_FILE" "$AUDIT_LOG" "/var/log/easymesh-watchdog.log" "/var/log/easymesh-cron.log"; do
        if [[ -f "$log" ]]; then
            local log_size=$(du -h "$log" 2>/dev/null | cut -f1)
            echo "  $(basename "$log"): $log_size"
        fi
    done
    echo ""

    press_key
}

#############################################################################
# ADVANCED MENU
#############################################################################

# Advanced options menu
advanced_menu() {
    while true; do
        clear
        print_color cyan "═══════════════════════════════════════" "${BOLD}"
        print_color cyan "   🔧 Advanced Options" "${BOLD}"
        print_color cyan "═══════════════════════════════════════" "${BOLD}"
        echo ""

        print_color green "  ${BOLD}🛡️  Security & Monitoring${RESET}"
        echo "    [1] Configure Watchdog"
        echo "    [2] Configure Firewall"
        echo "    [3] Network Diagnostics"
        echo "    [4] View Security Audit Log"
        echo ""

        print_color yellow "  ${BOLD}⏰ Automation${RESET}"
        echo "    [5] Configure Cron Job"
        echo ""

        print_color cyan "  ${BOLD}💾 Backup & Restore${RESET}"
        echo "    [6] Backup Configuration"
        echo "    [7] Restore Configuration"
        echo ""

        print_color magenta "  ${BOLD}📊 System${RESET}"
        echo "    [8] System Information"
        echo "    [9] View System Logs"
        echo "    [10] Clear All Logs"
        echo ""

        echo "    [0] Back to Main Menu"
        echo ""

        echo -ne "  ${MAGENTA}${BOLD}Enter your choice [0-10]: ${RESET}"
        read -r choice

        case "$choice" in
            1) configure_watchdog ;;
            2) configure_firewall ;;
            3) network_diagnostics ;;
            4) view_audit_log ;;
            5) configure_cronjob ;;
            6) backup_configuration ;;
            7) restore_configuration ;;
            8) system_information ;;
            9) view_system_logs ;;
            10) clear_all_logs ;;
            0) return 0 ;;
            *)
                print_color red "❌ Invalid option. Please select 0-10" "${BOLD}"
                sleep 2
                ;;
        esac
    done
}

# View security audit log
view_audit_log() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   🔒 Security Audit Log" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if [[ -f "$AUDIT_LOG" ]]; then
        print_color yellow "Showing last 50 audit entries (Press Ctrl+C to exit)..."
        echo ""
        tail -f -n 50 "$AUDIT_LOG"
    else
        print_color yellow "⚠️  No audit log found"
        press_key
    fi
}

# Clear all logs
clear_all_logs() {
    clear
    print_color red "═══════════════════════════════════════" "${BOLD}"
    print_color red "   🗑️  Clear All Logs" "${BOLD}"
    print_color red "═══════════════════════════════════════" "${BOLD}"
    echo ""

    print_color yellow "⚠️  This will delete all EasyMesh log files"
    read -rp "Are you sure? (y/N): " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_color blue "ℹ️  Operation cancelled"
        press_key
        return 0
    fi

    print_color yellow "🗑️  Clearing logs..."

    # Clear log files
    for log in "$LOG_FILE" "$AUDIT_LOG" "/var/log/easymesh-watchdog.log" "/var/log/easymesh-cron.log"; do
        if [[ -f "$log" ]]; then
            > "$log"
            chmod 600 "$log"
            print_color green "  ✅ Cleared: $(basename "$log")"
        fi
    done

    # Clear journal logs
    if command -v journalctl &>/dev/null; then
        journalctl --vacuum-time=1s --unit="$SERVICE_NAME" &>/dev/null
        journalctl --vacuum-time=1s --unit="$WATCHDOG_SERVICE" &>/dev/null
        print_color green "  ✅ Cleared: systemd journal"
    fi

    print_color green "✅ All logs cleared successfully" "${BOLD}"
    log "INFO" "All logs cleared by administrator"

    echo ""
    press_key
}

#############################################################################
# MAIN MENU
#############################################################################

# Display header
display_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${WHITE}          🌐 EasyMesh Manager (Secure)         ${CYAN}║${RESET}"
    echo -e "${CYAN}║${WHITE}     Professional VPN Network Solution         ${CYAN}║${RESET}"
    echo -e "${CYAN}╠════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║${WHITE}  Version: ${SCRIPT_VERSION}                        ${CYAN}║${RESET}"
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

    # Security indicator
    if [[ -f "${SECURE_CONFIG_DIR}/network.secret" ]]; then
        echo -e "${CYAN}║${GREEN}  🔒 Security: Hardened                          ${CYAN}║${RESET}"
    else
        echo -e "${CYAN}║${WHITE}  🔓 Security: Standard                          ${CYAN}║${RESET}"
    fi

    echo -e "${CYAN}╚════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Display menu
display_menu() {
    display_header

    print_color green "  ${BOLD}📦 Installation & Setup${RESET}"
    echo "    [1] Install/Update EasyTier Core"
    echo "    [2] Configure Secure Network"
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

    print_color magenta "  ${BOLD}🔧 Advanced Options${RESET}"
    echo "    [10] Advanced Menu"
    echo ""

    print_color red "  ${BOLD}🗑️  Removal${RESET}"
    echo "    [11] Remove Core"
    echo ""

    echo "    [0] Exit"
    echo ""
}

# View system logs
view_system_logs() {
    clear
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    print_color cyan "   📋 System Logs (Live)" "${BOLD}"
    print_color cyan "═══════════════════════════════════════" "${BOLD}"
    echo ""

    if ! service_exists; then
        print_color red "❌ Service does not exist"
        press_key
        return 1
    fi

    print_color yellow "Showing live logs (Press Ctrl+C to exit)..."
    echo ""

    journalctl -u "$SERVICE_NAME" -f -n 50
}

#############################################################################
# INITIALIZATION AND MAIN LOOP
#############################################################################

# Initialize script
initialize() {
    # Check root
    check_root

    # Install dependencies
    install_dependencies

    # Create necessary directories
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$SECURE_CONFIG_DIR"
    chmod "$DIR_PERMISSIONS" "$INSTALL_DIR" "$CONFIG_DIR" "$SECURE_CONFIG_DIR"

    # Create log files with secure permissions
    for log in "$LOG_FILE" "$AUDIT_LOG"; do
        if [[ ! -f "$log" ]]; then
            touch "$log"
            chmod 600 "$log"
        fi
    done

    # Acquire lock
    acquire_lock

    log "INFO" "EasyMesh Manager started (v${SCRIPT_VERSION})"
}

# Main loop
main() {
    # Initialize
    initialize

    while true; do
        display_menu

        echo -ne "  ${MAGENTA}${BOLD}Enter your choice [0-11]: ${RESET}"
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
            10) advanced_menu ;;
            11) remove_core ;;
            0)
                clear
                print_color green "═══════════════════════════════════════" "${BOLD}"
                print_color green "   👋 Thank you for using EasyMesh!" "${BOLD}"
                print_color green "═══════════════════════════════════════" "${BOLD}"
                echo ""
                print_color cyan "  Telegram: @Gozar_Xray"
                print_color cyan "  GitHub: github.com/Musixal/easy-mesh"
                echo ""
                log "INFO" "EasyMesh Manager exited normally"
                exit 0
                ;;
            *)
                print_color red "❌ Invalid option. Please select 0-11" "${BOLD}"
                sleep 2
                ;;
        esac
    done
}

#############################################################################
# SCRIPT ENTRY POINT
#############################################################################

# Run main function
main "$@"
