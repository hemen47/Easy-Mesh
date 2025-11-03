#!/bin/bash

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   sleep 1
   exit 1
fi

#color codes
GREEN="\033[0;32m"
CYAN="\033[0;36m"
WHITE="\033[1;37m"
RESET="\033[0m"
MAGENTA="\033[0;35m"
RED="\033[0;31m"
YELLOW="\033[0;33m"

# just press key to continue
press_key(){
 read -p "Press Enter to continue..."
}

# Define a function to colorize text
colorize() {
    local color="$1"
    local text="$2"
    local style="${3:-normal}"

    # Define ANSI color codes
    local black="\033[30m"
    local red="\033[31m"
    local green="\033[32m"
    local yellow="\033[33m"
    local blue="\033[34m"
    local magenta="\033[35m"
    local cyan="\033[36m"
    local white="\033[37m"
    local reset="\033[0m"

    # Define ANSI style codes
    local normal="\033[0m"
    local bold="\033[1m"
    local underline="\033[4m"

    # Select color code
    local color_code
    case $color in
        black) color_code=$black ;;
        red) color_code=$red ;;
        green) color_code=$green ;;
        yellow) color_code=$yellow ;;
        blue) color_code=$blue ;;
        magenta) color_code=$magenta ;;
        cyan) color_code=$cyan ;;
        white) color_code=$white ;;
        *) color_code=$reset ;;
    esac

    # Select style code
    local style_code
    case $style in
        bold) style_code=$bold ;;
        underline) style_code=$underline ;;
        normal | *) style_code=$normal ;;
    esac

    echo -e "${style_code}${color_code}${text}${reset}"
}

# Function to kill all easytier processes safely
kill_easytier_processes() {
    local pids=$(pgrep -f "easytier-core")
    if [ -n "$pids" ]; then
        colorize yellow "Stopping existing easytier processes..." bold
        # Try graceful shutdown first
        kill -15 $pids 2>/dev/null
        sleep 3
        # Force kill if still running
        pids=$(pgrep -f "easytier-core")
        if [ -n "$pids" ]; then
            kill -9 $pids 2>/dev/null
            sleep 1
        fi
        colorize green "Existing processes stopped." bold
    fi
}

# Function to check if port is available
check_port_available() {
    local port=$1
    if command -v ss &> /dev/null; then
        ss -tuln | grep -q ":$port " && return 1
    elif command -v netstat &> /dev/null; then
        netstat -tuln | grep -q ":$port " && return 1
    fi
    return 0
}

install_easytier() {
    # Define the directory and files
    DEST_DIR="/root/easytier"
    FILE1="easytier-core"
    FILE2="easytier-cli"

    # Version 1.2.0 URLs (More Stable)
    URL_X86="https://github.com/Musixal/Easy-Mesh/raw/main/core/v1.2.0/easytier-linux-x86_64/"
    URL_ARM_SOFT="https://github.com/Musixal/Easy-Mesh/raw/main/core/v1.2.0/easytier-linux-armv7/"
    URL_ARM_HARD="https://github.com/Musixal/Easy-Mesh/raw/main/core/v1.2.0/easytier-linux-armv7hf/"

    # Check if the directory exists
    if [ -d "$DEST_DIR" ]; then
        # Check if the files exist
        if [ -f "$DEST_DIR/$FILE1" ] && [ -f "$DEST_DIR/$FILE2" ]; then
            colorize green "EasyMesh Core v1.2.0 Installed" bold
            return 0
        fi
    fi

    # Detect the system architecture
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        URL=$URL_X86
    elif [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "aarch64" ]; then
        if [ "$(ldd /bin/ls 2>/dev/null | grep -c 'armhf')" -eq 1 ]; then
            URL=$URL_ARM_HARD
        else
            URL=$URL_ARM_SOFT
        fi
    else
        colorize red "Unsupported architecture: $ARCH\n" bold
        return 1
    fi

    mkdir -p $DEST_DIR &> /dev/null
    colorize yellow "Downloading EasyMesh Core v1.2.0...\n"

    # Download with error handling
    if ! curl -Ls "$URL/easytier-cli" -o "$DEST_DIR/easytier-cli"; then
        colorize red "Failed to download easytier-cli\n" bold
        return 1
    fi

    if ! curl -Ls "$URL/easytier-core" -o "$DEST_DIR/easytier-core"; then
        colorize red "Failed to download easytier-core\n" bold
        return 1
    fi

    if [ -f "$DEST_DIR/$FILE1" ] && [ -f "$DEST_DIR/$FILE2" ]; then
        chmod +x "$DEST_DIR/easytier-cli"
        chmod +x "$DEST_DIR/easytier-core"
        colorize green "EasyMesh Core v1.2.0 Installed Successfully...\n" bold
        sleep 1
        return 0
    else
        colorize red "Failed to install EasyMesh Core...\n" bold
        exit 1
    fi
}

# Call the function
install_easytier

generate_random_secret() {
    openssl rand -hex 12
}

# Validate IPv4 address
validate_ipv4() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Check if IP is private
is_private_ip() {
    local ip=$1
    if [[ $ip =~ ^10\. ]] || \
       [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
       [[ $ip =~ ^192\.168\. ]]; then
        return 0
    fi
    return 1
}

#Var
EASY_CLIENT='/root/easytier/easytier-cli'
SERVICE_FILE="/etc/systemd/system/easymesh.service"

connect_network_pool(){
    clear
    colorize cyan "Connect to the Mesh Network (v1.2.0)" bold
    echo
    colorize yellow "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMPORTANT CONFIGURATION GUIDE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. LOCAL IP must be PRIVATE (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
   - This is your MESH network IP (NOT your server's public IP)

2. PEER ADDRESSES should be PUBLIC IPs of other servers
   - Leave BLANK if this is the main server (reverse mode)

3. All servers must use the SAME network secret

EXAMPLE SETUP:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Server 1 (Kharej - Public IP: 198.245.214.80):
  - Peer: (leave blank)
  - Local IP: 10.144.144.1 ← PRIVATE mesh IP

Server 2 (Iran - Public IP: 185.x.x.x):
  - Peer: 198.245.214.80 ← Kharej's PUBLIC IP
  - Local IP: 10.144.144.2 ← PRIVATE mesh IP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"
    echo

    read -p "[-] Enter Peer PUBLIC IPv4/IPv6 (comma separated, blank for reverse): " PEER_ADDRESSES

    # Validate local IP with private IP check
    while true; do
        read -p "[*] Enter Local PRIVATE IPv4 (e.g., 10.144.144.1): " IP_ADDRESS
        if [ -z "$IP_ADDRESS" ]; then
            colorize red "IP address cannot be empty.\n"
            continue
        fi
        if ! validate_ipv4 "$IP_ADDRESS"; then
            colorize red "Invalid IPv4 address format.\n"
            continue
        fi
        if ! is_private_ip "$IP_ADDRESS"; then
            colorize red "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            colorize red "ERROR: Local IP must be PRIVATE!" bold
            colorize yellow "You entered: $IP_ADDRESS (This looks like a PUBLIC IP)"
            echo ""
            colorize cyan "Private IP ranges:" bold
            echo "  - 10.0.0.0 to 10.255.255.255"
            echo "  - 172.16.0.0 to 172.31.255.255"
            echo "  - 192.168.0.0 to 192.168.255.255"
            echo ""
            colorize yellow "Your server's PUBLIC IP should only be used in PEER addresses!"
            colorize red "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            continue
        fi
        break
    done

    # Validate hostname
    while true; do
        read -r -p "[*] Enter Hostname (e.g., Hetzner): " HOSTNAME
        if [ -z "$HOSTNAME" ]; then
            colorize red "Hostname cannot be empty.\n"
            continue
        fi
        # Sanitize hostname
        HOSTNAME=$(echo "$HOSTNAME" | tr -cd '[:alnum:]-_' | cut -c1-63)
        if [ -n "$HOSTNAME" ]; then
            break
        fi
    done

    # Validate port
    while true; do
        read -p "[-] Enter Tunnel Port (Default 2090): " PORT
        if [ -z "$PORT" ]; then
            PORT='2090'
            break
        fi
        if [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ]; then
            if check_port_available "$PORT"; then
                break
            else
                colorize red "Port $PORT is already in use. Choose another port.\n"
            fi
        else
            colorize red "Invalid port. Use 1024-65535.\n"
        fi
    done

    echo ''
    NETWORK_SECRET=$(generate_random_secret)
    colorize cyan "[✓] Generated Network Secret: $NETWORK_SECRET" bold

    while true; do
        read -p "[*] Enter Network Secret (min 8 chars, Enter for generated): " USER_SECRET
        if [ -z "$USER_SECRET" ]; then
            break
        fi
        if [ ${#USER_SECRET} -ge 8 ]; then
            NETWORK_SECRET="$USER_SECRET"
            break
        else
            colorize red "Network secret must be at least 8 characters.\n"
        fi
    done

    echo ''
    colorize green "[-] Select Default Protocol:" bold
    echo "1) tcp"
    echo "2) udp (Recommended for stability)"
    echo "3) ws"
    echo "4) wss"
    read -p "[*] Select protocol (default: 2 for udp): " PROTOCOL_CHOICE

    case $PROTOCOL_CHOICE in
        1) DEFAULT_PROTOCOL="tcp" ;;
        2|"") DEFAULT_PROTOCOL="udp" ;;
        3) DEFAULT_PROTOCOL="ws" ;;
        4) DEFAULT_PROTOCOL="wss" ;;
        *)
            colorize yellow "Invalid choice. Using udp."
            DEFAULT_PROTOCOL="udp"
            ;;
    esac

    echo
    read -p "[-] Enable encryption? (yes/no, default: yes): " ENCRYPTION_CHOICE
    case $ENCRYPTION_CHOICE in
        [Nn]*)
            ENCRYPTION_OPTION="--disable-encryption"
            colorize yellow "Encryption disabled"
            ;;
        *)
            ENCRYPTION_OPTION=""
            colorize yellow "Encryption enabled"
            ;;
    esac

    echo

    read -p "[-] Enable multi-thread? (yes/no, default: no): " MULTI_THREAD
    case $MULTI_THREAD in
        [Yy]*)
            MULTI_THREAD="--multi-thread"
            colorize yellow "Multi-thread enabled"
            ;;
        *)
            MULTI_THREAD=""
            colorize yellow "Multi-thread disabled (Recommended)"
            ;;
    esac

    echo

    read -p "[-] Enable IPv6? (yes/no, default: no): " IPV6_MODE
    case $IPV6_MODE in
        [Yy]*)
            IPV6_MODE=""
            colorize yellow "IPv6 enabled"
            ;;
        *)
            IPV6_MODE="--disable-ipv6"
            colorize yellow "IPv6 disabled"
            ;;
    esac

    echo

    # Process peer addresses with improved IPv6 handling
    IFS=',' read -ra ADDR_ARRAY <<< "$PEER_ADDRESSES"
    PROCESSED_ADDRESSES=()

    for ADDRESS in "${ADDR_ARRAY[@]}"; do
        ADDRESS=$(echo $ADDRESS | xargs)

        # Skip empty addresses
        if [ -z "$ADDRESS" ]; then
            continue
        fi

        # Handle IPv6 addresses (contains multiple colons)
        if [[ "$ADDRESS" == *:*:* ]]; then
            # This is an IPv6 address
            if [[ "$ADDRESS" != \[*\] ]]; then
                ADDRESS="[$ADDRESS]"
            fi
        fi

        PROCESSED_ADDRESSES+=("${DEFAULT_PROTOCOL}://${ADDRESS}:${PORT}")
    done

    JOINED_ADDRESSES=$(IFS=' '; echo "${PROCESSED_ADDRESSES[*]}")

    if [ -n "$JOINED_ADDRESSES" ]; then
        PEER_ADDRESS="--peers ${JOINED_ADDRESSES}"
    else
        PEER_ADDRESS=""
        colorize yellow "No peers specified. Running in reverse mode.\n"
    fi

    # Setup listeners based on IPv6 setting
    if [ "$IPV6_MODE" == "--disable-ipv6" ]; then
        LISTENERS="--listeners ${DEFAULT_PROTOCOL}://0.0.0.0:${PORT}"
    else
        LISTENERS="--listeners ${DEFAULT_PROTOCOL}://[::]:${PORT} ${DEFAULT_PROTOCOL}://0.0.0.0:${PORT}"
    fi

    # Kill any existing processes before creating service
    kill_easytier_processes

    # Create improved service file with better restart handling
    SERVICE_FILE="/etc/systemd/system/easymesh.service"

cat > $SERVICE_FILE <<EOF
[Unit]
Description=EasyMesh Network Service v1.2.0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/easytier
ExecStartPre=/bin/sleep 2
ExecStartPre=/bin/bash -c 'pkill -9 -f easytier-core || true'
ExecStart=/root/easytier/easytier-core --ipv4 $IP_ADDRESS $PEER_ADDRESS --hostname $HOSTNAME --network-name default --network-secret $NETWORK_SECRET $LISTENERS $MULTI_THREAD $ENCRYPTION_OPTION $IPV6_MODE
Restart=always
RestartSec=5
StartLimitInterval=0
StartLimitBurst=0
StandardOutput=journal
StandardError=journal
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Reload and start service
    sudo systemctl daemon-reload &> /dev/null
    sudo systemctl enable easymesh.service &> /dev/null
    sudo systemctl stop easymesh.service &> /dev/null
    sleep 2
    sudo systemctl start easymesh.service &> /dev/null

    # Wait and verify service started
    sleep 3
    if systemctl is-active --quiet easymesh.service; then
        colorize green "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" bold
        colorize green "✓ EasyMesh Network Service Started Successfully!" bold
        colorize green "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" bold
        echo "Configuration Summary:"
        echo "  - Local Mesh IP: $IP_ADDRESS"
        echo "  - Hostname: $HOSTNAME"
        echo "  - Protocol: $DEFAULT_PROTOCOL"
        echo "  - Port: $PORT"
        echo "  - Network Secret: $NETWORK_SECRET"
        if [ -n "$JOINED_ADDRESSES" ]; then
            echo "  - Peers: ${JOINED_ADDRESSES}"
        else
            echo "  - Mode: Reverse (waiting for connections)"
        fi
        colorize green "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" bold
    else
        colorize red "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" bold
        colorize red "✗ Failed to start EasyMesh service" bold
        colorize red "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" bold
        colorize yellow "Error Details:\n"
        journalctl -u easymesh.service -n 30 --no-pager
        echo ""
        colorize yellow "Common Solutions:" bold
        echo "1. Check if port $PORT is available: sudo ss -tuln | grep $PORT"
        echo "2. Verify easytier-core exists: ls -la /root/easytier/"
        echo "3. Test manual start: sudo /root/easytier/easytier-core --help"
        echo "4. Check firewall: sudo ufw status"
        colorize red "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" bold
    fi

    press_key
}

# Fixed display_peers function
display_peers() {
    if ! command -v watch &> /dev/null; then
        colorize yellow "Installing 'watch' command...\n"
        apt-get update -qq && apt-get install -y procps 2>/dev/null
    fi

    if [ ! -f "$EASY_CLIENT" ]; then
        colorize red "EasyTier CLI not found!\n" bold
        press_key
        return 1
    fi

    # Check if service is running
    if ! systemctl is-active --quiet easymesh.service; then
        colorize red "EasyMesh service is not running!\n" bold
        press_key
        return 1
    fi

    # Use watch with error handling
    watch -n 1 "$EASY_CLIENT peer 2>/dev/null || echo 'Waiting for peers...'"
}

display_routes() {
    if ! command -v watch &> /dev/null; then
        colorize yellow "Installing 'watch' command...\n"
        apt-get update -qq && apt-get install -y procps 2>/dev/null
    fi

    if [ ! -f "$EASY_CLIENT" ]; then
        colorize red "EasyTier CLI not found!\n" bold
        press_key
        return 1
    fi

    if ! systemctl is-active --quiet easymesh.service; then
        colorize red "EasyMesh service is not running!\n" bold
        press_key
        return 1
    fi

    watch -n 1 "$EASY_CLIENT route 2>/dev/null || echo 'Waiting for routes...'"
}

peer_center() {
    if ! command -v watch &> /dev/null; then
        colorize yellow "Installing 'watch' command...\n"
        apt-get update -qq && apt-get install -y procps 2>/dev/null
    fi

    if [ ! -f "$EASY_CLIENT" ]; then
        colorize red "EasyTier CLI not found!\n" bold
        press_key
        return 1
    fi

    if ! systemctl is-active --quiet easymesh.service; then
        colorize red "EasyMesh service is not running!\n" bold
        press_key
        return 1
    fi

    watch -n 1 "$EASY_CLIENT peer-center 2>/dev/null || echo 'Waiting for peer center...'"
}

restart_easymesh_service() {
    echo ''
    if [[ ! -f $SERVICE_FILE ]]; then
        colorize red "    EasyMesh service does not exist." bold
        sleep 1
        return 1
    fi

    colorize yellow "    Restarting EasyMesh service...\n" bold

    # Kill processes first
    kill_easytier_processes

    sudo systemctl daemon-reload &> /dev/null
    sudo systemctl restart easymesh.service &> /dev/null

    sleep 3

    if systemctl is-active --quiet easymesh.service; then
        colorize green "    ✓ EasyMesh service restarted successfully." bold
    else
        colorize red "    ✗ Failed to restart EasyMesh service." bold
        colorize yellow "    Check logs: sudo journalctl -u easymesh.service -n 50\n"
    fi

    echo ''
    read -p "    Press Enter to continue..."
}

remove_easymesh_service() {
    echo
    if [[ ! -f $SERVICE_FILE ]]; then
        colorize red "    EasyMesh service does not exist." bold
        sleep 1
        return 1
    fi

    colorize yellow "    Stopping EasyMesh service..." bold
    sudo systemctl stop easymesh.service &> /dev/null

    # Kill any remaining processes
    kill_easytier_processes

    colorize green "    EasyMesh service stopped.\n"

    colorize yellow "    Disabling EasyMesh service..." bold
    sudo systemctl disable easymesh.service &> /dev/null
    colorize green "    EasyMesh service disabled.\n"

    colorize yellow "    Removing EasyMesh service file..." bold
    sudo rm -f /etc/systemd/system/easymesh.service &> /dev/null
    colorize green "    EasyMesh service removed.\n"

    colorize yellow "    Reloading systemd daemon..." bold
    sudo systemctl daemon-reload &> /dev/null
    colorize green "    Systemd daemon reloaded.\n"

    read -p "    Press Enter to continue..."
}

show_network_secret() {
    echo ''
    if [[ -f $SERVICE_FILE ]]; then
        NETWORK_SECRET=$(grep -oP '(?<=--network-secret )[^ ]+' $SERVICE_FILE)

        if [[ -n $NETWORK_SECRET ]]; then
            colorize cyan "    Network Secret Key: $NETWORK_SECRET" bold
        else
            colorize red "    Network Secret key not found" bold
        fi
    else
        colorize red "    EasyMesh service does not exist." bold
    fi
    echo ''
    read -p "    Press Enter to continue..."
}

view_service_status() {
    if [[ ! -f $SERVICE_FILE ]]; then
        colorize red "    EasyMesh service does not exist." bold
        sleep 1
        return 1
    fi
    clear
    echo "=== Service Status ==="
    sudo systemctl status easymesh.service --no-pager
    echo ""
    echo "=== Recent Logs (last 30 lines) ==="
    sudo journalctl -u easymesh.service -n 30 --no-pager
    echo ""
    colorize cyan "Press Enter to return to menu"
    read -p ""
}

set_watchdog() {
    clear
    view_watchdog_status
    echo "---------------------------------------------"
    echo
    colorize cyan "Select your option:" bold
    colorize green "1) Create watchdog service"
    colorize red "2) Stop & remove watchdog service"
    colorize yellow "3) View Logs"
    colorize reset "4) Back"
    echo ''
    read -p "Enter your choice: " CHOICE
    case $CHOICE in
        1) start_watchdog ;;
        2) stop_watchdog ;;
        3) view_logs ;;
        4) return 0;;
        *) colorize red "Invalid option!" bold && sleep 1 && return 1;;
    esac
}

start_watchdog() {
    clear
    colorize cyan "Watchdog Service Setup
This monitors service health and restarts if issues detected.
Recommended: Run on external (Kharej) server only." bold
    echo ''

    read -p "Enter the local IP address to monitor: " IP_ADDRESS
    if ! validate_ipv4 "$IP_ADDRESS"; then
        colorize red "Invalid IP address.\n"
        sleep 2
        return 1
    fi

    read -p "Enter latency threshold in ms (default: 200): " LATENCY_THRESHOLD
    LATENCY_THRESHOLD=${LATENCY_THRESHOLD:-200}

    read -p "Enter check interval in seconds (default: 10): " CHECK_INTERVAL
    CHECK_INTERVAL=${CHECK_INTERVAL:-10}

    read -p "Enter max failed pings before restart (default: 3): " MAX_FAILURES
    MAX_FAILURES=${MAX_FAILURES:-3}

    stop_watchdog &>/dev/null

cat << 'WATCHDOG_SCRIPT' > /etc/monitor.sh
#!/bin/bash

# Configuration
IP_ADDRESS="IP_PLACEHOLDER"
LATENCY_THRESHOLD=LATENCY_PLACEHOLDER
CHECK_INTERVAL=CHECK_PLACEHOLDER
MAX_FAILURES=MAX_FAILURES_PLACEHOLDER
SERVICE_NAME="easymesh.service"
LOG_FILE="/var/log/easymesh-watchdog.log"
MAX_LOG_SIZE=5242880  # 5MB
FAILURE_COUNT=0

# Rotate log if too large
rotate_log() {
    if [ -f "$LOG_FILE" ]; then
        local size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null)
        if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
            mv "$LOG_FILE" "${LOG_FILE}.old"
            touch "$LOG_FILE"
        fi
    fi
}

# Restart service
restart_service() {
    local restart_time=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$restart_time: Restarting service due to $FAILURE_COUNT consecutive failures..." >> "$LOG_FILE"

    # Kill existing processes
    pkill -9 -f easytier-core
    sleep 2

    # Restart service
    systemctl daemon-reload
    systemctl restart "$SERVICE_NAME"

    if [ $? -eq 0 ]; then
        echo "$restart_time: Service restarted successfully." >> "$LOG_FILE"
        FAILURE_COUNT=0
    else
        echo "$restart_time: Failed to restart service!" >> "$LOG_FILE"
    fi

    rotate_log
}

# Calculate average latency
calculate_avg_latency() {
    local latencies=$(ping -c 3 -W 2 -i 0.2 "$IP_ADDRESS" 2>/dev/null | grep 'time=' | sed -n 's/.*time=\([0-9.]*\) ms.*/\1/p')

    if [ -z "$latencies" ]; then
        echo "0"
        return
    fi

    local total=0
    local count=0

    while IFS= read -r latency; do
        total=$(echo "$total + $latency" | bc)
        count=$((count + 1))
    done <<< "$latencies"

    if [ $count -gt 0 ]; then
        echo "scale=2; $total / $count" | bc
    else
        echo "0"
    fi
}

# Main loop
while true; do
    AVG_LATENCY=$(calculate_avg_latency)

    if [ "$AVG_LATENCY" == "0" ] || [ -z "$AVG_LATENCY" ]; then
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
        echo "$(date +"%Y-%m-%d %H:%M:%S"): Failed to ping $IP_ADDRESS (Failure $FAILURE_COUNT/$MAX_FAILURES)" >> "$LOG_FILE"

        if [ $FAILURE_COUNT -ge $MAX_FAILURES ]; then
            restart_service
        fi
    else
        LATENCY_INT=${AVG_LATENCY%.*}
        LATENCY_INT=${LATENCY_INT:-0}

        if [ "$LATENCY_INT" -gt "$LATENCY_THRESHOLD" ]; then
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
            echo "$(date +"%Y-%m-%d %H:%M:%S"): High latency ${AVG_LATENCY}ms > ${LATENCY_THRESHOLD}ms (Failure $FAILURE_COUNT/$MAX_FAILURES)" >> "$LOG_FILE"

            if [ $FAILURE_COUNT -ge $MAX_FAILURES ]; then
                restart_service
            fi
        else
            # Reset counter on success
            if [ $FAILURE_COUNT -gt 0 ]; then
                echo "$(date +"%Y-%m-%d %H:%M:%S"): Connection recovered. Latency: ${AVG_LATENCY}ms" >> "$LOG_FILE"
            fi
            FAILURE_COUNT=0
        fi
    fi

    sleep "$CHECK_INTERVAL"
done
WATCHDOG_SCRIPT

    # Replace placeholders
    sed -i "s/IP_PLACEHOLDER/$IP_ADDRESS/g" /etc/monitor.sh
    sed -i "s/LATENCY_PLACEHOLDER/$LATENCY_THRESHOLD/g" /etc/monitor.sh
    sed -i "s/CHECK_PLACEHOLDER/$CHECK_INTERVAL/g" /etc/monitor.sh
    sed -i "s/MAX_FAILURES_PLACEHOLDER/$MAX_FAILURES/g" /etc/monitor.sh

    chmod +x /etc/monitor.sh
    touch /var/log/easymesh-watchdog.log

    echo
    colorize yellow "Creating watchdog service..." bold

cat > /etc/systemd/system/easymesh-watchdog.service <<EOF
[Unit]
Description=EasyMesh Watchdog Service
After=network-online.target easymesh.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash /etc/monitor.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now easymesh-watchdog.service

    sleep 2

    if systemctl is-active --quiet easymesh-watchdog.service; then
        echo
        colorize green "✓ Watchdog service started successfully!" bold
        echo "  - Monitoring IP: $IP_ADDRESS"
        echo "  - Latency threshold: ${LATENCY_THRESHOLD}ms"
        echo "  - Check interval: ${CHECK_INTERVAL}s"
        echo "  - Max failures: $MAX_FAILURES"
        echo "  - Log file: /var/log/easymesh-watchdog.log"
    else
        colorize red "✗ Failed to start watchdog service" bold
    fi

    echo
    press_key
}

stop_watchdog() {
    echo
    SERVICE_FILE="/etc/systemd/system/easymesh-watchdog.service"

    if [[ ! -f $SERVICE_FILE ]]; then
        colorize red "Watchdog service does not exist." bold
        sleep 1
        return 1
    fi

    systemctl disable --now easymesh-watchdog.service &> /dev/null
    rm -f /etc/monitor.sh /var/log/easymesh-watchdog.log* &> /dev/null
    rm -f "$SERVICE_FILE" &> /dev/null
    systemctl daemon-reload &> /dev/null

    colorize green "✓ Watchdog service stopped and removed" bold
    echo
    sleep 2
}

view_watchdog_status() {
    if systemctl is-active --quiet "easymesh-watchdog.service"; then
        colorize green "    Watchdog service is running" bold
    else
        colorize red "    Watchdog service is not running" bold
    fi
}

view_logs() {
    if [ -f /var/log/easymesh-watchdog.log ]; then
        less +G /var/log/easymesh-watchdog.log
    else
        echo ''
        colorize yellow "No logs found.\n" bold
        press_key
    fi
}

# Improved cron job with faster recovery
add_cron_job() {
    echo
    local service_name="easymesh.service"

    colorize cyan "Fast Recovery Cron Job Setup" bold
    echo
    colorize yellow "This will restart the service at regular intervals.
For network stability issues, shorter intervals are recommended." bold
    echo
    echo "1. Every 5 minutes (Fastest recovery)"
    echo "2. Every 10 minutes"
    echo "3. Every 15 minutes"
    echo "4. Every 30 minutes"
    echo "5. Every 1 hour"
    echo "6. Every 2 hours"
    echo "7. Every 4 hours"
    echo "8. Every 6 hours"
    echo
    read -p "Enter your choice (1-8): " time_choice

    case $time_choice in
        1) restart_time="*/5 * * * *" ;;
        2) restart_time="*/10 * * * *" ;;
        3) restart_time="*/15 * * * *" ;;
        4) restart_time="*/30 * * * *" ;;
        5) restart_time="0 * * * *" ;;
        6) restart_time="0 */2 * * *" ;;
        7) restart_time="0 */4 * * *" ;;
        8) restart_time="0 */6 * * *" ;;
        *)
            colorize red "Invalid choice.\n"
            sleep 2
            return 1
            ;;
    esac

    delete_cron_job > /dev/null 2>&1

    local reset_path="/root/easytier/reset.sh"
    mkdir -p /root/easytier

cat << 'RESET_SCRIPT' > "$reset_path"
#!/bin/bash
# Fast reset script for EasyMesh

# Kill all easytier processes
pkill -9 -f easytier-core 2>/dev/null
sleep 2

# Reload and restart service
systemctl daemon-reload
systemctl restart easymesh.service

# Log the restart
echo "$(date): Service restarted by cron" >> /var/log/easymesh-cron.log

# Keep log file under 1MB
if [ -f /var/log/easymesh-cron.log ]; then
    size=$(stat -c%s /var/log/easymesh-cron.log 2>/dev/null || echo 0)
    if [ "$size" -gt 1048576 ]; then
        tail -n 100 /var/log/easymesh-cron.log > /var/log/easymesh-cron.log.tmp
        mv /var/log/easymesh-cron.log.tmp /var/log/easymesh-cron.log
    fi
fi
RESET_SCRIPT

    chmod +x "$reset_path"

    # Add to crontab
    (crontab -l 2>/dev/null | grep -v "#$service_name"; echo "$restart_time $reset_path #$service_name") | crontab -

    echo
    colorize green "✓ Cron job added successfully!" bold
    echo "  - Schedule: $restart_time"
    echo "  - Script: $reset_path"
    echo "  - Log: /var/log/easymesh-cron.log"
    echo
    sleep 2
}

delete_cron_job() {
    echo
    local service_name="easymesh.service"
    local reset_path="/root/easytier/reset.sh"

    crontab -l 2>/dev/null | grep -v "#$service_name" | crontab - 2>/dev/null
    rm -f "$reset_path" /var/log/easymesh-cron.log* >/dev/null 2>&1

    colorize green "✓ Cron job deleted successfully." bold
    sleep 2
}

set_cronjob() {
    clear
    colorize cyan "Cron-job Setting Menu" bold
    echo

    # Show current cron status
    if crontab -l 2>/dev/null | grep -q "#easymesh.service"; then
        colorize green "Current Status: Cron job is active" bold
        echo "Schedule: $(crontab -l 2>/dev/null | grep '#easymesh.service' | awk '{print $1, $2, $3, $4, $5}')"
    else
        colorize yellow "Current Status: No cron job configured" bold
    fi

    echo
    echo "---------------------------------------------"
    echo
    colorize green "1) Add/Update cron job"
    colorize red "2) Delete cron job"
    colorize yellow "3) View cron log"
    colorize reset "4) Return"

    echo
    echo -ne "Select your option [1-4]: "
    read -r choice

    case $choice in
        1) add_cron_job ;;
        2) delete_cron_job ;;
        3)
            if [ -f /var/log/easymesh-cron.log ]; then
                less +G /var/log/easymesh-cron.log
            else
                colorize yellow "No cron log found.\n"
                press_key
            fi
            ;;
        4) return 0 ;;
        *) colorize red "Invalid option!" && sleep 1 && return 1 ;;
    esac
}

check_core_status() {
    DEST_DIR="/root/easytier"
    FILE1="easytier-core"
    FILE2="easytier-cli"

    if [ -f "$DEST_DIR/$FILE1" ] && [ -f "$DEST_DIR/$FILE2" ]; then
        colorize green "Core v1.2.0 Installed" bold
        return 0
    else
        colorize red "Core Not Found" bold
        return 1
    fi
}

remove_easymesh_core() {
    echo

    if [[ ! -d '/root/easytier' ]]; then
        colorize red "    EasyMesh directory not found." bold
        sleep 2
        return 1
    fi

    # Kill processes first
    kill_easytier_processes

    # Remove directory
    rm -rf /root/easytier &> /dev/null

    colorize green "    ✓ Easymesh core deleted successfully." bold
    sleep 2
}

display_menu() {
    clear
    echo -e "   ${CYAN}╔════════════════════════════════════════╗"
    echo -e "   ║            🌐 ${WHITE}EasyMesh                 ${CYAN}║"
    echo -e "   ║        ${WHITE}VPN Network Solution            ${CYAN}║"
    echo -e "   ╠════════════════════════════════════════╣"
    echo -e "   ║  ${WHITE}Version: 1.2.0 (Stable - Fixed)       ${CYAN}║"
    echo -e "   ║  ${WHITE}Telegram: @Gozar_Xray                 ${CYAN}║"
    echo -e "   ║  ${WHITE}GitHub: Musixal/easy-mesh             ${CYAN}║"
    echo -e "   ╠════════════════════════════════════════╣${RESET}"
    echo -e "   ║        $(check_core_status)         ║"

    # Show service status
    if systemctl is-active --quiet easymesh.service 2>/dev/null; then
        echo -e "   ║        ${GREEN}Service: Running ✓${RESET}                ║"
    else
        echo -e "   ║        ${RED}Service: Stopped ✗${RESET}                ║"
    fi

    echo -e "   ╚════════════════════════════════════════╝"

    echo ''
    colorize green "    [1] Connect to Mesh Network" bold
    colorize yellow "    [2] Display Peers"
    colorize cyan "    [3] Display Routes"
    colorize reset "    [4] Peer-Center"
    colorize reset "    [5] Display Secret Key"
    colorize reset "    [6] View Service Status & Logs"
    colorize reset "    [7] Set Watchdog [Auto-Restarter]"
    colorize reset "    [8] Cron-job Setting [Fast Recovery]"
    colorize yellow "    [9] Restart Service"
    colorize red "    [10] Remove Service"
    colorize magenta "    [11] Remove Core"

    echo -e "    [0] Exit"
    echo ''
}

read_option() {
    echo -e "\t-------------------------------"
    echo -en "\t${MAGENTA}\033[1mEnter your choice:${RESET} "
    read -p '' choice
    case $choice in
        1) connect_network_pool ;;
        2) display_peers ;;
        3) display_routes ;;
        4) peer_center ;;
        5) show_network_secret ;;
        6) view_service_status ;;
        7) set_watchdog ;;
        8) set_cronjob ;;
        9) restart_easymesh_service ;;
        10) remove_easymesh_service ;;
        11) remove_easymesh_core ;;
        0)
            colorize green "Thank you for using EasyMesh!" bold
            exit 0
            ;;
        *) colorize red "    Invalid option!" bold && sleep 1 ;;
    esac
}

# Main script
while true
do
    display_menu
    read_option
done
