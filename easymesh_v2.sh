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

# Function to kill all easytier processes
kill_easytier_processes() {
    local pids=$(pgrep -f "easytier-core")
    if [ -n "$pids" ]; then
        colorize yellow "Stopping existing easytier processes..." bold
        kill -15 $pids 2>/dev/null
        sleep 2
        # Force kill if still running
        pids=$(pgrep -f "easytier-core")
        if [ -n "$pids" ]; then
            kill -9 $pids 2>/dev/null
            sleep 1
        fi
        colorize green "Existing processes stopped." bold
    fi
}

# Function to check port availability
check_port() {
    local port=$1
    if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    fi
    return 0
}

install_easytier() {
    # Define the directory and files
    DEST_DIR="/root/easytier"
    FILE1="easytier-core"
    FILE2="easytier-cli"

    # New Version URLs
    URL_X86="https://github.com/Musixal/Easy-Mesh/raw/main/core/v2.0.3/easytier-linux-x86_64/"
    URL_ARM_SOFT="https://github.com/Musixal/Easy-Mesh/raw/main/core/v2.0.3/easytier-linux-armv7/"
    URL_ARM_HARD="https://github.com/Musixal/Easy-Mesh/raw/main/core/v2.0.3/easytier-linux-armv7hf/"

    # Check if the directory exists
    if [ -d "$DEST_DIR" ]; then
        # Check if the files exist
        if [ -f "$DEST_DIR/$FILE1" ] && [ -f "$DEST_DIR/$FILE2" ]; then
            colorize green "EasyMesh Core Installed" bold
            return 0
        fi
    fi

    # Detect the system architecture
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        URL=$URL_X86
    elif [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "aarch64" ]; then
        if [ "$(ldd /bin/ls | grep -c 'armhf')" -eq 1 ]; then
            URL=$URL_ARM_HARD
        else
            URL=$URL_ARM_SOFT
        fi
    else
        colorize red "Unsupported architecture: $ARCH\n" bold
        return 1
    fi

    mkdir -p $DEST_DIR &> /dev/null
    colorize yellow "Downloading EasyMesh Core...\n"

    # Download with retry logic
    local max_retries=3
    local retry_count=0

    while [ $retry_count -lt $max_retries ]; do
        curl -Ls "$URL/easytier-cli" -o "$DEST_DIR/easytier-cli" && \
        curl -Ls "$URL/easytier-core" -o "$DEST_DIR/easytier-core"

        if [ -f "$DEST_DIR/$FILE1" ] && [ -f "$DEST_DIR/$FILE2" ]; then
            chmod +x "$DEST_DIR/easytier-cli"
            chmod +x "$DEST_DIR/easytier-core"
            colorize green "EasyMesh Core Installed Successfully...\n" bold
            sleep 1
            return 0
        fi

        retry_count=$((retry_count + 1))
        colorize yellow "Download attempt $retry_count failed, retrying...\n"
        sleep 2
    done

    colorize red "Failed to install EasyMesh Core after $max_retries attempts...\n" bold
    exit 1
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

# Validate network secret
validate_network_secret() {
    local secret=$1
    if [ ${#secret} -lt 8 ]; then
        colorize red "Network secret must be at least 8 characters long.\n"
        return 1
    fi
    return 0
}

#Var
EASY_CLIENT='/root/easytier/easytier-cli'
SERVICE_FILE="/etc/systemd/system/easymesh.service"

connect_network_pool(){
    clear
    colorize cyan "Connect to the Mesh Network" bold
    echo
    colorize yellow "Leave the peer addresses blank to enable reverse mode.
Ws and wss modes are not recommended for iran's network environment.
Disable multi-thread mode if your mesh network is unstable.
UDP mode is more stable than tcp mode.
"
    echo

    read -p "[-] Enter Peer IPv4/IPv6 Addresses (separate multiple addresses by ','): " PEER_ADDRESSES

    # Validate local IP
    while true; do
        read -p "[*] Enter Local IPv4 Address (e.g., 10.144.144.1): " IP_ADDRESS
        if [ -z "$IP_ADDRESS" ]; then
            colorize red "IP address cannot be empty.\n"
            continue
        fi
        if validate_ipv4 "$IP_ADDRESS"; then
            break
        else
            colorize red "Invalid IPv4 address format.\n"
        fi
    done

    # Validate hostname
    while true; do
        read -r -p "[*] Enter Hostname (e.g., Hetzner): " HOSTNAME
        if [ -z "$HOSTNAME" ]; then
            colorize red "Hostname cannot be empty.\n"
            continue
        fi
        # Remove invalid characters
        HOSTNAME=$(echo "$HOSTNAME" | tr -cd '[:alnum:]-_')
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
            if check_port "$PORT"; then
                break
            else
                colorize red "Port $PORT is already in use. Choose another port.\n"
            fi
        else
            colorize red "Invalid port number. Use 1024-65535.\n"
        fi
    done

    echo ''
    NETWORK_SECRET=$(generate_random_secret)
    colorize cyan "[✓] Generated Network Secret: $NETWORK_SECRET" bold

    while true; do
        read -p "[*] Enter Network Secret (min 8 chars, press Enter to use generated): " USER_SECRET
        if [ -z "$USER_SECRET" ]; then
            break
        fi
        if validate_network_secret "$USER_SECRET"; then
            NETWORK_SECRET="$USER_SECRET"
            break
        fi
    done

    echo ''
    colorize green "[-] Select Default Protocol:" bold
    echo "1) tcp"
    echo "2) udp (Recommended)"
    echo "3) ws"
    echo "4) wss"
    read -p "[*] Select your desired protocol (default: 2 for udp): " PROTOCOL_CHOICE

    case $PROTOCOL_CHOICE in
        1) DEFAULT_PROTOCOL="tcp" ;;
        2|"") DEFAULT_PROTOCOL="udp" ;;
        3) DEFAULT_PROTOCOL="ws" ;;
        4) DEFAULT_PROTOCOL="wss" ;;
        *)
            colorize red "Invalid choice. Defaulting to udp."
            DEFAULT_PROTOCOL="udp"
            ;;
    esac

    echo
    read -p "[-] Enable encryption? (yes/no, default: yes): " ENCRYPTION_CHOICE
    case $ENCRYPTION_CHOICE in
        [Nn]*)
            ENCRYPTION_OPTION="--disable-encryption"
            colorize yellow "Encryption is disabled"
            ;;
        *)
            ENCRYPTION_OPTION=""
            colorize yellow "Encryption is enabled"
            ;;
    esac

    echo

    read -p "[-] Enable multi-thread? (yes/no, default: no): " MULTI_THREAD
    case $MULTI_THREAD in
        [Yy]*)
            MULTI_THREAD="--multi-thread"
            colorize yellow "Multi-thread is enabled"
            ;;
        *)
            MULTI_THREAD=""
            colorize yellow "Multi-thread is disabled (Recommended for stability)"
            ;;
    esac

    echo

    read -p "[-] Enable IPv6? (yes/no, default: no): " IPV6_MODE
    case $IPV6_MODE in
        [Yy]*)
            IPV6_MODE=""
            colorize yellow "IPv6 is enabled"
            ;;
        *)
            IPV6_MODE="--disable-ipv6"
            colorize yellow "IPv6 is disabled"
            ;;
    esac

    echo

    # Process peer addresses
    IFS=',' read -ra ADDR_ARRAY <<< "$PEER_ADDRESSES"
    PROCESSED_ADDRESSES=()

    for ADDRESS in "${ADDR_ARRAY[@]}"; do
        ADDRESS=$(echo $ADDRESS | xargs)

        # Skip empty addresses
        if [ -z "$ADDRESS" ]; then
            continue
        fi

        # Handle IPv6 addresses
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

    # Setup listeners
    if [ "$IPV6_MODE" == "--disable-ipv6" ]; then
        LISTENERS="--listeners ${DEFAULT_PROTOCOL}://0.0.0.0:${PORT}"
    else
        LISTENERS="--listeners ${DEFAULT_PROTOCOL}://[::]:${PORT} ${DEFAULT_PROTOCOL}://0.0.0.0:${PORT}"
    fi

    # Kill any existing processes
    kill_easytier_processes

    # Create service file
    SERVICE_FILE="/etc/systemd/system/easymesh.service"

cat > $SERVICE_FILE <<EOF
[Unit]
Description=EasyMesh Network Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/sleep 2
ExecStartPre=/usr/bin/pkill -9 -f easytier-core
ExecStart=/root/easytier/easytier-core --ipv4 $IP_ADDRESS $PEER_ADDRESS --hostname $HOSTNAME --network-secret $NETWORK_SECRET --default-protocol $DEFAULT_PROTOCOL $LISTENERS $MULTI_THREAD $ENCRYPTION_OPTION $IPV6_MODE
Restart=always
RestartSec=10
StartLimitInterval=0
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd, enable and start the service
    sudo systemctl daemon-reload &> /dev/null
    sudo systemctl enable easymesh.service &> /dev/null
    sudo systemctl stop easymesh.service &> /dev/null
    sleep 2
    sudo systemctl start easymesh.service &> /dev/null

    # Wait and check if service started successfully
    sleep 3
    if systemctl is-active --quiet easymesh.service; then
        colorize green "EasyMesh Network Service Started Successfully.\n" bold
    else
        colorize red "Failed to start EasyMesh service. Check logs with: journalctl -u easymesh.service -n 50\n" bold
    fi

    press_key
}

display_peers() {
    watch -n1 $EASY_CLIENT peer
}

display_routes() {
    watch -n1 $EASY_CLIENT route
}

peer_center() {
    watch -n1 $EASY_CLIENT peer-center
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
        colorize green "    EasyMesh service restarted successfully." bold
    else
        colorize red "    Failed to restart EasyMesh service." bold
        colorize yellow "    Check logs: journalctl -u easymesh.service -n 50"
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

    if [[ $? -eq 0 ]]; then
        colorize green "    EasyMesh service stopped successfully.\n"
    else
        colorize red "    Failed to stop EasyMesh service.\n"
    fi

    colorize yellow "    Disabling EasyMesh service..." bold
    sudo systemctl disable easymesh.service &> /dev/null
    if [[ $? -eq 0 ]]; then
        colorize green "    EasyMesh service disabled successfully.\n"
    else
        colorize red "    Failed to disable EasyMesh service.\n"
    fi

    colorize yellow "    Removing EasyMesh service..." bold
    sudo rm /etc/systemd/system/easymesh.service &> /dev/null
    if [[ $? -eq 0 ]]; then
        colorize green "    EasyMesh service removed successfully.\n"
    else
        colorize red "    Failed to remove EasyMesh service.\n"
    fi

    colorize yellow "    Reloading systemd daemon..." bold
    sudo systemctl daemon-reload
    if [[ $? -eq 0 ]]; then
        colorize green "    Systemd daemon reloaded successfully.\n"
    else
        colorize red "    Failed to reload systemd daemon.\n"
    fi

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
    sudo systemctl status easymesh.service
    echo ""
    colorize cyan "Recent logs:" bold
    sudo journalctl -u easymesh.service -n 20 --no-pager
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
    colorize cyan "Important: Monitor service health and restart if latency exceeds threshold.
Recommended to run on external (Kharej) server only." bold
    echo ''

    read -p "Enter the local IP address to monitor: " IP_ADDRESS
    if ! validate_ipv4 "$IP_ADDRESS"; then
        colorize red "Invalid IP address.\n"
        sleep 2
        return 1
    fi

    read -p "Enter the latency threshold in ms (default: 200): " LATENCY_THRESHOLD
    LATENCY_THRESHOLD=${LATENCY_THRESHOLD:-200}

    read -p "Enter the time between checks in seconds (default: 10): " CHECK_INTERVAL
    CHECK_INTERVAL=${CHECK_INTERVAL:-10}

    stop_watchdog &>/dev/null
    touch /etc/monitor.sh /etc/monitor.log &> /dev/null

cat << 'EOF' | sudo tee /etc/monitor.sh > /dev/null
#!/bin/bash

# Configuration
IP_ADDRESS="IP_PLACEHOLDER"
LATENCY_THRESHOLD=LATENCY_PLACEHOLDER
CHECK_INTERVAL=CHECK_PLACEHOLDER
SERVICE_NAME="easymesh.service"
LOG_FILE="/etc/monitor.log"
MAX_LOG_SIZE=1048576  # 1MB

# Function to rotate log if too large
rotate_log() {
    if [ -f "$LOG_FILE" ]; then
        local size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null)
        if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
            mv "$LOG_FILE" "${LOG_FILE}.old"
            touch "$LOG_FILE"
        fi
    fi
}

# Function to restart the service
restart_service() {
    local restart_time=$(date +"%Y-%m-%d %H:%M:%S")

    # Kill existing processes
    pkill -9 -f easytier-core
    sleep 2

    sudo systemctl daemon-reload
    sudo systemctl restart "$SERVICE_NAME"

    if [ $? -eq 0 ]; then
        echo "$restart_time: Service $SERVICE_NAME restarted successfully." >> "$LOG_FILE"
    else
        echo "$restart_time: Failed to restart service $SERVICE_NAME." >> "$LOG_FILE"
    fi

    rotate_log
}

# Function to calculate average latency
calculate_average_latency() {
    local latencies=$(ping -c 3 -W 2 -i 0.2 "$IP_ADDRESS" 2>/dev/null | grep 'time=' | sed -n 's/.*time=\([0-9.]*\) ms.*/\1/p')

    if [ -z "$latencies" ]; then
        echo "0"
        return
    fi

    local total_latency=0
    local count=0

    while IFS= read -r latency; do
        total_latency=$(echo "$total_latency + $latency" | bc)
        count=$((count + 1))
    done <<< "$latencies"

    if [ $count -gt 0 ]; then
        local average_latency=$(echo "scale=2; $total_latency / $count" | bc)
        echo "$average_latency"
    else
        echo "0"
    fi
}

# Main monitoring loop
while true; do
    # Calculate average latency
    AVG_LATENCY=$(calculate_average_latency)

    if [ "$AVG_LATENCY" == "0" ] || [ -z "$AVG_LATENCY" ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S"): Failed to ping $IP_ADDRESS. Restarting service..." >> "$LOG_FILE"
        restart_service
    else
        LATENCY_INT=${AVG_LATENCY%.*}
        LATENCY_INT=${LATENCY_INT:-0}

        if [ "$LATENCY_INT" -gt "$LATENCY_THRESHOLD" ]; then
            echo "$(date +"%Y-%m-%d %H:%M:%S"): Average latency $AVG_LATENCY ms exceeds threshold of $LATENCY_THRESHOLD ms. Restarting service..." >> "$LOG_FILE"
            restart_service
        fi
    fi

    sleep "$CHECK_INTERVAL"
done
EOF

    # Replace placeholders
    sed -i "s/IP_PLACEHOLDER/$IP_ADDRESS/g" /etc/monitor.sh
    sed -i "s/LATENCY_PLACEHOLDER/$LATENCY_THRESHOLD/g" /etc/monitor.sh
    sed -i "s/CHECK_PLACEHOLDER/$CHECK_INTERVAL/g" /etc/monitor.sh

    chmod +x /etc/monitor.sh

    echo
    colorize yellow "Creating a service for watchdog" bold
    echo

    SERVICE_FILE="/etc/systemd/system/easymesh-watchdog.service"
cat > $SERVICE_FILE <<EOF
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

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now easymesh-watchdog.service

    sleep 2

    if systemctl is-active --quiet easymesh-watchdog.service; then
        echo
        colorize green "Watchdog service started successfully" bold
        echo
    else
        colorize red "Failed to start watchdog service" bold
    fi

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
    rm -f /etc/monitor.sh /etc/monitor.log /etc/monitor.log.old &> /dev/null
    rm -f "$SERVICE_FILE"  &> /dev/null
    systemctl daemon-reload &> /dev/null

    colorize yellow "Watchdog service stopped and removed successfully" bold
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
    if [ -f /etc/monitor.log ]; then
        less +G /etc/monitor.log
    else
        echo ''
        colorize yellow "No logs found.\n" bold
        press_key
    fi
}

add_cron_job() {
    echo

    local service_name="easymesh.service"

    colorize cyan "Select the restart time interval:" bold
    echo
    echo "1. Every 30th minute"
    echo "2. Every 1 hour"
    echo "3. Every 2 hours"
    echo "4. Every 4 hours"
    echo "5. Every 6 hours"
    echo "6. Every 12 hours"
    echo "7. Every 24 hours"
    echo
    read -p "Enter your choice: " time_choice

    case $time_choice in
        1) restart_time="*/30 * * * *" ;;
        2) restart_time="0 * * * *" ;;
        3) restart_time="0 */2 * * *" ;;
        4) restart_time="0 */4 * * *" ;;
        5) restart_time="0 */6 * * *" ;;
        6) restart_time="0 */12 * * *" ;;
        7) restart_time="0 0 * * *" ;;
        *)
            colorize red "Invalid choice. Please enter a number between 1 and 7.\n"
            sleep 2
            return 1
            ;;
    esac

    delete_cron_job > /dev/null 2>&1

    local reset_path="/root/easytier/reset.sh"

    cat << 'EOF' > "$reset_path"
#!/bin/bash
# Kill all easytier processes
pkill -9 -f easytier-core
sleep 2
# Reload and restart service
sudo systemctl daemon-reload
sudo systemctl restart easymesh.service
EOF

    chmod +x "$reset_path"

    crontab -l 2>/dev/null > /tmp/crontab.tmp || touch /tmp/crontab.tmp
    echo "$restart_time $reset_path #$service_name" >> /tmp/crontab.tmp
    crontab /tmp/crontab.tmp
    rm /tmp/crontab.tmp

    echo
    colorize green "Cron-job added successfully to restart the service '$service_name'." bold
    sleep 2
}

delete_cron_job() {
    echo
    local service_name="easymesh.service"
    local reset_path="/root/easytier/reset.sh"

    crontab -l 2>/dev/null | grep -v "#$service_name" | crontab - 2>/dev/null
    rm -f "$reset_path" >/dev/null 2>&1

    colorize green "Cron job for $service_name deleted successfully." bold
    sleep 2
}

set_cronjob() {
    clear
    colorize cyan "Cron-job setting menu" bold
    echo

    colorize green "1) Add a new cronjob"
    colorize red "2) Delete existing cronjob"
    colorize reset "3) Return..."

    echo
    echo -ne "Select your option [1-3]: "
    read -r choice

    case $choice in
        1) add_cron_job ;;
        2) delete_cron_job ;;
        3) return 0 ;;
        *) colorize red "Invalid option!" && sleep 1 && return 1 ;;
    esac
}

check_core_status() {
    DEST_DIR="/root/easytier"
    FILE1="easytier-core"
    FILE2="easytier-cli"

    if [ -f "$DEST_DIR/$FILE1" ] && [ -f "$DEST_DIR/$FILE2" ]; then
        colorize green "EasyMesh Core Installed" bold
        return 0
    else
        colorize red "EasyMesh Core not found" bold
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

    rm -rf /root/easytier &> /dev/null

    colorize green "    Easymesh core deleted successfully." bold
    sleep 2
}

display_menu() {
    clear
    echo -e "   ${CYAN}╔════════════════════════════════════════╗"
    echo -e "   ║            🌐 ${WHITE}EasyMesh                 ${CYAN}║"
    echo -e "   ║        ${WHITE}VPN Network Solution            ${CYAN}║"
    echo -e "   ╠════════════════════════════════════════╣"
    echo -e "   ║  ${WHITE}Core Version: 2.03 (Fixed)            ${CYAN}║"
    echo -e "   ║  ${WHITE}Telegram Channel: @Gozar_Xray         ${CYAN}║"
    echo -e "   ║  ${WHITE}GitHub: github.com/Musixal/easy-mesh  ${CYAN}║"
    echo -e "   ╠════════════════════════════════════════╣${RESET}"
    echo -e "   ║        $(check_core_status)         ║"
    echo -e "   ╚════════════════════════════════════════╝"

    echo ''
    colorize green "    [1] Connect to the Mesh Network" bold
    colorize yellow "    [2] Display Peers"
    colorize cyan "    [3] Display Routes"
    colorize reset "    [4] Peer-Center"
    colorize reset "    [5] Display Secret Key"
    colorize reset "    [6] View Service Status"
    colorize reset "    [7] Set Watchdog [Auto-Restarter]"
    colorize reset "    [8] Cron-job setting"
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
        0) exit 0 ;;
        *) colorize red "    Invalid option!" bold && sleep 1 ;;
    esac
}

# Main script
while true
do
    display_menu
    read_option
done
