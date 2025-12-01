#!/bin/bash

###############################################################################
# WireGuard Namespace Manager
# 
# Description: Manage multiple isolated WireGuard tunnels and Xray proxy instances
#              using Linux network namespaces. Each tunnel runs in its own
#              namespace with automatic Xray setup.
#
# Features:
#   - Create isolated WireGuard tunnels in network namespaces
#   - Automatic Xray proxy setup with VLESS protocol
#   - HTTP header obfuscation support
#   - Automatic dependency installation
#   - Port forwarding and NAT configuration
#   - Debug and monitoring tools
#
# Requirements:
#   - Root privileges
#   - Linux kernel with WireGuard support
#   - Network namespace support
#
# Usage:
#   bash setup-wg.sh
#
# Author: Auto-generated
# License: MIT
# Version: 1.0.0
# Repository: https://github.com/alihm-us/WireGuard-Namespace-Manager
###############################################################################

# Don't exit on error for cleanup operations (we handle errors manually)
set +e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

function check_and_install_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    local MISSING_DEPS=()
    
    # Check for required commands
    if ! command -v wg &> /dev/null; then
        MISSING_DEPS+=("wireguard-tools")
    fi
    
    if ! command -v ip &> /dev/null; then
        MISSING_DEPS+=("iproute2")
    fi
    
    if ! command -v iptables &> /dev/null; then
        MISSING_DEPS+=("iptables")
    fi
    
    if ! command -v curl &> /dev/null; then
        MISSING_DEPS+=("curl")
    fi
    
    if ! command -v ss &> /dev/null; then
        MISSING_DEPS+=("iproute2")
    fi
    
    # Check if wireguard module is loaded
    if ! lsmod | grep -q wireguard; then
        if ! modprobe wireguard 2>/dev/null; then
            MISSING_DEPS+=("wireguard-dkms")
        fi
    fi
    
    if [ ${#MISSING_DEPS[@]} -eq 0 ]; then
        echo -e "${GREEN}All dependencies are installed.${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}Missing dependencies: ${MISSING_DEPS[*]}${NC}"
    echo -e "${YELLOW}Do you want to install them automatically? (y/n)${NC}"
    read -p "> " INSTALL
    
    if [[ ! "$INSTALL" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Please install the following packages manually:${NC}"
        echo "  ${MISSING_DEPS[*]}"
        exit 1
    fi
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        UPDATE_CMD="apt-get update"
        INSTALL_CMD="apt-get install -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        UPDATE_CMD="yum check-update || true"
        INSTALL_CMD="yum install -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="dnf check-update || true"
        INSTALL_CMD="dnf install -y"
    else
        echo -e "${RED}Could not detect package manager. Please install manually.${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Updating package list...${NC}"
    $UPDATE_CMD >/dev/null 2>&1
    
    # Install packages
    local PKGS_TO_INSTALL=()
    for dep in "${MISSING_DEPS[@]}"; do
        case $dep in
            wireguard-tools)
                if [[ "$PKG_MANAGER" == "apt-get" ]]; then
                    PKGS_TO_INSTALL+=("wireguard-tools")
                elif [[ "$PKG_MANAGER" == "yum" ]] || [[ "$PKG_MANAGER" == "dnf" ]]; then
                    PKGS_TO_INSTALL+=("wireguard-tools")
                fi
                ;;
            wireguard-dkms)
                if [[ "$PKG_MANAGER" == "apt-get" ]]; then
                    PKGS_TO_INSTALL+=("wireguard-dkms")
                elif [[ "$PKG_MANAGER" == "yum" ]] || [[ "$PKG_MANAGER" == "dnf" ]]; then
                    PKGS_TO_INSTALL+=("wireguard")
                fi
                ;;
            iproute2)
                PKGS_TO_INSTALL+=("iproute2")
                ;;
            iptables)
                PKGS_TO_INSTALL+=("iptables")
                ;;
            curl)
                PKGS_TO_INSTALL+=("curl")
                ;;
        esac
    done
    
    # Remove duplicates
    PKGS_TO_INSTALL=($(printf "%s\n" "${PKGS_TO_INSTALL[@]}" | sort -u))
    
    if [ ${#PKGS_TO_INSTALL[@]} -gt 0 ]; then
        echo -e "${BLUE}Installing: ${PKGS_TO_INSTALL[*]}${NC}"
        $INSTALL_CMD "${PKGS_TO_INSTALL[@]}" || {
            echo -e "${RED}Installation failed. Please install manually.${NC}"
            exit 1
        }
    fi
    
    # Try to load wireguard module again
    if ! lsmod | grep -q wireguard; then
        modprobe wireguard 2>/dev/null || echo -e "${YELLOW}Warning: Could not load wireguard module. You may need to reboot.${NC}"
    fi
    
    echo -e "${GREEN}Dependencies installed successfully!${NC}"
    echo ""
}

function show_header() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        WireGuard Namespace Manager                 ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
    echo -e "Repo: https://github.com/alihm-us/WireGuard-Namespace-Manager"
    echo ""
}

declare -A GEO_CACHE

function geo_lookup() {
    # Lookup country and city for a given IP using ip-api.com (cached, best-effort)
    local IP="$1"
    local GEO=""

    if [ -z "$IP" ] || [ "$IP" = "N/A" ]; then
        echo ""
        return 0
    fi

    # Only IPv4 addresses are supported by this simple lookup
    if ! echo "$IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo ""
        return 0
    fi

    # Check cache first
    if [ -n "${GEO_CACHE[$IP]+set}" ]; then
        echo "${GEO_CACHE[$IP]}"
        return 0
    fi

    # Use CSV format for easy parsing: country,city
    local RESP
    RESP=$(curl -s --max-time 0.8 "http://ip-api.com/csv/$IP?fields=status,country,city" 2>/dev/null || echo "")

    if [ -n "$RESP" ]; then
        local STATUS COUNTRY CITY
        IFS=',' read -r STATUS COUNTRY CITY <<< "$RESP"
        if [ "$STATUS" = "success" ] && { [ -n "$COUNTRY" ] || [ -n "$CITY" ]; }; then
            GEO="${CITY}, ${COUNTRY}"
        fi
    fi

    # Cache result (even if empty, to avoid repeated lookups)
    GEO_CACHE["$IP"]="$GEO"
    echo "$GEO"
}

function parse_vless_uri() {
    # Parse a VLESS URI and extract UUID, network, security, header type, host, path
    # Supported format example:
    # vless://uuid@host:port?type=tcp&encryption=none&security=none&headerType=http&host=example.com&path=/foo#tag
    local URI="$1"

    VLESS_UUID=""
    VLESS_NETWORK="tcp"
    VLESS_SECURITY="none"
    VLESS_HEADER_TYPE=""
    VLESS_HOST_HEADER=""
    VLESS_PATH="/"

    if [ -z "$URI" ]; then
        return 1
    fi

    # Strip scheme
    URI="${URI#vless://}"

    # Remove fragment (#...)
    URI="${URI%%#*}"

    local BASE QUERY
    if echo "$URI" | grep -q "?"; then
        BASE="${URI%%\?*}"
        QUERY="${URI#*\?}"
    else
        BASE="$URI"
        QUERY=""
    fi

    # BASE is uuid@host:port
    if echo "$BASE" | grep -q "@"; then
        VLESS_UUID="${BASE%%@*}"
        # hostport="${BASE#*@}" # not used (we use our own PORT)
    else
        VLESS_UUID="$BASE"
    fi

    # Parse query params
    if [ -n "$QUERY" ]; then
        IFS='&' read -r -a PARAMS <<< "$QUERY"
        for P in "${PARAMS[@]}"; do
            KEY="${P%%=*}"
            VAL="${P#*=}"
            case "$KEY" in
                type) VLESS_NETWORK="$VAL" ;;
                security) VLESS_SECURITY="$VAL" ;;
                headerType) VLESS_HEADER_TYPE="$VAL" ;;
                host) VLESS_HOST_HEADER="$VAL" ;;
                path) VLESS_PATH="$VAL" ;;
            esac
        done
    fi

    # Only support tcp for now
    if [ "$VLESS_NETWORK" != "tcp" ]; then
        echo -e "${RED}Only TCP VLESS URIs are supported by this script.${NC}"
        return 1
    fi

    # Basic UUID validation
    if [[ ! "$VLESS_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        echo -e "${RED}Invalid UUID in VLESS URI.${NC}"
        return 1
    fi

    return 0
}

function list_setups() {
    echo -e "${YELLOW}Active Setups:${NC}"
    echo -e "------------------------------------------------------------------------"
    printf "%-12s %-8s %-10s %-10s %-15s %-25s\n" "Namespace" "Port" "Tunnel" "Xray" "VPN IP" "Location"
    echo -e "------------------------------------------------------------------------"
    
    NAMESPACES=$(ip netns list 2>/dev/null | awk '{print $1}' | grep -E "^(ns-|nsxray)" || true)
    
    if [ -z "$NAMESPACES" ]; then
        echo "No active setups found."
        echo ""
        echo "To create a new setup, select option 1 from the menu."
        echo ""
        return
    fi
    
    local FOUND_ANY=0
    for ns in $NAMESPACES; do
        # Verify namespace still exists
        if ! ip netns list 2>/dev/null | grep -q "^$ns "; then
            continue
        fi
        
        # IP & Port Logic
        if [[ "$ns" == "nsxray" ]]; then
            NS_IP="10.200.200.2"
        else
            NS_IP=$(ip netns exec "$ns" ip -4 addr show 2>/dev/null | grep -E "inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | awk '{print $2}' | cut -d'/' -f1 | grep "^10\.100" | head -1)
        fi

        if [ -z "$NS_IP" ]; then
            continue
        fi
        
        PORT=$(iptables -t nat -S PREROUTING 2>/dev/null | grep "to-destination $NS_IP" | head -1 | awk -F':' '{print $NF}' | awk '{print $1}')
        [ -z "$PORT" ] && PORT="Unknown"
        FOUND_ANY=1
        
        # Tunnel Status - Check if WireGuard interface exists and has recent handshake
        WG_OUTPUT=$(ip netns exec "$ns" wg show 2>/dev/null)
        if [ -n "$WG_OUTPUT" ]; then
            # Check if there's a handshake (indicates active connection)
            if echo "$WG_OUTPUT" | grep -q "latest handshake"; then
                # Also verify interface is UP
                WG_INTERFACE=$(echo "$WG_OUTPUT" | head -1 | awk '{print $2}' | tr -d ':')
                if [ -n "$WG_INTERFACE" ]; then
                    LINK_STATE=$(ip netns exec "$ns" ip link show "$WG_INTERFACE" 2>/dev/null | grep -o "state [A-Z]*" || echo "")
                    if echo "$LINK_STATE" | grep -qE "UNKNOWN|UP"; then
                        T_STATUS="${GREEN}Active${NC}"
                    else
                        T_STATUS="${RED}Down${NC}"
                    fi
                else
                    T_STATUS="${GREEN}Active${NC}"
                fi
            else
                T_STATUS="${RED}Down${NC}"
            fi
        else
            T_STATUS="${RED}Down${NC}"
        fi
        
        # Xray Status
        if [ "$PORT" != "Unknown" ]; then
            if ip netns exec "$ns" ss -ltnp 2>/dev/null | grep -q ":$PORT "; then
                X_STATUS="${GREEN}Running${NC}"
            else
                X_STATUS="${RED}Stopped${NC}"
            fi
        else
            X_STATUS="${YELLOW}?${NC}"
        fi
        
        # VPN IP
        VPN_IP=$(ip netns exec "$ns" curl -s --max-time 1 http://icanhazip.com 2>/dev/null || echo "N/A")

        # Geo lookup (country/city)
        GEO_LOCATION=$(geo_lookup "$VPN_IP")
        
        # Display with proper formatting
        echo -e "$(printf '%-12s %-8s %-10s %-10s %-15s %-25s' "$ns" "$PORT" "$T_STATUS" "$X_STATUS" "$VPN_IP" "$GEO_LOCATION")"
    done
    
    if [ $FOUND_ANY -eq 0 ]; then
        echo "No active setups found."
        echo ""
        echo "To create a new setup, select option 1 from the menu."
    fi
    echo ""
}

function create_setup() {
    echo -e "${GREEN}=== Create New Setup ===${NC}"
    
    # Config File
    while true; do
        echo -e "${YELLOW}Enter WireGuard config file path:${NC}"
        read -p "> " WG_CONFIG
        WG_CONFIG="${WG_CONFIG/#\~/$HOME}"
        if [ -f "$WG_CONFIG" ]; then break; else echo -e "${RED}File not found.${NC}"; fi
    done
    
    # Port
    while true; do
        echo -e "${YELLOW}Enter port number:${NC}"
        read -p "> " PORT
        if [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
            if ss -ltn | grep -q ":$PORT "; then
                echo -e "${YELLOW}Port $PORT is in use. Continue? (y/n)${NC}"
                read -p "> " CONT
                [[ "$CONT" =~ ^[Yy]$ ]] && break
            else
                break
            fi
        else
            echo -e "${RED}Invalid port.${NC}"
        fi
    done
    
    # --- Setup Logic ---
    SUBNET_OCTET=$(( (PORT % 250) + 1 ))
    NS_NAME="ns-${PORT}"
    VETH_HOST="veth-${PORT}"
    VETH_NS="vpeer-${PORT}"
    HOST_IP="10.100.${SUBNET_OCTET}.1"
    NS_IP="10.100.${SUBNET_OCTET}.2"
    SUBNET="10.100.${SUBNET_OCTET}.0/24"
    
    echo -e "${BLUE}Setting up $NS_NAME on port $PORT...${NC}"
    
    # Cleanup existing setup if any
    echo -e "${YELLOW}Cleaning up any existing setup...${NC}"
    if ip netns list | grep -q "^$NS_NAME "; then
        echo -e "${YELLOW}Removing existing namespace $NS_NAME...${NC}"
        ip netns delete "$NS_NAME" 2>/dev/null || true
        sleep 1
    fi
    if ip link show "$VETH_HOST" &>/dev/null; then
        echo -e "${YELLOW}Removing existing veth $VETH_HOST...${NC}"
        ip link delete "$VETH_HOST" 2>/dev/null || true
        sleep 1
    fi
    
    # Cleanup iptables rules if any
    iptables -t nat -D PREROUTING -p tcp --dport "$PORT" -j DNAT --to-destination "$NS_IP:$PORT" 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport "$PORT" -j DNAT --to-destination "$NS_IP:$PORT" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$SUBNET" ! -o "$VETH_HOST" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -p tcp -d "$NS_IP/32" --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -p udp -d "$NS_IP/32" --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -p tcp -s "$NS_IP/32" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -p udp -s "$NS_IP/32" -j ACCEPT 2>/dev/null || true
    
    # 1. Resolve Endpoint
    ENDPOINT=$(grep -i "^Endpoint" "$WG_CONFIG" | head -1 | cut -d'=' -f2 | tr -d ' ')
    ENDPOINT_HOST=$(echo "$ENDPOINT" | cut -d':' -f1)
    # Try multiple methods to resolve DNS
    ENDPOINT_IP=""
    if command -v getent &> /dev/null; then
        ENDPOINT_IP=$(getent ahosts "$ENDPOINT_HOST" 2>/dev/null | awk '{print $1}' | head -1)
    elif command -v host &> /dev/null; then
        ENDPOINT_IP=$(host "$ENDPOINT_HOST" 2>/dev/null | grep "has address" | head -1 | awk '{print $4}')
    elif command -v dig &> /dev/null; then
        ENDPOINT_IP=$(dig +short "$ENDPOINT_HOST" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    fi
    [ -z "$ENDPOINT_IP" ] && echo -e "${RED}Could not resolve endpoint: $ENDPOINT_HOST${NC}" && return 1
    
    # 2. Namespace & Veth
    echo -e "${BLUE}Creating namespace and veth pair...${NC}"
    ip netns add "$NS_NAME" || {
        echo -e "${RED}Failed to create namespace. Trying cleanup...${NC}"
        ip netns delete "$NS_NAME" 2>/dev/null || true
        sleep 2
        ip netns add "$NS_NAME" || {
            echo -e "${RED}Failed to create namespace after cleanup. Please check manually.${NC}"
            return 1
        }
    }
    
    # Delete veth if exists and create new
    ip link delete "$VETH_HOST" 2>/dev/null || true
    sleep 1
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS" || {
        echo -e "${RED}Failed to create veth pair. Cleaning up...${NC}"
        ip netns delete "$NS_NAME" 2>/dev/null || true
        return 1
    }
    ip link set "$VETH_HOST" up
    ip addr flush dev "$VETH_HOST" 2>/dev/null || true
    ip addr add "$HOST_IP/24" dev "$VETH_HOST"
    
    ip link set "$VETH_NS" netns "$NS_NAME"
    ip netns exec "$NS_NAME" ip link set lo up
    ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
    ip netns exec "$NS_NAME" ip addr flush dev "$VETH_NS" 2>/dev/null || true
    ip netns exec "$NS_NAME" ip addr add "$NS_IP/24" dev "$VETH_NS"
    
    # 3. WireGuard
    echo -e "${BLUE}Setting up WireGuard...${NC}"
    # Generate unique WireGuard interface name
    if command -v md5sum &> /dev/null; then
        WG_NAME="wg-$(echo $PORT | md5sum | cut -c1-8)"
    elif command -v md5 &> /dev/null; then
        WG_NAME="wg-$(echo $PORT | md5 | cut -c1-8)"
    else
        # Fallback to simple hash
        WG_NAME="wg-$(printf "%08x" $((PORT * 31)) | cut -c1-8)"
    fi
    WG_ADDRESS=$(grep -i "^Address" "$WG_CONFIG" | head -1 | cut -d'=' -f2 | tr -d ' ')
    [ -z "$WG_ADDRESS" ] && WG_ADDRESS="10.0.0.2/32"
    
    # Cleanup existing WireGuard interface
    ip netns exec "$NS_NAME" ip link delete "$WG_NAME" 2>/dev/null || true
    ip link delete "$WG_NAME" 2>/dev/null || true
    sleep 1
    
    ip link add "$WG_NAME" type wireguard || {
        echo -e "${RED}Failed to create WireGuard interface. Cleaning up...${NC}"
        ip link delete "$VETH_HOST" 2>/dev/null || true
        ip netns delete "$NS_NAME" 2>/dev/null || true
        return 1
    }
    # Configure WireGuard interface
    if ! grep -vE "^(Address|DNS|Table|MTU|PreUp|PostUp|PreDown|PostDown)" "$WG_CONFIG" | wg setconf "$WG_NAME" /dev/stdin 2>/dev/null; then
        echo -e "${RED}Failed to configure WireGuard interface. Please check your config file.${NC}"
        ip link delete "$WG_NAME" 2>/dev/null || true
        ip link delete "$VETH_HOST" 2>/dev/null || true
        ip netns delete "$NS_NAME" 2>/dev/null || true
        return 1
    fi
    ip link set "$WG_NAME" netns "$NS_NAME"
    ip netns exec "$NS_NAME" ip addr add "$WG_ADDRESS" dev "$WG_NAME"
    ip netns exec "$NS_NAME" ip link set "$WG_NAME" up
    
    # 4. Routing - Optimized: new traffic via WireGuard, established returns via veth
    ip netns exec "$NS_NAME" ip route flush table main 2>/dev/null || true
    ip netns exec "$NS_NAME" ip route flush table 100 2>/dev/null || true
    ip netns exec "$NS_NAME" ip route add 10.100.${SUBNET_OCTET}.0/24 dev "$VETH_NS" proto kernel scope link src "$NS_IP"
    ip netns exec "$NS_NAME" ip route add "$ENDPOINT_IP/32" via "$HOST_IP"
    ip netns exec "$NS_NAME" ip route add default dev "$WG_NAME"
    # Policy routing: established/related connections return via veth
    ip netns exec "$NS_NAME" ip route add default via "$HOST_IP" dev "$VETH_NS" table 100
    ip netns exec "$NS_NAME" ip rule add fwmark 1 lookup 100
    # Mark established/related connections from NS_IP to return via veth
    ip netns exec "$NS_NAME" iptables -t mangle -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -s "$NS_IP" -j MARK --set-mark 1
    
    # 5. NAT & Firewall - Same as nsxray setup
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    # MASQUERADE for outbound traffic through WireGuard (in namespace)
    ip netns exec "$NS_NAME" iptables -t nat -A POSTROUTING -o "$WG_NAME" -j MASQUERADE
    # MASQUERADE on host for namespace subnet (like nsxray)
    iptables -t nat -D POSTROUTING -s "$SUBNET" ! -o "$VETH_HOST" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -A POSTROUTING -s "$SUBNET" ! -o "$VETH_HOST" -j MASQUERADE
    
    # DNAT
    iptables -t nat -D PREROUTING -p tcp --dport "$PORT" -j DNAT --to-destination "$NS_IP:$PORT" 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport "$PORT" -j DNAT --to-destination "$NS_IP:$PORT" 2>/dev/null || true
    iptables -t nat -A PREROUTING -p tcp --dport "$PORT" -j DNAT --to-destination "$NS_IP:$PORT"
    iptables -t nat -A PREROUTING -p udp --dport "$PORT" -j DNAT --to-destination "$NS_IP:$PORT"
    
    # Forwarding
    iptables -D FORWARD -p tcp -d "$NS_IP/32" --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -p udp -d "$NS_IP/32" --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -I FORWARD 1 -p tcp -d "$NS_IP/32" --dport "$PORT" -j ACCEPT
    iptables -I FORWARD 1 -p udp -d "$NS_IP/32" --dport "$PORT" -j ACCEPT
    # Allow return traffic from namespace
    iptables -D FORWARD -p tcp -s "$NS_IP/32" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -p udp -s "$NS_IP/32" -j ACCEPT 2>/dev/null || true
    iptables -I FORWARD 1 -p tcp -s "$NS_IP/32" -j ACCEPT
    iptables -I FORWARD 1 -p udp -s "$NS_IP/32" -j ACCEPT
    
    # DNS
    mkdir -p /etc/netns/"$NS_NAME"
    echo "nameserver 1.1.1.1" > /etc/netns/"$NS_NAME"/resolv.conf
    
    echo -e "${GREEN}Setup complete!${NC}"
    
    # Auto-start Xray with default settings or imported VLESS URI
    echo -e "${BLUE}Automatically starting Xray inbound...${NC}"
    ensure_xray_binary
    
    # Kill existing Xray if any
    PIDS=$(ip netns exec "$NS_NAME" ss -ltnp 2>/dev/null | grep ":$PORT " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' || echo "")
    if [ -n "$PIDS" ]; then
        ip netns exec "$NS_NAME" kill $PIDS 2>/dev/null || true
        sleep 1
    fi
    
    # Optional: let user paste a full VLESS URI to auto-configure inbound
    echo -e "${YELLOW}Enter VLESS URI to import for this port (or press Enter to use default settings):${NC}"
    read -p "> " VLESS_URI

    CLIENT_UUID=""
    USE_HTTP_HEADER="n"
    HTTP_HOST="iran.ir"
    HTTP_PATH="/"

    if [ -n "$VLESS_URI" ]; then
        if ! parse_vless_uri "$VLESS_URI"; then
            echo -e "${RED}Failed to parse VLESS URI. Falling back to default settings.${NC}"
        else
            CLIENT_UUID="$VLESS_UUID"
            if [ "$VLESS_HEADER_TYPE" = "http" ]; then
                USE_HTTP_HEADER="y"
                [ -n "$VLESS_HOST_HEADER" ] && HTTP_HOST="$VLESS_HOST_HEADER"
                [ -n "$VLESS_PATH" ] && HTTP_PATH="$VLESS_PATH"
            else
                USE_HTTP_HEADER="n"
            fi
        fi
    fi

    # If URI was not given or failed, use default simple TCP with default UUID
    if [ -z "$CLIENT_UUID" ]; then
        DEFAULT_UUID="efdf43b5-2ac8-437c-95b2-673e1eff76c1"
        CLIENT_UUID="$DEFAULT_UUID"
        echo -e "${GREEN}Using default UUID for auto-start: $CLIENT_UUID${NC}"
        USE_HTTP_HEADER="n"
    fi

    # Create Xray config (either imported or default)
    XRAY_CONFIG="/tmp/xray-${PORT}.json"

    if [[ "$USE_HTTP_HEADER" =~ ^[Yy]$ ]]; then
        cat > "$XRAY_CONFIG" << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": ${PORT},
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${CLIENT_UUID}",
                        "flow": ""
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "header": {
                        "type": "http",
                        "request": {
                            "version": "1.1",
                            "method": "GET",
                            "path": ["${HTTP_PATH}"],
                            "headers": {
                                "Host": ["${HTTP_HOST}"]
                            }
                        }
                    }
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF
    else
        cat > "$XRAY_CONFIG" << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": ${PORT},
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${CLIENT_UUID}",
                        "flow": ""
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF
    fi
    
    # Start Xray
    nohup ip netns exec "$NS_NAME" /usr/local/bin/xray-ns -c "$XRAY_CONFIG" > "/tmp/xray-${PORT}.log" 2>&1 &
    sleep 2
    
    if ip netns exec "$NS_NAME" ss -ltnp 2>/dev/null | grep -q ":$PORT "; then
        echo -e "${GREEN}Xray started successfully!${NC}"
        echo -e "${BLUE}UUID: ${DEFAULT_UUID}${NC}"
        
        # Get public IP
        HOST_IP=$(curl -s --max-time 3 http://icanhazip.com 2>/dev/null || ip addr show eth0 2>/dev/null | grep -E "inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | awk '{print $2}' | cut -d'/' -f1 | head -1)
        [ -z "$HOST_IP" ] && HOST_IP=$(ip addr show | grep -E "inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | awk '{print $2}' | cut -d'/' -f1 | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | head -1)
        
        echo -e "${YELLOW}VLESS Connection String:${NC}"
        echo "vless://${DEFAULT_UUID}@${HOST_IP}:${PORT}?encryption=none&type=tcp&headerType=http&host=${HTTP_HOST}&path=${HTTP_PATH}&security=none"
    else
        echo -e "${YELLOW}Xray failed to start automatically. You can start it manually using option 2.${NC}"
        tail -n 5 "/tmp/xray-${PORT}.log" 2>/dev/null || true
    fi
    
    read -p "Press Enter to continue..."
}

function ensure_xray_binary() {
    # Check if xray-ns exists
    if [ -f "/usr/local/bin/xray-ns" ] && [ -x "/usr/local/bin/xray-ns" ]; then
        return 0
    fi
    
    # Try to find existing xray
    XRAY_BIN=$(find /usr/local/x-ui/bin /usr/bin /usr/local/bin -name "xray-linux-amd64" -o -name "xray" 2>/dev/null | head -1)
    if [ -n "$XRAY_BIN" ] && [ -x "$XRAY_BIN" ]; then
        # Copy to xray-ns for namespace use
        cp "$XRAY_BIN" /usr/local/bin/xray-ns 2>/dev/null && chmod +x /usr/local/bin/xray-ns && return 0
    fi
    
    # Download Xray if not found
    echo -e "${YELLOW}Xray binary not found. Downloading...${NC}"
    cd /tmp
    if command -v wget &> /dev/null; then
        wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -O xray.zip || {
            echo -e "${RED}Failed to download Xray${NC}"
            return 1
        }
    elif command -v curl &> /dev/null; then
        curl -L -s https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip || {
            echo -e "${RED}Failed to download Xray${NC}"
            return 1
        }
    else
        echo -e "${RED}Neither wget nor curl found. Cannot download Xray.${NC}"
        return 1
    fi
    
    if [ -f xray.zip ]; then
        # Check for unzip command
        if ! command -v unzip &> /dev/null; then
            echo -e "${YELLOW}unzip not found. Trying to install...${NC}"
            if command -v apt-get &> /dev/null; then
                apt-get update >/dev/null 2>&1 && apt-get install -y unzip >/dev/null 2>&1
            elif command -v yum &> /dev/null; then
                yum install -y unzip >/dev/null 2>&1
            elif command -v dnf &> /dev/null; then
                dnf install -y unzip >/dev/null 2>&1
            fi
        fi
        if command -v unzip &> /dev/null; then
            unzip -q -o xray.zip xray 2>/dev/null || {
                echo -e "${RED}Failed to extract Xray${NC}"
                return 1
            }
        else
            echo -e "${RED}unzip is required but not available. Please install unzip manually.${NC}"
            return 1
        fi
        if [ -f xray ]; then
            chmod +x xray
            mkdir -p /usr/local/bin
            mv xray /usr/local/bin/xray-ns
            rm -f xray.zip
            echo -e "${GREEN}Xray downloaded and installed to /usr/local/bin/xray-ns${NC}"
            return 0
        fi
    fi
    
    echo -e "${RED}Failed to install Xray${NC}"
    return 1
}

function manage_xray() {
    local TARGET_PORT="$1"
    local ACTION="$2"
    
    if [ -z "$TARGET_PORT" ]; then
        echo -e "${YELLOW}Enter Port number:${NC}"
        read -p "> " TARGET_PORT
    fi
    
    NS_NAME="ns-${TARGET_PORT}"
    if ! ip netns list | grep -q "$NS_NAME"; then
        if [ "$TARGET_PORT" == "9349" ] && ip netns list | grep -q "nsxray"; then
            NS_NAME="nsxray"
        else
            echo -e "${RED}Namespace for port $TARGET_PORT not found.${NC}"
            return
        fi
    fi
    
    if [ -z "$ACTION" ]; then
        echo -e "${BLUE}Xray Management for Port $TARGET_PORT ($NS_NAME)${NC}"
        echo "1. Start/Restart Xray"
        echo "2. Stop Xray"
        echo "3. Check Logs"
        read -p "> " ACTION_OPT
        case $ACTION_OPT in
            1) ACTION="start" ;;
            2) ACTION="stop" ;;
            3) ACTION="logs" ;;
            *) return ;;
        esac
    fi
    
    case $ACTION in
        start)
            echo -e "${BLUE}Starting Xray...${NC}"
            
            # Ensure Xray binary exists
            if ! ensure_xray_binary; then
                echo -e "${RED}Failed to ensure Xray binary. Exiting.${NC}"
                return 1
            fi
            
            # Kill existing
            PIDS=$(ip netns exec "$NS_NAME" ss -ltnp 2>/dev/null | grep ":$TARGET_PORT " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' || echo "")
            if [ -n "$PIDS" ]; then
                echo -e "${YELLOW}Stopping existing Xray processes...${NC}"
                ip netns exec "$NS_NAME" kill $PIDS 2>/dev/null || true
                sleep 1
            fi
            
            # Optional: let user paste a full VLESS URI to auto-configure inbound
            echo -e "${YELLOW}Enter VLESS URI to import (or press Enter to configure manually):${NC}"
            read -p "> " VLESS_URI

            CLIENT_UUID=""
            USE_HTTP_HEADER="n"
            HTTP_HOST="iran.ir"
            HTTP_PATH="/"

            if [ -n "$VLESS_URI" ]; then
                if ! parse_vless_uri "$VLESS_URI"; then
                    echo -e "${RED}Failed to parse VLESS URI. Falling back to manual configuration.${NC}"
                else
                    CLIENT_UUID="$VLESS_UUID"
                    # Only tcp is supported; already validated in parse_vless_uri
                    if [ "$VLESS_HEADER_TYPE" = "http" ]; then
                        USE_HTTP_HEADER="y"
                        [ -n "$VLESS_HOST_HEADER" ] && HTTP_HOST="$VLESS_HOST_HEADER"
                        [ -n "$VLESS_PATH" ] && HTTP_PATH="$VLESS_PATH"
                    else
                        USE_HTTP_HEADER="n"
                    fi
                fi
            fi

            # If URI was not given or failed, ask user for minimal manual config
            if [ -z "$CLIENT_UUID" ]; then
                DEFAULT_UUID="efdf43b5-2ac8-437c-95b2-673e1eff76c1"
                echo -e "${YELLOW}Enter UUID for vless client (or press Enter to use default: ${DEFAULT_UUID}):${NC}"
                read -p "> " CLIENT_UUID
                if [ -z "$CLIENT_UUID" ]; then
                    CLIENT_UUID="$DEFAULT_UUID"
                    echo -e "${GREEN}Using default UUID: $CLIENT_UUID${NC}"
                fi
            fi

            # Validate UUID format
            if [[ ! "$CLIENT_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                echo -e "${RED}Invalid UUID format. Please use format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx${NC}"
                return 1
            fi

            # If not imported from URI, ask about HTTP header
            if [ -z "$VLESS_URI" ]; then
                echo -e "${YELLOW}Use HTTP header obfuscation? (y/n, default: n)${NC}"
                read -p "> " USE_HTTP_HEADER
                if [[ ! "$USE_HTTP_HEADER" =~ ^[Nn]$ ]]; then
                    echo -e "${YELLOW}Enter HTTP Host header (default: iran.ir, press Enter for default):${NC}"
                    read -p "> " HTTP_HOST
                    [ -z "$HTTP_HOST" ] && HTTP_HOST="iran.ir"
                    
                    echo -e "${YELLOW}Enter HTTP Path (default: /, press Enter for default):${NC}"
                    read -p "> " HTTP_PATH
                    [ -z "$HTTP_PATH" ] && HTTP_PATH="/"
                    
                    USE_HTTP_HEADER="y"
                else
                    USE_HTTP_HEADER="n"
                fi
            fi
            
            # Create config file
            XRAY_CONFIG="/tmp/xray-${TARGET_PORT}.json"
            
            if [[ "$USE_HTTP_HEADER" =~ ^[Yy]$ ]]; then
                cat > "$XRAY_CONFIG" << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": ${TARGET_PORT},
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${CLIENT_UUID}",
                        "flow": ""
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "header": {
                        "type": "http",
                        "request": {
                            "version": "1.1",
                            "method": "GET",
                            "path": ["${HTTP_PATH}"],
                            "headers": {
                                "Host": ["${HTTP_HOST}"]
                            }
                        }
                    }
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF
            else
                cat > "$XRAY_CONFIG" << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": ${TARGET_PORT},
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${CLIENT_UUID}",
                        "flow": ""
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF
            fi
            
            echo -e "${GREEN}Xray config created at: $XRAY_CONFIG${NC}"
            echo -e "${BLUE}UUID: $CLIENT_UUID${NC}"
            echo -e "${BLUE}Port: $TARGET_PORT${NC}"
            
            # Start
            nohup ip netns exec "$NS_NAME" /usr/local/bin/xray-ns -c "$XRAY_CONFIG" > "/tmp/xray-${TARGET_PORT}.log" 2>&1 &
            sleep 2
            
            if ip netns exec "$NS_NAME" ss -ltnp 2>/dev/null | grep -q ":$TARGET_PORT "; then
                echo -e "${GREEN}Xray started successfully on port $TARGET_PORT${NC}"
                echo -e "${GREEN}UUID: $CLIENT_UUID${NC}"
                echo -e "${YELLOW}VLESS connection string:${NC}"
                HOST_IP=$(ip addr show eth0 2>/dev/null | grep -E "inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | awk '{print $2}' | cut -d'/' -f1 | head -1)
                if [ -z "$HOST_IP" ]; then
                    HOST_IP=$(curl -s --max-time 3 http://icanhazip.com 2>/dev/null || ip addr show | grep -E "inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | awk '{print $2}' | cut -d'/' -f1 | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | head -1)
                fi
                
                if [[ "$USE_HTTP_HEADER" =~ ^[Yy]$ ]]; then
                    echo "vless://${CLIENT_UUID}@${HOST_IP}:${TARGET_PORT}?encryption=none&type=tcp&headerType=http&host=${HTTP_HOST}&path=${HTTP_PATH}&security=none"
                else
                    echo "vless://${CLIENT_UUID}@${HOST_IP}:${TARGET_PORT}?type=tcp&encryption=none&security=none"
                fi
            else
                echo -e "${RED}Xray failed to start. Check logs:${NC}"
                tail -n 10 "/tmp/xray-${TARGET_PORT}.log"
            fi
            ;;
            
        stop)
            echo -e "${BLUE}Stopping Xray...${NC}"
            PIDS=$(ip netns exec "$NS_NAME" ss -ltnp 2>/dev/null | grep ":$TARGET_PORT " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' || echo "")
            if [ -n "$PIDS" ]; then
                ip netns exec "$NS_NAME" kill $PIDS
                echo -e "${GREEN}Stopped.${NC}"
            else
                echo -e "${YELLOW}Not running.${NC}"
            fi
            ;;
            
        logs)
            echo -e "${BLUE}Last 20 lines of log (/tmp/xray-${TARGET_PORT}.log):${NC}"
            tail -n 20 "/tmp/xray-${TARGET_PORT}.log"
            ;;
    esac
    
    if [ -z "$1" ]; then read -p "Press Enter to continue..."; fi
}

function debug_setup() {
    echo -e "${BLUE}=== Debug Setup ===${NC}"
    echo -e "${YELLOW}Enter Port number to debug:${NC}"
    read -p "> " PORT
    
    NS_NAME="ns-${PORT}"
    NAMESPACE_EXISTS=0
    if ip netns list 2>/dev/null | grep -q "^$NS_NAME "; then
        NAMESPACE_EXISTS=1
    elif [ "$PORT" == "9349" ] && ip netns list 2>/dev/null | grep -q "^nsxray "; then
        NS_NAME="nsxray"
        NAMESPACE_EXISTS=1
    fi
    
    if [ $NAMESPACE_EXISTS -eq 0 ]; then
        echo -e "${YELLOW}Namespace not found, but cleaning up orphaned iptables rules...${NC}"
    fi
    
    LOG_FILE="/tmp/debug-${PORT}.log"
    echo "=== Debug Log for Port $PORT ($NS_NAME) ===" > "$LOG_FILE"
    echo "Timestamp: $(date)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    echo -e "${BLUE}Collecting debug information...${NC}"
    
    # 1. Namespace info
    echo "=== Namespace Info ===" >> "$LOG_FILE"
    ip netns list | grep "$NS_NAME" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    # 2. IP addresses
    echo "=== IP Addresses ===" >> "$LOG_FILE"
    ip netns exec "$NS_NAME" ip addr show >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    # 3. Routing
    echo "=== Routing Table ===" >> "$LOG_FILE"
    ip netns exec "$NS_NAME" ip route show >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    ip netns exec "$NS_NAME" ip rule show >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    # 4. WireGuard status
    echo "=== WireGuard Status ===" >> "$LOG_FILE"
    ip netns exec "$NS_NAME" wg show >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    # 5. Listening ports
    echo "=== Listening Ports ===" >> "$LOG_FILE"
    ip netns exec "$NS_NAME" ss -tulnp >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    # 6. iptables rules
    echo "=== Host iptables NAT PREROUTING ===" >> "$LOG_FILE"
    iptables -t nat -L PREROUTING -n -v | grep -E "($PORT|10.100)" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    echo "=== Host iptables FORWARD ===" >> "$LOG_FILE"
    iptables -L FORWARD -n -v | grep -E "($PORT|10.100)" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    echo "=== Host iptables NAT POSTROUTING ===" >> "$LOG_FILE"
    iptables -t nat -L POSTROUTING -n -v | grep -E "($PORT|10.100)" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    echo "=== Namespace iptables ===" >> "$LOG_FILE"
    ip netns exec "$NS_NAME" iptables -t nat -L -n -v >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    # 7. Connectivity test
    echo "=== Connectivity Test ===" >> "$LOG_FILE"
    echo "Testing route to 8.8.8.8:" >> "$LOG_FILE"
    ip netns exec "$NS_NAME" ip route get 8.8.8.8 >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    echo "Testing curl:" >> "$LOG_FILE"
    ip netns exec "$NS_NAME" curl -s --max-time 5 http://icanhazip.com >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    # 8. Connection tracking
    echo "=== Connection Tracking ===" >> "$LOG_FILE"
    conntrack -L -n 2>&1 | grep -E "($PORT|10.100)" | head -10 >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    # 9. Veth interface
    SUBNET_OCTET=$(( (PORT % 250) + 1 ))
    VETH_HOST="veth-${PORT}"
    echo "=== Veth Interface ===" >> "$LOG_FILE"
    ip addr show "$VETH_HOST" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE"
    
    echo -e "${GREEN}Debug information saved to: $LOG_FILE${NC}"
    echo ""
    echo -e "${YELLOW}Last 50 lines of log:${NC}"
    tail -n 50 "$LOG_FILE"
    echo ""
    
    # Ask for real-time logging
    echo -e "${YELLOW}Do you want to enable real-time packet logging? (y/n)${NC}"
    read -p "> " ENABLE_LOG
    if [[ "$ENABLE_LOG" =~ ^[Yy]$ ]]; then
        enable_realtime_logging "$PORT" "$NS_NAME"
    fi
    
    read -p "Press Enter to continue..."
}

function enable_realtime_logging() {
    local PORT="$1"
    local NS_NAME="$2"
    
    SUBNET_OCTET=$(( (PORT % 250) + 1 ))
    NS_IP="10.100.${SUBNET_OCTET}.2"
    
    echo -e "${BLUE}Enabling real-time packet logging for port $PORT...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop logging${NC}"
    echo ""
    
    # Add LOG rules
    iptables -t nat -I PREROUTING 1 -p tcp --dport "$PORT" -j LOG --log-prefix "[DNAT-$PORT] " --log-level 4
    iptables -t nat -I PREROUTING 1 -p udp --dport "$PORT" -j LOG --log-prefix "[DNAT-$PORT] " --log-level 4
    iptables -I FORWARD 1 -p tcp -d "$NS_IP/32" --dport "$PORT" -j LOG --log-prefix "[FWD-$PORT] " --log-level 4
    iptables -I FORWARD 1 -p udp -d "$NS_IP/32" --dport "$PORT" -j LOG --log-prefix "[FWD-$PORT] " --log-level 4
    iptables -I FORWARD 1 -p tcp -s "$NS_IP/32" -j LOG --log-prefix "[RET-$PORT] " --log-level 4
    iptables -I FORWARD 1 -p udp -s "$NS_IP/32" -j LOG --log-prefix "[RET-$PORT] " --log-level 4
    
    # Monitor kernel log
    tail -f /var/log/kern.log 2>/dev/null | grep -E "\[(DNAT|FWD|RET)-$PORT\]" || dmesg -w | grep -E "\[(DNAT|FWD|RET)-$PORT\]" &
    LOG_PID=$!
    
    trap "kill $LOG_PID 2>/dev/null; iptables -t nat -D PREROUTING -p tcp --dport $PORT -j LOG --log-prefix '[DNAT-$PORT] ' --log-level 4 2>/dev/null; iptables -t nat -D PREROUTING -p udp --dport $PORT -j LOG --log-prefix '[DNAT-$PORT] ' --log-level 4 2>/dev/null; iptables -D FORWARD -p tcp -d $NS_IP/32 --dport $PORT -j LOG --log-prefix '[FWD-$PORT] ' --log-level 4 2>/dev/null; iptables -D FORWARD -p udp -d $NS_IP/32 --dport $PORT -j LOG --log-prefix '[FWD-$PORT] ' --log-level 4 2>/dev/null; iptables -D FORWARD -p tcp -s $NS_IP/32 -j LOG --log-prefix '[RET-$PORT] ' --log-level 4 2>/dev/null; iptables -D FORWARD -p udp -s $NS_IP/32 -j LOG --log-prefix '[RET-$PORT] ' --log-level 4 2>/dev/null; exit" INT TERM
    
    wait $LOG_PID
}

function restart_wireguard() {
    echo -e "${BLUE}=== Restart WireGuard ===${NC}"
    echo -e "${YELLOW}Enter Port number to restart WireGuard:${NC}"
    read -p "> " PORT
    
    NS_NAME="ns-${PORT}"
    if ! ip netns list 2>/dev/null | grep -q "^$NS_NAME "; then
        if [ "$PORT" == "9349" ] && ip netns list 2>/dev/null | grep -q "^nsxray "; then
            NS_NAME="nsxray"
        else
            echo -e "${RED}Namespace for port $PORT not found.${NC}"
            read -p "Press Enter to continue..."
            return 1
        fi
    fi
    
    echo -e "${BLUE}Restarting WireGuard in $NS_NAME...${NC}"

    # Get WireGuard interface name
    WG_INTERFACE=$(ip netns exec "$NS_NAME" wg show 2>/dev/null | head -1 | awk '{print $2}' | tr -d ':')
    if [ -z "$WG_INTERFACE" ]; then
        echo -e "${RED}WireGuard interface not found in namespace.${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi

    # Derive subnet and endpoint info based on port (same logic as create_setup)
    SUBNET_OCTET=$(( (PORT % 250) + 1 ))
    NS_IP="10.100.${SUBNET_OCTET}.2"
    HOST_IP="10.100.${SUBNET_OCTET}.1"

    # Try to get endpoint host from WireGuard config currently applied
    WG_CONFIG_TMP="/tmp/wg-restart-${PORT}.conf"
    ip netns exec "$NS_NAME" wg showconf "$WG_INTERFACE" > "$WG_CONFIG_TMP" 2>/dev/null
    ENDPOINT_HOST=""
    if [ -s "$WG_CONFIG_TMP" ]; then
        ENDPOINT_FIELD=$(grep -i "^Endpoint" "$WG_CONFIG_TMP" | head -1 | cut -d'=' -f2 | tr -d ' ')
        ENDPOINT_HOST=$(echo "$ENDPOINT_FIELD" | cut -d':' -f1)
    fi

    # Resolve endpoint IP if possible
    ENDPOINT_IP=""
    if [ -n "$ENDPOINT_HOST" ]; then
        if command -v getent &> /dev/null; then
            ENDPOINT_IP=$(getent ahosts "$ENDPOINT_HOST" 2>/dev/null | awk '{print $1}' | head -1)
        elif command -v host &> /dev/null; then
            ENDPOINT_IP=$(host "$ENDPOINT_HOST" 2>/dev/null | grep "has address" | head -1 | awk '{print $4}')
        elif command -v dig &> /dev/null; then
            ENDPOINT_IP=$(dig +short "$ENDPOINT_HOST" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        fi
    fi

    echo -e "${YELLOW}Bringing WireGuard interface DOWN...${NC}"
    ip netns exec "$NS_NAME" ip link set "$WG_INTERFACE" down 2>/dev/null
    sleep 2

    echo -e "${YELLOW}Bringing WireGuard interface UP...${NC}"
    ip netns exec "$NS_NAME" ip link set "$WG_INTERFACE" up 2>/dev/null
    sleep 2

    # Rebuild minimal routing (same shape as create_setup, but non-destructive)
    echo -e "${YELLOW}Refreshing routes...${NC}"
    # Local subnet route via veth
    ip netns exec "$NS_NAME" ip route replace "10.100.${SUBNET_OCTET}.0/24" dev "vpeer-${PORT}" proto kernel scope link src "$NS_IP" 2>/dev/null
    # Endpoint route via host side of veth (only if we have endpoint IP)
    if [ -n "$ENDPOINT_IP" ]; then
        ip netns exec "$NS_NAME" ip route replace "$ENDPOINT_IP/32" via "$HOST_IP" dev "vpeer-${PORT}" 2>/dev/null
    fi
    # Default route via WireGuard
    ip netns exec "$NS_NAME" ip route replace default dev "$WG_INTERFACE" 2>/dev/null

    echo -e "${YELLOW}Waiting for WireGuard handshake...${NC}"
    HANDSHAKE_DETECTED=0
    for i in {1..10}; do
        sleep 2
        if ip netns exec "$NS_NAME" wg show "$WG_INTERFACE" 2>/dev/null | grep -q "latest handshake"; then
            HANDSHAKE_DETECTED=1
            break
        fi
        echo -n "."
    done
    echo ""
    
    if [ $HANDSHAKE_DETECTED -eq 1 ]; then
        echo -e "${GREEN}WireGuard restarted successfully!${NC}"
        HANDSHAKE=$(ip netns exec "$NS_NAME" wg show "$WG_INTERFACE" 2>/dev/null | grep "latest handshake" | awk '{print $3, $4}')
        if [ -n "$HANDSHAKE" ]; then
            echo -e "${BLUE}Latest handshake: $HANDSHAKE${NC}"
        fi
        echo -e "${YELLOW}Current routing table in namespace:${NC}"
        ip netns exec "$NS_NAME" ip route show
    else
        echo -e "${YELLOW}WireGuard restarted but no handshake detected yet.${NC}"
        echo -e "${YELLOW}It may take a few moments. Please check again later.${NC}"
    fi
    
    rm -f "$WG_CONFIG_TMP"
    read -p "Press Enter to continue..."
}

function delete_setup() {
    echo -e "${RED}=== Delete Setup ===${NC}"
    echo -e "${YELLOW}Enter Port number to delete:${NC}"
    read -p "> " PORT
    
    NS_NAME="ns-${PORT}"
    NAMESPACE_EXISTS=0
    if ip netns list 2>/dev/null | grep -q "^$NS_NAME "; then
        NAMESPACE_EXISTS=1
    elif [ "$PORT" == "9349" ] && ip netns list 2>/dev/null | grep -q "^nsxray "; then
        NS_NAME="nsxray"
        NAMESPACE_EXISTS=1
    fi
    
    if [ $NAMESPACE_EXISTS -eq 0 ]; then
        echo -e "${YELLOW}Namespace not found, but cleaning up orphaned iptables rules...${NC}"
    fi
    
    echo -e "${RED}Deleting setup for Port $PORT ($NS_NAME)...${NC}"
    
    if [[ "$NS_NAME" == "nsxray" ]]; then
        VETH_HOST="veth-host"
        NS_IP="10.200.200.2"
        SUBNET="10.200.200.0/24"
    else
        SUBNET_OCTET=$(( (PORT % 250) + 1 ))
        VETH_HOST="veth-${PORT}"
        NS_IP="10.100.${SUBNET_OCTET}.2"
        SUBNET="10.100.${SUBNET_OCTET}.0/24"
    fi
    
    if [ $NAMESPACE_EXISTS -eq 1 ]; then
        ip netns delete "$NS_NAME" 2>/dev/null || true
    fi
    ip link delete "$VETH_HOST" 2>/dev/null || true
    
    # Cleanup iptables rules (even if namespace doesn't exist)
    iptables -t nat -D PREROUTING -p tcp --dport "$PORT" -j DNAT --to-destination "$NS_IP:$PORT" 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport "$PORT" -j DNAT --to-destination "$NS_IP:$PORT" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$SUBNET" ! -o "$VETH_HOST" -j MASQUERADE 2>/dev/null || true
    
    iptables -D FORWARD -p tcp -d "$NS_IP/32" --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -p udp -d "$NS_IP/32" --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -p tcp -s "$NS_IP/32" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -p udp -s "$NS_IP/32" -j ACCEPT 2>/dev/null || true
    
    # Cleanup LOG rules if any
    iptables -t nat -D PREROUTING -p tcp --dport "$PORT" -j LOG --log-prefix "[DNAT-$PORT] " --log-level 4 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport "$PORT" -j LOG --log-prefix "[DNAT-$PORT] " --log-level 4 2>/dev/null || true
    iptables -D FORWARD -p tcp -d "$NS_IP/32" --dport "$PORT" -j LOG --log-prefix "[FWD-$PORT] " --log-level 4 2>/dev/null || true
    iptables -D FORWARD -p udp -d "$NS_IP/32" --dport "$PORT" -j LOG --log-prefix "[FWD-$PORT] " --log-level 4 2>/dev/null || true
    iptables -D FORWARD -p tcp -s "$NS_IP/32" -j LOG --log-prefix "[RET-$PORT] " --log-level 4 2>/dev/null || true
    iptables -D FORWARD -p udp -s "$NS_IP/32" -j LOG --log-prefix "[RET-$PORT] " --log-level 4 2>/dev/null || true
    
    echo -e "${GREEN}Deleted successfully.${NC}"
    read -p "Press Enter to continue..."
}

# Check dependencies on first run
FIRST_RUN_FILE="/tmp/.setup-wg-first-run"
if [ ! -f "$FIRST_RUN_FILE" ]; then
    check_and_install_dependencies
    touch "$FIRST_RUN_FILE"
fi

# Main Loop
while true; do
    show_header
    list_setups
    echo "1. Create New Setup"
    echo "2. Manage Xray (Start/Stop)"
    echo "3. Restart WireGuard"
    echo "4. Delete Setup"
    echo "5. Debug Setup"
    echo "6. Exit"
    echo ""
    read -p "Select option (1-6): " OPTION
    
    case $OPTION in
        1) create_setup ;;
        2) manage_xray ;;
        3) restart_wireguard ;;
        4) delete_setup ;;
        5) debug_setup ;;
        6) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
done
