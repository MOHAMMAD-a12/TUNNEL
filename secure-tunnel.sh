#!/usr/bin/env bash
# secure-tunnel.sh
#
# Provisions a narrow, authenticated WireGuard tunnel between two Ubuntu hosts
# you administer. It forwards explicitly selected TCP/UDP ports from the Iran
# ingress host to services on the Foreign host. This is not an obfuscation or
# restriction-evasion tool.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="secure-tunnel"
readonly WG_INTERFACE="wg0"
readonly WG_DIRECTORY="/etc/wireguard"
readonly WG_CONFIG="${WG_DIRECTORY}/${WG_INTERFACE}.conf"
readonly STATE_DIRECTORY="/etc/secure-tunnel"
readonly MANIFEST="${STATE_DIRECTORY}/manifest.conf"
readonly IDENTITY_KEY="${STATE_DIRECTORY}/identity.key"
readonly SYSCTL_CONFIG="/etc/sysctl.d/99-secure-tunnel.conf"
readonly FILTER_INPUT_CHAIN="SECURE_TUNNEL_INPUT"
readonly FILTER_FORWARD_CHAIN="SECURE_TUNNEL_FORWARD"
readonly NAT_PREROUTING_CHAIN="SECURE_TUNNEL_PRE"
readonly NAT_POSTROUTING_CHAIN="SECURE_TUNNEL_POST"
readonly COMMENT_PREFIX="secure-tunnel"

ROLE=""
WAN_INTERFACE=""
REMOTE_PUBLIC_IP=""
WG_LISTEN_PORT=""
LOCAL_TUNNEL_IP=""
PEER_TUNNEL_IP=""
PEER_PUBLIC_KEY=""
LOCAL_PRIVATE_KEY=""
LOCAL_PUBLIC_KEY=""
declare -a FORWARD_MAPPINGS=() # protocol:public-port:foreign-service-port
declare -a SERVICE_RULES=()    # protocol:foreign-service-port

# Rule arrays are deliberately constrained to the authenticated peer tunnel.

error() {
    printf 'ERROR: %s\n' "$*" >&2
}

warn() {
    printf 'WARNING: %s\n' "$*" >&2
}

info() {
    printf '\n==> %s\n' "$*"
}

on_error() {
    local exit_code=$?
    error "Command failed at line ${BASH_LINENO[0]} (exit ${exit_code}). No broad firewall flush was performed."
    exit "$exit_code"
}
trap on_error ERR

require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        error "Run this installer as root, for example: sudo bash ${SCRIPT_NAME}.sh"
        exit 1
    fi
}

require_ubuntu_version() {
    if [[ ! -r /etc/os-release ]]; then
        error "Cannot determine operating system: /etc/os-release is unavailable."
        exit 1
    fi

    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ ${ID:-} != "ubuntu" || ( ${VERSION_ID:-} != "20.04" && ${VERSION_ID:-} != "22.04" ) ]]; then
        error "This script supports Ubuntu 20.04 and 22.04 only (detected: ${PRETTY_NAME:-unknown})."
        exit 1
    fi
}

require_command() {
    local command_name=$1
    if ! command -v "$command_name" >/dev/null 2>&1; then
        error "Required command is unavailable: ${command_name}"
        exit 1
    fi
}

ufw_is_active() {
    command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active$'
}

ensure_dependencies() {
    require_command apt-get
    require_command systemctl

    if ufw_is_active; then
        error "UFW is active. This installer uses iptables-persistent and will not mix two firewall managers."
        error "Disable or replace UFW under your change-control process, then run this script again."
        exit 1
    fi

    local -a missing_commands=()
    local command_name
    for command_name in wg ip iptables iptables-save netfilter-persistent; do
        command -v "$command_name" >/dev/null 2>&1 || missing_commands+=("$command_name")
    done

    if (( ${#missing_commands[@]} == 0 )); then
        return
    fi

    info "Installing required packages: wireguard, iptables, iptables-persistent"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    if command -v debconf-set-selections >/dev/null 2>&1; then
        printf '%s\n' \
            'iptables-persistent iptables-persistent/autosave_v4 boolean false' \
            'iptables-persistent iptables-persistent/autosave_v6 boolean false' \
            | debconf-set-selections
    fi
    apt-get install -y wireguard iptables iptables-persistent

    for command_name in wg ip iptables iptables-save netfilter-persistent; do
        require_command "$command_name"
    done
}

validate_ipv4() {
    local address=$1
    local -a octets=()
    local octet

    [[ $address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a octets <<< "$address"
    for octet in "${octets[@]}"; do
        [[ $octet =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

validate_port() {
    local port=$1
    [[ $port =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 ))
}

validate_interface() {
    local interface_name=$1
    [[ $interface_name =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] && ip link show dev "$interface_name" >/dev/null 2>&1
}

validate_wireguard_key() {
    local key=$1
    [[ $key =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

ip_to_integer() {
    local address=$1
    local -a octets=()
    IFS='.' read -r -a octets <<< "$address"
    printf '%u' "$(( (10#${octets[0]} << 24) + (10#${octets[1]} << 16) + (10#${octets[2]} << 8) + 10#${octets[3]} ))"
}

validate_tunnel_pair() {
    local local_integer peer_integer local_host_part peer_host_part
    local_integer=$(ip_to_integer "$1")
    peer_integer=$(ip_to_integer "$2")
    local_host_part=$(( local_integer & 3 ))
    peer_host_part=$(( peer_integer & 3 ))

    (( local_host_part > 0 && local_host_part < 3 &&
       peer_host_part > 0 && peer_host_part < 3 &&
       local_integer != peer_integer &&
       (local_integer & 4294967292) == (peer_integer & 4294967292) ))
}

default_wan_interface() {
    ip -4 route show default | awk '/^default/ { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
}

prompt_with_default() {
    local variable_name=$1
    local prompt_text=$2
    local default_value=$3
    local value

    read -r -p "${prompt_text} [${default_value}]: " value
    printf -v "$variable_name" '%s' "${value:-$default_value}"
}

prompt_ipv4() {
    local variable_name=$1
    local prompt_text=$2
    local default_value=$3
    local value

    while true; do
        prompt_with_default value "$prompt_text" "$default_value"
        if validate_ipv4 "$value"; then
            printf -v "$variable_name" '%s' "$value"
            return
        fi
        warn "Enter a valid IPv4 address."
    done
}

prompt_port() {
    local variable_name=$1
    local prompt_text=$2
    local default_value=$3
    local value

    while true; do
        prompt_with_default value "$prompt_text" "$default_value"
        if validate_port "$value"; then
            printf -v "$variable_name" '%s' "$value"
            return
        fi
        warn "Enter a port from 1 through 65535."
    done
}

prompt_protocol() {
    local protocol
    while true; do
        read -r -p "Protocol (tcp/udp): " protocol
        protocol=${protocol,,}
        if [[ $protocol == "tcp" || $protocol == "udp" ]]; then
            printf '%s' "$protocol"
            return
        fi
        warn "Protocol must be tcp or udp."
    done
}

prompt_yes_no() {
    local prompt_text=$1
    local answer
    read -r -p "${prompt_text} [y/N]: " answer
    [[ ${answer,,} == "y" || ${answer,,} == "yes" ]]
}

choose_role() {
    local selection
    printf '%s\n' \
        "" \
        "Select this host's role:" \
        "  1) Iran Server (public ingress and port-forwarding host)" \
        "  2) Foreign Server (hosts the destination services)"

    while true; do
        read -r -p "Choice [1-2]: " selection
        case $selection in
            1) ROLE="iran"; return ;;
            2) ROLE="foreign"; return ;;
            *) warn "Choose 1 or 2." ;;
        esac
    done
}

mapping_public_port_exists() {
    local protocol=$1 public_port=$2 existing
    for existing in "${FORWARD_MAPPINGS[@]}"; do
        [[ $existing == "${protocol}:${public_port}:"* ]] && return 0
    done
    return 1
}

service_rule_exists() {
    local candidate=$1 existing
    for existing in "${SERVICE_RULES[@]}"; do
        [[ $existing == "$candidate" ]] && return 0
    done
    return 1
}

collect_iran_mappings() {
    local protocol public_port destination_port mapping
    info "Add the public ports that this host will forward to the Foreign server"
    printf '%s\n' "Each mapping is public-port -> service-port on ${PEER_TUNNEL_IP}."

    while prompt_yes_no "Add a forwarding mapping?"; do
        protocol=$(prompt_protocol)
        prompt_port public_port "Public listening port" "443"
        if [[ $protocol == "udp" && $public_port == "$WG_LISTEN_PORT" ]]; then
            warn "UDP ${WG_LISTEN_PORT} is reserved for WireGuard and cannot be a forwarded public port."
            continue
        fi
        prompt_port destination_port "Foreign service port" "$public_port"
        mapping="${protocol}:${public_port}:${destination_port}"
        if mapping_public_port_exists "$protocol" "$public_port"; then
            warn "A ${protocol} mapping already uses public port ${public_port}."
        else
            FORWARD_MAPPINGS+=("$mapping")
        fi
    done

    if (( ${#FORWARD_MAPPINGS[@]} == 0 )); then
        warn "No port mappings were selected. The WireGuard tunnel will be installed without public service forwarding."
    fi
}

collect_foreign_service_rules() {
    local protocol service_port rule
    info "Allow only the forwarded service ports received from the Iran tunnel"
    printf '%s\n' "Enter the same protocol/service ports configured as destinations on the Iran host."

    while prompt_yes_no "Allow a service port from the tunnel?"; do
        protocol=$(prompt_protocol)
        prompt_port service_port "Foreign service port" "443"
        rule="${protocol}:${service_port}"
        if service_rule_exists "$rule"; then
            warn "That service rule is already present."
        else
            SERVICE_RULES+=("$rule")
        fi
    done

    if (( ${#SERVICE_RULES[@]} == 0 )); then
        warn "No service ports were selected. The tunnel will start, but this installer will not permit tunneled service traffic through its managed INPUT chain."
    fi
}

load_or_generate_identity() {
    install -d -m 0700 "$STATE_DIRECTORY"

    if [[ -f $IDENTITY_KEY ]]; then
        LOCAL_PRIVATE_KEY=$(<"$IDENTITY_KEY")
        if ! validate_wireguard_key "$LOCAL_PRIVATE_KEY"; then
            error "${IDENTITY_KEY} does not contain a valid WireGuard private key."
            exit 1
        fi
    else
        LOCAL_PRIVATE_KEY=$(wg genkey)
        umask 077
        printf '%s\n' "$LOCAL_PRIVATE_KEY" > "$IDENTITY_KEY"
        chmod 0600 "$IDENTITY_KEY"
    fi

    LOCAL_PUBLIC_KEY=$(printf '%s' "$LOCAL_PRIVATE_KEY" | wg pubkey)
}

collect_configuration() {
    local wan_default local_default peer_default

    # Reset role-specific entries when this function is invoked in the same shell.
    FORWARD_MAPPINGS=()
    SERVICE_RULES=()

    choose_role
    wan_default=$(default_wan_interface)
    if [[ -z $wan_default ]]; then
        error "No IPv4 default-route interface was detected. Configure networking first."
        exit 1
    fi

    while true; do
        prompt_with_default WAN_INTERFACE "External/default-route interface" "$wan_default"
        if validate_interface "$WAN_INTERFACE"; then
            break
        fi
        warn "Interface does not exist or has an unsafe name."
    done

    prompt_ipv4 REMOTE_PUBLIC_IP "Public/reachable IPv4 address of the other server" "203.0.113.10"
    prompt_port WG_LISTEN_PORT "WireGuard UDP listen port (use the same port on both hosts)" "51820"

    if [[ $ROLE == "iran" ]]; then
        local_default="10.77.0.1"
        peer_default="10.77.0.2"
    else
        local_default="10.77.0.2"
        peer_default="10.77.0.1"
    fi

    while true; do
        prompt_ipv4 LOCAL_TUNNEL_IP "This host's WireGuard tunnel IPv4" "$local_default"
        prompt_ipv4 PEER_TUNNEL_IP "Other host's WireGuard tunnel IPv4" "$peer_default"
        if validate_tunnel_pair "$LOCAL_TUNNEL_IP" "$PEER_TUNNEL_IP"; then
            break
        fi
        warn "Tunnel addresses must be different usable addresses in the same /30 network."
    done

    load_or_generate_identity

    printf '\n%s\n%s\n%s\n' \
        "Your local WireGuard public key (copy it to the other host):" \
        "$LOCAL_PUBLIC_KEY" \
        ""

    read -r -p "Other host's WireGuard public key (press Enter to exit and exchange keys first): " PEER_PUBLIC_KEY
    if [[ -z $PEER_PUBLIC_KEY ]]; then
        info "No peer key supplied. Local identity is stored at ${IDENTITY_KEY}; no tunnel or firewall changes were applied."
        exit 0
    fi
    if ! validate_wireguard_key "$PEER_PUBLIC_KEY"; then
        error "Peer key must be a WireGuard public key in base64 form (44 characters)."
        exit 1
    fi

    if [[ $ROLE == "iran" ]]; then
        collect_iran_mappings
    else
        collect_foreign_service_rules
    fi
}

ensure_chain() {
    local table=$1 chain=$2
    iptables -w -t "$table" -nL "$chain" >/dev/null 2>&1 || iptables -w -t "$table" -N "$chain"
    iptables -w -t "$table" -F "$chain"
}

ensure_hook() {
    local table=$1 builtin_chain=$2 target_chain=$3 hook_comment=$4

    while iptables -w -t "$table" -C "$builtin_chain" -m comment --comment "$hook_comment" -j "$target_chain" 2>/dev/null; do
        iptables -w -t "$table" -D "$builtin_chain" -m comment --comment "$hook_comment" -j "$target_chain"
    done
    iptables -w -t "$table" -I "$builtin_chain" 1 -m comment --comment "$hook_comment" -j "$target_chain"
}

setup_managed_chains() {
    ensure_chain filter "$FILTER_INPUT_CHAIN"
    ensure_chain filter "$FILTER_FORWARD_CHAIN"
    ensure_chain nat "$NAT_PREROUTING_CHAIN"
    ensure_chain nat "$NAT_POSTROUTING_CHAIN"

    # Insert at the top so a pre-existing restrictive firewall evaluates the
    # explicitly scoped managed rules before its generic reject rule.
    ensure_hook filter INPUT "$FILTER_INPUT_CHAIN" "${COMMENT_PREFIX}:input-hook"
    ensure_hook filter FORWARD "$FILTER_FORWARD_CHAIN" "${COMMENT_PREFIX}:forward-hook"
    ensure_hook nat PREROUTING "$NAT_PREROUTING_CHAIN" "${COMMENT_PREFIX}:prerouting-hook"
    ensure_hook nat POSTROUTING "$NAT_POSTROUTING_CHAIN" "${COMMENT_PREFIX}:postrouting-hook"
}

add_common_firewall_rules() {
    iptables -w -t filter -A "$FILTER_INPUT_CHAIN" \
        -p udp --dport "$WG_LISTEN_PORT" \
        -m comment --comment "${COMMENT_PREFIX}:wireguard-udp" -j ACCEPT
}

add_iran_firewall_rules() {
    local mapping protocol public_port destination_port

    for mapping in "${FORWARD_MAPPINGS[@]}"; do
        IFS=':' read -r protocol public_port destination_port <<< "$mapping"

        # DNAT sends only the chosen public port to the peer's WireGuard IP.
        iptables -w -t nat -A "$NAT_PREROUTING_CHAIN" \
            -i "$WAN_INTERFACE" -p "$protocol" --dport "$public_port" \
            -m comment --comment "${COMMENT_PREFIX}:dnat:${protocol}:${public_port}" \
            -j DNAT --to-destination "${PEER_TUNNEL_IP}:${destination_port}"

        # Permit that new public flow across the tunnel; the next rule permits
        # only tracked response packets in the opposite direction.
        iptables -w -t filter -A "$FILTER_FORWARD_CHAIN" \
            -i "$WAN_INTERFACE" -o "$WG_INTERFACE" -p "$protocol" \
            -d "$PEER_TUNNEL_IP" --dport "$destination_port" \
            -m comment --comment "${COMMENT_PREFIX}:forward:${protocol}:${public_port}" -j ACCEPT
    done

    iptables -w -t filter -A "$FILTER_FORWARD_CHAIN" \
        -i "$WG_INTERFACE" -o "$WAN_INTERFACE" \
        -m conntrack --ctstate ESTABLISHED,RELATED \
        -m comment --comment "${COMMENT_PREFIX}:forward-return" -j ACCEPT

    # Masquerade only connections that were DNATed by the chain above. This
    # makes the Foreign host return traffic through the authenticated tunnel.
    iptables -w -t nat -A "$NAT_POSTROUTING_CHAIN" \
        -o "$WG_INTERFACE" -d "$PEER_TUNNEL_IP" \
        -m conntrack --ctstate DNAT \
        -m comment --comment "${COMMENT_PREFIX}:masquerade-dnat" -j MASQUERADE
}

add_foreign_firewall_rules() {
    local rule protocol service_port

    for rule in "${SERVICE_RULES[@]}"; do
        IFS=':' read -r protocol service_port <<< "$rule"
        # This exposes the selected local service only to the authenticated
        # Iran tunnel peer. The service must listen on the Foreign WireGuard
        # address or another non-loopback address.
        iptables -w -t filter -A "$FILTER_INPUT_CHAIN" \
            -i "$WG_INTERFACE" -s "$PEER_TUNNEL_IP" -d "$LOCAL_TUNNEL_IP" \
            -p "$protocol" --dport "$service_port" \
            -m comment --comment "${COMMENT_PREFIX}:service:${protocol}:${service_port}" -j ACCEPT
    done
}

enable_ip_forwarding() {
    install -d -m 0700 "$STATE_DIRECTORY"
    cat > "$SYSCTL_CONFIG" <<'EOF'
# Managed by secure-tunnel.sh. Enables routing for the WireGuard tunnel.
net.ipv4.ip_forward=1
EOF
    chmod 0644 "$SYSCTL_CONFIG"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    if [[ $(sysctl -n net.ipv4.ip_forward) != "1" ]]; then
        error "IPv4 forwarding could not be enabled."
        exit 1
    fi
}

write_wireguard_config() {
    local temporary_config backup_config="" service_was_active=0
    temporary_config=$(mktemp "${WG_DIRECTORY}/.${WG_INTERFACE}.conf.XXXXXX")
    chmod 0600 "$temporary_config"

    cat > "$temporary_config" <<EOF
# Managed by secure-tunnel.sh. Edit via this script or under change control.
[Interface]
Address = ${LOCAL_TUNNEL_IP}/30
ListenPort = ${WG_LISTEN_PORT}
PrivateKey = ${LOCAL_PRIVATE_KEY}

[Peer]
PublicKey = ${PEER_PUBLIC_KEY}
AllowedIPs = ${PEER_TUNNEL_IP}/32
Endpoint = ${REMOTE_PUBLIC_IP}:${WG_LISTEN_PORT}
PersistentKeepalive = 25
EOF

    if [[ -f $WG_CONFIG ]]; then
        backup_config="${WG_CONFIG}.secure-tunnel-backup"
        cp --preserve=mode "$WG_CONFIG" "$backup_config"
    fi
    if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}"; then
        service_was_active=1
    fi

    mv "$temporary_config" "$WG_CONFIG"
    chmod 0600 "$WG_CONFIG"

    if (( service_was_active )); then
        if ! systemctl restart "wg-quick@${WG_INTERFACE}"; then
            error "WireGuard restart failed; restoring the previous configuration."
            if [[ -n $backup_config && -f $backup_config ]]; then
                mv "$backup_config" "$WG_CONFIG"
                systemctl restart "wg-quick@${WG_INTERFACE}" || true
            else
                rm -f "$WG_CONFIG"
            fi
            exit 1
        fi
    else
        systemctl enable --now "wg-quick@${WG_INTERFACE}"
    fi

    [[ -z $backup_config ]] || rm -f "$backup_config"
    if ! wg show "$WG_INTERFACE" >/dev/null 2>&1; then
        error "WireGuard interface ${WG_INTERFACE} did not become available."
        exit 1
    fi
}

write_manifest() {
    install -d -m 0700 "$STATE_DIRECTORY"
    {
        printf 'VERSION=1\n'
        printf 'ROLE=%s\n' "$ROLE"
        printf 'WAN_INTERFACE=%s\n' "$WAN_INTERFACE"
        printf 'REMOTE_PUBLIC_IP=%s\n' "$REMOTE_PUBLIC_IP"
        printf 'WG_LISTEN_PORT=%s\n' "$WG_LISTEN_PORT"
        printf 'LOCAL_TUNNEL_IP=%s\n' "$LOCAL_TUNNEL_IP"
        printf 'PEER_TUNNEL_IP=%s\n' "$PEER_TUNNEL_IP"
        printf 'LOCAL_PUBLIC_KEY=%s\n' "$LOCAL_PUBLIC_KEY"
        local mapping
        for mapping in "${FORWARD_MAPPINGS[@]}"; do
            printf 'FORWARD_MAPPING=%s\n' "$mapping"
        done
        local service_rule
        for service_rule in "${SERVICE_RULES[@]}"; do
            printf 'SERVICE_RULE=%s\n' "$service_rule"
        done
    } > "$MANIFEST"
    chmod 0600 "$MANIFEST"
}

save_persistent_firewall() {
    systemctl enable netfilter-persistent
    netfilter-persistent save
}

install_or_update() {
    info "Pre-flight checks"
    require_root
    require_ubuntu_version
    ensure_dependencies

    if [[ -f $WG_CONFIG && ! -f $MANIFEST ]]; then
        error "${WG_CONFIG} exists but is not owned by this installer (no ${MANIFEST})."
        error "Refusing to overwrite an existing WireGuard configuration."
        exit 1
    fi
    if [[ -f $WG_CONFIG && ! -f $IDENTITY_KEY ]]; then
        error "${WG_CONFIG} exists but ${IDENTITY_KEY} is missing."
        error "Refusing to create a replacement identity that would invalidate the current peer configuration."
        exit 1
    fi

    collect_configuration

    info "Writing WireGuard configuration"
    install -d -m 0700 "$WG_DIRECTORY"
    write_wireguard_config

    info "Enabling IPv4 forwarding"
    enable_ip_forwarding

    info "Applying narrowly scoped firewall and NAT rules"
    setup_managed_chains
    add_common_firewall_rules
    if [[ $ROLE == "iran" ]]; then
        add_iran_firewall_rules
    else
        add_foreign_firewall_rules
    fi
    save_persistent_firewall
    write_manifest

    info "Installation complete"
    printf '%s\n' \
        "Role: ${ROLE}" \
        "WireGuard public key: ${LOCAL_PUBLIC_KEY}" \
        "Tunnel address: ${LOCAL_TUNNEL_IP}/30" \
        "Peer endpoint: ${REMOTE_PUBLIC_IP}:${WG_LISTEN_PORT}" \
        "" \
        "Confirm a recent handshake with: wg show ${WG_INTERFACE}" \
        "Inspect managed rules with: iptables -S ${FILTER_INPUT_CHAIN}; iptables -t nat -S ${NAT_PREROUTING_CHAIN}" \
        ""
}

delete_hook() {
    local table=$1 builtin_chain=$2 target_chain=$3 hook_comment=$4
    while iptables -w -t "$table" -C "$builtin_chain" -m comment --comment "$hook_comment" -j "$target_chain" 2>/dev/null; do
        iptables -w -t "$table" -D "$builtin_chain" -m comment --comment "$hook_comment" -j "$target_chain"
    done
}

delete_chain() {
    local table=$1 chain=$2
    if iptables -w -t "$table" -nL "$chain" >/dev/null 2>&1; then
        iptables -w -t "$table" -F "$chain"
        iptables -w -t "$table" -X "$chain"
    fi
}

remove_managed_firewall_rules() {
    delete_hook filter INPUT "$FILTER_INPUT_CHAIN" "${COMMENT_PREFIX}:input-hook"
    delete_hook filter FORWARD "$FILTER_FORWARD_CHAIN" "${COMMENT_PREFIX}:forward-hook"
    delete_hook nat PREROUTING "$NAT_PREROUTING_CHAIN" "${COMMENT_PREFIX}:prerouting-hook"
    delete_hook nat POSTROUTING "$NAT_POSTROUTING_CHAIN" "${COMMENT_PREFIX}:postrouting-hook"

    delete_chain filter "$FILTER_INPUT_CHAIN"
    delete_chain filter "$FILTER_FORWARD_CHAIN"
    delete_chain nat "$NAT_PREROUTING_CHAIN"
    delete_chain nat "$NAT_POSTROUTING_CHAIN"
}

show_status() {
    require_root
    printf '%s\n' "" "=== secure-tunnel status ==="
    if [[ -f $MANIFEST ]]; then
        printf '%s\n' "Managed deployment: yes"
        # The manifest deliberately excludes the private key.
        sed -n '/^\(VERSION\|ROLE\|WAN_INTERFACE\|REMOTE_PUBLIC_IP\|WG_LISTEN_PORT\|LOCAL_TUNNEL_IP\|PEER_TUNNEL_IP\|LOCAL_PUBLIC_KEY\|FORWARD_MAPPING\|SERVICE_RULE\)=/p' "$MANIFEST"
    else
        printf '%s\n' "Managed deployment: no manifest found"
    fi

    printf '\n%s\n' "WireGuard:"
    systemctl --no-pager --full status "wg-quick@${WG_INTERFACE}" || true
    wg show "$WG_INTERFACE" || true

    printf '\nIPv4 forwarding: '
    sysctl -n net.ipv4.ip_forward || true
    printf '\n%s\n' "Managed firewall chains:"
    iptables -S "$FILTER_INPUT_CHAIN" 2>/dev/null || true
    iptables -S "$FILTER_FORWARD_CHAIN" 2>/dev/null || true
    iptables -t nat -S "$NAT_PREROUTING_CHAIN" 2>/dev/null || true
    iptables -t nat -S "$NAT_POSTROUTING_CHAIN" 2>/dev/null || true
}

uninstall() {
    require_root

    if [[ ! -f $MANIFEST ]]; then
        error "No ${MANIFEST} exists; this installer has nothing it can safely remove."
        exit 1
    fi

    printf '%s\n' \
        "" \
        "This removes only the WireGuard configuration, sysctl file, and iptables chains managed by this installer." \
        "Existing unrelated firewall rules and services are not flushed or changed."
    local confirmation
    read -r -p "Type REMOVE to continue: " confirmation
    if [[ $confirmation != "REMOVE" ]]; then
        info "Uninstall cancelled"
        return
    fi

    info "Removing managed firewall rules"
    remove_managed_firewall_rules
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    fi

    info "Stopping managed WireGuard interface"
    systemctl disable --now "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
    rm -f "$WG_CONFIG" "$SYSCTL_CONFIG" "$MANIFEST" "$IDENTITY_KEY"
    rmdir "$STATE_DIRECTORY" 2>/dev/null || true

    # Re-evaluate all remaining sysctl configuration. Do not force forwarding
    # off because another administrator may legitimately rely on it.
    sysctl --system >/dev/null
    info "Uninstall complete"
}

main_menu() {
    local selection
    printf '%s\n' \
        "" \
        "Secure WireGuard Tunnel Manager" \
        "1) Install or update a managed tunnel" \
        "2) Show status" \
        "3) Uninstall this managed tunnel" \
        "4) Exit"

    while true; do
        read -r -p "Choice [1-4]: " selection
        case $selection in
            1) install_or_update; return ;;
            2) show_status; return ;;
            3) uninstall; return ;;
            4) return ;;
            *) warn "Choose a number from 1 through 4." ;;
        esac
    done
}

main_menu
