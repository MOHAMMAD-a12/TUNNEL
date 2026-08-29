#!/usr/bin/env bash
# xray-service-tunnel.sh
#
# Provisions a narrow, authenticated Xray-based TCP service tunnel between two
# Ubuntu hosts you administer. It forwards explicitly selected TCP ports from
# the Iran ingress host to services directly hosted on the Foreign host, using
# one authenticated Shadowsocks (aes-256-gcm) transport per mapping.
#
# This is not an obfuscation, DPI-evasion, restriction-circumvention, or generic
# proxy tool. There is no default route, no SOCKS/HTTP proxy, and no arbitrary
# outbound relay: each Foreign Shadowsocks listener delivers only to the single
# local service port selected during setup.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="xray-service-tunnel"
readonly STATE_DIRECTORY="/etc/${SCRIPT_NAME}"
readonly CONFIG_FILE="${STATE_DIRECTORY}/config.json"
readonly MANIFEST="${STATE_DIRECTORY}/manifest.conf"
readonly BINARY_DIRECTORY="/usr/local/lib/${SCRIPT_NAME}"
readonly BINARY="${BINARY_DIRECTORY}/xray"
readonly BINARY_LINK="/usr/local/bin/${SCRIPT_NAME}"
readonly SYSTEMD_UNIT="/etc/systemd/system/${SCRIPT_NAME}.service"
readonly SYSTEMD_USER="${SCRIPT_NAME}"
readonly FILTER_INPUT_CHAIN="XRAY_SERVICE_TUNNEL_INPUT"
readonly COMMENT_PREFIX="xray-service-tunnel"
readonly SS_METHOD="aes-256-gcm"

ROLE=""
WAN_INTERFACE=""
WAN_IP=""
PEER_PUBLIC_IP=""
declare -a MAPPINGS=()          # iran: public:service:ss_port:password
declare -a FOREIGN_SERVICES=()  # foreign: service:ss_port:password

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
    if [[ ${ID:-} != "ubuntu" || ( ${VERSION_ID:-} != "20.04" && ${VERSION_ID:-} != "22.04" && ${VERSION_ID:-} != "24.04" ) ]]; then
        error "This script supports Ubuntu 20.04, 22.04, and 24.04 only (detected: ${PRETTY_NAME:-unknown})."
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
    require_command curl

    if ufw_is_active; then
        error "UFW is active. This installer uses iptables-persistent and will not mix two firewall managers."
        error "Disable or replace UFW under your change-control process, then run this script again."
        exit 1
    fi

    local -a missing_commands=()
    local command_name
    for command_name in jq iptables iptables-save netfilter-persistent unzip; do
        command -v "$command_name" >/dev/null 2>&1 || missing_commands+=("$command_name")
    done

    if (( ${#missing_commands[@]} == 0 )); then
        return
    fi

    info "Installing required packages: jq, iptables, iptables-persistent, unzip"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    if command -v debconf-set-selections >/dev/null 2>&1; then
        printf '%s\n' \
            'iptables-persistent iptables-persistent/autosave_v4 boolean false' \
            'iptables-persistent iptables-persistent/autosave_v6 boolean false' \
            | debconf-set-selections
    fi
    apt-get install -y jq iptables iptables-persistent unzip
    for command_name in jq iptables iptables-save netfilter-persistent unzip; do
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

default_wan_interface() {
    ip -4 route show default | awk '/^default/ { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
}

primary_wan_ip() {
    local iface=$1
    ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1
}

rand_port() {
    local p
    p=$(od -An -N2 -tu2 /dev/urandom | tr -d ' \n')
    p=$(( 10#$p % 19999 + 30000 ))
    printf '%s' "$p"
}

gen_password() {
    head -c 18 /dev/urandom | base64 | tr -d '/+='
}

prompt_with_default() {
    local variable_name=$1 prompt_text=$2 default_value=$3 value
    read -r -p "${prompt_text} [${default_value}]: " value
    printf -v "$variable_name" '%s' "${value:-$default_value}"
}

prompt_ipv4() {
    local variable_name=$1 prompt_text=$2 default_value=$3 value
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
    local variable_name=$1 prompt_text=$2 default_value=$3 value
    while true; do
        prompt_with_default value "$prompt_text" "$default_value"
        if validate_port "$value"; then
            printf -v "$variable_name" '%s' "$value"
            return
        fi
        warn "Enter a port from 1 through 65535."
    done
}

prompt_yes_no() {
    local prompt_text=$1 answer
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

iran_mapping_exists() {
    local public_port=$1 existing
    for existing in "${MAPPINGS[@]}"; do
        [[ $existing == "${public_port}:"* ]] && return 0
    done
    return 1
}

iran_ss_port_used() {
    local ss_port=$1 existing
    for existing in "${MAPPINGS[@]}"; do
        IFS=':' read -r _ _ _ m_ss _ <<< "$existing"
        [[ $m_ss == "$ss_port" ]] && return 0
    done
    return 1
}

collect_iran_mappings() {
    local public_port service_port ss_port password mapping
    info "Add the public TCP ports that this host will forward to the Foreign server"
    printf '%s\n' "Each mapping is public-port -> service-port hosted directly on Foreign."

    while prompt_yes_no "Add a forwarding mapping?"; do
        prompt_port public_port "Public listening port" "443"
        if iran_mapping_exists "$public_port"; then
            warn "A mapping already uses public port ${public_port}."
            continue
        fi
        prompt_port service_port "Foreign service port" "$public_port"

        ss_port=$(rand_port)
        while iran_ss_port_used "$ss_port" || [[ $ss_port == "$public_port" ]]; do
            ss_port=$(rand_port)
        done
        password=$(gen_password)

        mapping="${public_port}:${service_port}:${ss_port}:${password}"
        MAPPINGS+=("$mapping")

        printf '\n%s\n' \
            "Generated Foreign-side Shadowsocks listener for this mapping:" \
            "  Public port : ${public_port}" \
            "  Service port : ${service_port}" \
            "  Foreign SS listen port : ${ss_port}" \
            "  Shared secret (copy to Foreign) : ${password}" ""
    done

    if (( ${#MAPPINGS[@]} == 0 )); then
        warn "No port mappings were selected. The tunnel cannot forward any traffic."
        warn "Exit without applying changes."
        exit 0
    fi
}

foreign_service_exists() {
    local ss_port=$1 existing
    for existing in "${FOREIGN_SERVICES[@]}"; do
        IFS=':' read -r _ f_ss _ <<< "$existing"
        [[ $f_ss == "$ss_port" ]] && return 0
    done
    return 1
}

collect_foreign_services() {
    local ss_port password service_port entry
    info "For each mapping, enter the Shadowsocks listener port and secret shown by the Iran host"
    printf '%s\n' "Also enter the local service port hosted directly on this Foreign server."

    while true; do
        read -r -p "Foreign Shadowsocks listen port (press Enter to finish): " ss_port
        if [[ -z $ss_port ]]; then
            break
        fi
        if ! validate_port "$ss_port"; then
            warn "Enter a port from 1 through 65535."
            continue
        fi
        if foreign_service_exists "$ss_port"; then
            warn "A service already uses Shadowsocks port ${ss_port}."
            continue
        fi
        read -r -p "Shared secret (from Iran host): " password
        if [[ -z $password ]]; then
            warn "A shared secret is required."
            continue
        fi
        prompt_port service_port "Local Foreign service port" "443"
        entry="${service_port}:${ss_port}:${password}"
        FOREIGN_SERVICES+=("$entry")
    done

    if (( ${#FOREIGN_SERVICES[@]} == 0 )); then
        warn "No service mappings were entered. No tunnel or firewall changes were applied."
        exit 0
    fi
}

collect_configuration() {
    MAPPINGS=()
    FOREIGN_SERVICES=()

    choose_role
    local wan_default wan_ip_default
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

    wan_ip_default=$(primary_wan_ip "$WAN_INTERFACE")
    prompt_ipv4 WAN_IP "This host's public/reachable IPv4 address" "${wan_ip_default:-203.0.113.10}"
    prompt_ipv4 PEER_PUBLIC_IP "Public/reachable IPv4 address of the other server" "203.0.113.10"

    if [[ $ROLE == "iran" ]]; then
        collect_iran_mappings
    else
        collect_foreign_services
    fi
}

install_xray_binary() {
    if [[ -x $BINARY ]]; then
        info "Xray binary already present at ${BINARY}; skipping download"
        return
    fi

    local arch release_json tag asset_name asset_url dgst_url tmp_dir zip_file dgst_file expected_sha actual_sha
    arch=$(uname -m)
    case $arch in
        x86_64) asset_name="Xray-linux-64.zip" ;;
        aarch64|arm64) asset_name="Xray-linux-arm64-v8a.zip" ;;
        *) error "Unsupported architecture for Xray: ${arch}"; exit 1 ;;
    esac

    info "Resolving latest Xray-core release from GitHub"
    release_json=$(curl -fsSL "https://api.github.com/repos/XTLS/Xray-core/releases/latest")
    tag=$(jq -r '.tag_name' <<<"$release_json")
    if [[ -z $tag || $tag == "null" ]]; then
        error "Could not determine the latest Xray release tag."
        exit 1
    fi
    asset_url=$(jq -r --arg n "$asset_name" '.assets[] | select(.name == $n) | .browser_download_url' <<<"$release_json")
    dgst_url=$(jq -r --arg n "${asset_name}.dgst" '.assets[] | select(.name == $n) | .browser_download_url' <<<"$release_json")
    if [[ -z $asset_url || -z $dgst_url ]]; then
        error "Could not locate Xray release assets for ${asset_name}."
        exit 1
    fi

    info "Downloading Xray ${tag} (${asset_name})"
    tmp_dir=$(mktemp -d)
    zip_file="${tmp_dir}/${asset_name}"
    dgst_file="${tmp_dir}/${asset_name}.dgst"

    curl -fsSL "$asset_url" -o "$zip_file"
    curl -fsSL "$dgst_url" -o "$dgst_file"

    expected_sha=$(awk -F'=' '/^SHA2-256=/ { gsub(/[ \t]/, "", $2); print $2; exit }' "$dgst_file")
    if [[ -z $expected_sha ]]; then
        error "Could not read SHA2-256 from the upstream .dgst file; refusing to proceed."
        exit 1
    fi
    actual_sha=$(sha256sum "$zip_file" | awk '{print $1}')
    if [[ $actual_sha != "$expected_sha" ]]; then
        error "Integrity check failed: downloaded ${asset_name} SHA2-256 ${actual_sha} does not match upstream ${expected_sha}."
        exit 1
    fi

    install -d -m 0755 "$BINARY_DIRECTORY"
    unzip -o -q "$zip_file" -d "$BINARY_DIRECTORY"
    chmod 0755 "${BINARY_DIRECTORY}/xray"
    ln -sf "${BINARY_DIRECTORY}/xray" "$BINARY_LINK"
    rm -rf "$tmp_dir"

    if ! "$BINARY" version >/dev/null 2>&1; then
        error "Installed Xray binary did not report a version."
        exit 1
    fi
    info "Xray ${tag} installed at ${BINARY}"
}

ensure_system_user() {
    if ! id -u "$SYSTEMD_USER" >/dev/null 2>&1; then
        useradd -r -s /usr/sbin/nologin -d /nonexistent "$SYSTEMD_USER"
    fi
}

build_iran_config() {
    local inbounds='[]' outbounds outbounds_base rules='[]' mapping public_port service_port ss_port password
    outbounds_base=$(jq -n '[{protocol:"blackhole", tag:"block"}]')
    for mapping in "${MAPPINGS[@]}"; do
        IFS=':' read -r public_port service_port ss_port password <<< "$mapping"

        inbounds=$(jq --arg tag "tunnel-${public_port}" \
            --arg listen "$WAN_IP" --argjson port "$public_port" --argjson service "$service_port" \
            '. + [{
                tag: $tag,
                protocol: "tunnel",
                listen: $listen,
                port: $port,
                settings: {
                    allowedNetwork: "tcp",
                    followRedirect: false,
                    rewriteAddress: "127.0.0.1",
                    rewritePort: $service
                }
            }]' <<<"$inbounds")

        outbounds_base=$(jq --arg tag "ss-client-${service_port}" \
            --arg addr "$PEER_PUBLIC_IP" --argjson port "$ss_port" --arg method "$SS_METHOD" --arg pass "$password" \
            '. + [{
                protocol: "shadowsocks",
                tag: $tag,
                settings: {
                    address: $addr,
                    port: $port,
                    method: $method,
                    password: $pass
                }
            }]' <<<"$outbounds_base")

        rules=$(jq --arg tag "tunnel-${public_port}" --arg out "ss-client-${service_port}" \
            '. + [{inboundTag: [$tag], outboundTag: $out}]' <<<"$rules")
    done
    outbounds="$outbounds_base"

    jq -n --argjson inbounds "$inbounds" --argjson outbounds "$outbounds" --argjson rules "$rules" \
        '{inbounds: $inbounds, outbounds: $outbounds, routing: {rules: $rules}}'
}

build_foreign_config() {
    local inbounds='[]' outbounds_base rules='[]' entry service_port ss_port password
    outbounds_base=$(jq -n '[{protocol:"blackhole", tag:"block"}]')
    for entry in "${FOREIGN_SERVICES[@]}"; do
        IFS=':' read -r service_port ss_port password <<< "$entry"

        inbounds=$(jq --arg tag "ss-server-${service_port}" \
            --arg listen "$WAN_IP" --argjson port "$ss_port" --arg method "$SS_METHOD" --arg pass "$password" \
            '. + [{
                tag: $tag,
                protocol: "shadowsocks",
                listen: $listen,
                port: $port,
                settings: {
                    network: "tcp",
                    method: $method,
                    password: $pass
                }
            }]' <<<"$inbounds")

        outbounds_base=$(jq --arg tag "freedom-${service_port}" --argjson service "$service_port" \
            '. + [{
                protocol: "freedom",
                tag: $tag,
                settings: {redirect: ("127.0.0.1:" + ($service | tostring))}
            }]' <<<"$outbounds_base")

        rules=$(jq --arg tag "ss-server-${service_port}" --arg out "freedom-${service_port}" \
            '. + [{inboundTag: [$tag], outboundTag: $out}]' <<<"$rules")
    done

    jq -n --argjson inbounds "$inbounds" --argjson outbounds "$outbounds_base" --argjson rules "$rules" \
        '{inbounds: $inbounds, outbounds: $outbounds, routing: {rules: $rules}}'
}

write_config_and_unit() {
    local temporary_config config_json unit_text
    temporary_config=$(mktemp "${STATE_DIRECTORY}/.config.json.XXXXXX")
    chmod 0600 "$temporary_config"

    if [[ $ROLE == "iran" ]]; then
        config_json=$(build_iran_config)
    else
        config_json=$(build_foreign_config)
    fi
    printf '%s\n' "$config_json" > "$temporary_config"

    info "Validating generated Xray configuration"
    if ! "$BINARY" run -test -c "$temporary_config" >/dev/null 2>&1; then
        error "Generated Xray configuration failed validation:"
        "$BINARY" run -test -c "$temporary_config" || true
        rm -f "$temporary_config"
        exit 1
    fi

    mv "$temporary_config" "$CONFIG_FILE"
    chown "$SYSTEMD_USER": "$CONFIG_FILE"
    chmod 0600 "$CONFIG_FILE"

    unit_text=$(cat <<EOF
[Unit]
Description=Xray Private TCP Service Tunnel (managed by ${SCRIPT_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BINARY} run -c ${CONFIG_FILE}
User=${SYSTEMD_USER}
Group=${SYSTEMD_USER}
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
)
    printf '%s\n' "$unit_text" > "$SYSTEMD_UNIT"
    chmod 0644 "$SYSTEMD_UNIT"
    systemctl daemon-reload
    systemctl enable --now "$SYSTEMD_UNIT"

    if ! systemctl is-active --quiet "$SYSTEMD_UNIT"; then
        error "The ${SYSTEMD_UNIT} service did not start. Inspect with: systemctl status ${SCRIPT_NAME}"
        exit 1
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

setup_managed_chain() {
    ensure_chain filter "$FILTER_INPUT_CHAIN"
    iptables -w -t filter -A "$FILTER_INPUT_CHAIN" \
        -m conntrack --ctstate ESTABLISHED,RELATED \
        -m comment --comment "${COMMENT_PREFIX}:established" -j ACCEPT
    ensure_hook filter INPUT "$FILTER_INPUT_CHAIN" "${COMMENT_PREFIX}:input-hook"
}

add_iran_firewall_rules() {
    local mapping public_port
    for mapping in "${MAPPINGS[@]}"; do
        IFS=':' read -r public_port _ _ _ <<< "$mapping"
        iptables -w -t filter -A "$FILTER_INPUT_CHAIN" \
            -i "$WAN_INTERFACE" -p tcp --dport "$public_port" \
            -m comment --comment "${COMMENT_PREFIX}:ingress:${public_port}" -j ACCEPT
    done
}

add_foreign_firewall_rules() {
    local entry ss_port
    for entry in "${FOREIGN_SERVICES[@]}"; do
        IFS=':' read -r _ ss_port _ <<< "$entry"
        iptables -w -t filter -A "$FILTER_INPUT_CHAIN" \
            -i "$WAN_INTERFACE" -s "$PEER_PUBLIC_IP" -p tcp --dport "$ss_port" \
            -m comment --comment "${COMMENT_PREFIX}:ss:${ss_port}" -j ACCEPT
    done
}

save_persistent_firewall() {
    systemctl enable netfilter-persistent
    netfilter-persistent save
}

write_manifest() {
    install -d -m 0700 "$STATE_DIRECTORY"
    {
        printf 'VERSION=1\n'
        printf 'ROLE=%s\n' "$ROLE"
        printf 'WAN_INTERFACE=%s\n' "$WAN_INTERFACE"
        printf 'WAN_IP=%s\n' "$WAN_IP"
        printf 'PEER_PUBLIC_IP=%s\n' "$PEER_PUBLIC_IP"
        local mapping entry
        for mapping in "${MAPPINGS[@]}"; do
            printf 'MAPPING=%s\n' "$mapping"
        done
        for entry in "${FOREIGN_SERVICES[@]}"; do
            printf 'FOREIGN_SERVICE=%s\n' "$entry"
        done
    } > "$MANIFEST"
    chmod 0600 "$MANIFEST"
}

install_or_update() {
    info "Pre-flight checks"
    require_root
    require_ubuntu_version
    ensure_dependencies

    if [[ -f $CONFIG_FILE && ! -f $MANIFEST ]]; then
        error "${CONFIG_FILE} exists but is not owned by this installer (no ${MANIFEST})."
        error "Refusing to overwrite an existing Xray configuration."
        exit 1
    fi
    if [[ -f $SYSTEMD_UNIT && ! -f $MANIFEST ]]; then
        error "${SYSTEMD_UNIT} exists but is not owned by this installer."
        error "Refusing to overwrite an existing systemd unit."
        exit 1
    fi

    collect_configuration

    info "Installing Xray binary"
    install_xray_binary
    ensure_system_user

    info "Writing configuration and starting managed service"
    install -d -m 0700 "$STATE_DIRECTORY"
    write_config_and_unit

    info "Applying narrowly scoped firewall rules"
    setup_managed_chain
    if [[ $ROLE == "iran" ]]; then
        add_iran_firewall_rules
    else
        add_foreign_firewall_rules
    fi
    save_persistent_firewall
    write_manifest

    info "Installation complete"
    if [[ $ROLE == "iran" ]]; then
        printf '%s\n' \
            "Role: iran (public ingress)" \
            "Forwarded public ports: $(IFS=' '; echo "${MAPPINGS[*]%%:*}")" \
            "" \
            "On Foreign, add each mapping using the Shadowsocks listen port and secret printed above." \
            "Verify the service: systemctl status ${SCRIPT_NAME}" \
            "Inspect managed rules: iptables -S ${FILTER_INPUT_CHAIN}"
    else
        printf '%s\n' \
            "Role: foreign (service host)" \
            "Listening Shadowsocks ports: $(IFS=' '; echo "${FOREIGN_SERVICES[@]}")" \
            "" \
            "Each port delivers only to its configured local service." \
            "Verify the service: systemctl status ${SCRIPT_NAME}" \
            "Inspect managed rules: iptables -S ${FILTER_INPUT_CHAIN}"
    fi
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
    delete_chain filter "$FILTER_INPUT_CHAIN"
}

show_status() {
    require_root
    printf '%s\n' "" "=== ${SCRIPT_NAME} status ==="
    if [[ -f $MANIFEST ]]; then
        printf '%s\n' "Managed deployment: yes"
        sed -n '/^\(VERSION\|ROLE\|WAN_INTERFACE\|WAN_IP\|PEER_PUBLIC_IP\|MAPPING\|FOREIGN_SERVICE\)=/p' "$MANIFEST"
    else
        printf '%s\n' "Managed deployment: no manifest found"
    fi

    printf '\n%s\n' "Service:"
    systemctl --no-pager --full status "$SYSTEMD_UNIT" || true

    printf '\n%s\n' "Xray version:"
    "$BINARY" version 2>/dev/null || true

    printf '\n%s\n' "Managed firewall chain:"
    iptables -S "$FILTER_INPUT_CHAIN" 2>/dev/null || true
}

uninstall() {
    require_root

    if [[ ! -f $MANIFEST ]]; then
        error "No ${MANIFEST} exists; this installer has nothing it can safely remove."
        exit 1
    fi

    printf '%s\n' \
        "" \
        "This removes only the Xray configuration, systemd unit, and iptables chain managed by this installer." \
        "Existing unrelated firewall rules, services, and any system Xray installation are not changed."
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

    info "Stopping managed service"
    systemctl disable --now "$SYSTEMD_UNIT" 2>/dev/null || true
    rm -f "$SYSTEMD_UNIT"
    systemctl daemon-reload 2>/dev/null || true

    info "Removing installer-owned files"
    rm -f "$CONFIG_FILE" "$MANIFEST" "$BINARY_LINK"
    rm -rf "$BINARY_DIRECTORY"
    rmdir "$STATE_DIRECTORY" 2>/dev/null || true

    if id -u "$SYSTEMD_USER" >/dev/null 2>&1; then
        userdel "$SYSTEMD_USER" 2>/dev/null || true
    fi

    info "Uninstall complete"
}

main_menu() {
    local selection
    printf '%s\n' \
        "" \
        "Xray Private TCP Service Tunnel Manager" \
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
