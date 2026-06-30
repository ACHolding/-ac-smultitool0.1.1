#!/bin/bash

# AC's Multitool 0.1 — OPSEC Toolkit
# Authorized use on owned systems only. No logs. No telemetry. Offline bundle.

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

resolve_script_dir() {
    local src path
    if [ -n "${BASH_SOURCE[0]}" ]; then
        src="${BASH_SOURCE[0]}"
    else
        src="$0"
    fi
    while [ -L "$src" ]; do
        path="$(readlink "$src" 2>/dev/null)" || break
        if [ "${path#/}" = "$path" ]; then
            src="$(cd "$(dirname "$src")" && cd "$(dirname "$path")" && pwd)/$(basename "$path")"
        else
            src="$path"
        fi
    done
    cd "$(dirname "$src")" && pwd
}

extract_embedded_tools() {
    mkdir -p "$TOOLS_DIR/lib"

    cat > "$TOOLS_DIR/lib/common.sh" <<'EOF'
#!/bin/bash
# Shared helpers for AC Multitool tool modules.

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

log_info()  { printf '[INFO] %s\n' "$*"; }
log_warn()  { printf '[WARN] %s\n' "$*" >&2; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }

opsec_init() {
    export HISTFILE=/dev/null
    export HISTSIZE=0
    export HISTFILESIZE=0
    set +o history 2>/dev/null || true
}

opsec_run() {
    local path="$1"
    shift
    HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 \
        bash --noprofile --norc "$path" "$@"
}

opsec_cleanup() {
    unset choice target portrange pass keychain_dump net wifi 2>/dev/null || true
    history -c 2>/dev/null || true
    hash -r 2>/dev/null || true
}

print_authorization_warning() {
    cat <<'WARN_EOF'
[WARNING] Authorized use only.
          Use on systems you own or have explicit written permission to test.
          Unauthorized access is illegal.
WARN_EOF
}
EOF

    cat > "$TOOLS_DIR/portscan.sh" <<'EOF'
#!/bin/bash
# TCP connect scanner — uses nc only. No disk output.

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
opsec_init

usage() {
    cat <<'USAGE_EOF'
Usage: portscan.sh <target> [port-range]

Port range formats:
  1-1024        range (default)
  22,80,443     comma-separated
  8080          single port
USAGE_EOF
}

scan_port() {
    local host="$1" port="$2"
    if nc -z -w 1 "$host" "$port" 2>/dev/null; then
        printf '  %-6s OPEN\n' "$port"
        return 0
    fi
    return 1
}

scan_range() {
    local host="$1" start="$2" end="$3"
    local port
    for ((port = start; port <= end; port++)); do
        scan_port "$host" "$port" || true
    done
}

main() {
    local target="${1:-}"
    local portrange="${2:-1-1024}"

    if [ -z "$target" ]; then
        log_error "Target required."
        usage
        return 1
    fi

    if ! command -v nc &>/dev/null; then
        log_error "nc (netcat) not found. Cannot scan."
        return 1
    fi

    log_info "Target: $target"
    log_info "Port range: $portrange"
    printf '\nPORT   STATE\n'
    echo '----   -----'

    if [[ "$portrange" =~ ^[0-9]+-[0-9]+$ ]]; then
        local start="${portrange%-*}" end="${portrange#*-}"
        if [ "$start" -gt "$end" ]; then
            log_error "Invalid range: start must be <= end."
            return 1
        fi
        scan_range "$target" "$start" "$end"
    elif [[ "$portrange" =~ , ]]; then
        local port
        IFS=',' read -ra ports <<< "$portrange"
        for port in "${ports[@]}"; do
            port="${port//[[:space:]]/}"
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            scan_port "$target" "$port" || true
        done
    elif [[ "$portrange" =~ ^[0-9]+$ ]]; then
        scan_port "$target" "$portrange" || true
    else
        log_error "Invalid port range: $portrange"
        usage
        return 1
    fi

    printf '\n[INFO] Scan complete. No results written to disk.\n'
    unset target portrange port ports start end
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    opsec_cleanup
fi
EOF

    cat > "$TOOLS_DIR/wifi-recovery.sh" <<'EOF'
#!/bin/bash
# Wireless credential recovery — macOS Keychain / Linux nmcli / iwconfig.

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
opsec_init

recover_macos() {
    local iface found=0

    log_info "Enumerating saved wireless networks."
    for iface in en0 en1 wlan0; do
        if networksetup -listpreferredwirelessnetworks "$iface" &>/dev/null; then
            echo "Interface: $iface"
            networksetup -listpreferredwirelessnetworks "$iface" 2>/dev/null | sed 's/^[[:space:]]*/  /'
            found=1
        fi
    done
    [ "$found" -eq 1 ] || log_warn "No wireless interface found."

    printf '\n'
    log_info "Keychain entries (AirPort / Wi-Fi passwords):"

    local keychain_dump
    keychain_dump=$(security dump-keychain 2>/dev/null \
        | awk -F'"' '/"svce"<blob>="AirPort"/ {getline; if ($0 ~ /"acct"/) print $4}' \
        | sort -u)

    if [ -n "$keychain_dump" ]; then
        while IFS= read -r wifi; do
            [ -z "$wifi" ] && continue
            printf '  Network: %s\n' "$wifi"
            if security find-generic-password -D "AirPort network password" -a "$wifi" -w 2>/dev/null; then
                printf '  Password: [retrieved above]\n'
            elif security find-generic-password -l "$wifi" -w 2>/dev/null; then
                printf '  Password: [retrieved above]\n'
            else
                printf '  Password: [access denied or not stored]\n'
            fi
            printf '\n'
        done <<< "$keychain_dump"
    else
        security find-generic-password -D "AirPort network password" 2>&1 \
            | grep -E '"acct"|"svce"' || log_info "No Keychain entries accessible without unlock."
    fi

    unset keychain_dump wifi
}

recover_linux() {
    if command -v nmcli &>/dev/null; then
        log_info "Saved wireless connections (nmcli):"
        nmcli -t -f NAME,TYPE connection show | awk -F: '$2 == "802-11-wireless" {print "  " $1}'

        printf '\n'
        log_info "Credentials:"
        nmcli -t -f NAME,TYPE connection show \
            | awk -F: '$2 == "802-11-wireless" {print $1}' \
            | while IFS= read -r net; do
                [ -z "$net" ] && continue
                pass=$(nmcli -s -g 802-11-wireless-security.psk connection show "$net" 2>/dev/null)
                printf '  %s -> %s\n' "$net" "${pass:-[restricted]}"
                unset pass
            done
    elif command -v iwconfig &>/dev/null; then
        log_info "Wireless interfaces (iwconfig):"
        iwconfig 2>/dev/null | grep -E '^[a-z]|ESSID|IEEE' || log_warn "No wireless interfaces detected."
        log_warn "Credential extraction requires nmcli on Linux."
    else
        log_error "No supported backend (nmcli or iwconfig)."
        return 1
    fi
}

main() {
    local os
    os="$(uname -s)"
    log_info "Extracting stored wireless credentials (stdout only)."

    case "$os" in
        Darwin) recover_macos ;;
        Linux)  recover_linux ;;
        *)      log_error "Unsupported OS: $os" ; return 1 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    opsec_cleanup
fi
EOF

    cat > "$TOOLS_DIR/sysinfo.sh" <<'EOF'
#!/bin/bash
# System reconnaissance: host, processes, network configuration.

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
opsec_init

show_processes() {
    printf '\n--- PROCESSES ---\n'
    if command -v ps &>/dev/null; then
        ps -eo pid,user,%cpu,%mem,comm 2>/dev/null | head -n 21 \
            || ps aux 2>/dev/null | head -n 21
    else
        log_warn "ps not available."
    fi
}

show_network_config() {
    local os="$1"
    printf '\n--- NETWORK CONFIG ---\n'

    case "$os" in
        Darwin)
            networksetup -listallhardwareports 2>/dev/null
            printf '\n'
            ifconfig 2>/dev/null | awk '/^[a-z]/ {iface=$1} /inet / {gsub(/:/,"",$2); print iface, $2}'
            ;;
        Linux)
            if command -v ip &>/dev/null; then
                ip -brief addr 2>/dev/null || ip addr show | grep inet
            else
                ifconfig 2>/dev/null | awk '/^[a-z]/ {iface=$1} /inet / {print iface, $2}'
            fi
            if command -v iwconfig &>/dev/null; then
                printf '\n'
                iwconfig 2>/dev/null | grep -E '^[a-z]|ESSID|Frequency|Bit Rate' || true
            fi
            ;;
        *)
            if command -v ifconfig &>/dev/null; then
                ifconfig 2>/dev/null | grep inet
            fi
            ;;
    esac
}

show_listeners() {
    printf '\n--- LISTENING PORTS ---\n'
    if command -v lsof &>/dev/null; then
        lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | head -n 25 \
            || log_info "No listening sockets found or access denied."
    elif command -v netstat &>/dev/null; then
        netstat -an 2>/dev/null | grep LISTEN | head -n 25
    else
        log_warn "lsof/netstat not available."
    fi
}

main() {
    local os
    os="$(uname -s)"

    log_info "Collecting system intelligence (memory only, no disk writes)."
    printf '\n--- KERNEL ---\n'
    uname -a

    printf '\n--- HOST ---\n'
    if command -v hostnamectl &>/dev/null; then
        hostnamectl
    else
        printf 'Hostname: %s\n' "$(hostname)"
        case "$os" in
            Darwin)
                sw_vers 2>/dev/null
                local model cpu mem
                model=$(sysctl -n hw.model 2>/dev/null)
                cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
                mem=$(sysctl -n hw.memsize 2>/dev/null)
                [ -n "$model" ] && printf 'Hardware: %s\n' "$model"
                [ -n "$cpu" ]   && printf 'CPU: %s\n' "$cpu"
                if [ -n "$mem" ] && [ "$mem" -gt 0 ] 2>/dev/null; then
                    printf 'Memory: %s MB\n' "$((mem / 1048576))"
                fi
                ;;
            *)
                printf 'OS: %s\n' "$os"
                ;;
        esac
    fi

    show_processes
    show_network_config "$os"
    show_listeners

    printf '\n--- DISK ---\n'
    df -h / 2>/dev/null | tail -n +2

    printf '\n--- UPTIME ---\n'
    uptime 2>/dev/null || true

    printf '\n[INFO] Reconnaissance complete.\n'
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    opsec_cleanup
fi
EOF

    chmod +x "$TOOLS_DIR"/*.sh "$TOOLS_DIR/lib/"*.sh
}

bootstrap_tools() {
    if [ -f "$COMMON_LIB" ]; then
        return 0
    fi
    printf '[SYSTEM] Bundled tools not found. Extracting to %s\n' "$TOOLS_DIR"
    extract_embedded_tools
}

SCRIPT_DIR="$(resolve_script_dir)"
TOOLS_DIR="$SCRIPT_DIR/tools"
COMMON_LIB="$TOOLS_DIR/lib/common.sh"

bootstrap_tools

if [ ! -f "$COMMON_LIB" ]; then
    printf '[ERROR] Failed to install toolkit library: %s\n' "$COMMON_LIB" >&2
    exit 1
fi

# shellcheck source=tools/lib/common.sh
source "$COMMON_LIB"
opsec_init

cleanup_session() {
    opsec_cleanup
    unset choice target portrange SCRIPT_DIR TOOLS_DIR COMMON_LIB 2>/dev/null || true
}

trap cleanup_session EXIT INT TERM

run_tool() {
    local tool="$1"
    shift
    local path="$TOOLS_DIR/$tool"

    if [ ! -f "$path" ]; then
        log_error "Tool not found: $path"
        return 1
    fi
    opsec_run "$path" "$@"
}

clear

cat << "ASCII"

    ___    _____   _____ _   _ _____ ___ ___  _   _ 
   / _ \  / ___|  |_   _| | | |_   _|_ _/ _ \| | | |
  / /_\ \| |       | | | |_| | | |  | | | | | | | |
 / /___\ \\ |___    | | |  _  | | |  | | |_| | |_| |
 \____/ \/ \____|   |_| |_| |_| |_| |___\___/ \___/ 

              ac's multitool 0.1
ASCII

print_authorization_warning
printf '\n[SYSTEM] OPSEC toolkit online. No disk logging enabled.\n'

while true; do
    printf '\n=== OPSEC OPERATIONS MENU ===\n'
    echo "1) Port Scanner"
    echo "2) WiFi Credential Recovery"
    echo "3) System Reconnaissance"
    echo "4) Terminate Session"
    read -r -p "Select operation [1-4]: " choice

    case $choice in
        1)
            printf '[SCAN] Initiating TCP port reconnaissance.\n'
            read -r -p "Target IP or hostname: " target
            read -r -p "Port range (default 1-1024): " portrange
            portrange=${portrange:-1-1024}
            run_tool portscan.sh "$target" "$portrange"
            unset target portrange
            ;;
        2)
            run_tool wifi-recovery.sh
            ;;
        3)
            run_tool sysinfo.sh
            ;;
        4)
            printf '[SYSTEM] Terminating session. Clearing variables.\n'
            exit 0
            ;;
        *)
            printf '[WARN] Invalid selection. Re-enter operation code.\n'
            ;;
    esac
    unset choice
done
