#!/bin/bash

# AC's Multitool 0.1 — OPSEC Toolkit
# Authorized use on owned systems only. No logs. No telemetry. Offline bundle.

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
COMMON_LIB="$TOOLS_DIR/lib/common.sh"

if [ ! -f "$COMMON_LIB" ]; then
    printf '[ERROR] Missing toolkit library: %s\n' "$COMMON_LIB" >&2
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
