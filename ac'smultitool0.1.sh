#!/bin/bash

# AC Multitool 0.1 — Tactical Operations Suite
# Authorized use on owned systems only.

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"

run_tool() {
    local tool="$1"
    shift
    local path="$TOOLS_DIR/$tool"

    if [ ! -f "$path" ]; then
        printf '[ERROR] Tool not found: %s\n' "$path" >&2
        return 1
    fi
    bash "$path" "$@"
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

printf '\n[SYSTEM] Ready.\n'

while true; do
    printf '\n=== OPERATIONS MENU ===\n'
    echo "1) Port Scanner"
    echo "2) WiFi Credential Recovery"
    echo "3) System Reconnaissance"
    echo "4) Terminate Session"
    read -p "Select operation [1-4]: " choice

    case $choice in
        1)
            printf '[SCAN] Initiating port reconnaissance.\n'
            read -p "Target IP or hostname: " target
            read -p "Port range (default 1-1024): " portrange
            portrange=${portrange:-1-1024}
            run_tool portscan.sh "$target" "$portrange"
            ;;
        2)
            run_tool wifi-recovery.sh
            ;;
        3)
            run_tool sysinfo.sh
            ;;
        4)
            printf '[SYSTEM] Session terminated. Stand by.\n'
            exit 0
            ;;
        *)
            printf '[WARN] Invalid selection. Re-enter operation code.\n'
            ;;
    esac
done
