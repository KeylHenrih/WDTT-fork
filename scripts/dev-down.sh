#!/usr/bin/env bash
set -euo pipefail

# scripts/dev-down.sh - Stop local WDTT test client and tear down WireGuard interface

PID_FILE="$HOME/.config/wdtt-dev/wdttd.pid"

# 1. Stop wdttd daemon
if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping wdttd (PID $PID)..."
        kill "$PID" 2>/dev/null || true
        for _ in {1..10}; do
            if ! kill -0 "$PID" 2>/dev/null; then
                break
            fi
            sleep 0.2
        done
        if kill -0 "$PID" 2>/dev/null; then
            kill -9 "$PID" 2>/dev/null || true
        fi
    fi
    rm -f "$PID_FILE"
fi

# Fallback check for any stray wdttd processes started by this user
pkill -u "$(id -u)" -x wdttd 2>/dev/null || true

# 2. Tear down WireGuard interface wg-wdtt
if ip link show wg-wdtt &>/dev/null; then
    echo "Tearing down WireGuard interface wg-wdtt..."
    sudo ip link del dev wg-wdtt 2>/dev/null || true
fi

echo "Client teardown complete. (wg-wdtt removed, wdttd stopped)"
