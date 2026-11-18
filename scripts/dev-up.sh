#!/usr/bin/env bash
set -euo pipefail

# scripts/dev-up.sh - Start local WDTT test client and WireGuard interface

ENV_FILE="${WDTT_TEST_ENV:-$HOME/.config/wdtt-dev/test.env}"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "Error: Config file $ENV_FILE not found." >&2
    exit 1
fi

# Load environment
# shellcheck source=/dev/null
source "$ENV_FILE"

PID_FILE="$HOME/.config/wdtt-dev/wdttd.pid"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WDTTD_BIN="${WDTTD_BIN:-$REPO_ROOT/target/release/wdttd}"

if [[ ! -x "$WDTTD_BIN" ]]; then
    echo "Error: $WDTTD_BIN not found or not executable. Build it first with: cargo build --release --bin wdttd" >&2
    exit 1
fi

# Determine server relayed address
SERVER_RELAYED="${1:-${SERVER_RELAYED:-}}"
if [[ -z "$SERVER_RELAYED" ]]; then
    echo "Fetching server relayed address from remote host..."
    SERVER_RELAYED=$(ssh -o StrictHostKeyChecking=accept-new "root@$SERVER_HOST" "cat /opt/wdtt-test/relayed_addr.txt 2>/dev/null" || true)
fi

if [[ -z "$SERVER_RELAYED" ]]; then
    echo "Error: Could not determine SERVER_RELAYED. Pass it as \$1 or ensure /opt/wdtt-test/relayed_addr.txt exists." >&2
    exit 1
fi

echo "Using server relayed address: $SERVER_RELAYED"

# 1. Clean up existing wg-wdtt interface if present
sudo ip link del dev wg-wdtt 2>/dev/null || true

# 2. Create WireGuard interface wg-wdtt
echo "Configuring WireGuard interface wg-wdtt ($CLIENT_WG_IP)..."
sudo ip link add dev wg-wdtt type wireguard
sudo ip addr add "$CLIENT_WG_IP" dev wg-wdtt

# Configure WireGuard peer pointing to local wdttd bridge
TMP_KEY=$(mktemp)
echo "$CLIENT_WG_PRIVKEY" > "$TMP_KEY"
sudo wg set wg-wdtt \
    private-key "$TMP_KEY" \
    peer "$SERVER_WG_PUBKEY" \
    endpoint "127.0.0.1:$CLIENT_WG_PORT" \
    allowed-ips "10.88.88.0/24" \
    persistent-keepalive 25
rm -f "$TMP_KEY"

# Bring interface up
sudo ip link set up dev wg-wdtt

# Ensure route is strictly 10.88.88.0/24 (no default route changes)
echo "WireGuard interface wg-wdtt is UP. Route strictly for 10.88.88.0/24:"
ip route show dev wg-wdtt

# 3. Start wdttd daemon
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Stopping previously running wdttd..."
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    sleep 1
fi

echo "Starting wdttd daemon..."
: > "$HOME/.config/wdtt-dev/wdttd.log"
setsid "$WDTTD_BIN" \
    --turn-server "$SERVER_HOST:$COTURN_PORT" \
    --turn-user "$COTURN_USER" \
    --turn-pass "$COTURN_PASS" \
    --turn-realm "$COTURN_REALM" \
    --server-relayed "$SERVER_RELAYED" \
    --wg-listen "127.0.0.1:$CLIENT_WG_PORT" \
    --psk "$PSK" \
    < /dev/null > "$HOME/.config/wdtt-dev/wdttd.log" 2>&1 &

WDTTD_PID=$!
echo "$WDTTD_PID" > "$PID_FILE"
echo "wdttd started with PID $WDTTD_PID (logs: ~/.config/wdtt-dev/wdttd.log)"

# Wait for tunnel initialization
echo -n "Waiting for tunnel ready..."
for _ in {1..20}; do
    if grep -q "Tunnel ready" "$HOME/.config/wdtt-dev/wdttd.log" 2>/dev/null; then
        echo " READY!"
        break
    fi
    if ! kill -0 "$WDTTD_PID" 2>/dev/null; then
        echo " FAILED!"
        echo "wdttd exited unexpectedly. Log:"
        cat "$HOME/.config/wdtt-dev/wdttd.log"
        exit 1
    fi
    sleep 0.5
    echo -n "."
done

echo "Client setup complete! Tunnel active."
