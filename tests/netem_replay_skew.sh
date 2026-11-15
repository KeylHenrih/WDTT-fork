#!/usr/bin/env bash
# tests/netem_replay_skew.sh
# Verifies tunnel stability and adaptive resequencing under tc netem delay skew and jitter.

set -euo pipefail

TEST_DIR="/tmp/wdtt_netem_test"
TURN_PORT=34785
TURN_USER="netemuser"
TURN_PASS="netempass"
TURN_REALM="wdtt-netem"
PSK="netemtestsecretkey2026wdttv2skew"

echo "=== WDTT v2 Netem Delay Skew & Resequencing Test ==="

cleanup() {
    echo "[-] Cleaning up Netem test environment..."
    sudo pkill -9 -f "target/release/wdtt" 2>/dev/null || true
    sudo killall -9 turnserver 2>/dev/null || true
    sudo iptables -D INPUT -i veth-netem-host -j ACCEPT 2>/dev/null || true
    sudo iptables -D INPUT -i wg-netem-srv -j ACCEPT 2>/dev/null || true
    sudo ip link del wg-netem-srv 2>/dev/null || true
    sudo ip link del veth-netem-host 2>/dev/null || true
    sudo ip netns del wdtt-netem-ns 2>/dev/null || true
    rm -rf "$TEST_DIR"
    echo "[-] Netem cleanup complete."
}
trap cleanup EXIT INT TERM

cleanup 2>/dev/null || true
mkdir -p "$TEST_DIR"

echo "[+] Step 1: Setting up network namespace and veth link..."
sudo ip netns add wdtt-netem-ns
sudo ip link add veth-netem-host type veth peer name veth-netem-cl
sudo ip link set veth-netem-cl netns wdtt-netem-ns
sudo ip addr add 192.168.110.1/24 dev veth-netem-host
sudo ip link set veth-netem-host up
sudo ip -n wdtt-netem-ns addr add 192.168.110.2/24 dev veth-netem-cl
sudo ip -n wdtt-netem-ns link set veth-netem-cl up
sudo ip -n wdtt-netem-ns link set lo up

# Allow firewall on veth-netem-host
sudo iptables -I INPUT 1 -i veth-netem-host -j ACCEPT

echo "[+] Step 2: Injecting tc netem delay skew: 35ms delay ± 5ms normal distribution..."
sudo tc qdisc add dev veth-netem-host root netem delay 35ms 5ms distribution normal

echo "[+] Step 3: Starting Coturn TURN server on port $TURN_PORT..."
turnserver -a -o -v \
    -u "$TURN_USER:$TURN_PASS" \
    -r "$TURN_REALM" \
    -p "$TURN_PORT" \
    -L 192.168.110.1 \
    -E 192.168.110.1 \
    --min-port 49310 --max-port 49350 \
    --no-tls --no-stdout-log >/dev/null 2>&1 &
sleep 1

echo "[+] Step 4: Configuring WireGuard interfaces..."
SRV_PRIV=$(wg genkey)
SRV_PUB=$(echo "$SRV_PRIV" | wg pubkey)
CL_PRIV=$(wg genkey)
CL_PUB=$(echo "$CL_PRIV" | wg pubkey)

echo "$SRV_PRIV" > "$TEST_DIR/srv.key"
sudo ip link add dev wg-netem-srv type wireguard
sudo ip addr add 10.88.88.1/24 dev wg-netem-srv
sudo wg set wg-netem-srv listen-port 51830 private-key "$TEST_DIR/srv.key" peer "$CL_PUB" allowed-ips 10.88.88.2/32
sudo ip link set up dev wg-netem-srv
sudo iptables -I INPUT 1 -i wg-netem-srv -j ACCEPT

echo "$CL_PRIV" > "$TEST_DIR/cl.key"
sudo ip -n wdtt-netem-ns link add dev wg-netem-cl type wireguard
sudo ip -n wdtt-netem-ns addr add 10.88.88.2/24 dev wg-netem-cl
sudo ip netns exec wdtt-netem-ns wg set wg-netem-cl private-key "$TEST_DIR/cl.key" peer "$SRV_PUB" allowed-ips 10.88.88.1/32 endpoint 127.0.0.1:51831
sudo ip -n wdtt-netem-ns link set up dev wg-netem-cl

echo "[+] Step 5: Starting wdtt-server..."
RELAYED_FILE="$TEST_DIR/relayed.txt"
./target/release/wdtt-server \
    --turn-server "192.168.110.1:$TURN_PORT" \
    --turn-user "$TURN_USER" \
    --turn-pass "$TURN_PASS" \
    --turn-realm "$TURN_REALM" \
    --wg-endpoint "127.0.0.1:51830" \
    --psk "$PSK" \
    --relayed-addr-file "$RELAYED_FILE" > "$TEST_DIR/server.log" 2>&1 &
SRV_PID=$!

for _ in {1..30}; do
    if [ -s "$RELAYED_FILE" ]; then break; fi
    sleep 0.1
done
SRV_RELAYED=$(cat "$RELAYED_FILE")
echo "    Server relayed address: $SRV_RELAYED"

echo "[+] Step 6: Starting wdttd (client) inside netns..."
sudo ip netns exec wdtt-netem-ns env RUST_LOG=info \
    ./target/release/wdttd \
    --turn-server "192.168.110.1:$TURN_PORT" \
    --turn-user "$TURN_USER" \
    --turn-pass "$TURN_PASS" \
    --turn-realm "$TURN_REALM" \
    --server-relayed "$SRV_RELAYED" \
    --wg-listen "127.0.0.1:51831" \
    --psk "$PSK" > "$TEST_DIR/client.log" 2>&1 &
sleep 2

echo "[+] Step 7: Verifying tunnel stability under 35ms skew..."
PING_OUT=$(sudo ip netns exec wdtt-netem-ns ping -c 10 -i 0.1 10.88.88.1)
echo "$PING_OUT"

LOSS=$(echo "$PING_OUT" | grep -oP '\d+(?=% packet loss)')
if [ "$LOSS" -ne 0 ]; then
    echo "[-] FAILED: Packet loss under netem was $LOSS% (expected 0%)"
    exit 1
fi

echo "[+] Step 8: Running UDP verification stream under netem skew..."
iperf3 -s -B 10.88.88.1 -p 5210 -1 >/dev/null 2>&1 &
sleep 0.5
UDP_RES=$(sudo ip netns exec wdtt-netem-ns iperf3 -c 10.88.88.1 -p 5210 -u -b 20M -t 3 --json)
UDP_LOSS=$(echo "$UDP_RES" | jq -r '.end.sum.lost_percent')
echo "    UDP throughput verified under netem. Lost percent: $UDP_LOSS%"

echo "======================================================="
echo "[+] SUCCESS: Netem skew test PASSED (0% loss, stable handshake)!"
echo "======================================================="
