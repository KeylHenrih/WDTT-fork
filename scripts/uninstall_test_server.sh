#!/usr/bin/env bash
set -euo pipefail

# scripts/uninstall_test_server.sh - Cleanly remove all test artifacts from the remote server
# Restores iptables, removes units, user, directory, and wg-test0 interface.

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

echo "=== Stopping test services ==="
systemctl stop wdtt-test-server 2>/dev/null || true
systemctl stop wdtt-test-coturn 2>/dev/null || true
systemctl disable wdtt-test-server 2>/dev/null || true
systemctl disable wdtt-test-coturn 2>/dev/null || true

# Kill any test python HTTP servers or iperf3 instances on test IP
pkill -f "http.server.*10.88.88.1" 2>/dev/null || true
pkill -f "iperf3.*-s" 2>/dev/null || true

echo "=== Removing systemd service units ==="
rm -f /etc/systemd/system/wdtt-test-server.service
rm -f /etc/systemd/system/wdtt-test-coturn.service
systemctl daemon-reload

echo "=== Removing WireGuard test interface ==="
if ip link show wg-test0 &>/dev/null; then
    ip link del dev wg-test0 2>/dev/null || true
fi

echo "=== Removing iptables test rules ==="
# Remove specific rules added for wdtt-test
while iptables -C INPUT -p udp --dport 34788 -m comment --comment "wdtt-test-coturn" -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p udp --dport 34788 -m comment --comment "wdtt-test-coturn" -j ACCEPT
done

while iptables -C INPUT -p udp --dport 49260:49300 -m comment --comment "wdtt-test-relay" -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p udp --dport 49260:49300 -m comment --comment "wdtt-test-relay" -j ACCEPT
done

echo "Current iptables INPUT rules:"
iptables -S INPUT

echo "=== Removing test directory and user ==="
rm -rf /opt/wdtt-test

if id "wdtt-test" &>/dev/null; then
    userdel -r wdtt-test 2>/dev/null || userdel wdtt-test 2>/dev/null || true
fi

echo "=== Test server uninstall completed successfully ==="
