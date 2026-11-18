#!/usr/bin/env bash
set -euo pipefail

SERVER_HOST="${1:?usage: $0 <server-host> [server-user]}"
SERVER_USER="${2:-root}"
SSH_TARGET="${SERVER_USER}@${SERVER_HOST}"

echo "=== Uninstalling wdtt-vk from ${SSH_TARGET} ==="
ssh -o ConnectTimeout=5 "${SSH_TARGET}" bash -s <<'EOF'
set -euo pipefail

if [[ -f /opt/wdtt-vk/rollback.sh ]]; then
    /opt/wdtt-vk/rollback.sh
else
    systemctl stop wdtt-vk-server 2>/dev/null || true
    rm -f /etc/systemd/system/wdtt-vk-server.service
    systemctl daemon-reload
    ip link del dev wg-vk0 2>/dev/null || true
    iptables -D INPUT -p udp --dport 56010 -m comment --comment "wdtt-vk-server" -j ACCEPT 2>/dev/null || true
    rm -rf /opt/wdtt-vk
    userdel wdtt-vk 2>/dev/null || true
fi

echo "--- Current iptables -S INPUT ---"
iptables -S INPUT
echo ""
echo "--- Listening UDP ports ---"
ss -ulnp | grep -E "56000|56001" || true
EOF

echo "Uninstall completed."
