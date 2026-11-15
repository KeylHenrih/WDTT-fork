#!/usr/bin/env bash
set -euo pipefail

SERVER_HOST="${1:?usage: $0 <server-host> [server-user]}"
SERVER_USER="${2:-root}"
SSH_TARGET="${SERVER_USER}@${SERVER_HOST}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
SERVER_BIN="${PROJECT_ROOT}/target/release/wdtt-server"

PSK_HEX="${WDTT_PSK_HEX:?set WDTT_PSK_HEX to the 32-byte pre-shared key in hex}"
CLIENT_PUBKEY="${WDTT_CLIENT_PUBKEY:?set WDTT_CLIENT_PUBKEY to the client WireGuard public key}"
SERVER_KEY_FILE="${WDTT_SERVER_KEY_FILE:-/tmp/wdtt-keys/server.key}"

if [[ ! -f "${SERVER_BIN}" ]]; then
    echo "Error: Binary ${SERVER_BIN} not found. Run cargo build --release -p wdtt-server first."
    exit 1
fi

if [[ ! -f "${SERVER_KEY_FILE}" ]]; then
    echo "Error: Server key file ${SERVER_KEY_FILE} not found."
    exit 1
fi

SERVER_PRIVKEY="$(cat "${SERVER_KEY_FILE}")"

echo "=== 1. Checking pre-deployment state on ${SSH_TARGET} ==="
ssh -o ConnectTimeout=5 "${SSH_TARGET}" "iptables -S INPUT"
echo ""

echo "=== 2. Deploying files and configuration to ${SSH_TARGET} ==="
ssh -o ConnectTimeout=5 "${SSH_TARGET}" bash -s <<EOF
set -euo pipefail

# Create system user if not exists
if ! id -u wdtt-vk >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin wdtt-vk
fi

mkdir -p /opt/wdtt-vk
chmod 750 /opt/wdtt-vk

# Write WireGuard server key
echo "${SERVER_PRIVKEY}" > /opt/wdtt-vk/wg-server.key
chmod 600 /opt/wdtt-vk/wg-server.key

# Write rollback script
cat > /opt/wdtt-vk/rollback.sh << 'ROLLBACK'
#!/usr/bin/env bash
echo "Rolling back wdtt-vk deployment..."
systemctl stop wdtt-vk-server 2>/dev/null || true
rm -f /etc/systemd/system/wdtt-vk-server.service
systemctl daemon-reload
ip link del dev wg-vk0 2>/dev/null || true
iptables -D INPUT -p udp --dport 56010 -m comment --comment "wdtt-vk-server" -j ACCEPT 2>/dev/null || true
rm -rf /opt/wdtt-vk
userdel wdtt-vk 2>/dev/null || true
echo "Rollback completed."
ROLLBACK
chmod +x /opt/wdtt-vk/rollback.sh

# Configure WireGuard interface wg-vk0
ip link del dev wg-vk0 2>/dev/null || true
ip link add dev wg-vk0 type wireguard
ip addr add 10.99.99.1/24 dev wg-vk0
ip link set mtu 1360 dev wg-vk0
wg set wg-vk0 listen-port 51822 private-key /opt/wdtt-vk/wg-server.key peer "${CLIENT_PUBKEY}" allowed-ips 10.99.99.2/32
ip link set up dev wg-vk0
EOF

# Copy wdtt-server binary
scp -o ConnectTimeout=5 "${SERVER_BIN}" "${SSH_TARGET}:/opt/wdtt-vk/wdtt-server"

ssh -o ConnectTimeout=5 "${SSH_TARGET}" bash -s <<EOF
set -euo pipefail

chmod 755 /opt/wdtt-vk/wdtt-server
chown -R wdtt-vk:wdtt-vk /opt/wdtt-vk

# Systemd unit (NO enable)
cat > /etc/systemd/system/wdtt-vk-server.service << 'UNIT'
[Unit]
Description=WDTT v2 Server (VK Direct Mode)
After=network.target

[Service]
Type=simple
User=wdtt-vk
Group=wdtt-vk
ExecStart=/opt/wdtt-vk/wdtt-server --listen 0.0.0.0:56010 --wg-endpoint 127.0.0.1:51822 --psk ${PSK_HEX} --runtime multi_thread --workers 2
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl start wdtt-vk-server

# Add single iptables rule
iptables -I INPUT 1 -p udp --dport 56010 -m comment --comment "wdtt-vk-server" -j ACCEPT
EOF

echo "=== 3. Checking post-deployment state on ${SSH_TARGET} ==="
ssh -o ConnectTimeout=5 "${SSH_TARGET}" bash -s <<'EOF'
echo "--- iptables -S INPUT ---"
iptables -S INPUT
echo ""
echo "--- Listening UDP ports (56000, 56001, 56010, 51822) ---"
ss -ulnp | grep -E "56000|56001|56010|51822" || true
echo ""
echo "--- wdtt-vk-server service status ---"
systemctl status wdtt-vk-server --no-pager | head -n 15
EOF

echo "Deployment finished successfully."
