#!/usr/bin/env bash
# scripts/deploy_test_server.sh
# Выводит точный план и команды для развёртывания изолированного тестового сервера WDTT v2.
# ВНИМАНИЕ: Скрипт СТРОГО НИЧЕГО НЕ ВЫПОЛНЯЕТ сам. Он только печатает по секциям
# команды для предварительного согласования администратором сервера.

set -euo pipefail

# Настраиваемые параметры через переменные окружения
SERVER_USER="${SERVER_USER:-wdtt-test}"
TEST_DIR="${TEST_DIR:-/opt/wdtt-test}"
TURN_PORT="${TURN_PORT:-34788}"
RELAY_PORT_MIN="${RELAY_PORT_MIN:-49260}"
RELAY_PORT_MAX="${RELAY_PORT_MAX:-49300}"
WG_PORT="${WG_PORT:-51828}"
TEST_REALM="${TEST_REALM:-wdtt-test-realm}"
TEST_USER="${TEST_USER:-wdtt-test-user}"

# Генерация псевдослучайных одноразовых секретов для вывода плана
TEST_TURN_PASS="TurnPass_$(head -c 16 /dev/urandom | xxd -p || echo 'SecureRandomPass2026')"
TEST_PSK="PskSecret_$(head -c 16 /dev/urandom | xxd -p || echo 'PskRandomBytes2026')"

cat << EOF
================================================================================
          ПЛАН РАЗВЁРТЫВАНИЯ ТЕСТОВОГО СТЕНДА WDTT-SERVER
================================================================================

СТАТУС: ЧИСТЫЙ ВЫВОД ПЛАНА (DRY-RUN / NO-EXECUTION).
Никакие изменения на сервере не производятся без вашего прямого решения.

ГАРАНТИИ ИЗОЛЯЦИИ:
1. Действующие службы и другие туннели: НЕ ЗАТРАГИВАЮТСЯ.
2. Никаких изменений sysctl или глобальных net.ipv4.ip_forward (NAT отключён).
3. Никакой замены или сброса существующих цепочек iptables/nftables (только точечные правила).
4. Все тестовые службы запускаются от непривилегированного пользователя '${SERVER_USER}'.

--------------------------------------------------------------------------------
СЕКЦИЯ 0. ПРЕДВАРИТЕЛЬНАЯ ПРОВЕРКА ПОРТОВ
--------------------------------------------------------------------------------
# Проверка, что тестовые порты свободны:
# Порты: UDP ${TURN_PORT} (TURN), UDP ${RELAY_PORT_MIN}-${RELAY_PORT_MAX} (Relay pool), UDP ${WG_PORT} (WireGuard)
ss -ulnp | grep -E ':(${TURN_PORT}|${WG_PORT}|${RELAY_PORT_MIN%0}[0-9]|${RELAY_PORT_MAX})\b' || echo "[OK] Все тестовые порты свободны."

--------------------------------------------------------------------------------
СЕКЦИЯ 1. ПОЛЬЗОВАТЕЛЬ И КАТАЛОГ СТЕНДА (ROOT)
--------------------------------------------------------------------------------
# Создание изолированного системного пользователя без оболочки и sudo:
useradd -r -s /usr/sbin/nologin -m -d ${TEST_DIR} ${SERVER_USER}

# Права доступа к каталогу (только для ${SERVER_USER} и root):
chmod 0750 ${TEST_DIR}

--------------------------------------------------------------------------------
СЕКЦИЯ 2. СЕТЕВЫЕ ПРАВИЛА И ФАЙРВОЛ (IPTABLES / NFT / UFW)
--------------------------------------------------------------------------------
# Просмотр порядка существующих правил в цепочке INPUT:
iptables -S INPUT

# Добавление разрешающих правил в начало цепочки (-I INPUT 1..3),
# чтобы предотвратить их перехват конечными правилами DROP/REJECT:
iptables -I INPUT 1 -p udp --dport ${TURN_PORT} -m comment --comment "wdtt-test-turn-udp" -j ACCEPT
iptables -I INPUT 2 -p udp --dport ${RELAY_PORT_MIN}:${RELAY_PORT_MAX} -m comment --comment "wdtt-test-relay-ports" -j ACCEPT
iptables -I INPUT 3 -p udp --dport ${WG_PORT} -m comment --comment "wdtt-test-wg-endpoint" -j ACCEPT

# Проверка вставки правил с номерами строк:
iptables -L INPUT --line-numbers -n | grep "wdtt-test"

--------------------------------------------------------------------------------
СЕКЦИЯ 3. ИНТЕРФЕЙС ТЕСТОВОГО WIREGUARD ЯДРА (ROOT)
--------------------------------------------------------------------------------
# Генерация ключей для тестового пира (в ${TEST_DIR}, права 0600):
wg genkey | install -m 0600 /dev/stdin ${TEST_DIR}/test_wg_srv.key
chown ${SERVER_USER}:${SERVER_USER} ${TEST_DIR}/test_wg_srv.key

# Создание изолированного интерфейса ядра wg-test0 (IP 10.88.88.1/24):
ip link add dev wg-test0 type wireguard
ip addr add 10.88.88.1/24 dev wg-test0
wg set wg-test0 listen-port ${WG_PORT} private-key ${TEST_DIR}/test_wg_srv.key peer <CLIENT_TEST_PUBKEY> allowed-ips 10.88.88.2/32
ip link set up dev wg-test0

# Внимание: IP-forwarding и NAT (MASQUERADE) НЕ ВКЛЮЧАЮТСЯ. Трафик изолирован
# строго между тестовым клиентом и сервером.

--------------------------------------------------------------------------------
СЕКЦИЯ 4. КОНФИГУРАЦИЯ И ЗАПУСК COTURN (ТЕСТОВЫЙ ПОРТ ${TURN_PORT})
--------------------------------------------------------------------------------
Файл конфигурации: ${TEST_DIR}/turnserver.conf (владелец ${SERVER_USER}:${SERVER_USER}, 0600)
Содержимое:
--------------------------------------------------------------------------------
listening-port=${TURN_PORT}
alt-listening-port=0
min-port=${RELAY_PORT_MIN}
max-port=${RELAY_PORT_MAX}
realm=${TEST_REALM}
user=${TEST_USER}:${TEST_TURN_PASS}

# Безопасность и жесткая изоляция:
no-cli
no-tls
no-dtls
no-tcp
no-tcp-relay
mobility
fingerprint

# Защита локальной сети и других служб:
# Разрешено ретранслировать пакеты ТОЛЬКО на локальный тестовый wdtt-server:
allowed-peer-ip=127.0.0.1
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.2-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.0.2.0-192.0.2.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=198.51.100.0-198.51.100.255
denied-peer-ip=203.0.113.0-203.0.113.255
denied-peer-ip=::/0

# Лимиты и квоты:
user-quota=4
total-quota=8
# max-bps задаётся в байтах/с (0 = без искусственного троттлинга для тестов производительности):
max-bps=0
stale-nonce=600
--------------------------------------------------------------------------------

Команда запуска от пользователя ${SERVER_USER}:
su -s /bin/bash ${SERVER_USER} -c "turnserver -c ${TEST_DIR}/turnserver.conf --no-stdout-log --simple-log >${TEST_DIR}/turnserver.log 2>&1 &"

--------------------------------------------------------------------------------
СЕКЦИЯ 5. ЗАПУСК ТЕСТОВОГО WDTT-SERVER (STATIC MUSL)
--------------------------------------------------------------------------------
# Бинарник: ${TEST_DIR}/wdtt-server (x86_64 static musl)
# Запуск от пользователя ${SERVER_USER}:
su -s /bin/bash ${SERVER_USER} -c "${TEST_DIR}/wdtt-server \\
    --turn-server 127.0.0.1:${TURN_PORT} \\
    --turn-user ${TEST_USER} \\
    --turn-pass '${TEST_TURN_PASS}' \\
    --turn-realm ${TEST_REALM} \\
    --wg-endpoint 127.0.0.1:${WG_PORT} \\
    --psk '${TEST_PSK}' \\
    --relayed-addr-file ${TEST_DIR}/relayed_addr.txt > ${TEST_DIR}/server.log 2>&1 &"

--------------------------------------------------------------------------------
СЕКЦИЯ 6. SYSTEMD ЮНИТЫ (ОПЦИОНАЛЬНО)
--------------------------------------------------------------------------------
Файл 1: /etc/systemd/system/wdtt-test-coturn.service
[Unit]
Description=Test Coturn Relay for WDTT v2
After=network.target

[Service]
Type=simple
User=${SERVER_USER}
Group=${SERVER_USER}
ExecStart=/usr/bin/turnserver -c ${TEST_DIR}/turnserver.conf --no-stdout-log
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target

Файл 2: /etc/systemd/system/wdtt-test-server.service
[Unit]
Description=Test WDTT v2 Standalone Server
After=network.target wdtt-test-coturn.service

[Service]
Type=simple
User=${SERVER_USER}
Group=${SERVER_USER}
WorkingDirectory=${TEST_DIR}
ExecStart=${TEST_DIR}/wdtt-server --turn-server 127.0.0.1:${TURN_PORT} --turn-user ${TEST_USER} --turn-pass ${TEST_TURN_PASS} --turn-realm ${TEST_REALM} --wg-endpoint 127.0.0.1:${WG_PORT} --psk ${TEST_PSK}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target

--------------------------------------------------------------------------------
СЕКЦИЯ 7. КОМАНДЫ ПОЛНОГО ОТКАТА И УДАЛЕНИЯ СЛЕДОВ (ROOT)
--------------------------------------------------------------------------------
# 1. Остановка процессов:
pkill -u ${SERVER_USER} || true
systemctl stop wdtt-test-server 2>/dev/null || true
systemctl stop wdtt-test-coturn 2>/dev/null || true
systemctl disable wdtt-test-server 2>/dev/null || true
systemctl disable wdtt-test-coturn 2>/dev/null || true
rm -f /etc/systemd/system/wdtt-test-server.service /etc/systemd/system/wdtt-test-coturn.service
systemctl daemon-reload

# 2. Удаление тестового интерфейса WireGuard:
ip link del dev wg-test0 2>/dev/null || true

# 3. Удаление точечных правил iptables:
iptables -D INPUT -p udp --dport ${TURN_PORT} -m comment --comment "wdtt-test-turn-udp" 2>/dev/null || true
iptables -D INPUT -p udp --dport ${RELAY_PORT_MIN}:${RELAY_PORT_MAX} -m comment --comment "wdtt-test-relay-ports" 2>/dev/null || true
iptables -D INPUT -p udp --dport ${WG_PORT} -m comment --comment "wdtt-test-wg-endpoint" 2>/dev/null || true

# 4. Удаление пользователя и каталога:
userdel -r ${SERVER_USER} 2>/dev/null || true
rm -rf ${TEST_DIR}

================================================================================
EOF
exit 0
