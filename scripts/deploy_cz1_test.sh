#!/usr/bin/env bash
# scripts/deploy_cz1_test.sh
# Выводит точный план и команды для развёртывания изолированного тестового wdtt-server на cz-1.
# ВНИМАНИЕ: Скрипт СТРОГО НИЧЕГО НЕ ВЫПОЛНЯЕТ сам. Он только печатает по секциям
# команды для предварительного согласования с пользователем.

set -euo pipefail

# Генерация детерминированного случайного пароля для вывода плана
TEST_TURN_PASS="WdttTestTurnPass_$(head -c 16 /dev/urandom | xxd -p || echo 'SecureRandomPass2026')"
TEST_PSK="WdttPsk2026_$(head -c 16 /dev/urandom | xxd -p || echo 'PskRandomBytes2026')"

cat << EOF
================================================================================
          ПЛАН РАЗВЁРТЫВАНИЯ ТЕСТОВОГО СТЕНДА WDTT-SERVER НА CZ-1
================================================================================

СТАТУС: ЧИСТЫЙ ВЫВОД ПЛАНА (DRY-RUN / NO-EXECUTION).
Никакие изменения на сервере cz-1 не производятся без вашего прямого решения.

ГАРАНТИИ ИЗОЛЯЦИИ:
1. Действующий WDTT Plus: НЕ ЗАТРАГИВАЕТСЯ. Интерфейс wdtt0, база, порты и процессы интактны.
2. Никаких изменений /etc/sysctl.conf или глобальных net.ipv4.ip_forward (NAT отключён).
3. Никакой замены или сброса существующих цепочек iptables (только точечные -A / -D).
4. Все тестовые службы запускаются от непривилегированного пользователя 'wdtt-test'.

--------------------------------------------------------------------------------
СЕКЦИЯ 1. ПОЛЬЗОВАТЕЛЬ И КАТАЛОГ СТЕНДА (ROOT)
--------------------------------------------------------------------------------
# Создание изолированного системного пользователя без оболочки и sudo:
useradd -r -s /usr/sbin/nologin -m -d /opt/wdtt-test wdtt-test

# Права доступа к каталогу (только для wdtt-test и root):
chmod 0750 /opt/wdtt-test

--------------------------------------------------------------------------------
СЕКЦИЯ 2. СЕТЕВЫЕ ПРАВИЛА IPTABLES (ТОЧЕЧНЫЙ СПИСОК, БЕЗ NAT)
--------------------------------------------------------------------------------
# Добавление разрешающих правил (ТОЛЬКО для тестовых портов, без MASQUERADE):
iptables -A INPUT -p udp --dport 34788 -m comment --comment "wdtt-test-turn-udp" -j ACCEPT
iptables -A INPUT -p udp --dport 49260:49300 -m comment --comment "wdtt-test-relay-ports" -j ACCEPT
iptables -A INPUT -p udp --dport 51828 -m comment --comment "wdtt-test-wg-endpoint" -j ACCEPT

# ПРОВЕРКА ОТСУТСТВИЯ ИЗМЕНЕНИЙ В СУЩЕСТВУЮЩИХ ПРАВИЛАХ:
iptables -L INPUT -n -v | grep "wdtt-test"

--------------------------------------------------------------------------------
СЕКЦИЯ 3. ИНТЕРФЕЙС ТЕСТОВОГО WIREGUARD ЯДРА (ROOT)
--------------------------------------------------------------------------------
# Генерация ключей для тестового пира (в /opt/wdtt-test, права 0600):
# Ключи тестовые, не имеют отношения к wdtt0:
wg genkey | install -m 0600 /dev/stdin /opt/wdtt-test/test_wg_srv.key
chown wdtt-test:wdtt-test /opt/wdtt-test/test_wg_srv.key
SRV_PUB=\$(wg pubkey < /opt/wdtt-test/test_wg_srv.key)

# Создание изолированного интерфейса ядра wg-test0 (IP 10.88.88.1/24):
ip link add dev wg-test0 type wireguard
ip addr add 10.88.88.1/24 dev wg-test0
wg set wg-test0 listen-port 51828 private-key /opt/wdtt-test/test_wg_srv.key peer <CLIENT_TEST_PUBKEY> allowed-ips 10.88.88.2/32
ip link set up dev wg-test0

# Внимание: IP-forwarding и NAT (MASQUERADE) НЕ ВКЛЮЧАЮТСЯ. Трафик изолирован
# внутри подсети 10.88.88.0/24 строго между тестовым клиентом и сервером.

--------------------------------------------------------------------------------
СЕКЦИЯ 4. КОНФИГУРАЦИЯ И ЗАПУСК COTURN (ТЕСТОВЫЙ ПОРТ 34788)
--------------------------------------------------------------------------------
Файл конфигурации: /opt/wdtt-test/turnserver.conf (владелец wdtt-test:wdtt-test, 0600)
Содержимое:
--------------------------------------------------------------------------------
listening-port=34788
alt-listening-port=0
min-port=49260
max-port=49300
realm=wdtt-cz1-test
user=wdtt-test-user:${TEST_TURN_PASS}

# Безопасность и жесткая изоляция:
no-cli
no-tls
no-dtls
no-tcp
no-tcp-relay
mobility
fingerprint

# Защита локальной сети и чужих служб:
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
max-bps=50000000
stale-nonce=600
--------------------------------------------------------------------------------

Команда запуска от пользователя wdtt-test:
su -s /bin/bash wdtt-test -c "turnserver -c /opt/wdtt-test/turnserver.conf --no-stdout-log --simple-log >/opt/wdtt-test/turnserver.log 2>&1 &"

--------------------------------------------------------------------------------
СЕКЦИЯ 5. ЗАПУСК ТЕСТОВОГО WDTT-SERVER (STATIC MUSL)
--------------------------------------------------------------------------------
# Бинарник: /opt/wdtt-test/wdtt-server (x86_64 static musl)
# Запуск от пользователя wdtt-test:
su -s /bin/bash wdtt-test -c "/opt/wdtt-test/wdtt-server \\
    --turn-server 127.0.0.1:34788 \\
    --turn-user wdtt-test-user \\
    --turn-pass '${TEST_TURN_PASS}' \\
    --turn-realm wdtt-cz1-test \\
    --wg-endpoint 127.0.0.1:51828 \\
    --psk '${TEST_PSK}' \\
    --relayed-addr-file /opt/wdtt-test/relayed_addr.txt > /opt/wdtt-test/server.log 2>&1 &"

--------------------------------------------------------------------------------
СЕКЦИЯ 6. SYSTEMD ЮНИТЫ (ОПЦИОНАЛЬНО, ТОЛЬКО ЕСЛИ НУЖЕН АВТОЗАПУСК)
--------------------------------------------------------------------------------
Файл 1: /etc/systemd/system/wdtt-test-coturn.service
[Unit]
Description=Test Coturn Relay for WDTT v2 Testbed
After=network.target

[Service]
Type=simple
User=wdtt-test
Group=wdtt-test
ExecStart=/usr/bin/turnserver -c /opt/wdtt-test/turnserver.conf --no-stdout-log
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
User=wdtt-test
Group=wdtt-test
WorkingDirectory=/opt/wdtt-test
ExecStart=/opt/wdtt-test/wdtt-server --turn-server 127.0.0.1:34788 --turn-user wdtt-test-user --turn-pass ${TEST_TURN_PASS} --turn-realm wdtt-cz1-test --wg-endpoint 127.0.0.1:51828 --psk ${TEST_PSK}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target

--------------------------------------------------------------------------------
СЕКЦИЯ 7. КОМАНДЫ ПОЛНОГО ОТКАТА И УДАЛЕНИЯ СЛЕДОВ (ROOT)
--------------------------------------------------------------------------------
# 1. Остановка процессов:
pkill -u wdtt-test || true
systemctl stop wdtt-test-server 2>/dev/null || true
systemctl stop wdtt-test-coturn 2>/dev/null || true
systemctl disable wdtt-test-server 2>/dev/null || true
systemctl disable wdtt-test-coturn 2>/dev/null || true
rm -f /etc/systemd/system/wdtt-test-server.service /etc/systemd/system/wdtt-test-coturn.service
systemctl daemon-reload

# 2. Удаление тестового интерфейса WireGuard:
ip link del dev wg-test0 2>/dev/null || true

# 3. Удаление точечных правил iptables:
iptables -D INPUT -p udp --dport 34788 -m comment --comment "wdtt-test-turn-udp" -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p udp --dport 49260:49300 -m comment --comment "wdtt-test-relay-ports" -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p udp --dport 51828 -m comment --comment "wdtt-test-wg-endpoint" -j ACCEPT 2>/dev/null || true

# 4. Удаление пользователя и каталога:
userdel -r wdtt-test 2>/dev/null || true
rm -rf /opt/wdtt-test

================================================================================
EOF
exit 0
