#!/usr/bin/env bash
# scripts/deploy_cz1_test.sh
# Развёртывание тестового wdtt-server и coturn на cz-1 на отдельных портах
# ВНИМАНИЕ: Скрипт подготовлен для ревью, НЕ ВЫПОЛНЯТЬ БЕЗ ЯВНОГО РЕШЕНИЯ ПОЛЬЗОВАТЕЛЯ!

set -euo pipefail

# ==============================================================================
# ТОЧНЫЙ СПИСОК РЕСУРСОВ И ПОРТОВ:
# 1. Системный пользователь: wdtt-test (UID/GID выделенный, без sudo, shell /bin/false)
# 2. Каталог установки:     /opt/wdtt-test (права 0750 wdtt-test:wdtt-test)
# 3. Порты Coturn (тест):   UDP/TCP 34788 (основной), UDP 49260..49300 (релеи)
# 4. Порт WireGuard (тест): UDP 51828 (интерфейс wg-test0, подсеть 10.88.88.0/24)
# 5. Действующий WDTT Plus: НЕ ЗАТРАГИВАЕТСЯ (порты и интерфейс wdtt0 изолированы)
# ==============================================================================

ACTION="${1:-dry-run}"

echo "=== Скрипт развёртывания тестового стенда wdtt-server на cz-1 ==="
echo "Режим: $ACTION"

if [ "$ACTION" = "dry-run" ]; then
    cat << 'EOF'
[DRY-RUN] Никакие команды на сервере не выполняются.
Ниже приведён точный перечень действий, разделённый по правам доступа:

--------------------------------------------------------------------------------
ШАГ А. ТРЕБУЕТ КОРНЕВЫХ ПРАВ (ROOT):
--------------------------------------------------------------------------------
1. Создание непривилегированного пользователя:
   id -u wdtt-test &>/dev/null || useradd -r -s /bin/false -m -d /opt/wdtt-test wdtt-test

2. Настройка фаервола (iptables) для тестовых портов:
   # Разрешить тестовый порт TURN:
   iptables -A INPUT -p udp --dport 34788 -j ACCEPT
   iptables -A INPUT -p tcp --dport 34788 -j ACCEPT
   # Разрешить тестовый диапазон TURN Relay:
   iptables -A INPUT -p udp --dport 49260:49300 -j ACCEPT
   # Разрешить локальный трафик тестового WireGuard:
   iptables -A INPUT -p udp --dport 51828 -j ACCEPT

3. Создание тестового интерфейса WireGuard ядра (wg-test0):
   ip link add dev wg-test0 type wireguard
   ip addr add 10.88.88.1/24 dev wg-test0
   wg set wg-test0 listen-port 51828 private-key /opt/wdtt-test/server_wg.key peer <CLIENT_WG_PUBKEY> allowed-ips 10.88.88.2/32
   ip link set up dev wg-test0

4. Опциональная маршрутизация / NAT (только если нужен выход в Интернет через cz-1):
   iptables -t nat -A POSTROUTING -s 10.88.88.0/24 -o eth0 -j MASQUERADE

--------------------------------------------------------------------------------
ШАГ Б. ВЫПОЛНЯЕТСЯ ОТ НЕПРИВИЛЕГИРОВАННОГО ПОЛЬЗОВАТЕЛЯ (WDTT-TEST):
--------------------------------------------------------------------------------
1. Запуск изолированного экземпляра Coturn:
   su -s /bin/bash wdtt-test -c "turnserver \
       -a -o \
       -u testuser:testpassword123 \
       -r wdtt-test-cz1 \
       -p 34788 \
       --min-port 49260 --max-port 49300 \
       --no-tls --no-stdout-log >/opt/wdtt-test/turnserver.log 2>&1 &"

2. Запуск статического бинарника wdtt-server (x86_64-unknown-linux-musl):
   su -s /bin/bash wdtt-test -c "/opt/wdtt-test/wdtt-server \
       --turn-server 127.0.0.1:34788 \
       --turn-user testuser \
       --turn-pass testpassword123 \
       --turn-realm wdtt-test-cz1 \
       --wg-endpoint 127.0.0.1:51828 \
       --psk $(cat /opt/wdtt-test/psk.txt) \
       --relayed-addr-file /opt/wdtt-test/relayed_addr.txt >/opt/wdtt-test/server.log 2>&1 &"

--------------------------------------------------------------------------------
ШАГ В. КОМАНДЫ ПОЛНОЙ ОЧИСТКИ И УДАЛЕНИЯ (ROOT):
--------------------------------------------------------------------------------
   pkill -u wdtt-test || true
   ip link del dev wg-test0 2>/dev/null || true
   iptables -D INPUT -p udp --dport 34788 -j ACCEPT 2>/dev/null || true
   iptables -D INPUT -p tcp --dport 34788 -j ACCEPT 2>/dev/null || true
   iptables -D INPUT -p udp --dport 49260:49300 -j ACCEPT 2>/dev/null || true
   iptables -D INPUT -p udp --dport 51828 -j ACCEPT 2>/dev/null || true
   iptables -t nat -D POSTROUTING -s 10.88.88.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
   userdel -r wdtt-test 2>/dev/null || true
   rm -rf /opt/wdtt-test
EOF
    exit 0
fi

echo "Выполнение развёртывания заблокировано до явного подтверждения пользователя."
exit 1
