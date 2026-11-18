# WDTT v0.1 Poke Quickstart

## 1. Запуск сервисов на сервере
```bash
ssh root@<SERVER_HOST> "systemctl start wdtt-test-coturn && systemctl start wdtt-test-server"
```

## 2. Подъём туннеля на клиенте
```bash
./scripts/dev-up.sh
```

## 3. Проверка связности и скорости
```bash
ping -c 4 10.88.88.1
curl -s http://10.88.88.1:8080
iperf3 -c 10.88.88.1 -t 10 -P 1
iperf3 -c 10.88.88.1 -u -b 20M -t 10
```

## 4. Остановка туннеля на клиенте
```bash
./scripts/dev-down.sh
```

## 5. Полное удаление с сервера
```bash
ssh root@<SERVER_HOST> "/root/scripts/uninstall_test_server.sh"
```
