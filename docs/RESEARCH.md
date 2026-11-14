# Исследование существующих реализаций WDTT (Этап 0)

В данном документе приведён сравнительный архитектурный и технический анализ существующих реализаций туннеля «WireGuard поверх TURN/DTLS с маскировкой под медиатрафик звонка» на основе прямого изучения исходного кода эталонных репозиториев.

---

## 1. Исследованные проекты и лицензионный статус

| Проект | Репозиторий | Стек | Лицензия | Применимость в wdtt-rs |
|---|---|---|---|---|
| **PWDTT** | `luminescq/PWDTT` | Go (pion/dtls, pion/turn) + Wails (React/Vite) | GPL-3.0 | Источник идей для ПК, совместимость ссылок `wdtt://` и `qwdtt://` |
| **CSQTT** | `amurcanov/csqtt` | Android (Compose) + Rust (aws-lc-rs, io_uring) | PolyForm Noncommercial 1.0.0 | **Только чтение.** Копирование кода **запрещено** (несовместима с GPL) |
| **proxy-turn-vk-android** | `amurcanov/proxy-turn-vk-android` | Android (Kotlin) + WireGuard GoBackend + Go core | GPL-3.0 | Оригинальный Android-клиент, источник анализа жизненного цикла |
| **qWDTT** | `SpaceNeuroX/proxy-turn-vk-android` | Android + Go client/server | GPL-3.0 | Анализ мульти-хешинга, ротации, raw-режима |
| **WDTT Plus** | `Ivan4537/WDTT-Plus` | Android + Go client/server | GPL-3.0 | Анализ серверных скриптов, DNS, masque/warp расширений |
| **vk-turn-proxy** | `cacggghp/vk-turn-proxy` | Go (pion/dtls, pion/turn) | MIT / GPL-3.0 | Первоначальное ядро протокола (клиент/сервер) |
| **vk-turn-proxy-android**| `MYSOREZ/vk-turn-proxy-android` | Android (Kotlin) + Go | GPL-3.0 | Форк UI и интеграции с Android VpnService |
| **vk-turn-proxy-ios** | `anton48/vk-turn-proxy-ios` | Swift (NetworkExtension) + Go core | GPL-3.0 | Анализ симуляции anti-replay окна WireGuard и SRTP |

---

## 2. Анализ каждого проекта

### 2.1 `cacggghp/vk-turn-proxy` (Go core)

#### Что реализовано
- Минимальный клиент и сервер на Go с использованием библиотек Pion (`pion/dtls/v3`, `pion/turn/v5`).
- Режимы работы: UDP (проксирование WireGuard) и VLESS (smux + KCP поверх DTLS для проксирования TCP/Xray).
- Авторизация в VK Звонках и Яндекс Телемосте для автоматического получения временных TURN-учётных данных.
- Поддержка параллельных DTLS-потоков (флаг `-n`, по умолчанию 10 для VK, 1 для Яндекса).

#### Проводной протокол (Wire Protocol)
- **Транспорт:** DTLS 1.2 поверх UDP или TCP соединения с TURN-сервером через STUN ChannelData (`0x4000..0x7FFF`).
- **DTLS параметры:** `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, самоподписанный ECDSA-сертификат, сгенерированный на лету (`selfsign.GenerateSelfSigned`), Extended Master Secret обязателен, Connection ID (CID) 8 байт.
- **Полезная нагрузка:** В режиме WireGuard сырые UDP-пакеты WireGuard передаются непосредственно как DTLS Application Data без дополнительной инкапсуляции.

#### Получение TURN-учётных данных (VK API цепочка)
1. **Токен 1 (Анонимный доступ):** POST `https://login.vk.ru/?act=get_anonym_token`
   - Параметры: `client_id`, `client_secret`, `token_type=messages`, `version=1`, `app_id`.
   - Ответ: JSON с `data.access_token` (`token1`).
2. **Предпросмотр звонка:** POST `https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id=...`
   - Параметры: `vk_join_link=https://vk.com/call/join/<hash>`, `access_token=token1`.
3. **Токен 2 (Анонимный токен звонка):** POST `https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=...`
   - Параметры: `vk_join_link`, `name` (псевдослучайное имя), `access_token=token1`.
   - Ответ: `response.token` (`token2`) либо объект ошибки капчи `error`.
4. **Токен 3 (Сессионный ключ OK CDN):** POST `https://calls.okcdn.ru/fb.do`
   - Параметры: `method=auth.anonymLogin`, `session_data={"version":2,"device_id":"<uuid>","client_version":1.1,"client_type":"SDK_JS"}`, `application_key=CGMMEJLGDIHBABABA`.
   - Ответ: `session_key` (`token3`).
5. **Токен 4 (TURN сервер):** POST `https://calls.okcdn.ru/fb.do`
   - Параметры: `method=vchat.joinConversationByLink`, `joinLink=<hash>`, `anonymToken=token2`, `session_key=token3`, `isVideo=false`, `protocolVersion=5`, `capabilities=2F7F`.
   - Ответ: JSON с объектом `turn_server`:
     - `username`: строка авторизации TURN (например, `<call_id>:<user_id>`).
     - `credential`: пароль TURN.
     - `urls`: список адресов вида `turns:turn-msk-xxx.okcdn.ru:443?transport=tcp` или UDP.

#### Потоки и балансировка (Bottlenecks)
- Все N параллельных DTLS-воркеров конкурируют за один канал Go `inboundChan := make(chan *UDPPacket, 2000)`.
- **Критический дефект:** Пакеты WireGuard читаются из локального UDP-сокета и сбрасываются в общий канал. Воркеры разбирают их в произвольном порядке планировщика Go. Это приводит к **катастрофическому переупорядочиванию пакетов (out-of-order delivery)**. В результате TCP внутри WireGuard страдает от лавины Duplicate ACK, сброса окна перегрузки (congestion window collapse) и резкого падения скорости.
- На стороне сервера: каждый DTLS-коннект выполняет отдельный `net.Dial("udp", wgPort)`. WireGuard видит каждый DTLS-поток как отдельный эфемерный порт, обновляя roaming endpoint по последнему пришедшему пакету. Возвратный трафик уходит только в один DTLS-поток!

#### Обработка капчи
- Автоматическая: парсинг Proof-of-Work (PoW) и попытка решения слайдер-капчи по градиентам изображения.
- Ручная (`manual_captcha`): запуск локального HTTP reverse-proxy на `127.0.0.1:8765`, открытие системного браузера на перехваченном URL капчи, перехват результирующего `success_token`.

---

### 2.2 `luminescq/PWDTT` (Go + Wails)

#### Что реализовано
- Кроссплатформенный клиент для Windows, Linux и macOS на базе фреймворка Wails v2 (Go бэкенд + веб-интерфейс на React / Vite).
- Формат ссылок: поддержка устаревшего `wdtt://` и нового `qwdtt://config?...`.
- Дополнительный уровень обфускации трафика: **RTP-obfs (ChaCha20-Poly1305)** поверх DTLS.
- Автоматический запрос конфигурации WireGuard с сервера (`GETCONF`).

#### Формат ссылок (URL)
1. **Legacy `wdtt://`:**
   `wdtt://<IP>:<DTLS_PORT>:<WG_PORT>:<PROXY_PORT>:<PASSWORD>[:<HASH1>,<HASH2>,...][#<NAME>]`
   - Пример: `wdtt://198.51.100.1:56000:56001:0:SecretPass:hash1,hash2#HomeServer`
2. **Modern `qwdtt://config?`:**
   `qwdtt://config?peer=<IP>:<PORT>&pass=<PASSWORD>&hashes=<H1>,<H2>&workers=<N>&port=<LOCAL_PORT>&name=<NAME>`
   - Диапазон workers: 9–108 (до 4 хешей по 27 воркеров).

#### RTP-obfs и криптография
- Пакеты WireGuard маскируются под RTP v2 медиапоток (RFC 3550).
- **Заголовок RTP (12 байт):**
  - Байт 0: `0x80 | 0x20` (V=2, P=1 — флаг наличия padding).
  - Байт 1: `PayloadType` (111 — Opus audio, 96 — video).
  - Байты 2–3: `Sequence Number` (uint16, big-endian).
  - Байты 4–7: `Timestamp` (uint32, big-endian, инкремент 960 на пакет в аудио).
  - Байты 8–11: `SSRC` (uint32, псевдослучайный идентификатор источника).
- **Шифрование полезной нагрузки:** ChaCha20-Poly1305 (IETF, 12-байтный nonce).
  - Вывод ключа: HKDF-SHA256:
    - Secret: пароль сервера (`password`).
    - Salt: `b"WDTT-WRAP-v1"`.
    - Info: `b"rtp-obfs/chacha20poly1305"`.
    - Key Length: 32 байта.
  - Nonce (12 байт): `SSRC (4 байта) || seq (2 байта) || 0x00 0x00 (2 байта) || Timestamp (4 байта)`.
  - AAD: первые 12 байт RTP-заголовка.
  - Padding: в конец пакета дописывается случайный паддинг (1–24 байта для аудио, 1–60 байт для видео), последний байт содержит общую длину паддинга `padTotal`.

#### Управление WireGuard и права доступа (Узкие места)
- **Linux:** выполняет внешние команды `sudo -n ip route ...` и `sudo -n ip link ...`. Для работы требует запуска скрипта `install-sudoers.sh`, прописывающего NOPASSWD в `/etc/sudoers.d/pwdtt`. Это создаёт серьёзный риск безопасности.
- **Windows:** динамически распаковывает `wintun.dll` во временный каталог, настраивает интерфейс через netsh/route.
- **Потребление ресурсов:** фреймворк Wails запускает полноценный WebView2 / WebKit. В результате процесс GUI потребляет **180–260 МБ RSS** в простое при открытом окне.

---

### 2.3 `amurcanov/csqtt` (Android + Rust, PolyForm NC)

> [!WARNING]
> Лицензия `csqtt` — PolyForm Noncommercial 1.0.0. Исходный код **запрещено** копировать или адаптировать. Анализ проводится исключительно в режиме изучения архитектурных решений (clean-room).

#### Архитектурные особенности
- Разделение на `rust-client` (статическая библиотека под Android через JNI), `rust-server` и `shared`.
- Полный отказ от Go: реализация DTLS 1.2 на Rust поверх криптографической библиотеки `aws-lc-rs` (AWS libcrypto).
- Встроенная реализация DTLS-SRTP расширения (`EXT_USE_SRTP = 14`, профили `SRTP_AEAD_AES_128_GCM`, `SRTP_AEAD_AES_256_GCM`).
- **Собственная фрагментация пакетов:**
  - Заголовок фрагмента 8 байт: Magic `0xCF`, `frag_idx` (u8), `total_frags` (u8), `reserved` (u8), `packet_id` (u16 be), `total_len` (u16 be).
  - Сборщик фрагментов на сервере и клиенте: 512 слотов (`REASSEMBLER_SLOTS`), кольцевой буфер с таймаутом устаревания 300 мс.
- **Взаимодействие с Android:**
  - `TunVpnService` получает дескриптор виртуального интерфейса `vpnInterface.fd`.
  - Передача fd в Rust осуществлялась через локальный абстрактный Unix Domain Socket (`FdReceiver` с `recvmsg` и `SCM_RIGHTS`).
  - Постоянный WakeLock на 24 часа (`PARTIAL_WAKE_LOCK`) и `WifiLock` (`WIFI_MODE_FULL_HIGH_PERF`).

---

### 2.4 `SpaceNeuroX/proxy-turn-vk-android` (qWDTT) и `Ivan4537/WDTT-Plus`

#### Особенности форков
- **Агрегация до 4 ссылок VK Calls:** клиент разбивает общий пул воркеров по хешам (например, 4 хеша по 18 воркеров = 72 потока).
- **Режим Direct / Raw-IP:** передача IP-пакетов без WireGuard (RTP-obfs инкапсулирует голые IP-пакеты напрямую в TUN-интерфейс сервера `wdttraw0` с NAT).
- **Серверная база данных:** учет клиентских устройств (`ClientDevice`), привязка паролей к `deviceID`, отслеживание активных соединений, встроенный Telegram-бот управления.
- **Проблемы производительности:**
  - Replay-окно реализовано через Go `map[[12]byte]uint64` с `sync.Mutex` на каждое соединение (`wrapPacketConn`). Аллокация ключа мапы и лок на каждый пакет вызывают высокий расход CPU и задержки.
  - Раздувание пула горутин: при 72–108 воркерах контекстные переключения и contention на семафорах приводят к высокому джиттеру.

---

### 2.5 `anton48/vk-turn-proxy-ios`

#### Ключевой инсайт: Anti-Replay окно WireGuard
В репозитории `vk-turn-proxy-ios` (в инструменте `tools/turn_srtp_server`) обнаружено строгое описание проблемы рассинхронизации пакетов:
- В ядре WireGuard для каждой Security Association действует **одно** скользящее окно защиты от повторов (anti-replay window, RFC 6479) размером 8128 пакетов (`127 * 64`).
- Если один сеанс WireGuard полосатится (striping) по N независимым путям TURN без сохранения попоточного порядка, пакеты по более медленным путям отстают от счетчика быстрых путей.
- Если отставание превышает 8128 пакетов, WireGuard **молча отбрасывает пакеты на стороне приёма** (silent packet discard), что невозможно зафиксировать обычным дампом pcap на входе.
- **Вывод для wdtt-rs:** Случайный round-robin или гонка воркеров за пакетами недопустимы. Необходим **Flow Hashing** (хеширование 5-tuple внутреннего IP-пакета), гарантирующий, что все пакеты одного TCP-соединения идут строго по одному DTLS-потоку.

---

## 3. Сводная матрица накладных расходов и MTU

В следующей таблице рассчитаны накладные расходы протокольных заголовков при различных режимах передачи:

| Уровень / Заголовок | Размер (байт) | Примечание |
|---|---|---|
| Внутренний IP-пакет (WireGuard payload) | $MTU_{inner}$ | Целевой MTU туннеля (TCP MSS = $MTU_{inner} - 40$) |
| WireGuard Data Header | 32 | Type (4) + Receiver Index (4) + Counter (8) + Poly1305 Tag (16) |
| RTP Header | 12 | V=2, P=1, PT, Seq, Timestamp, SSRC |
| AEAD Tag (RTP-obfs) | 16 | Poly1305 или AES-GCM tag |
| Random Padding | 1..24 (audio) / 1..60 (video) | Выравнивание длины, защита от анализа длин |
| DTLS 1.2 Record Header | 13 | ContentType (1) + Version (2) + Epoch (2) + Seq (6) + Length (2) |
| DTLS Record IV + AEAD Tag | 16..24 | Явный nonce / auth tag DTLS |
| STUN ChannelData Header | 4 | Channel Number (2) + Length (2) |
| Внешний UDP Header | 8 | Порты, длина, контрольная сумма |
| Внешний IPv4 Header | 20 | Без опций |
| **Итого накладные расходы** | **122 .. 189 байт** | Зависит от режима padding и наличия DTLS |

### Расчёт оптимального MTU WireGuard:
При стандартном внешнем MTU сети оператора $MTU_{outer} = 1500$:
$$MTU_{inner} \le 1500 - 189 = 1311 \text{ байт}$$
Однако в сотовых сетях (LTE/5G) и IPv6-туннелях внешний MTU часто составляет **1280 байт** (минимальный IPv6 MTU).
Если $MTU_{outer} = 1280$:
$$MTU_{inner} \le 1280 - 189 = 1091 \text{ байт}$$
Если установить MTU WireGuard в 1280 (как в существующих проектах), на сотовых сетях гарантированно возникнет IP-фрагментация внешних UDP-пакетов, которые часто отбрасываются ТСПУ/DPI операторов.

> [!IMPORTANT]
> В `wdtt-rs` MTU внутреннего интерфейса должен динамически согласовываться или настраиваться по умолчанию в **1200 байт** (для стандартного Ethernet) и **1120 байт** (для сетей со строгим MTU 1280).

---

## 4. Выявленные критические дефекты существующих систем

1. **Недетерминированный порядок пакетов (Packet Reordering):**
   Все исследованные клиенты распределяют пакеты WireGuard между воркерами через неблокирующее чтение из одного общего канала Go (`chan *UDPPacket`). Из-за разницы сетевых задержек в потоках пакеты приходят на сервер вперемешку, ломая работу TCP congestion control и вызывая отбрасывание пакетов replay-окном WireGuard.
2. **Аллокации памяти в горячем пути:**
   В Go-версиях на каждый входящий и исходящий пакет выделяются буферы `make([]byte, 1600)`, замыкания и дескрипторы каналов. В `qwdtt` проверка replay-окна использует `map[[12]byte]uint64` с аллокацией нод под мьютексом.
3. **Отсутствие безопасного системного демона на ПК:**
   `PWDTT` требует `sudo` без пароля для утилит `ip` и `wg`, что небезопасно и не работает в корпоративных или защищённых ОС.
4. **Неэффективный GUI на ПК:**
   Использование Wails/WebView2 даёт оверхед по памяти более 200 МБ RSS для статического интерфейса со статусом подключения.
5. **Агрессивный разряд батареи на Android:**
   `proxy-turn-vk-android` и `csqtt` удерживают непрерывный 24-часовой `PARTIAL_WAKE_LOCK` и `WIFI_MODE_FULL_HIGH_PERF`, игнорируя механизмы энергосбережения Android Doze Mode.
6. **Двойной цикл VPN на Android:**
   Запуск отдельного GoBackend для WireGuard и локального прокси на `127.0.0.1:9000` создаёт лишние пересылки через ядро и контекстные переключения на каждый пакет.
