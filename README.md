# wdtt-rs

Высокопроизводительный туннель «WireGuard поверх TURN/DTLS с маскировкой под медиатрафик звонка».

Разрабатывается как независимая реализация по собственной спецификации (`docs/PROTOCOL.md`) под лицензией GPL-3.0.

## Структура проекта

```
crates/proto        # Кадры v2, парсер ссылок (wdtt://, qwdtt://, wdtt2://), без I/O
crates/crypto       # AEAD, HKDF, zeroize, RFC 6479 anti-replay окно
crates/turn         # Минимальный TURN/STUN клиент (UDP/TCP/TLS)
crates/provider     # Trait TurnCredentialProvider + vk + static/rest
crates/core         # Сессии, адаптивный пул потоков, flow-hash планировщик, статистика
crates/tun          # TUN-абстракция (Linux netlink, Windows wintun, macOS utun, Android fd)
crates/ipc          # Протокол демон <-> GUI (формат postcard)
crates/server       # Серверный бинарь
crates/daemon       # wdttd (системная служба ПК)
crates/gui-desktop  # Slint GUI
crates/ffi-android  # UniFFI + cargo-ndk
android/            # Kotlin + Jetpack Compose приложение
docs/               # Спецификации, модель угроз, ADR
```
