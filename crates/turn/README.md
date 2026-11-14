# wdtt-turn

Asynchronous STUN and TURN (RFC 5389 / RFC 5766 / RFC 6156) client implementation in pure Rust.

## Features
- **STUN Codec**: Complete parsing and encoding for STUN Binding, Allocate, CreatePermission, ChannelBind, and Refresh transactions.
- **RFC 5389 Message-Integrity**: HMAC-SHA1 authentication with MD5 long-term credential calculation (`user:realm:pass`).
- **ChannelData Framing**: High-throughput zero-copy ChannelData parsing and serialization (`0x4000..=0x7FFF`).
- **Async Client**: Non-blocking Tokio-based TURN client managing allocation lifecycle, permissions, channel binding, and background keepalive refreshing.
- **Embedded Mock Server**: Built-in test harness for end-to-end integration testing without external daemons.
- **Coturn Integration**: Docker/Podman compose configurations for validation against production Coturn relays.
