# wdtt-turn

Asynchronous STUN and TURN (RFC 5389 / RFC 5766 / RFC 6156) client implementation in pure Rust.

## Features
- **STUN Codec**: Complete parsing and encoding for STUN Binding, Allocate, CreatePermission, ChannelBind, and Refresh transactions.
- **RFC 5389 Message-Integrity**: HMAC-SHA1 authentication with MD5 long-term credential calculation (`user:realm:pass`).
- **438 Stale Nonce Recovery**: Automatic nonce rotation and request retry without session interruption.
- **Error Handling**: Comprehensive 4xx/5xx handling (`400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `437 Allocation Mismatch`, `438 Stale Nonce`, `486 Allocation Quota Reached`, `500 Server Error`).
- **ChannelData Framing**: High-throughput zero-copy ChannelData parsing and serialization (`0x4000..=0x7FFF`).
- **Async Client**: Non-blocking Tokio-based TURN client managing allocation lifecycle, permissions, channel binding, and background keepalive refreshing.
- **Embedded Mock Server**: Built-in test harness supporting end-to-end multi-client relay routing (`Client A <-> Relay <-> Client B`), 438 recovery, and error simulation without external daemons.
- **Coturn Integration**: Docker/Podman compose configurations for validation against production Coturn relays.

## Transport & Protocol Roadmap
- **UDP Transport**: Fully implemented and tested in Phase 2.
- **TCP / TLS Transports (RFC 5766 / RFC 6062)**: Framework interfaces defined; full multi-platform network socket integration is scheduled for **Phase 4** (Desktop/Mobile Client Networking & NAT Traversal).
- **IPv6 Relaying (RFC 6156)**: Dual-stack XOR-address encoding implemented; production multi-homed IPv6 routing scheduled for **Phase 4**.
