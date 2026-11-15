# wdtt-proto

WDTT v2 protocol definitions, binary frame codecs, URL format parsers, and WireGuard resequencing engine.

## Features
- **URL Parsers**: `wdtt2://`, `qwdtt://config?`, `wdtt://connect?v=1...`, and legacy positional `wdtt://`.
- **WireGuard Inspector**: Zero-copy parser for WireGuard Handshake and Data packet headers.
- **Binary Frame Codec**: 8-byte WDTT v2 frames (`Data`, `Frag`, `HandshakeInit`, `HandshakeResp`, `Ping`, `Pong`, `StreamFeedback`, `Disconnect`).
- **Resequencer**: Monotonic WireGuard sequence counter restoration across multi-stream TURN relays with per-receiver-index tracking, configurable gap timeout, and overflow protection.
