# wdtt-crypto

Cryptographic primitives for the WDTT v2 tunnel ecosystem.

## Features
- **AEAD Engines**: ChaCha20-Poly1305 and AES-128-GCM with hardware AES-NI detection and zero-copy in-place operations.
- **Key Derivation**: HKDF-SHA256 for session keys (`client_key`, `server_key`, `knock_key`) with domain separation salts.
- **Pre-Auth Knock**: Cryptographic token authentication for DTLS / silent discard protection against DPI active probing.
- **Anti-Replay Window**: RFC 6479 constant-time 2048-bit sliding bitmap with zero runtime heap allocations.
- **Zeroize**: Constant-time wiping of all sensitive key material on drop.
