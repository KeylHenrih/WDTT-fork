# Testing Guide: Fuzzing, Property-Based, and Integration Tests

This document describes the testing architecture for `wdtt-rs`, including continuous fuzzing with `cargo-fuzz`, property-based testing with `proptest`, and local integration tests with Coturn.

---

## 1. Fuzz Testing (`cargo-fuzz`)

Fuzz targets reside in `fuzz/` and target protocol decoders against arbitrary, malformed, or malicious inputs.

### Targets
1. **`fuzz_url`** (`fuzz/fuzz_targets/fuzz_url.rs`):
   Fuzzes URL parser against random byte sequences and malformed URI components for `wdtt2://`, `qwdtt://config?`, `wdtt://connect?v=1...`, and legacy positional formats.
2. **`fuzz_frame`** (`fuzz/fuzz_targets/fuzz_frame.rs`):
   Fuzzes WDTT v2 binary frame header parser (`FrameView::decode`) and WireGuard packet inspector (`inspect_wg_packet`).
3. **`fuzz_stun`** (`fuzz/fuzz_targets/fuzz_stun.rs`):
   Fuzzes RFC 5389 / RFC 5766 STUN message parser (`StunMessage::decode`) and RFC 5766 ChannelData framing (`decode_channel_data`).

### Prerequisites
`cargo-fuzz` requires nightly Rust for AddressSanitizer (ASan) instrumentation:
```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

### Running Fuzz Targets Locally
```bash
# Run URL fuzzing for 60 seconds
cargo +nightly fuzz run fuzz_url -- -max_total_time=60

# Run Frame fuzzing for 60 seconds
cargo +nightly fuzz run fuzz_frame -- -max_total_time=60

# Run STUN fuzzing for 60 seconds
cargo +nightly fuzz run fuzz_stun -- -max_total_time=60
```

### Fuzzing in CI
Short smoke fuzz runs (10 seconds per target) execute automatically on every push in `.github/workflows/ci.yml`.

---

## 2. Property-Based Testing (`proptest`)

Property-based tests assert invariant correctness across thousands of pseudorandom permutations:
- **Resequencer Invariant**: Ingesting random permutations of packets $0..N$ always emits packets in strictly monotonic counter order without drops.
- **Anti-Replay Window Invariant**: The RFC 6479 2048-bit sliding window never allows duplicate counters to be accepted.

Run all property tests:
```bash
cargo test --workspace
```

---

## 3. Integration Testing with Coturn

Integration tests can run against an embedded deterministic mock server or a real containerized Coturn relay.

### Running with Docker / Podman
```bash
# Start coturn container
docker compose up -d

# Run the live coturn test
cargo test -p wdtt-turn --test coturn_integration -- --nocapture

# Stop coturn container
docker compose down
```
