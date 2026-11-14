# Contributing to WDTT Ecosystem (`wdtt-rs`)

Thank you for your interest in contributing to `wdtt-rs`! This document sets out the guidelines for contributing to ensure quality, security, and clean licensing.

---

## 1. Licensing and Clean Implementation Requirements

- **License:** All contributions to this repository must be licensed under the **GNU General Public License v3.0 (GPL-3.0-only)**.
- **Strict Prohibition of Non-GPL / Non-Commercial Code:**
  Under no circumstances may code, algorithms, or copy-paste fragments be taken from projects licensed under proprietary, non-commercial, or incompatible terms (such as `CSQTT` / PolyForm Noncommercial). All implementations must be independent clean contributions written according to the open protocol specification in [docs/PROTOCOL.md](docs/PROTOCOL.md).
- **Attribution:** When adapting ideas or references from other open-source projects, always provide accurate attribution in code comments and documentation.

---

## 2. Code Quality and Rust Standards

All Rust code in this repository must adhere to the following standards:
- **Rust Edition:** Rust 2024.
- **Safety:** Strive for `#![forbid(unsafe_code)]` wherever possible. Any use of `unsafe` (e.g. platform FFI for vector I/O) must be strictly localized, justified, and annotated with a comprehensive `// SAFETY:` invariant comment.
- **Documentation:** All public types, functions, and traits must have doc-comments (`#![deny(missing_docs)]`).
- **Formatting:** Code must pass `cargo fmt --check`.
- **Linting:** Code must pass `cargo clippy --all-targets -- -D warnings`.
- **Testing:**
  - Unit tests for all business logic and edge cases.
  - Property-based tests (`proptest`) for parsing, framing, and state machines.
  - Integration tests for protocol exchanges.

---

## 3. Pull Request Workflow

1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/my-improvement
   ```
2. Verify local checks before pushing:
   ```bash
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test --workspace
   ```
3. Ensure no credentials, tokens, local IP addresses, or secrets are present:
   ```bash
   gitleaks protect --staged -v
   ```
4. Open a Pull Request on GitHub against `main`. Describe what your PR changes, why, and include benchmark or test results if applicable.
