# Security Policy

## Reporting a Vulnerability

We take the security and integrity of `wdtt-rs` seriously. If you discover a security vulnerability, we appreciate your help in disclosing it to us responsibly.

> [!IMPORTANT]
> **Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report vulnerabilities privately using **GitHub Security Advisories**:
1. Navigate to the **Security** tab of the repository on GitHub.
2. Click on **Advisories** and then **Report a vulnerability**.
3. Provide a detailed description of the vulnerability, including steps to reproduce, affected components, and potential impact.

If GitHub Security Advisories is temporarily unavailable, please contact the maintainers privately via the repository security contact or maintainer profile.

### Response Timeline
- **Initial Response:** Within 48 hours acknowledging receipt of your report.
- **Triage and Assessment:** Within 5 business days detailing the severity and reproduction status.
- **Fix and Disclosure:** A security release will be prepared and coordinated with a CVE identifier where applicable before public disclosure.

## Scope and Threat Model

This project implements a WireGuard-over-TURN encapsulation tunnel with traffic disguise. Please review [docs/PROTOCOL.md](docs/PROTOCOL.md) for details on cryptographic guarantees:
- **Inner Data Security:** WireGuard (Noise protocol, ChaCha20-Poly1305, Curve25519) provides end-to-end encryption between client and server.
- **Outer Transport:** DTLS 1.2 or RTP-obfs encapsulates datagrams over TURN relays.
- **Probe Protection:** Pre-Auth Knock mechanism ensures unauthenticated probing datagrams are discarded without response (0 bytes).

### Out of Scope
- Denial of service attacks against external third-party TURN infrastructure.
- Local attacks requiring prior root/administrator compromise of the host OS.
- Attacks relying on modified/compromised client memory or debugger attachment.
