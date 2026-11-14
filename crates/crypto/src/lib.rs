//! Cryptographic primitives for WDTT v2.
//!
//! Provides AEAD encryption (ChaCha20-Poly1305 and AES-GCM), HKDF key derivation,
//! zeroize-backed secrets management, and constant-time RFC 6479 anti-replay window.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Length of an AEAD authentication tag in bytes.
pub const AEAD_TAG_LEN: usize = 16;

/// Length of a standard AEAD nonce in bytes.
pub const AEAD_NONCE_LEN: usize = 12;

/// Length of a derived symmetric session key in bytes.
pub const KEY_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_constants() {
        assert_eq!(AEAD_TAG_LEN, 16);
        assert_eq!(AEAD_NONCE_LEN, 12);
        assert_eq!(KEY_LEN, 32);
    }
}
