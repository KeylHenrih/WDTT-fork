use thiserror::Error;

/// Cryptographic errors.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CryptoError {
    #[error("AEAD encryption failure")]
    EncryptionError,

    #[error("AEAD decryption or authentication tag verification failure")]
    DecryptionError,

    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),

    #[error(
        "replay detected: packet counter {counter} has already been seen or is outside anti-replay window"
    )]
    ReplayDetected { counter: u64 },

    #[error("invalid knock authentication token: verification failed")]
    InvalidKnockToken,

    #[error("expired knock timestamp: clock skew {skew_ms}ms exceeds threshold {max_skew_ms}ms")]
    KnockTimestampExpired { skew_ms: u64, max_skew_ms: u64 },
}
