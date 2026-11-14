use crate::error::CryptoError;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit Pre-Shared Key (PSK) configured for the tunnel.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Psk([u8; 32]);

impl Psk {
    /// Construct from a 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Construct from an arbitrary slice (must be 32 bytes).
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Ok(Self(key))
    }

    /// Expose read-only reference to underlying key bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Psk([REDACTED])")
    }
}

/// 256-bit symmetric AEAD encryption key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; 32]);

impl AeadKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Ok(Self(key))
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AeadKey([REDACTED])")
    }
}

/// 256-bit key used for Pre-Auth Knock envelope generation and verification.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KnockKey([u8; 32]);

impl KnockKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time comparison between two knock tags.
    #[inline]
    pub fn verify_tag(expected: &[u8], actual: &[u8]) -> bool {
        expected.ct_eq(actual).into()
    }
}

impl std::fmt::Debug for KnockKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KnockKey([REDACTED])")
    }
}

/// Derived session keys for client and server directions.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub client_write_key: AeadKey,
    pub server_write_key: AeadKey,
    pub knock_key: KnockKey,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionKeys([REDACTED])")
    }
}
