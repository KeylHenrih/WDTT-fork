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

    /// Parse a PSK from its textual form.
    ///
    /// Accepts either 64 hex characters (decoded to 32 bytes) or a raw
    /// 32-byte ASCII string, which is taken verbatim for backwards
    /// compatibility with older deployments.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let trimmed = s.trim();
        if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut key = [0u8; 32];
            for (i, chunk) in trimmed.as_bytes().as_chunks::<2>().0.iter().enumerate() {
                let hi = hex_val(chunk[0]).ok_or_else(|| {
                    CryptoError::InvalidHex(format!("non-hex character at position {}", i * 2))
                })?;
                let lo = hex_val(chunk[1]).ok_or_else(|| {
                    CryptoError::InvalidHex(format!("non-hex character at position {}", i * 2 + 1))
                })?;
                key[i] = (hi << 4) | lo;
            }
            return Ok(Self(key));
        }
        if trimmed.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(trimmed.as_bytes());
            return Ok(Self(key));
        }
        Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: trimmed.len(),
        })
    }
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_parse_hex() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let psk = Psk::parse(hex).expect("valid hex psk");
        let expected: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(psk.as_bytes(), &expected);
    }

    #[test]
    fn psk_parse_hex_uppercase() {
        let hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        let psk = Psk::parse(hex).expect("valid uppercase hex psk");
        let expected: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(psk.as_bytes(), &expected);
    }

    #[test]
    fn psk_parse_raw_ascii() {
        let raw = "0123456789abcdef0123456789abcdef";
        let psk = Psk::parse(raw).expect("raw 32-byte psk");
        assert_eq!(psk.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn psk_parse_rejects_wrong_length() {
        assert!(matches!(
            Psk::parse("deadbeef"),
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 8
            })
        ));
    }

    #[test]
    fn psk_parse_trims_whitespace() {
        let hex = "  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";
        let psk = Psk::parse(hex).expect("padded hex psk");
        let expected: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(psk.as_bytes(), &expected);
    }
}
