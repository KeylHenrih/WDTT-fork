use crate::error::CryptoError;
use crate::key::KnockKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Length of Pre-Auth Knock authentication tag in bytes.
pub const KNOCK_TAG_LEN: usize = 16;

/// Default maximum allowable clock skew between client and server for knock tokens (60 seconds).
pub const DEFAULT_MAX_CLOCK_SKEW_SEC: u64 = 60;

/// Pre-Auth Knock token generator and verifier.
pub struct KnockAuthenticator {
    key: KnockKey,
    max_skew_sec: u64,
}

impl KnockAuthenticator {
    /// Construct a new knock authenticator with given key and skew tolerance.
    pub fn new(key: KnockKey, max_skew_sec: u64) -> Self {
        Self { key, max_skew_sec }
    }

    /// Generate 16-byte knock authentication tag for handshake initiation.
    pub fn generate_tag(&self, timestamp_sec: u64, nonce: &[u8; 16]) -> [u8; KNOCK_TAG_LEN] {
        let mut mac =
            HmacSha256::new_from_slice(self.key.as_bytes()).expect("HMAC can take key of any size");

        mac.update(b"WDTT-v2-KNOCK-V1");
        mac.update(&timestamp_sec.to_be_bytes());
        mac.update(nonce);

        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; KNOCK_TAG_LEN];
        tag.copy_from_slice(&result[..KNOCK_TAG_LEN]);
        tag
    }

    /// Verify a knock authentication tag against timestamp and nonce in constant time.
    pub fn verify_tag(
        &self,
        current_time_sec: u64,
        timestamp_sec: u64,
        nonce: &[u8; 16],
        tag: &[u8; KNOCK_TAG_LEN],
    ) -> Result<(), CryptoError> {
        let skew = current_time_sec.abs_diff(timestamp_sec);
        if skew > self.max_skew_sec {
            return Err(CryptoError::KnockTimestampExpired {
                skew_ms: skew * 1000,
                max_skew_ms: self.max_skew_sec * 1000,
            });
        }

        let expected = self.generate_tag(timestamp_sec, nonce);
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidKnockToken)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_knock_generate_and_verify_success() {
        let key = KnockKey::from_bytes([0x55; 32]);
        let auth = KnockAuthenticator::new(key, 60);

        let now = 1_700_000_000u64;
        let nonce = [7u8; 16];

        let tag = auth.generate_tag(now, &nonce);
        assert!(auth.verify_tag(now, now, &nonce, &tag).is_ok());
        assert!(auth.verify_tag(now + 30, now, &nonce, &tag).is_ok());
    }

    #[test]
    fn test_knock_expired_timestamp() {
        let key = KnockKey::from_bytes([0x55; 32]);
        let auth = KnockAuthenticator::new(key, 60);

        let now = 1_700_000_000u64;
        let nonce = [7u8; 16];
        let tag = auth.generate_tag(now, &nonce);

        // Skew is 65 seconds (> 60s)
        let res = auth.verify_tag(now + 65, now, &nonce, &tag);
        assert!(matches!(
            res,
            Err(CryptoError::KnockTimestampExpired { .. })
        ));
    }

    #[test]
    fn test_knock_tampered_tag() {
        let key = KnockKey::from_bytes([0x55; 32]);
        let auth = KnockAuthenticator::new(key, 60);

        let now = 1_700_000_000u64;
        let nonce = [7u8; 16];
        let mut tag = auth.generate_tag(now, &nonce);
        tag[0] ^= 0xFF;

        assert_eq!(
            auth.verify_tag(now, now, &nonce, &tag),
            Err(CryptoError::InvalidKnockToken)
        );
    }
}
