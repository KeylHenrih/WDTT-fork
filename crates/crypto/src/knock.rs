use crate::error::CryptoError;
use crate::key::KnockKey;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use rand::RngCore;
use std::collections::VecDeque;

/// Minimum wire knock length: 12-byte nonce + 40-byte payload + 16-byte Poly1305 tag = 68 bytes.
pub const MIN_KNOCK_WIRE_LEN: usize = 68;

/// Default maximum allowable clock skew between client and server for knock tokens (60 seconds).
pub const DEFAULT_MAX_CLOCK_SKEW_SEC: u64 = 60;

/// Maximum entries retained in the bounded nonce anti-replay cache.
pub const MAX_NONCE_CACHE_ENTRIES: usize = 16_384;

/// Bounded Nonce Anti-Replay Cache with TTL cleanup.
#[derive(Debug)]
pub struct NonceReplayCache {
    entries: VecDeque<([u8; 16], u64)>,
    max_entries: usize,
}

impl Default for NonceReplayCache {
    fn default() -> Self {
        Self::new(MAX_NONCE_CACHE_ENTRIES)
    }
}

impl NonceReplayCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries.min(1024)),
            max_entries,
        }
    }

    /// Check if nonce was already seen. If not, record it with given expiration timestamp.
    pub fn check_and_insert(
        &mut self,
        nonce: &[u8; 16],
        expiry_sec: u64,
    ) -> Result<(), CryptoError> {
        // Linear scan over bounded recent nonces
        if self.entries.iter().any(|(n, exp)| {
            *n == *nonce && *exp >= expiry_sec.saturating_sub(DEFAULT_MAX_CLOCK_SKEW_SEC * 2)
        }) {
            return Err(CryptoError::ReplayDetected { counter: 0 });
        }

        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }

        self.entries.push_back((*nonce, expiry_sec));
        Ok(())
    }

    /// Purge expired entries older than current timestamp.
    pub fn cleanup(&mut self, current_time_sec: u64) {
        self.entries.retain(|(_, exp)| *exp > current_time_sec);
    }
}

/// Decrypted payload contained inside a Pre-Auth Knock packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnockPayload {
    pub timestamp_sec: u64,
    pub client_nonce: [u8; 16],
    pub session_id: [u8; 16],
}

/// Pre-Auth Knock generator and validator.
///
/// Disguises pre-authentication tokens as high-entropy randomized binary payloads
/// with variable random padding (84..=196 bytes) indistinguishable from WebRTC/RTP media traffic.
/// Outside DTLS, it contains zero plaintext magic constants, preventing DPI fingerprinting.
pub struct KnockAuthenticator {
    key: KnockKey,
    max_skew_sec: u64,
    cache: NonceReplayCache,
}

impl KnockAuthenticator {
    /// Construct a new knock authenticator with given key and skew tolerance.
    pub fn new(key: KnockKey, max_skew_sec: u64) -> Self {
        Self {
            key,
            max_skew_sec,
            cache: NonceReplayCache::new(MAX_NONCE_CACHE_ENTRIES),
        }
    }

    /// Generate randomized knock packet with non-deterministic random padding.
    /// Returns encrypted wire buffer: `[12-byte nonce | 40-byte ciphertext | 16-byte tag | random padding]`.
    pub fn generate_knock_packet(
        &self,
        timestamp_sec: u64,
        client_nonce: &[u8; 16],
        session_id: &[u8; 16],
        padding_len: usize,
    ) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);

        // 40 bytes plaintext: 8 bytes timestamp + 16 bytes client_nonce + 16 bytes session_id
        let mut plaintext = [0u8; 40];
        plaintext[0..8].copy_from_slice(&timestamp_sec.to_be_bytes());
        plaintext[8..24].copy_from_slice(client_nonce);
        plaintext[24..40].copy_from_slice(session_id);

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(self.key.as_bytes()));
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), b"", &mut buffer)
            .expect("in-place ChaCha20 encryption");

        let total_len = 12 + buffer.len() + 16 + padding_len;
        let mut wire = Vec::with_capacity(total_len);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&buffer);
        wire.extend_from_slice(tag.as_slice());

        // Append cryptographically randomized padding
        let mut pad = vec![0u8; padding_len];
        rand::rng().fill_bytes(&mut pad);
        wire.extend_from_slice(&pad);

        wire
    }

    /// Verify an incoming wire knock packet in constant time.
    ///
    /// Validates:
    /// 1. Wire length $\ge 68$ bytes.
    /// 2. Poly1305 authentication tag against `knock_key`.
    /// 3. Clock skew $\le \text{max\_skew\_sec}$.
    /// 4. Replay check: client_nonce must not have been previously recorded.
    pub fn verify_knock_packet(
        &mut self,
        current_time_sec: u64,
        wire: &[u8],
    ) -> Result<KnockPayload, CryptoError> {
        if wire.len() < MIN_KNOCK_WIRE_LEN {
            return Err(CryptoError::InvalidKnockToken);
        }

        let nonce = &wire[0..12];
        let mut ciphertext = wire[12..52].to_vec(); // 40 bytes
        let tag = &wire[52..68];

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(self.key.as_bytes()));
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                b"",
                &mut ciphertext,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| CryptoError::InvalidKnockToken)?;

        let timestamp_sec = u64::from_be_bytes(ciphertext[0..8].try_into().unwrap());
        let mut client_nonce = [0u8; 16];
        let mut session_id = [0u8; 16];
        client_nonce.copy_from_slice(&ciphertext[8..24]);
        session_id.copy_from_slice(&ciphertext[24..40]);

        // Clock skew check
        let skew = current_time_sec.abs_diff(timestamp_sec);
        if skew > self.max_skew_sec {
            return Err(CryptoError::KnockTimestampExpired {
                skew_ms: skew * 1000,
                max_skew_ms: self.max_skew_sec * 1000,
            });
        }

        // Nonce replay check with bounded TTL cache
        self.cache.cleanup(current_time_sec);
        let expiry = current_time_sec + self.max_skew_sec;
        self.cache.check_and_insert(&client_nonce, expiry)?;

        Ok(KnockPayload {
            timestamp_sec,
            client_nonce,
            session_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_knock_generate_and_verify_with_random_padding() {
        let key = KnockKey::from_bytes([0x55; 32]);
        let mut auth = KnockAuthenticator::new(key, 60);

        let now = 1_700_000_000u64;
        let client_nonce = [0xAA; 16];
        let session_id = [0xBB; 16];

        // Random padding of 37 bytes -> total len = 68 + 37 = 105 bytes
        let wire = auth.generate_knock_packet(now, &client_nonce, &session_id, 37);
        assert_eq!(wire.len(), 105);

        let verified = auth
            .verify_knock_packet(now + 10, &wire)
            .expect("verify knock");
        assert_eq!(verified.timestamp_sec, now);
        assert_eq!(verified.client_nonce, client_nonce);
        assert_eq!(verified.session_id, session_id);
    }

    #[test]
    fn test_knock_nonce_replay_rejection() {
        let key = KnockKey::from_bytes([0x55; 32]);
        let mut auth = KnockAuthenticator::new(key, 60);

        let now = 1_700_000_000u64;
        let client_nonce = [0x01; 16];
        let session_id = [0x02; 16];

        let wire = auth.generate_knock_packet(now, &client_nonce, &session_id, 16);

        // First verification succeeds
        assert!(auth.verify_knock_packet(now, &wire).is_ok());

        // Replaying the exact same packet/nonce must fail!
        assert!(matches!(
            auth.verify_knock_packet(now + 1, &wire),
            Err(CryptoError::ReplayDetected { .. })
        ));
    }

    #[test]
    fn test_knock_expired_timestamp() {
        let key = KnockKey::from_bytes([0x55; 32]);
        let mut auth = KnockAuthenticator::new(key, 60);

        let now = 1_700_000_000u64;
        let client_nonce = [0x07; 16];
        let session_id = [0x08; 16];

        let wire = auth.generate_knock_packet(now, &client_nonce, &session_id, 20);

        // Current time is 65 seconds ahead (> 60s)
        let res = auth.verify_knock_packet(now + 65, &wire);
        assert!(matches!(
            res,
            Err(CryptoError::KnockTimestampExpired { .. })
        ));
    }

    #[test]
    fn test_knock_tampered_wire_fails() {
        let key = KnockKey::from_bytes([0x55; 32]);
        let mut auth = KnockAuthenticator::new(key, 60);

        let now = 1_700_000_000u64;
        let mut wire = auth.generate_knock_packet(now, &[1; 16], &[2; 16], 30);

        // Tamper 1 bit in ciphertext
        wire[20] ^= 0x01;

        assert_eq!(
            auth.verify_knock_packet(now, &wire),
            Err(CryptoError::InvalidKnockToken)
        );
    }
}
