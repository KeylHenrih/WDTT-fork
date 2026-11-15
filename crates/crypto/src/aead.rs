use crate::error::CryptoError;
use crate::key::AeadKey;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use bytes::BytesMut;
use chacha20poly1305::ChaCha20Poly1305;

/// Supported AEAD cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305 (RFC 8439, 256-bit key, 96-bit nonce, 128-bit tag).
    #[default]
    ChaCha20Poly1305,
    /// AES-128-GCM (NIST SP 800-38D, 128-bit key, 96-bit nonce, 128-bit tag).
    Aes128Gcm,
}

/// Standard 96-bit (12-byte) AEAD Nonce.
pub const NONCE_LEN: usize = 12;

/// Standard 128-bit (16-byte) AEAD Authentication Tag.
pub const TAG_LEN: usize = 16;

/// Construct a 12-byte AEAD nonce from stream ID and monotonic packet counter.
#[inline]
pub fn make_nonce(stream_id: u8, counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0] = 0;
    nonce[1] = 0;
    nonce[2] = 0;
    nonce[3] = stream_id;
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Unified AEAD Encryptor/Decryptor.
pub struct AeadEngine {
    suite: CipherSuite,
}

impl AeadEngine {
    pub const fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// Encrypt plaintext in place within `buffer` and append 16-byte authentication tag.
    pub fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        buffer: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let n = GenericArray::from_slice(nonce);
        let tag = match self.suite {
            CipherSuite::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
                cipher
                    .encrypt_in_place_detached(n, ad, buffer)
                    .map_err(|_| CryptoError::EncryptionError)?
            }
            CipherSuite::Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&key.as_bytes()[..16]));
                cipher
                    .encrypt_in_place_detached(n, ad, buffer)
                    .map_err(|_| CryptoError::EncryptionError)?
            }
        };

        buffer.extend_from_slice(tag.as_slice());
        Ok(())
    }

    /// Decrypt ciphertext in place and authenticate against tag.
    ///
    /// `buffer` must contain `[ciphertext... | 16-byte tag]`.
    /// Returns slice to decrypted plaintext on success.
    pub fn decrypt<'a>(
        &self,
        key: &AeadKey,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        if buffer.len() < TAG_LEN {
            return Err(CryptoError::DecryptionError);
        }
        let split_pos = buffer.len() - TAG_LEN;
        let (payload, tag_slice) = buffer.split_at_mut(split_pos);
        let n = GenericArray::from_slice(nonce);
        let tag = GenericArray::from_slice(tag_slice);

        match self.suite {
            CipherSuite::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
                cipher
                    .decrypt_in_place_detached(n, ad, payload, tag)
                    .map_err(|_| CryptoError::DecryptionError)?;
                Ok(payload)
            }
            CipherSuite::Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&key.as_bytes()[..16]));
                cipher
                    .decrypt_in_place_detached(n, ad, payload, tag)
                    .map_err(|_| CryptoError::DecryptionError)?;
                Ok(payload)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_roundtrip() {
        let engine = AeadEngine::new(CipherSuite::ChaCha20Poly1305);
        let key = AeadKey::from_bytes([7u8; 32]);
        let nonce = make_nonce(1, 100);
        let ad = b"additional-data-header";
        let plaintext = b"Confidential tunnel packet payload";

        let mut buf = BytesMut::from(&plaintext[..]);
        engine.encrypt(&key, &nonce, ad, &mut buf).unwrap();

        assert_eq!(buf.len(), plaintext.len() + TAG_LEN);

        let decrypted = engine.decrypt(&key, &nonce, ad, &mut buf).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_gcm_roundtrip() {
        let engine = AeadEngine::new(CipherSuite::Aes128Gcm);
        let key = AeadKey::from_bytes([9u8; 32]);
        let nonce = make_nonce(2, 200);
        let ad = b"header-ad";
        let plaintext = b"AES-GCM accelerated payload";

        let mut buf = BytesMut::from(&plaintext[..]);
        engine.encrypt(&key, &nonce, ad, &mut buf).unwrap();

        assert_eq!(buf.len(), plaintext.len() + TAG_LEN);

        let decrypted = engine.decrypt(&key, &nonce, ad, &mut buf).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let engine = AeadEngine::new(CipherSuite::ChaCha20Poly1305);
        let key = AeadKey::from_bytes([7u8; 32]);
        let nonce = make_nonce(1, 100);
        let ad = b"header";
        let plaintext = b"secret payload";

        let mut buf = BytesMut::from(&plaintext[..]);
        engine.encrypt(&key, &nonce, ad, &mut buf).unwrap();

        // Tamper 1 bit
        buf[0] ^= 0x01;

        assert_eq!(
            engine.decrypt(&key, &nonce, ad, &mut buf),
            Err(CryptoError::DecryptionError)
        );
    }

    #[test]
    fn test_tampered_ad_fails() {
        let engine = AeadEngine::new(CipherSuite::ChaCha20Poly1305);
        let key = AeadKey::from_bytes([7u8; 32]);
        let nonce = make_nonce(1, 100);
        let plaintext = b"secret payload";

        let mut buf = BytesMut::from(&plaintext[..]);
        engine
            .encrypt(&key, &nonce, b"original-ad", &mut buf)
            .unwrap();

        assert_eq!(
            engine.decrypt(&key, &nonce, b"altered-ad", &mut buf),
            Err(CryptoError::DecryptionError)
        );
    }
}
