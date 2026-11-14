use crate::error::CryptoError;
use crate::key::{AeadKey, KnockKey, Psk, SessionKeys};
use hkdf::Hkdf;
use sha2::Sha256;

const SALT_SESSION_PREFIX: &[u8] = b"WDTT-v2-SESSION-SALT-2026";
const INFO_CLIENT_KEY: &[u8] = b"wdtt2 client write key";
const INFO_SERVER_KEY: &[u8] = b"wdtt2 server write key";
const INFO_KNOCK_KEY: &[u8] = b"wdtt2 pre-auth knock key";

/// Derive session keys from Pre-Shared Key (PSK) and exchanged session nonces.
pub fn derive_session_keys(
    psk: &Psk,
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
) -> Result<SessionKeys, CryptoError> {
    // Salt is constructed by combining fixed domain prefix with both random nonces.
    let mut salt = Vec::with_capacity(SALT_SESSION_PREFIX.len() + 32);
    salt.extend_from_slice(SALT_SESSION_PREFIX);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), psk.as_bytes());

    let mut client_key_bytes = [0u8; 32];
    hk.expand(INFO_CLIENT_KEY, &mut client_key_bytes)
        .map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        })?;

    let mut server_key_bytes = [0u8; 32];
    hk.expand(INFO_SERVER_KEY, &mut server_key_bytes)
        .map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        })?;

    let mut knock_key_bytes = [0u8; 32];
    hk.expand(INFO_KNOCK_KEY, &mut knock_key_bytes)
        .map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        })?;

    Ok(SessionKeys {
        client_write_key: AeadKey::from_bytes(client_key_bytes),
        server_write_key: AeadKey::from_bytes(server_key_bytes),
        knock_key: KnockKey::from_bytes(knock_key_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_derivation_deterministic() {
        let psk = Psk::from_bytes([0x42; 32]);
        let c_nonce = [1u8; 16];
        let s_nonce = [2u8; 16];

        let keys1 = derive_session_keys(&psk, &c_nonce, &s_nonce).unwrap();
        let keys2 = derive_session_keys(&psk, &c_nonce, &s_nonce).unwrap();

        assert_eq!(
            keys1.client_write_key.as_bytes(),
            keys2.client_write_key.as_bytes()
        );
        assert_eq!(
            keys1.server_write_key.as_bytes(),
            keys2.server_write_key.as_bytes()
        );
        assert_eq!(keys1.knock_key.as_bytes(), keys2.knock_key.as_bytes());

        // Client and server keys must be cryptographically distinct
        assert_ne!(
            keys1.client_write_key.as_bytes(),
            keys1.server_write_key.as_bytes()
        );
    }

    #[test]
    fn test_kdf_different_nonces_yield_different_keys() {
        let psk = Psk::from_bytes([0x42; 32]);
        let c_nonce1 = [1u8; 16];
        let c_nonce2 = [3u8; 16];
        let s_nonce = [2u8; 16];

        let keys1 = derive_session_keys(&psk, &c_nonce1, &s_nonce).unwrap();
        let keys2 = derive_session_keys(&psk, &c_nonce2, &s_nonce).unwrap();

        assert_ne!(
            keys1.client_write_key.as_bytes(),
            keys2.client_write_key.as_bytes()
        );
    }
}
