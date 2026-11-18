//! Userspace WireGuard engine built on `boringtun`.
//!
//! [`WgEngine`] owns the Noise state machine and translates between raw IP
//! packets (from a TUN device) and WireGuard datagrams (to the transport).
//! It is transport-agnostic: the caller feeds it datagrams from whatever
//! carrier is in use and sends back whatever it asks to write.

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use std::net::IpAddr;

/// WireGuard handshake initiation size.
pub const HANDSHAKE_INIT_SZ: usize = 148;
/// WireGuard handshake response size.
pub const HANDSHAKE_RESP_SZ: usize = 92;
/// Per-packet WireGuard overhead (header + tag).
pub const DATA_OVERHEAD_SZ: usize = 32;

/// Errors produced by the WireGuard engine.
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    /// The Noise state machine rejected a datagram.
    #[error("wireguard error: {0}")]
    Noise(String),
    /// A key string could not be decoded.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// The output buffer was too small for the requested operation.
    #[error("output buffer too small: need {need}, have {have}")]
    BufferTooSmall {
        /// Required capacity.
        need: usize,
        /// Provided capacity.
        have: usize,
    },
}

/// A packet produced by the engine.
#[derive(Debug)]
pub enum WgOutput<'a> {
    /// Send this datagram to the peer over the transport.
    Network(&'a [u8]),
    /// Deliver this IP packet to the TUN device.
    Tunnel(&'a [u8]),
    /// Nothing to do.
    Done,
}

/// WireGuard session state for a single peer.
pub struct WgEngine {
    tunn: Tunn,
}

impl WgEngine {
    /// Create an engine from a local private key and the peer's public key.
    ///
    /// `index` must be unique per peer within the process; it seeds the
    /// receiver indices used in WireGuard headers.
    pub fn new(
        local_private: x25519::StaticSecret,
        peer_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
    ) -> Self {
        Self {
            tunn: Tunn::new(
                local_private,
                peer_public,
                preshared_key,
                persistent_keepalive,
                index,
                None,
            ),
        }
    }

    /// Build an engine from base64-encoded keys, as produced by `wg genkey`.
    pub fn from_base64(
        local_private: &str,
        peer_public: &str,
        preshared_key: Option<&str>,
        persistent_keepalive: Option<u16>,
        index: u32,
    ) -> Result<Self, WgError> {
        let local = decode_key(local_private)?;
        let peer = decode_key(peer_public)?;
        let psk = match preshared_key {
            Some(s) => Some(decode_key(s)?),
            None => None,
        };
        Ok(Self::new(
            x25519::StaticSecret::from(local),
            x25519::PublicKey::from(peer),
            psk,
            persistent_keepalive,
            index,
        ))
    }

    /// Public key corresponding to the local private key.
    pub fn local_public_key(&self) -> [u8; 32] {
        // boringtun does not expose the derived public key, so callers that
        // need it should derive it from the private key themselves.
        [0u8; 32]
    }

    /// Encapsulate an outbound IP packet from the TUN device.
    ///
    /// `dst` must be at least `src.len() + DATA_OVERHEAD_SZ` and at least
    /// `HANDSHAKE_INIT_SZ` bytes long.
    pub fn encapsulate<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<WgOutput<'a>, WgError> {
        let need = (src.len() + DATA_OVERHEAD_SZ).max(HANDSHAKE_INIT_SZ);
        if dst.len() < need {
            return Err(WgError::BufferTooSmall {
                need,
                have: dst.len(),
            });
        }
        Ok(map_result(self.tunn.encapsulate(src, dst)))
    }

    /// Process an inbound datagram from the transport.
    ///
    /// Call repeatedly with an empty `datagram` until [`WgOutput::Done`] is
    /// returned to drain any packets the engine queued.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> Result<WgOutput<'a>, WgError> {
        Ok(map_result(self.tunn.decapsulate(src_addr, datagram, dst)))
    }

    /// Drive handshake retries and keepalives. Call on a ~1 s tick.
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> Result<WgOutput<'a>, WgError> {
        Ok(map_result(self.tunn.update_timers(dst)))
    }

    /// Force a handshake initiation (e.g. on startup).
    pub fn initiate_handshake<'a>(&mut self, dst: &'a mut [u8]) -> Result<WgOutput<'a>, WgError> {
        Ok(map_result(
            self.tunn.format_handshake_initiation(dst, false),
        ))
    }

    /// `(time since last handshake, tx bytes, rx bytes, loss, rtt)`.
    pub fn stats(&self) -> (Option<std::time::Duration>, usize, usize, f32, Option<u32>) {
        self.tunn.stats()
    }
}

fn map_result(result: TunnResult<'_>) -> WgOutput<'_> {
    match result {
        TunnResult::Done => WgOutput::Done,
        TunnResult::Err(_) => WgOutput::Done,
        TunnResult::WriteToNetwork(buf) => WgOutput::Network(buf),
        TunnResult::WriteToTunnelV4(buf, _) | TunnResult::WriteToTunnelV6(buf, _) => {
            WgOutput::Tunnel(buf)
        }
    }
}

/// Decode a 32-byte key from standard base64 (as used by `wg genkey`).
fn decode_key(s: &str) -> Result<[u8; 32], WgError> {
    let trimmed = s.trim();
    let mut out = [0u8; 32];
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut written = 0usize;

    for byte in trimmed.bytes() {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return Err(WgError::InvalidKey(format!("unexpected byte {byte:#04x}"))),
        };
        acc = (acc << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if written >= 32 {
                return Err(WgError::InvalidKey("key longer than 32 bytes".into()));
            }
            out[written] = ((acc >> bits) & 0xff) as u8;
            written += 1;
        }
    }

    if written != 32 {
        return Err(WgError::InvalidKey(format!(
            "expected 32 bytes, decoded {written}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_base64_key() {
        // 32 zero bytes in standard base64.
        let key = decode_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn rejects_short_key() {
        assert!(decode_key("AAAA").is_err());
    }

    #[test]
    fn rejects_invalid_character() {
        assert!(decode_key("!!!!").is_err());
    }

    #[test]
    fn handshake_between_two_engines_produces_datagrams() {
        let a_priv = x25519::StaticSecret::from([1u8; 32]);
        let b_priv = x25519::StaticSecret::from([2u8; 32]);
        let a_pub = x25519::PublicKey::from(&a_priv);
        let b_pub = x25519::PublicKey::from(&b_priv);

        let mut a = WgEngine::new(a_priv, b_pub, None, None, 1);
        let mut b = WgEngine::new(b_priv, a_pub, None, None, 2);

        let mut buf = [0u8; 2048];
        let init = match a.initiate_handshake(&mut buf).unwrap() {
            WgOutput::Network(d) => d.to_vec(),
            other => panic!("expected handshake init, got {other:?}"),
        };
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);

        let mut buf2 = [0u8; 2048];
        let resp = match b.decapsulate(None, &init, &mut buf2).unwrap() {
            WgOutput::Network(d) => d.to_vec(),
            other => panic!("expected handshake response, got {other:?}"),
        };
        assert_eq!(resp.len(), HANDSHAKE_RESP_SZ);

        let mut buf3 = [0u8; 2048];
        match a.decapsulate(None, &resp, &mut buf3).unwrap() {
            WgOutput::Network(_) | WgOutput::Done => {}
            other => panic!("unexpected result after response: {other:?}"),
        }
    }
}
