//! TURN server over TCP and TLS streams (RFC 5766 Section 11.5 / RFC 6062).
//!
//! Accepts length-prefixed TURN connections, performs long-term credential
//! authentication (401 challenge + MessageIntegrity verification), and exposes
//! a per-connection handle for relaying ChannelData payloads.

use crate::TurnIncoming;
use crate::error::TurnError;
use crate::stun::*;
use crate::transport::{decode_tcp_frame, encode_tcp_channel_data};
use bytes::{BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha1::Sha1;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

type HmacSha1 = Hmac<Sha1>;

/// Configuration for the stream TURN server.
#[derive(Debug, Clone)]
pub struct StreamServerConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// TURN username expected from clients.
    pub username: String,
    /// TURN password expected from clients.
    pub password: String,
    /// TURN realm advertised in the 401 challenge.
    pub realm: String,
    /// Channel number assigned to the peer.
    pub channel_number: u16,
    /// Allocation lifetime in seconds.
    pub lifetime_sec: u32,
    /// Optional TLS certificate chain (DER). When set, TLS is enabled.
    pub tls_cert_der: Option<Vec<u8>>,
    /// Optional TLS private key (PKCS#8 DER). Required with `tls_cert_der`.
    pub tls_key_der: Option<Vec<u8>>,
}

impl Default for StreamServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            username: String::new(),
            password: String::new(),
            realm: "wdtt".to_string(),
            channel_number: 0x4000,
            lifetime_sec: 600,
            tls_cert_der: None,
            tls_key_der: None,
        }
    }
}

/// A single accepted stream connection.
pub struct StreamConnectionHandle {
    /// Remote peer address.
    pub peer_addr: SocketAddr,
    /// Queue for outbound ChannelData payloads (already framed by the caller).
    pub tx: mpsc::Sender<Bytes>,
    /// Queue of inbound ChannelData payloads.
    pub rx: mpsc::Receiver<Bytes>,
    /// Queue of pre-framed STUN responses produced by the connection task.
    pub control_rx: mpsc::Receiver<Bytes>,
}

/// TURN server accepting TCP/TLS stream connections.
pub struct StreamTurnServer {
    config: StreamServerConfig,
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
}

impl StreamTurnServer {
    /// Bind the listener and prepare the optional TLS acceptor.
    pub async fn bind(config: StreamServerConfig) -> Result<Self, TurnError> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let acceptor = match (&config.tls_cert_der, &config.tls_key_der) {
            (Some(cert), Some(key)) => {
                let certs = vec![CertificateDer::from(cert.clone())];
                let key = PrivateKeyDer::Pkcs8(key.clone().into());
                let server_cfg = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| TurnError::TlsError(format!("invalid TLS cert/key: {e}")))?;
                Some(TlsAcceptor::from(Arc::new(server_cfg)))
            }
            (None, None) => None,
            _ => {
                return Err(TurnError::TlsError(
                    "tls_cert_der and tls_key_der must be provided together".into(),
                ));
            }
        };
        info!(
            "Stream TURN server listening on {} ({})",
            listener.local_addr()?,
            if acceptor.is_some() { "TLS" } else { "TCP" }
        );
        Ok(Self {
            config,
            listener,
            acceptor,
        })
    }

    /// Local listening address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept the next connection and complete the TURN handshake.
    ///
    /// Returns a handle whose `rx` yields inbound ChannelData payloads and whose
    /// `tx` accepts outbound ChannelData payloads.
    pub async fn accept(&self) -> Result<StreamConnectionHandle, TurnError> {
        let (stream, peer_addr) = self.listener.accept().await?;
        let _ = stream.set_nodelay(true);

        let conn: Box<dyn AsyncStream> = match &self.acceptor {
            Some(acceptor) => Box::new(acceptor.accept(stream).await?),
            None => Box::new(stream),
        };

        let (reader, mut writer) = tokio::io::split(conn);
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(1024);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(1024);
        let (ctl_tx, ctl_rx) = mpsc::channel::<Bytes>(64);

        let writer_task = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
            }
        });

        let cfg = self.config.clone();
        let handshake = tokio::spawn(async move {
            run_connection(reader, in_tx, ctl_tx, cfg).await;
        });

        // Wait for the handshake task to finish (it runs for the connection lifetime).
        // We return the handle immediately; the caller drives the data path.
        tokio::spawn(async move {
            let _ = handshake.await;
            writer_task.abort();
        });

        Ok(StreamConnectionHandle {
            peer_addr,
            tx: out_tx,
            rx: in_rx,
            control_rx: ctl_rx,
        })
    }
}

trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Per-connection STUN responder loop.
async fn run_connection<R>(
    mut reader: R,
    in_tx: mpsc::Sender<Bytes>,
    ctl_tx: mpsc::Sender<Bytes>,
    cfg: StreamServerConfig,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut read_buf = BytesMut::with_capacity(65536);
    let mut chunk = [0u8; 8192];
    let nonce = generate_nonce();
    let key = compute_long_term_key(&cfg.username, &cfg.realm, &cfg.password);
    let mut channels: HashMap<u16, SocketAddr> = HashMap::new();

    loop {
        match decode_tcp_frame(&mut read_buf) {
            Ok(Some(TurnIncoming::ChannelData { channel, payload })) => {
                if channels.contains_key(&channel) && in_tx.send(payload).await.is_err() {
                    break;
                }
            }
            Ok(Some(TurnIncoming::Stun(msg))) => {
                if let Some(resp) = handle_stun(&msg, &cfg, &key, &nonce, &mut channels) {
                    // STUN responses go through the control channel; the core layer
                    // forwards them to the connection writer.
                    if ctl_tx.send(resp).await.is_err() {
                        break;
                    }
                }
            }
            Ok(Some(TurnIncoming::DataIndication { .. })) => {}
            Ok(None) => match reader.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => read_buf.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    debug!("stream read error: {e}");
                    break;
                }
            },
            Err(e) => {
                warn!("invalid stream frame: {e}");
                break;
            }
        }
    }
}

fn generate_nonce() -> String {
    let mut raw = [0u8; 16];
    rand::rng().fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// Handle a STUN request, returning an encoded response if one is required.
fn handle_stun(
    msg: &StunMessage,
    cfg: &StreamServerConfig,
    key: &[u8; 16],
    nonce: &str,
    channels: &mut HashMap<u16, SocketAddr>,
) -> Option<Bytes> {
    match msg.message_type {
        ALLOCATE_REQUEST => {
            if msg.realm().is_none() || msg.nonce().is_none() {
                // Unauthenticated: issue 401 challenge.
                let resp = StunMessage::new(ALLOCATE_ERROR_RESPONSE, msg.transaction_id)
                    .with_attribute(StunAttribute::ErrorCode {
                        code: CODE_UNAUTHORIZED,
                        reason: "Unauthorized".into(),
                    })
                    .with_attribute(StunAttribute::Realm(cfg.realm.clone()))
                    .with_attribute(StunAttribute::Nonce(nonce.to_string()));
                return Some(resp.encode().freeze());
            }
            if !verify_integrity(msg, key) {
                let resp = StunMessage::new(ALLOCATE_ERROR_RESPONSE, msg.transaction_id)
                    .with_attribute(StunAttribute::ErrorCode {
                        code: CODE_UNAUTHORIZED,
                        reason: "Unauthorized".into(),
                    })
                    .with_attribute(StunAttribute::Realm(cfg.realm.clone()))
                    .with_attribute(StunAttribute::Nonce(nonce.to_string()));
                return Some(resp.encode().freeze());
            }
            let resp = StunMessage::new(ALLOCATE_RESPONSE, msg.transaction_id)
                .with_attribute(StunAttribute::XorRelayedAddress(cfg.listen_addr))
                .with_attribute(StunAttribute::Lifetime(cfg.lifetime_sec));
            Some(resp.encode_with_integrity(key).freeze())
        }
        CREATE_PERMISSION_REQUEST => {
            if !verify_integrity(msg, key) {
                return None;
            }
            let resp = StunMessage::new(CREATE_PERMISSION_RESPONSE, msg.transaction_id);
            Some(resp.encode_with_integrity(key).freeze())
        }
        CHANNEL_BIND_REQUEST => {
            if !verify_integrity(msg, key) {
                return None;
            }
            if let Some(peer) = msg.peer_address() {
                channels.insert(cfg.channel_number, peer);
            }
            let resp = StunMessage::new(CHANNEL_BIND_RESPONSE, msg.transaction_id);
            Some(resp.encode_with_integrity(key).freeze())
        }
        REFRESH_REQUEST => {
            if !verify_integrity(msg, key) {
                return None;
            }
            let resp = StunMessage::new(REFRESH_RESPONSE, msg.transaction_id)
                .with_attribute(StunAttribute::Lifetime(cfg.lifetime_sec));
            Some(resp.encode_with_integrity(key).freeze())
        }
        BINDING_REQUEST => {
            let resp = StunMessage::new(BINDING_RESPONSE, msg.transaction_id);
            Some(resp.encode().freeze())
        }
        _ => None,
    }
}

/// Verify the MessageIntegrity attribute of an incoming STUN message.
fn verify_integrity(msg: &StunMessage, key: &[u8; 16]) -> bool {
    let Some(expected) = msg.attributes.iter().find_map(|a| match a {
        StunAttribute::MessageIntegrity(digest) => Some(*digest),
        _ => None,
    }) else {
        return false;
    };

    // Re-encode the message without the integrity attribute, then hash with the
    // body length adjusted to include the 24-byte MI attribute.
    let mut body = BytesMut::new();
    for attr in &msg.attributes {
        if matches!(attr, StunAttribute::MessageIntegrity(_)) {
            continue;
        }
        attr.encode(&msg.transaction_id, &mut body);
    }
    let total_body_len = (body.len() + 24) as u16;

    let mut to_hash = BytesMut::with_capacity(STUN_HEADER_LEN + body.len());
    to_hash.put_u16(msg.message_type);
    to_hash.put_u16(total_body_len);
    to_hash.put_u32(STUN_MAGIC_COOKIE);
    to_hash.put_slice(&msg.transaction_id);
    to_hash.put_slice(&body);

    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&to_hash);
    let computed = mac.finalize().into_bytes();
    computed.as_slice() == expected
}

/// Encode a ChannelData frame for transmission over the stream.
pub fn encode_outbound(channel: u16, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(payload.len() + 8);
    encode_tcp_channel_data(channel, payload, &mut out);
    out.freeze()
}

/// Timeout used when waiting for a connection handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[allow(dead_code)]
fn _assert_oneshot_used(_: oneshot::Sender<()>) {}
