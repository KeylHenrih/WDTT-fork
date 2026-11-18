//! Stream transport implementation for TURN over TCP and TLS (RFC 5766 Section 11.5 / RFC 6062).
//!
//! Provides length-prefixed framing with 4-byte alignment, non-blocking I/O,
//! bounded transmit queues with head-drop (dropping oldest datagrams on bufferbloat),
//! and secure TLS verification via rustls and webpki-roots.

use crate::TurnIncoming;
use crate::error::TurnError;
use crate::stun::StunMessage;
use bytes::{BufMut, Bytes, BytesMut};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Default capacity for the bounded transmit queue (number of datagrams).
pub const DEFAULT_TX_QUEUE_CAPACITY: usize = 256;

/// Transport mode for TURN connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TurnTransportMode {
    /// Standard UDP datagram transport.
    #[default]
    Udp,
    /// Unencrypted TCP stream transport (RFC 5766 / RFC 6062).
    Tcp,
    /// Encrypted TLS stream transport (RFC 5766 / RFC 6062).
    Tls,
    /// Automatic selection: probe UDP, fallback to TLS if UDP fails or has >10% loss.
    Auto,
}

impl TurnTransportMode {
    /// Determine transport mode from a TURN URI (e.g. "turns:turn.voip.vk.com:443?transport=tcp").
    pub fn from_uri(uri: &str) -> Self {
        let is_turns = uri.starts_with("turns:");
        let is_tcp = uri.contains("transport=tcp");
        match (is_turns, is_tcp) {
            (true, _) => Self::Tls,
            (false, true) => Self::Tcp,
            (false, false) => Self::Udp,
        }
    }
}

/// Encode ChannelData for TCP/TLS stream with 4-byte padding alignment (RFC 5766 Section 11.5).
pub fn encode_tcp_channel_data(channel: u16, payload: &[u8], out: &mut BytesMut) {
    let len = payload.len();
    assert!(len <= 0xFFFF, "ChannelData payload exceeds u16::MAX");
    let pad_len = (4 - (len % 4)) % 4;
    let total_len = 4 + len + pad_len;

    out.reserve(total_len);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(payload);
    for _ in 0..pad_len {
        out.put_u8(0);
    }
}

/// Decode the next frame (STUN or ChannelData) from a TCP/TLS byte stream.
/// Returns `Ok(Some(TurnIncoming))` if a full frame was parsed, or `Ok(None)` if more data is needed.
pub fn decode_tcp_frame(buf: &mut BytesMut) -> Result<Option<TurnIncoming>, TurnError> {
    if buf.len() < 4 {
        return Ok(None);
    }

    let first_byte = buf[0];
    let top_bits = first_byte & 0xC0;

    if top_bits == 0x00 {
        // STUN message: begins with 0b00
        if buf.len() < 20 {
            return Ok(None);
        }
        let stun_attr_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let total_size = 20 + stun_attr_len;
        if buf.len() < total_size {
            return Ok(None);
        }
        let raw = buf.split_to(total_size);
        let msg = StunMessage::decode(&raw)?;
        Ok(Some(TurnIncoming::Stun(msg)))
    } else if top_bits == 0x40 {
        // ChannelData message: begins with 0b01 (0x4000..=0x7FFF)
        let channel = u16::from_be_bytes([buf[0], buf[1]]);
        let payload_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let pad_len = (4 - (payload_len % 4)) % 4;
        let total_size = 4 + payload_len + pad_len;
        if buf.len() < total_size {
            return Ok(None);
        }
        let raw = buf.split_to(total_size);
        let payload = raw.freeze().slice(4..4 + payload_len);
        Ok(Some(TurnIncoming::ChannelData { channel, payload }))
    } else {
        // Corrupted stream or unknown framing
        Err(TurnError::Transport(format!(
            "invalid frame discriminator 0x{first_byte:02X} in TCP stream"
        )))
    }
}

/// Bounded transmit queue that drops oldest datagrams on overflow to avoid bufferbloat.
pub struct BoundedTxQueue {
    queue: VecDeque<Bytes>,
    capacity: usize,
    dropped_packets: AtomicU64,
}

impl BoundedTxQueue {
    /// Create a new bounded queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            dropped_packets: AtomicU64::new(0),
        }
    }

    /// Push an outgoing frame into the queue.
    /// If the queue is full, drops the oldest frame (head-drop) to prioritize fresher packets.
    pub fn push(&mut self, frame: Bytes) {
        if self.queue.len() >= self.capacity {
            self.queue.pop_front();
            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
        }
        self.queue.push_back(frame);
    }

    /// Pop the next frame to transmit.
    pub fn pop(&mut self) -> Option<Bytes> {
        self.queue.pop_front()
    }

    /// Returns the number of packets dropped due to queue saturation.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_packets.load(Ordering::Relaxed)
    }

    /// Current queue length.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Unified stream connection wrapping either a raw TCP stream or a TLS-encrypted TCP stream.
pub enum StreamConnection {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for StreamConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamConnection::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            StreamConnection::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for StreamConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            StreamConnection::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            StreamConnection::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamConnection::Tcp(s) => Pin::new(s).poll_flush(cx),
            StreamConnection::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamConnection::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            StreamConnection::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl StreamConnection {
    /// Connect unencrypted TCP stream to server.
    pub async fn connect_tcp(
        server_addr: SocketAddr,
        bind_interface: Option<&str>,
    ) -> Result<Self, TurnError> {
        let stream = connect_stream_socket(server_addr, bind_interface).await?;
        tune_tcp_socket(&stream)?;
        Ok(Self::Tcp(stream))
    }

    /// Connect TLS stream to server with SNI verification.
    pub async fn connect_tls(
        server_addr: SocketAddr,
        sni: &str,
        custom_ca: Option<&[u8]>,
        bind_interface: Option<&str>,
    ) -> Result<Self, TurnError> {
        let stream = connect_stream_socket(server_addr, bind_interface).await?;
        tune_tcp_socket(&stream)?;
        let tls_cfg = build_tls_config(custom_ca)?;
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| TurnError::TlsError(format!("invalid SNI host {sni:?}: {e}")))?
            .to_owned();
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| TurnError::TlsError(format!("TLS handshake failed: {e}")))?;
        Ok(Self::Tls(Box::new(tls_stream)))
    }
}

/// Helper connecting a TcpStream, optionally applying SO_BINDTODEVICE on Linux.
async fn connect_stream_socket(
    server_addr: SocketAddr,
    bind_interface: Option<&str>,
) -> Result<TcpStream, TurnError> {
    if let Some(iface) = bind_interface {
        let socket = socket2::Socket::new(
            if server_addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        #[cfg(target_os = "linux")]
        socket.bind_device(Some(iface.as_bytes()))?;
        socket.set_nonblocking(true)?;
        match socket.connect(&server_addr.into()) {
            Ok(()) => Ok(TcpStream::from_std(socket.into())?),
            Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) => {
                let stream = TcpStream::from_std(socket.into())?;
                stream.writable().await?;
                if let Some(e) = stream.take_error()? {
                    return Err(TurnError::Io(e));
                }
                Ok(stream)
            }
            Err(e) => Err(TurnError::Io(e)),
        }
    } else {
        Ok(TcpStream::connect(server_addr).await?)
    }
}

/// Build a rustls ClientConfig verifying certificates against webpki-roots or custom CA.
pub fn build_tls_config(custom_ca: Option<&[u8]>) -> Result<ClientConfig, TurnError> {
    let mut root_store = rustls::RootCertStore::empty();
    if let Some(ca_der) = custom_ca {
        let cert = CertificateDer::from(ca_der.to_vec());
        root_store
            .add(cert)
            .map_err(|e| TurnError::TlsError(format!("failed to add custom CA: {e}")))?;
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

/// Tune TCP socket options: TCP_NODELAY and keepalive.
pub fn tune_tcp_socket(stream: &TcpStream) -> Result<(), TurnError> {
    stream.set_nodelay(true)?;
    let sock_ref = socket2::SockRef::from(stream);
    let mut keepalive = socket2::TcpKeepalive::new();
    keepalive = keepalive.with_time(Duration::from_secs(15));
    keepalive = keepalive.with_interval(Duration::from_secs(5));
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_tcp_channel_data() {
        let mut buf = BytesMut::new();
        let payload = b"Hello WireGuard over TCP!";
        encode_tcp_channel_data(0x4001, payload, &mut buf);

        // 4 bytes header + 25 bytes payload + 3 bytes padding = 32 bytes
        assert_eq!(buf.len(), 32);

        let incoming = decode_tcp_frame(&mut buf).unwrap().expect("frame decoded");
        if let TurnIncoming::ChannelData {
            channel,
            payload: p,
        } = incoming
        {
            assert_eq!(channel, 0x4001);
            assert_eq!(&p[..], payload);
        } else {
            panic!("expected ChannelData");
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn test_bounded_tx_queue_head_drop() {
        let mut queue = BoundedTxQueue::new(3);
        queue.push(Bytes::from_static(b"frame 1"));
        queue.push(Bytes::from_static(b"frame 2"));
        queue.push(Bytes::from_static(b"frame 3"));
        assert_eq!(queue.len(), 3);
        assert_eq!(queue.dropped_count(), 0);

        // 4th frame should drop "frame 1" (head drop)
        queue.push(Bytes::from_static(b"frame 4"));
        assert_eq!(queue.len(), 3);
        assert_eq!(queue.dropped_count(), 1);

        assert_eq!(queue.pop().unwrap(), Bytes::from_static(b"frame 2"));
        assert_eq!(queue.pop().unwrap(), Bytes::from_static(b"frame 3"));
        assert_eq!(queue.pop().unwrap(), Bytes::from_static(b"frame 4"));
        assert!(queue.is_empty());
    }

    #[test]
    fn test_interleaved_stun_and_channel_data() {
        let mut stream_buf = BytesMut::new();

        // 1. STUN message
        let tx_id = [7u8; 12];
        let stun_msg = StunMessage::new(crate::stun::BINDING_REQUEST, tx_id);
        let stun_bytes = stun_msg.encode();
        stream_buf.extend_from_slice(&stun_bytes);

        // 2. ChannelData
        let payload = b"Interleaved data packet";
        encode_tcp_channel_data(0x4000, payload, &mut stream_buf);

        // Parse first frame -> STUN
        let f1 = decode_tcp_frame(&mut stream_buf).unwrap().expect("f1");
        if let TurnIncoming::Stun(msg) = f1 {
            assert_eq!(msg.transaction_id, tx_id);
        } else {
            panic!("expected STUN");
        }

        // Parse second frame -> ChannelData
        let f2 = decode_tcp_frame(&mut stream_buf).unwrap().expect("f2");
        if let TurnIncoming::ChannelData {
            channel,
            payload: p,
        } = f2
        {
            assert_eq!(channel, 0x4000);
            assert_eq!(&p[..], payload);
        } else {
            panic!("expected ChannelData");
        }

        assert!(stream_buf.is_empty());
    }
}
