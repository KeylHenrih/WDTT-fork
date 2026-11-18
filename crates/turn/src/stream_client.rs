//! Asynchronous TURN Client over TCP and TLS streams (RFC 5766 Section 11.5 / RFC 6062).
//!
//! Provides automatic 438 Stale Nonce recovery, dynamic refresh interval tracking,
//! bounded transmit queues with head-drop on congestion, and length-prefixed framing.

use crate::TurnIncoming;
use crate::error::TurnError;
use crate::stun::*;
use crate::transport::{
    BoundedTxQueue, DEFAULT_TX_QUEUE_CAPACITY, StreamConnection, TurnTransportMode,
    decode_tcp_frame, encode_tcp_channel_data,
};
use bytes::{Bytes, BytesMut};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

const TIMEOUT_DURATION: Duration = Duration::from_secs(5);

/// Configuration for connecting to TURN server over TCP or TLS.
#[derive(Debug, Clone)]
pub struct StreamClientConfig {
    /// Remote TURN server address.
    pub server_addr: SocketAddr,
    /// Destination peer address.
    pub peer_addr: SocketAddr,
    /// TURN username.
    pub username: String,
    /// TURN password.
    pub password: String,
    /// Channel number (default 0x4000).
    pub channel_number: u16,
    /// Requested allocation lifetime in seconds (default 600).
    pub lifetime_sec: u32,
    /// Transport mode: Tcp or Tls.
    pub transport: TurnTransportMode,
    /// SNI server name for TLS verification.
    pub sni: Option<String>,
    /// Optional custom CA certificate in DER format (for testing).
    pub custom_ca_der: Option<Vec<u8>>,
    /// Optional network interface name for SO_BINDTODEVICE.
    pub bind_interface: Option<String>,
    /// Bounded transmit queue capacity.
    pub tx_queue_capacity: usize,
}

impl Default for StreamClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:3478".parse().unwrap(),
            peer_addr: "127.0.0.1:51820".parse().unwrap(),
            username: String::new(),
            password: String::new(),
            channel_number: 0x4000,
            lifetime_sec: 600,
            transport: TurnTransportMode::Tcp,
            sni: None,
            custom_ca_der: None,
            bind_interface: None,
            tx_queue_capacity: DEFAULT_TX_QUEUE_CAPACITY,
        }
    }
}

/// TURN Client over TCP or TLS stream.
pub struct StreamTurnClient {
    config: StreamClientConfig,
    relayed_addr: Option<SocketAddr>,
    realm: String,
    nonce: String,
    key: [u8; 16],
    allocated: Arc<AtomicBool>,
    negotiated_lifetime_sec: u32,
    reader: ReadHalf<StreamConnection>,
    read_buf: BytesMut,
    tx_sender: mpsc::Sender<Bytes>,
    tx_queue: Arc<Mutex<BoundedTxQueue>>,
    pending_stun: Arc<Mutex<HashMap<[u8; 12], oneshot::Sender<StunMessage>>>>,
    writer_task: tokio::task::JoinHandle<()>,
}

impl StreamTurnClient {
    /// Connect to TURN server via TCP or TLS.
    pub async fn connect(config: StreamClientConfig) -> Result<Self, TurnError> {
        let conn = match config.transport {
            TurnTransportMode::Tcp => {
                StreamConnection::connect_tcp(config.server_addr, config.bind_interface.as_deref())
                    .await?
            }
            TurnTransportMode::Tls | TurnTransportMode::Auto => {
                let sni = config
                    .sni
                    .clone()
                    .unwrap_or_else(|| config.server_addr.ip().to_string());
                StreamConnection::connect_tls(
                    config.server_addr,
                    &sni,
                    config.custom_ca_der.as_deref(),
                    config.bind_interface.as_deref(),
                )
                .await?
            }
            TurnTransportMode::Udp => {
                return Err(TurnError::Transport(
                    "StreamTurnClient only supports TCP and TLS".into(),
                ));
            }
        };

        let (reader, mut writer) = tokio::io::split(conn);
        let tx_capacity = config.tx_queue_capacity;
        let tx_queue = Arc::new(Mutex::new(BoundedTxQueue::new(tx_capacity)));
        let (tx_sender, mut tx_receiver) = mpsc::channel::<Bytes>(tx_capacity);

        let writer_task = tokio::spawn(async move {
            let mut write_buf = Vec::with_capacity(32);
            while let Some(frame) = tx_receiver.recv().await {
                write_buf.clear();
                write_buf.push(frame);
                // Drain any additional frames currently pending in channel to write in batch
                while let Ok(f) = tx_receiver.try_recv() {
                    write_buf.push(f);
                }

                for f in &write_buf {
                    if let Err(e) = writer.write_all(f).await {
                        error!("TCP/TLS writer error: {e}");
                        return;
                    }
                }
                if let Err(e) = writer.flush().await {
                    error!("TCP/TLS flush error: {e}");
                    return;
                }
            }
        });

        let lifetime = config.lifetime_sec;
        Ok(Self {
            config,
            relayed_addr: None,
            realm: String::new(),
            nonce: String::new(),
            key: [0u8; 16],
            allocated: Arc::new(AtomicBool::new(false)),
            negotiated_lifetime_sec: lifetime,
            reader,
            read_buf: BytesMut::with_capacity(65536),
            tx_sender,
            tx_queue,
            pending_stun: Arc::new(Mutex::new(HashMap::new())),
            writer_task,
        })
    }

    /// Negotiated allocation lifetime in seconds.
    pub fn negotiated_lifetime(&self) -> u32 {
        self.negotiated_lifetime_sec
    }

    /// Refresh interval for allocation (75% of server lifetime).
    pub fn allocation_refresh_interval(&self) -> Duration {
        let sec = (self.negotiated_lifetime_sec as u64 * 3) / 4;
        Duration::from_secs(sec.max(10))
    }

    /// Refresh interval for permissions (75% of min(300, lifetime)).
    pub fn permission_refresh_interval(&self) -> Duration {
        let sec = 300.min(self.negotiated_lifetime_sec as u64);
        Duration::from_secs(((sec * 3) / 4).max(10))
    }

    /// Refresh interval for channel binding (75% of min(600, lifetime)).
    pub fn channel_bind_refresh_interval(&self) -> Duration {
        let sec = 600.min(self.negotiated_lifetime_sec as u64);
        Duration::from_secs(((sec * 3) / 4).max(10))
    }

    /// Return configured channel number.
    pub fn channel_number(&self) -> u16 {
        self.config.channel_number
    }

    /// Allocated relayed address.
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed_addr
    }

    /// Update target peer and establish permission and channel binding.
    pub async fn bind_peer(&mut self, peer_addr: SocketAddr) -> Result<(), TurnError> {
        self.config.peer_addr = peer_addr;
        self.create_permission_internal().await?;
        self.channel_bind_custom(peer_addr, self.config.channel_number)
            .await?;
        Ok(())
    }

    /// Perform authenticated ChannelBind for specified peer address and channel number.
    pub async fn channel_bind_custom(
        &mut self,
        peer_addr: SocketAddr,
        channel_number: u16,
    ) -> Result<(), TurnError> {
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let req = StunMessage::new(CHANNEL_BIND_REQUEST, tx_id)
            .with_attribute(StunAttribute::ChannelNumber(channel_number))
            .with_attribute(StunAttribute::XorPeerAddress(peer_addr))
            .with_attribute(StunAttribute::Username(self.config.username.clone()))
            .with_attribute(StunAttribute::Realm(self.realm.clone()))
            .with_attribute(StunAttribute::Nonce(self.nonce.clone()));

        let resp = self.send_authenticated_request(req, &tx_id).await?;
        if let Some((code, reason)) = resp.error_code() {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: reason.to_string(),
            });
        }
        info!(
            "TURN ChannelBind succeeded over stream: channel 0x{:04X} -> {}",
            channel_number, peer_addr
        );
        Ok(())
    }

    /// Perform TURN allocation only, obtaining the relayed address.
    pub async fn allocate_relay(&mut self) -> Result<SocketAddr, TurnError> {
        info!(
            "Initiating TURN allocation to {} ({:?}-stream)",
            self.config.server_addr, self.config.transport
        );

        // 1. Initial unauthenticated Allocate to get 401 challenge
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let initial_req = StunMessage::new(ALLOCATE_REQUEST, tx_id)
            .with_attribute(StunAttribute::RequestedTransport(17)); // UDP relay requested

        let resp = self.send_stun_packet(&initial_req, &tx_id, None).await?;

        // Expect 401 Unauthorized
        if let Some((code, _)) = resp.error_code()
            && code != CODE_UNAUTHORIZED
        {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: "unexpected error code on initial allocate".into(),
            });
        }

        self.realm = resp
            .realm()
            .ok_or(TurnError::MissingAttribute("REALM"))?
            .to_string();
        self.nonce = resp
            .nonce()
            .ok_or(TurnError::MissingAttribute("NONCE"))?
            .to_string();

        self.key = compute_long_term_key(&self.config.username, &self.realm, &self.config.password);

        // 2. Authenticated Allocate
        let alloc_resp = self.send_authenticated_allocate().await?;
        let relayed_addr = alloc_resp
            .relayed_address()
            .ok_or(TurnError::MissingAttribute("XOR-RELAYED-ADDRESS"))?;
        if let Some(lifetime) = alloc_resp.lifetime() {
            self.negotiated_lifetime_sec = lifetime;
        }
        self.relayed_addr = Some(relayed_addr);
        info!(
            "TURN allocation granted over stream: relayed addr = {relayed_addr}, lifetime = {}s",
            self.negotiated_lifetime_sec
        );

        self.allocated.store(true, Ordering::SeqCst);
        Ok(relayed_addr)
    }

    /// Refresh allocation lifetime (RFC 5766 Section 7).
    pub async fn refresh_allocation(&mut self, lifetime_sec: u32) -> Result<u32, TurnError> {
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let req = StunMessage::new(REFRESH_REQUEST, tx_id)
            .with_attribute(StunAttribute::Lifetime(lifetime_sec))
            .with_attribute(StunAttribute::Username(self.config.username.clone()))
            .with_attribute(StunAttribute::Realm(self.realm.clone()))
            .with_attribute(StunAttribute::Nonce(self.nonce.clone()));

        let resp = self.send_authenticated_request(req, &tx_id).await?;
        if let Some((code, reason)) = resp.error_code() {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: reason.to_string(),
            });
        }
        let granted = resp.lifetime().unwrap_or(lifetime_sec);
        self.negotiated_lifetime_sec = granted;
        debug!("TURN allocation refreshed over stream: lifetime = {granted}s");
        Ok(granted)
    }

    /// Refresh permissions for peer address.
    pub async fn refresh_permission(&mut self) -> Result<(), TurnError> {
        self.create_permission_internal().await
    }

    /// Refresh channel binding for peer address.
    pub async fn refresh_channel_bind(&mut self) -> Result<(), TurnError> {
        self.channel_bind_custom(self.config.peer_addr, self.config.channel_number)
            .await
    }

    /// Send ChannelData payload over stream with 4-byte padding alignment.
    /// Drops oldest packet if transmit queue is saturated.
    pub async fn send_channel_data(&mut self, payload: &[u8]) -> Result<(), TurnError> {
        let mut out = BytesMut::new();
        encode_tcp_channel_data(self.config.channel_number, payload, &mut out);
        let frame = out.freeze();

        // Enforce bounded queue with head-drop
        let mut q = self.tx_queue.lock().await;
        q.push(frame.clone());
        drop(q);

        // Notify writer task
        let _ = self.tx_sender.try_send(frame);
        Ok(())
    }

    /// Returns the count of datagrams dropped due to TX queue saturation.
    pub async fn dropped_tx_count(&self) -> u64 {
        self.tx_queue.lock().await.dropped_count()
    }

    /// Receive the next incoming frame from the stream.
    pub async fn recv_frame(&mut self) -> Result<TurnIncoming, TurnError> {
        loop {
            // Check if a full frame is already in buffer
            if let Some(frame) = decode_tcp_frame(&mut self.read_buf)? {
                match frame {
                    TurnIncoming::Stun(msg) => {
                        // Check if a pending STUN request is waiting for this response
                        let mut pending = self.pending_stun.lock().await;
                        if let Some(sender) = pending.remove(&msg.transaction_id) {
                            let _ = sender.send(msg);
                            continue;
                        }
                        return Ok(TurnIncoming::Stun(msg));
                    }
                    other => return Ok(other),
                }
            }

            // Read more data from stream
            let mut chunk = [0u8; 8192];
            let n = self.reader.read(&mut chunk).await?;
            if n == 0 {
                return Err(TurnError::Transport(
                    "TCP/TLS stream closed by server".into(),
                ));
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn send_authenticated_allocate(&mut self) -> Result<StunMessage, TurnError> {
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let req = StunMessage::new(ALLOCATE_REQUEST, tx_id)
            .with_attribute(StunAttribute::RequestedTransport(17))
            .with_attribute(StunAttribute::Lifetime(self.config.lifetime_sec))
            .with_attribute(StunAttribute::Username(self.config.username.clone()))
            .with_attribute(StunAttribute::Realm(self.realm.clone()))
            .with_attribute(StunAttribute::Nonce(self.nonce.clone()));

        self.send_authenticated_request(req, &tx_id).await
    }

    async fn create_permission_internal(&mut self) -> Result<(), TurnError> {
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let req = StunMessage::new(CREATE_PERMISSION_REQUEST, tx_id)
            .with_attribute(StunAttribute::XorPeerAddress(self.config.peer_addr))
            .with_attribute(StunAttribute::Username(self.config.username.clone()))
            .with_attribute(StunAttribute::Realm(self.realm.clone()))
            .with_attribute(StunAttribute::Nonce(self.nonce.clone()));

        let resp = self.send_authenticated_request(req, &tx_id).await?;
        if let Some((code, reason)) = resp.error_code() {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: reason.to_string(),
            });
        }
        debug!(
            "TURN CreatePermission succeeded over stream for {}",
            self.config.peer_addr
        );
        Ok(())
    }

    async fn send_authenticated_request(
        &mut self,
        mut req: StunMessage,
        tx_id: &[u8; 12],
    ) -> Result<StunMessage, TurnError> {
        let key = self.key;
        let resp = self.send_stun_packet(&req, tx_id, Some(&key)).await?;

        // 438 Stale Nonce recovery
        if let Some((code, _)) = resp.error_code()
            && code == CODE_STALE_NONCE
            && let Some(new_nonce) = resp.nonce()
        {
            warn!("Received 438 Stale Nonce over stream. Retrying with {new_nonce}...");
            self.nonce = new_nonce.to_string();
            self.key =
                compute_long_term_key(&self.config.username, &self.realm, &self.config.password);

            for attr in &mut req.attributes {
                if let StunAttribute::Nonce(n) = attr {
                    *n = self.nonce.clone();
                }
            }

            let key = self.key;
            return self.send_stun_packet(&req, tx_id, Some(&key)).await;
        }

        Ok(resp)
    }

    async fn send_stun_packet(
        &mut self,
        req: &StunMessage,
        tx_id: &[u8; 12],
        key: Option<&[u8]>,
    ) -> Result<StunMessage, TurnError> {
        let encoded = match key {
            Some(k) => req.encode_with_integrity(k),
            None => req.encode(),
        };

        let (resp_tx, mut resp_rx) = oneshot::channel();
        {
            let mut pending = self.pending_stun.lock().await;
            pending.insert(*tx_id, resp_tx);
        }

        let frame = Bytes::from(encoded);
        self.tx_sender
            .send(frame)
            .await
            .map_err(|e| TurnError::Transport(format!("failed to enqueue STUN frame: {e}")))?;

        let res = timeout(TIMEOUT_DURATION, async {
            loop {
                // If the background reader already stored the response
                tokio::select! {
                    resp = &mut resp_rx => {
                        return resp.map_err(|_| TurnError::Timeout);
                    }
                    incoming = self.recv_frame() => {
                        // Keep polling reader in case this task drives read loop
                        if let Ok(TurnIncoming::Stun(msg)) = incoming
                            && msg.transaction_id == *tx_id {
                                return Ok(msg);
                            }
                    }
                }
            }
        })
        .await;

        match res {
            Ok(r) => r,
            Err(_) => {
                let mut pending = self.pending_stun.lock().await;
                pending.remove(tx_id);
                Err(TurnError::Timeout)
            }
        }
    }
}

impl Drop for StreamTurnClient {
    fn drop(&mut self) {
        self.writer_task.abort();
    }
}
