//! Single-stream tunnel endpoint engines for client and server.

#![forbid(unsafe_code)]

use crate::batch::{BatchedUdpSocket, RecvMeta};
use crate::metrics::TunnelMetrics;
use bytes::BytesMut;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};
use wdtt_crypto::{
    CryptoError, DEFAULT_MAX_CLOCK_SKEW_SEC, KnockAuthenticator, Psk, derive_pre_auth_knock_key,
};
use wdtt_proto::{
    FrameType, FrameView, ProtoError, WgResequencer, encode_frame, inspect_wg_packet,
};
use wdtt_turn::{TurnClient, TurnClientConfig, TurnError, TurnIncoming};

const RESEQUENCER_TICK_INTERVAL: Duration = Duration::from_millis(10);
const MAX_PACKET_LEN: usize = 2048;
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(300);

/// Helper to create and bind non-blocking UDP socket with 4 MB send/recv buffers.
fn tune_socket_buffers(sock: &socket2::Socket) {
    if std::env::var("WDTT_DISABLE_SOCK_TUNE").is_ok() {
        return;
    }
    let default_size = 4 * 1024 * 1024;
    let rcv_size = match std::env::var("WDTT_SOCK_RCVBUF") {
        Ok(v) => v.parse::<usize>().unwrap_or(0),
        Err(_) => default_size,
    };
    if rcv_size > 0 {
        let _ = sock.set_recv_buffer_size(rcv_size);
    }
    let snd_size = match std::env::var("WDTT_SOCK_SNDBUF") {
        Ok(v) => v.parse::<usize>().unwrap_or(0),
        Err(_) => default_size,
    };
    if snd_size > 0 {
        let _ = sock.set_send_buffer_size(snd_size);
    }
}

fn bind_tuned_udp_socket(addr: SocketAddr) -> Result<UdpSocket, std::io::Error> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let sock2 = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock2.set_nonblocking(true)?;
    tune_socket_buffers(&sock2);
    if let Ok(actual_rcv) = sock2.recv_buffer_size() {
        tracing::debug!(endpoint = %addr, actual_rcv_buf = actual_rcv, "Bound UDP socket");
    }
    sock2.bind(&addr.into())?;
    let std_socket: std::net::UdpSocket = sock2.into();
    UdpSocket::from_std(std_socket)
}

/// Error type for tunnel session operations.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// TURN relay communication error.
    #[error("TURN error: {0}")]
    Turn(#[from] TurnError),

    /// Cryptographic verification failure.
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Protocol framing error.
    #[error("Protocol error: {0}")]
    Proto(#[from] ProtoError),

    /// Standard I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Timeout awaiting remote response.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Unauthorized peer connection attempt.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

/// Configuration parameters for establishing a client tunnel session.
#[derive(Debug, Clone)]
pub struct TunnelClientConfig {
    /// TURN relay server address.
    pub turn_server_addr: SocketAddr,
    /// TURN credentials username.
    pub turn_username: String,
    /// TURN credentials password.
    pub turn_password: String,
    /// TURN realm string.
    pub turn_realm: String,
    /// Pre-allocated or known server relayed address on TURN relay.
    pub server_relayed_addr: SocketAddr,
    /// Local UDP address where client listens for WireGuard interface packets.
    pub wg_listen_addr: SocketAddr,
    /// Pre-shared key for knock authentication and session establishment.
    pub psk: [u8; 32],
}

/// Configuration parameters for establishing a server tunnel session.
#[derive(Debug, Clone)]
pub struct TunnelServerConfig {
    /// TURN relay server address.
    pub turn_server_addr: SocketAddr,
    /// TURN credentials username.
    pub turn_username: String,
    /// TURN credentials password.
    pub turn_password: String,
    /// TURN realm string.
    pub turn_realm: String,
    /// WireGuard backend UDP endpoint address (e.g. 127.0.0.1:51820).
    pub wg_endpoint_addr: SocketAddr,
    /// Pre-shared key for knock authentication and session establishment.
    pub psk: [u8; 32],
}

/// Authorized client session state tracked by the server.
#[derive(Debug, Clone)]
pub struct AuthorizedClientSession {
    /// Relayed address of the client on the TURN server.
    pub relayed_addr: SocketAddr,
    /// Unique session identifier from the client's knock.
    pub session_id: [u8; 16],
    /// When the session was first authenticated.
    pub authorized_at: Instant,
    /// When the last valid packet was received from the client.
    pub last_activity: Instant,
    /// Session expiration duration without activity.
    pub session_ttl: Duration,
}

impl AuthorizedClientSession {
    /// Whether the session has timed out due to inactivity.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= self.session_ttl
    }
}

/// Client tunnel session terminating local WireGuard and relaying via TURN.
pub struct TunnelClient {
    config: TunnelClientConfig,
    metrics: Arc<TunnelMetrics>,
}

impl TunnelClient {
    /// Create a new tunnel client instance.
    pub fn new(config: TunnelClientConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(TunnelMetrics::new()),
        }
    }

    /// Access metrics collector for this tunnel session.
    pub fn metrics(&self) -> Arc<TunnelMetrics> {
        self.metrics.clone()
    }

    /// Run the client datapath with optional notification sender for when relay allocation completes.
    pub async fn run_with_notify(
        &mut self,
        mut cancel_rx: watch::Receiver<bool>,
        on_allocated: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), TunnelError> {
        info!(
            "Starting TunnelClient: relaying to {} via TURN {}",
            self.config.server_relayed_addr, self.config.turn_server_addr
        );

        let wg_socket = Arc::new(bind_tuned_udp_socket(self.config.wg_listen_addr)?);
        info!("WireGuard bridge listening on {}", wg_socket.local_addr()?);

        let turn_cfg = TurnClientConfig {
            server_addr: self.config.turn_server_addr,
            peer_addr: self.config.server_relayed_addr,
            username: self.config.turn_username.clone(),
            password: self.config.turn_password.clone(),
            channel_number: 0x4000,
            lifetime_sec: 600,
        };

        let mut turn_client = TurnClient::bind("0.0.0.0:0".parse().unwrap(), turn_cfg).await?;
        let my_relayed = turn_client.allocate_relay().await?;
        info!("Client allocated relay address: {my_relayed}");

        if let Some(tx) = on_allocated {
            let _ = tx.send(my_relayed);
        }

        turn_client
            .bind_peer(self.config.server_relayed_addr)
            .await?;
        info!("Client bound peer {}", self.config.server_relayed_addr);

        // Derive dynamic refresh intervals from negotiated TURN LIFETIME
        let mut alloc_refresh_timer = interval(turn_client.allocation_refresh_interval());
        let mut perm_refresh_timer = interval(turn_client.permission_refresh_interval());
        let mut chan_bind_refresh_timer = interval(turn_client.channel_bind_refresh_interval());

        // Send Pre-Auth Knock
        let knock_key = derive_pre_auth_knock_key(&Psk::from_bytes(self.config.psk));
        let auth = KnockAuthenticator::new(knock_key, DEFAULT_MAX_CLOCK_SKEW_SEC);
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut client_nonce = [0u8; 16];
        let mut session_id = [0u8; 16];
        rand::rng().fill_bytes(&mut client_nonce);
        rand::rng().fill_bytes(&mut session_id);

        let knock_wire = auth.generate_knock_packet(now_sec, &client_nonce, &session_id, 32);
        let mut knock_frame = BytesMut::new();
        encode_frame(
            FrameType::HandshakeInit,
            0,
            0,
            0,
            &knock_wire,
            &mut knock_frame,
        );
        turn_client.send_channel_data(&knock_frame).await?;
        debug!("Pre-Auth knock sent to server");

        let batched_wg = BatchedUdpSocket::new(wg_socket.clone());
        let batched_turn = BatchedUdpSocket::new(turn_client.socket().clone());

        let mut resequencer = WgResequencer::new(4096, Duration::from_millis(15));
        let mut wg_peer_addr: Option<SocketAddr> = None;
        let mut seq_tx: u16 = 0;

        const BATCH_SIZE: usize = 16;
        let mut wg_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut wg_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        let mut turn_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut turn_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];
        let mut tick_timer = interval(RESEQUENCER_TICK_INTERVAL);

        loop {
            tokio::select! {
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        info!("TunnelClient shutting down via cancel signal");
                        break;
                    }
                }

                _ = tick_timer.tick(), if !resequencer.is_empty() => {
                    let mut timed_out = Vec::new();
                    resequencer.tick(Instant::now(), &mut timed_out);
                    if let Some(target) = wg_peer_addr {
                        for pkt in timed_out {
                            let _ = wg_socket.send_to(&pkt, target).await;
                        }
                    }
                }

                _ = alloc_refresh_timer.tick() => {
                    let requested_sec = turn_client.negotiated_lifetime();
                    trace!("TunnelClient dynamically refreshing TURN allocation ({requested_sec}s)");
                    if let Err(e) = turn_client.refresh_allocation(requested_sec).await {
                        warn!("Failed to refresh TURN allocation: {e}");
                    }
                }

                _ = perm_refresh_timer.tick() => {
                    trace!("TunnelClient dynamically refreshing TURN permission");
                    if let Err(e) = turn_client.refresh_permission().await {
                        warn!("Failed to refresh TURN permission: {e}");
                    }
                }

                _ = chan_bind_refresh_timer.tick() => {
                    trace!("TunnelClient dynamically refreshing TURN channel bind");
                    if let Err(e) = turn_client.refresh_channel_bind().await {
                        warn!("Failed to refresh TURN channel bind: {e}");
                    }
                }

                // Packets from local WireGuard interface -> send over TURN (batched via recvmmsg)
                read_res = batched_wg.recv_batch(&mut wg_batch_bufs, &mut wg_batch_metas) => {
                    match read_res {
                        Ok(count) => {
                            for i in 0..count {
                                let meta = wg_batch_metas[i];
                                wg_peer_addr = Some(meta.addr);
                                let payload = &wg_batch_bufs[i][..meta.len];

                                let mut frame = BytesMut::new();
                                encode_frame(FrameType::Data, 0, 0, seq_tx, payload, &mut frame);
                                seq_tx = seq_tx.wrapping_add(1);

                                if let Err(e) = turn_client.send_channel_data(&frame).await {
                                    warn!("Failed to forward WG packet to TURN: {e}");
                                } else {
                                    self.metrics.record_tx(meta.len);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error reading from WireGuard socket: {e}");
                        }
                    }
                }

                // Packets from TURN relay -> forward to local WireGuard (batched via recvmmsg)
                turn_batch_res = batched_turn.recv_batch(&mut turn_batch_bufs, &mut turn_batch_metas) => {
                    match turn_batch_res {
                        Ok(count) => {
                            for i in 0..count {
                                let meta = turn_batch_metas[i];
                                let slice = &turn_batch_bufs[i][..meta.len];
                                if let Ok(Some(TurnIncoming::ChannelData { payload, .. })) =
                                    turn_client.parse_incoming(slice, meta.addr)
                                    && let Ok((view, _)) = FrameView::decode(&payload)
                                {
                                        match view.header.frame_type {
                                            FrameType::Data => {
                                                let data_payload = view.payload;
                                                self.metrics.record_rx(data_payload.len());

                                                if let Some(target) = wg_peer_addr {
                                                    if let Ok(wg_hdr) = inspect_wg_packet(data_payload) {
                                                        if wg_hdr.is_data()
                                                            && let (Some(rcv_idx), Some(counter)) =
                                                                (wg_hdr.receiver_index, wg_hdr.counter)
                                                        {
                                                            let mut ordered = Vec::new();
                                                            resequencer.push(
                                                                rcv_idx,
                                                                counter,
                                                                bytes::Bytes::copy_from_slice(data_payload),
                                                                Instant::now(),
                                                                &mut ordered,
                                                            );
                                                            for pkt in ordered {
                                                                let _ = wg_socket.send_to(&pkt, target).await;
                                                            }
                                                        } else {
                                                            // WireGuard handshake bypass
                                                            let _ = wg_socket.send_to(data_payload, target).await;
                                                        }
                                                    } else {
                                                        let _ = wg_socket.send_to(data_payload, target).await;
                                                    }
                                                }
                                            }
                                            FrameType::HandshakeResp => {
                                                info!("Received HandshakeResp from tunnel server");
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        Err(e) => {
                            trace!("TURN recv incoming notice: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the client datapath until cancellation signal is received.
    pub async fn run(&mut self, cancel_rx: watch::Receiver<bool>) -> Result<(), TunnelError> {
        self.run_with_notify(cancel_rx, None).await
    }
}

/// Server tunnel session terminating TURN relay and forwarding to WireGuard endpoint.
pub struct TunnelServer {
    config: TunnelServerConfig,
    metrics: Arc<TunnelMetrics>,
    relayed_addr: Option<SocketAddr>,
}

impl TunnelServer {
    /// Create a new tunnel server instance.
    pub fn new(config: TunnelServerConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(TunnelMetrics::new()),
            relayed_addr: None,
        }
    }

    /// Access metrics collector for this tunnel session.
    pub fn metrics(&self) -> Arc<TunnelMetrics> {
        self.metrics.clone()
    }

    /// Return the allocated relayed address on the TURN server, if allocated.
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed_addr
    }

    /// Run the server datapath with optional notification sender for when relay allocation completes.
    pub async fn run_with_notify(
        &mut self,
        mut cancel_rx: watch::Receiver<bool>,
        on_allocated: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), TunnelError> {
        info!(
            "Starting TunnelServer: connecting to TURN {} forwarding to WG {}",
            self.config.turn_server_addr, self.config.wg_endpoint_addr
        );

        let wg_socket = Arc::new(bind_tuned_udp_socket("0.0.0.0:0".parse().unwrap())?);
        info!("Server WG forwarder bound to {}", wg_socket.local_addr()?);

        let turn_cfg = TurnClientConfig {
            server_addr: self.config.turn_server_addr,
            peer_addr: "0.0.0.0:0".parse().unwrap(),
            username: self.config.turn_username.clone(),
            password: self.config.turn_password.clone(),
            channel_number: 0x4000,
            lifetime_sec: 600,
        };

        let mut turn_client = TurnClient::bind("0.0.0.0:0".parse().unwrap(), turn_cfg).await?;
        let my_relayed = turn_client.allocate_relay().await?;
        self.relayed_addr = Some(my_relayed);
        info!("Server allocated relay address: {my_relayed}");

        // Pre-authorize the relay IP and TURN server IP for incoming client connections
        let _ = turn_client.create_permission(my_relayed).await;
        let _ = turn_client
            .create_permission(self.config.turn_server_addr)
            .await;

        if let Some(tx) = on_allocated {
            let _ = tx.send(my_relayed);
        }

        // Derive dynamic refresh intervals from negotiated TURN LIFETIME
        let mut alloc_refresh_timer = interval(turn_client.allocation_refresh_interval());
        let mut perm_refresh_timer = interval(turn_client.permission_refresh_interval());
        let mut chan_bind_refresh_timer = interval(turn_client.channel_bind_refresh_interval());

        let batched_wg = BatchedUdpSocket::new(wg_socket.clone());
        let batched_turn = BatchedUdpSocket::new(turn_client.socket().clone());

        let knock_key = derive_pre_auth_knock_key(&Psk::from_bytes(self.config.psk));
        let mut auth = KnockAuthenticator::new(knock_key, DEFAULT_MAX_CLOCK_SKEW_SEC);

        let mut active_session: Option<AuthorizedClientSession> = None;
        let mut seq_tx: u16 = 0;

        const BATCH_SIZE: usize = 16;
        let mut wg_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut wg_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        let mut turn_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut turn_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        loop {
            tokio::select! {
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        info!("TunnelServer shutting down via cancel signal");
                        break;
                    }
                }

                _ = alloc_refresh_timer.tick() => {
                    let requested_sec = turn_client.negotiated_lifetime();
                    trace!("TunnelServer dynamically refreshing TURN allocation ({requested_sec}s)");
                    if let Err(e) = turn_client.refresh_allocation(requested_sec).await {
                        warn!("Failed to refresh TURN allocation: {e}");
                    }
                }

                _ = perm_refresh_timer.tick() => {
                    if active_session.is_some() {
                        trace!("TunnelServer dynamically refreshing TURN permission");
                        if let Err(e) = turn_client.refresh_permission().await {
                            warn!("Failed to refresh TURN permission: {e}");
                        }
                    }
                }

                _ = chan_bind_refresh_timer.tick() => {
                    if active_session.is_some() {
                        trace!("TunnelServer dynamically refreshing TURN channel bind");
                        if let Err(e) = turn_client.refresh_channel_bind().await {
                            warn!("Failed to refresh TURN channel bind: {e}");
                        }
                    }
                }

                // Packets from TURN relay -> validate knock or forward to WireGuard (batched)
                turn_batch_res = batched_turn.recv_batch(&mut turn_batch_bufs, &mut turn_batch_metas) => {
                    match turn_batch_res {
                        Ok(count) => {
                            for i in 0..count {
                                let meta = turn_batch_metas[i];
                                let slice = &turn_batch_bufs[i][..meta.len];
                                if let Ok(Some(turn_msg)) = turn_client.parse_incoming(slice, meta.addr) {
                                    let (peer_from_turn, payload) = match turn_msg {
                                        TurnIncoming::DataIndication { peer_addr, payload } => (Some(peer_addr), payload),
                                        TurnIncoming::ChannelData { payload, .. } => (
                                            active_session.as_ref().map(|s| s.relayed_addr),
                                            payload,
                                        ),
                                        _ => (None, bytes::Bytes::new()),
                                    };

                                    if payload.is_empty() {
                                        continue;
                                    }

                                    let now = Instant::now();

                                    // 1. Session expiration check
                                    if let Some(ref session) = active_session
                                        && session.is_expired(now)
                                    {
                                        info!(
                                            "Client session {} expired due to inactivity (TTL {:?})",
                                            session.relayed_addr, session.session_ttl
                                        );
                                        active_session = None;
                                    }

                                    // 2. Check for Pre-Auth Knock (HandshakeInit)
                                    if let Ok((view, _)) = FrameView::decode(&payload)
                                        && view.header.frame_type == FrameType::HandshakeInit
                                    {
                                        let now_sec = SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs();

                                        match auth.verify_knock_packet(now_sec, view.payload) {
                                            Ok(knock_payload) => {
                                                let client_peer = peer_from_turn
                                                    .or_else(|| active_session.as_ref().map(|s| s.relayed_addr));

                                                if let Some(peer) = client_peer {
                                                    info!(
                                                        "Pre-Auth Knock verified for peer {} (session {:?})!",
                                                        peer, knock_payload.session_id
                                                    );

                                                    // Re-bind peer on TURN
                                                    if let Err(e) = turn_client.bind_peer(peer).await {
                                                        warn!("Failed to bind peer {peer} on TURN: {e}");
                                                    }

                                                    active_session = Some(AuthorizedClientSession {
                                                        relayed_addr: peer,
                                                        session_id: knock_payload.session_id,
                                                        authorized_at: now,
                                                        last_activity: now,
                                                        session_ttl: DEFAULT_SESSION_TTL,
                                                    });

                                                    // Send HandshakeResp
                                                    let mut resp_frame = BytesMut::new();
                                                    encode_frame(
                                                        FrameType::HandshakeResp,
                                                        0,
                                                        0,
                                                        0,
                                                        b"WDTT2-OK",
                                                        &mut resp_frame,
                                                    );
                                                    let _ = turn_client.send_channel_data(&resp_frame).await;
                                                } else {
                                                    debug!("Knock verified but peer address unknown; silent discard");
                                                }
                                            }
                                            Err(e) => {
                                                debug!("Invalid knock rejected silently: {e}");
                                            }
                                        }
                                        continue;
                                    }

                                    // 3. Authenticated Data forwarding
                                    if let Some(ref mut session) = active_session {
                                        if let Some(peer) = peer_from_turn
                                            && peer != session.relayed_addr
                                        {
                                            debug!(
                                                "Packet from unauthorized peer {peer} silently dropped; expected {}",
                                                session.relayed_addr
                                            );
                                            continue;
                                        }

                                        if let Ok((view, _)) = FrameView::decode(&payload)
                                            && view.header.frame_type == FrameType::Data
                                        {
                                            session.last_activity = now;
                                            self.metrics.record_rx(view.payload.len());
                                            let _ = wg_socket
                                                .send_to(view.payload, self.config.wg_endpoint_addr)
                                                .await;
                                        }
                                    } else {
                                        debug!("Unauthenticated data packet dropped silently");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            trace!("TURN incoming batch error: {e}");
                        }
                    }
                }

                // Packets from WireGuard endpoint -> send over TURN to client (batched)
                wg_batch_res = batched_wg.recv_batch(&mut wg_batch_bufs, &mut wg_batch_metas), if active_session.is_some() => {
                    match wg_batch_res {
                        Ok(count) => {
                            for i in 0..count {
                                let meta = wg_batch_metas[i];
                                let payload = &wg_batch_bufs[i][..meta.len];
                                let mut frame = BytesMut::new();
                                encode_frame(FrameType::Data, 0, 0, seq_tx, payload, &mut frame);
                                seq_tx = seq_tx.wrapping_add(1);

                                if let Err(e) = turn_client.send_channel_data(&frame).await {
                                    warn!("Failed to forward server WG packet over TURN: {e}");
                                } else {
                                    self.metrics.record_tx(meta.len);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error reading from WireGuard forwarder: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the server datapath until cancellation signal is received.
    pub async fn run(&mut self, cancel_rx: watch::Receiver<bool>) -> Result<(), TunnelError> {
        self.run_with_notify(cancel_rx, None).await
    }
}
