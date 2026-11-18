//! Single-stream tunnel endpoint engines for client and server.

#![forbid(unsafe_code)]

use crate::batch::{BatchedUdpSocket, RecvMeta, TransmitPacket};
use crate::keepalive::{AdaptiveKeepalive, AdaptiveKeepaliveConfig};
use crate::metrics::TunnelMetrics;
use bytes::{Bytes, BytesMut};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};
use wdtt_crypto::{
    CryptoError, DEFAULT_MAX_CLOCK_SKEW_SEC, KnockAuthenticator, Psk, derive_pre_auth_knock_key,
};
use wdtt_proto::{
    FrameType, FrameView, PingPayload, PongPayload, ProtoError, WgResequencer, encode_frame, flags,
    inspect_wg_packet,
};
use wdtt_turn::{
    StreamClientConfig, StreamServerConfig, StreamTurnClient, StreamTurnServer, TurnClient,
    TurnClientConfig, TurnError, TurnIncoming, TurnTransportMode, encode_channel_data,
    encode_tcp_channel_data,
};

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

    /// TUN device or WireGuard engine failure.
    #[error("TUN error: {0}")]
    Tun(#[from] wdtt_tun::TunError),

    /// WireGuard engine failure.
    #[error("WireGuard error: {0}")]
    Wg(#[from] wdtt_tun::WgError),
}

/// Keepalive and NAT maintenance mode for client tunnel session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeepaliveMode {
    /// Adaptive keepalive with Pong feedback (10s floor, starts at 20s, max 28s NAT ceiling).
    #[default]
    PowerSave,
    /// Continuous low-rate chaff traffic mimicking Opus voice codec (50 pps @ 20ms).
    Chaff,
    /// Keepalive disabled (manual testing).
    Disabled,
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
    /// Keepalive mode for connection maintenance and DPI chaffing.
    pub keepalive_mode: KeepaliveMode,
    /// Optional transmit coalescing window (e.g. 1-2 ms) for grouping sparse packets.
    pub coalesce_window: Option<Duration>,
    /// Transport mode: Udp, Tcp, Tls, or Auto.
    pub turn_transport: TurnTransportMode,
    /// Optional SNI hostname for TLS verification.
    pub turn_sni: Option<String>,
    /// Optional custom CA certificate DER bytes for TLS testing.
    pub custom_ca_der: Option<Vec<u8>>,
    /// Optional network interface name for SO_BINDTODEVICE.
    pub bind_interface: Option<String>,
    /// Optional TUN interface name. When set, the client owns a real TUN
    /// device and runs WireGuard in-process instead of bridging a UDP socket.
    pub tun_name: Option<String>,
    /// TUN interface MTU (default 1360).
    pub tun_mtu: u16,
    /// Local WireGuard private key (base64, as produced by `wg genkey`).
    pub wg_private_key: Option<String>,
    /// Peer WireGuard public key (base64).
    pub wg_peer_public_key: Option<String>,
    /// Optional WireGuard preshared key (base64).
    pub wg_preshared_key: Option<String>,
    /// WireGuard persistent keepalive in seconds.
    pub wg_keepalive: Option<u16>,
}

/// Configuration parameters for establishing a server tunnel session.
#[derive(Debug, Clone)]
pub struct TunnelServerConfig {
    /// TURN relay server address (used if direct_listen_addr is None).
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
    /// Optional transmit coalescing window (e.g. 1-2 ms) for grouping sparse packets.
    pub coalesce_window: Option<Duration>,
    /// Optional direct UDP listen address (VK / direct mode).
    pub direct_listen_addr: Option<SocketAddr>,
    /// Optional TCP/TLS listen address for the stream TURN server.
    pub stream_listen_addr: Option<SocketAddr>,
    /// Optional TLS certificate chain (DER) for the stream listener.
    pub tls_cert_der: Option<Vec<u8>>,
    /// Optional TLS private key (PKCS#8 DER) for the stream listener.
    pub tls_key_der: Option<Vec<u8>>,
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

/// Adaptive coalescing controller.
///
/// Evaluates arrival patterns per socket wakeup:
/// - Sparse / uniform traffic (packets_per_wakeup < 2): coalescing window (1-2 ms) is active to batch frames.
/// - Bursty traffic (packets_per_wakeup >= 2, e.g. TCP streams): coalescing is immediately disabled to minimize latency.
/// - Control frames (Handshake, Ping, Pong, Keepalive) ALWAYS bypass the coalescing window.
#[derive(Debug, Clone)]
pub struct AdaptiveCoalescer {
    window: Option<Duration>,
    last_batch_size: usize,
}

impl AdaptiveCoalescer {
    /// Create a new adaptive coalescer instance with optional window duration.
    pub fn new(window: Option<Duration>) -> Self {
        Self {
            window,
            last_batch_size: 1,
        }
    }

    /// Record the number of packets read during the latest wakeup batch.
    pub fn on_wakeup_batch(&mut self, batch_size: usize) {
        self.last_batch_size = batch_size;
    }

    /// Returns true if coalescing should be applied for the current packet batch.
    ///
    /// Enabled only if a coalescing window is configured AND traffic is sparse/uniform (batch_size < 2).
    /// Disabled immediately when traffic is bursty (batch_size >= 2).
    pub fn is_coalescing_active(&self) -> bool {
        self.window.is_some() && self.last_batch_size < 2
    }

    /// Get configured coalescing window duration.
    pub fn window(&self) -> Option<Duration> {
        self.window
    }
}

/// Control or signaling frames that must immediately bypass the coalescing window.
#[inline]
pub fn is_control_frame(frame_type: FrameType) -> bool {
    matches!(
        frame_type,
        FrameType::HandshakeInit
            | FrameType::HandshakeResp
            | FrameType::Ping
            | FrameType::Pong
            | FrameType::StreamFeedback
            | FrameType::Disconnect
    )
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
        cancel_rx: watch::Receiver<bool>,
        on_allocated: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), TunnelError> {
        if self.config.tun_name.is_some() {
            return self.run_tun_with_notify(cancel_rx, on_allocated).await;
        }
        match self.config.turn_transport {
            TurnTransportMode::Udp => self.run_udp_with_notify(cancel_rx, on_allocated).await,
            TurnTransportMode::Tcp | TurnTransportMode::Tls => {
                self.run_stream_with_notify(cancel_rx, on_allocated).await
            }
            TurnTransportMode::Auto => {
                let use_stream = self.probe_should_use_stream().await;
                if use_stream {
                    info!("Auto-selection: UDP unreachable or high loss, selecting TLS stream");
                    self.config.turn_transport = TurnTransportMode::Tls;
                    self.run_stream_with_notify(cancel_rx, on_allocated).await
                } else {
                    info!("Auto-selection: UDP reachable, selecting UDP datagram transport");
                    self.config.turn_transport = TurnTransportMode::Udp;
                    self.run_udp_with_notify(cancel_rx, on_allocated).await
                }
            }
        }
    }

    async fn probe_should_use_stream(&self) -> bool {
        let turn_cfg = TurnClientConfig {
            server_addr: self.config.turn_server_addr,
            peer_addr: self.config.server_relayed_addr,
            username: self.config.turn_username.clone(),
            password: self.config.turn_password.clone(),
            channel_number: 0x4000,
            lifetime_sec: 60,
        };
        let probe_fut = async {
            let mut client = TurnClient::bind("0.0.0.0:0".parse().unwrap(), turn_cfg).await?;
            client.allocate_relay().await
        };
        !matches!(
            tokio::time::timeout(Duration::from_millis(1500), probe_fut).await,
            Ok(Ok(_))
        )
    }

    async fn run_udp_with_notify(
        &mut self,
        mut cancel_rx: watch::Receiver<bool>,
        on_allocated: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), TunnelError> {
        info!(
            "Starting TunnelClient (UDP mode): relaying to {} via TURN {}",
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

        turn_client
            .bind_peer(self.config.server_relayed_addr)
            .await?;
        info!("Client bound peer {}", self.config.server_relayed_addr);

        // Derive dynamic refresh intervals from negotiated TURN LIFETIME
        let mut alloc_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + turn_client.allocation_refresh_interval(),
            turn_client.allocation_refresh_interval(),
        );
        let mut perm_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + turn_client.permission_refresh_interval(),
            turn_client.permission_refresh_interval(),
        );
        let mut chan_bind_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + turn_client.channel_bind_refresh_interval(),
            turn_client.channel_bind_refresh_interval(),
        );

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
        info!("Pre-Auth knock sent to server");

        if let Some(tx) = on_allocated {
            let _ = tx.send(my_relayed);
        }

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

        let mut adaptive_keepalive =
            AdaptiveKeepalive::new(AdaptiveKeepaliveConfig::default(), Instant::now());
        let mut last_chaff_activity = Instant::now();

        let mut powersave_deadline =
            tokio::time::Instant::now() + adaptive_keepalive.current_interval();
        let powersave_sleep = tokio::time::sleep_until(powersave_deadline);
        tokio::pin!(powersave_sleep);

        let mut chaff_ticker = interval(Duration::from_millis(20));
        chaff_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut consecutive_losses: u32 = 0;

        // Coalescing buffers for client
        let mut pending_turn_frames: Vec<BytesMut> = Vec::with_capacity(BATCH_SIZE);
        let mut coalesce_turn_deadline: Option<tokio::time::Instant> = None;
        let coalesce_turn_sleep = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(coalesce_turn_sleep);

        let mut pending_wg_frames: Vec<BytesMut> = Vec::with_capacity(BATCH_SIZE);
        let mut coalesce_wg_deadline: Option<tokio::time::Instant> = None;
        let coalesce_wg_sleep = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(coalesce_wg_sleep);

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

                () = &mut powersave_sleep, if self.config.keepalive_mode == KeepaliveMode::PowerSave => {
                    let now = Instant::now();
                    if adaptive_keepalive.has_pending_probe() {
                        warn!("Keepalive probe timed out, rolling back to floor");
                        adaptive_keepalive.on_loss(now);
                        consecutive_losses += 1;
                        if consecutive_losses >= 3 {
                            warn!("3 consecutive keepalive timeouts; attempting reconnection...");
                            if let Ok(new_relayed) = turn_client.reconnect().await {
                                info!("TunnelClient successfully reconnected to TURN relay at {new_relayed}");
                                let now_sec = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                let mut client_nonce = [0u8; 16];
                                let mut session_id = [0u8; 16];
                                rand::rng().fill_bytes(&mut client_nonce);
                                rand::rng().fill_bytes(&mut session_id);
                                let knock_wire = auth.generate_knock_packet(now_sec, &client_nonce, &session_id, 32);
                                let mut knock_frame = BytesMut::new();
                                encode_frame(FrameType::HandshakeInit, 0, 0, 0, &knock_wire, &mut knock_frame);
                                let _ = turn_client.send_channel_data(&knock_frame).await;
                                consecutive_losses = 0;
                            }
                        }
                        powersave_deadline = tokio::time::Instant::now() + adaptive_keepalive.current_interval();
                        powersave_sleep.as_mut().reset(powersave_deadline);
                    } else {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let probe_id = seq_tx;
                        let ping = PingPayload {
                            timestamp: now_ms,
                            probe_id,
                        };
                        let mut pbuf = [0u8; PingPayload::LEN];
                        ping.encode(&mut pbuf);
                        let mut ping_frame = BytesMut::new();
                        encode_frame(
                            FrameType::Ping,
                            0,
                            0,
                            probe_id,
                            &pbuf,
                            &mut ping_frame,
                        );
                        seq_tx = seq_tx.wrapping_add(1);

                        if let Err(e) = turn_client.send_channel_data(&ping_frame).await {
                            warn!("Failed to send Keepalive Ping: {e}");
                            adaptive_keepalive.on_loss(now);
                            powersave_deadline = tokio::time::Instant::now() + adaptive_keepalive.current_interval();
                        } else {
                            self.metrics.record_ping_tx();
                            adaptive_keepalive.record_probe_sent(probe_id, now);
                            powersave_deadline = tokio::time::Instant::now() + adaptive_keepalive.probe_timeout();
                        }
                        powersave_sleep.as_mut().reset(powersave_deadline);
                    }
                }

                _ = chaff_ticker.tick(), if self.config.keepalive_mode == KeepaliveMode::Chaff => {
                    let now = Instant::now();
                    if now.saturating_duration_since(last_chaff_activity) >= Duration::from_millis(18) {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let ping = PingPayload {
                            timestamp: now_ms,
                            probe_id: seq_tx,
                        };
                        let mut pbuf = [0u8; PingPayload::LEN];
                        ping.encode(&mut pbuf);

                        let pad_len = 60 + ((now_ms ^ (seq_tx as u64)) % 81) as usize;
                        let mut chaff_payload = Vec::with_capacity(PingPayload::LEN + pad_len);
                        chaff_payload.extend_from_slice(&pbuf);
                        chaff_payload.resize(PingPayload::LEN + pad_len, 0xAA);

                        let mut frame = BytesMut::new();
                        encode_frame(
                            FrameType::Ping,
                            flags::PADDING_PRESENT,
                            0,
                            seq_tx,
                            &chaff_payload,
                            &mut frame,
                        );
                        seq_tx = seq_tx.wrapping_add(1);

                        if let Err(e) = turn_client.send_channel_data(&frame).await {
                            warn!("Failed to send Chaff Ping: {e}");
                        } else {
                            self.metrics.record_ping_tx();
                        }
                        last_chaff_activity = now;
                    }
                }

                () = &mut coalesce_turn_sleep, if coalesce_turn_deadline.is_some() => {
                    if !pending_turn_frames.is_empty() {
                        let pkts: Vec<TransmitPacket> = pending_turn_frames.iter().map(|b| TransmitPacket {
                            buf: b,
                            addr: self.config.turn_server_addr,
                            gso_segment_size: None,
                        }).collect();
                        let _ = batched_turn.send_batch(&pkts).await;
                        pending_turn_frames.clear();
                    }
                    coalesce_turn_deadline = None;
                }

                () = &mut coalesce_wg_sleep, if coalesce_wg_deadline.is_some() => {
                    if !pending_wg_frames.is_empty() {
                        if let Some(target) = wg_peer_addr {
                            let pkts: Vec<TransmitPacket> = pending_wg_frames.iter().map(|b| TransmitPacket {
                                buf: b,
                                addr: target,
                                gso_segment_size: None,
                            }).collect();
                            let _ = batched_wg.send_batch(&pkts).await;
                        }
                        pending_wg_frames.clear();
                    }
                    coalesce_wg_deadline = None;
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
                            self.metrics.record_batch_rx(count);
                            if count > 0 {
                                let now = Instant::now();
                                last_chaff_activity = now;
                                adaptive_keepalive.on_tx(now);
                                if self.config.keepalive_mode == KeepaliveMode::PowerSave && !adaptive_keepalive.has_pending_probe() {
                                    powersave_deadline = tokio::time::Instant::now() + adaptive_keepalive.current_interval();
                                    powersave_sleep.as_mut().reset(powersave_deadline);
                                }
                            }
                            for i in 0..count {
                                let meta = wg_batch_metas[i];
                                wg_peer_addr = Some(meta.addr);
                                let payload = &wg_batch_bufs[i][..meta.len];

                                let mut frame = BytesMut::new();
                                encode_frame(FrameType::Data, 0, 0, seq_tx, payload, &mut frame);
                                seq_tx = seq_tx.wrapping_add(1);

                                let mut chan_buf = BytesMut::new();
                                if encode_channel_data(turn_client.channel_number(), &frame, false, &mut chan_buf).is_ok() {
                                    pending_turn_frames.push(chan_buf);
                                    self.metrics.record_tx(meta.len);
                                }
                            }

                            if let Some(window) = self.config.coalesce_window {
                                if pending_turn_frames.len() >= BATCH_SIZE {
                                    let pkts: Vec<TransmitPacket> = pending_turn_frames.iter().map(|b| TransmitPacket {
                                        buf: b,
                                        addr: self.config.turn_server_addr,
                                        gso_segment_size: None,
                                    }).collect();
                                    let _ = batched_turn.send_batch(&pkts).await;
                                    pending_turn_frames.clear();
                                    coalesce_turn_deadline = None;
                                } else if !pending_turn_frames.is_empty() && coalesce_turn_deadline.is_none() {
                                    let d = tokio::time::Instant::now() + window;
                                    coalesce_turn_deadline = Some(d);
                                    coalesce_turn_sleep.as_mut().reset(d);
                                }
                            } else if !pending_turn_frames.is_empty() {
                                trace!("TunnelClient sending {} frames to TURN {}", pending_turn_frames.len(), self.config.turn_server_addr);
                                let pkts: Vec<TransmitPacket> = pending_turn_frames.iter().map(|b| TransmitPacket {
                                    buf: b,
                                    addr: self.config.turn_server_addr,
                                    gso_segment_size: None,
                                }).collect();
                                let _ = batched_turn.send_batch(&pkts).await;
                                pending_turn_frames.clear();
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
                            self.metrics.record_batch_rx(count);
                            for i in 0..count {
                                let meta = turn_batch_metas[i];
                                let slice = &turn_batch_bufs[i][..meta.len];
                                let incoming = turn_client.parse_incoming(slice, meta.addr);
                                let payload = match incoming {
                                    Ok(Some(TurnIncoming::ChannelData { payload, .. })) => Some(payload),
                                    Ok(Some(TurnIncoming::DataIndication { payload, .. })) => Some(payload),
                                    _ => None,
                                };
                                if let Some(payload) = payload
                                    && let Ok((view, _)) = FrameView::decode(&payload)
                                {
                                        trace!("TunnelClient received frame type: {:?}", view.header.frame_type);
                                        match view.header.frame_type {
                                            FrameType::Data => {
                                                let data_payload = view.payload;
                                                adaptive_keepalive.on_rx_data(Instant::now());
                                                self.metrics.record_rx(data_payload.len());

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
                                                            let mut b = BytesMut::new();
                                                            b.extend_from_slice(&pkt);
                                                            pending_wg_frames.push(b);
                                                        }
                                                    } else {
                                                        let mut b = BytesMut::new();
                                                        b.extend_from_slice(data_payload);
                                                        pending_wg_frames.push(b);
                                                    }
                                                } else {
                                                    let mut b = BytesMut::new();
                                                    b.extend_from_slice(data_payload);
                                                    pending_wg_frames.push(b);
                                                }
                                            }
                                            FrameType::Pong => {
                                                if let Ok(pong) = PongPayload::decode(view.payload) {
                                                    let now = Instant::now();
                                                    let now_ms = SystemTime::now()
                                                        .duration_since(UNIX_EPOCH)
                                                        .unwrap_or_default()
                                                        .as_millis() as u64;
                                                    let rtt = now_ms.saturating_sub(pong.echo_timestamp);
                                                    self.metrics.record_rtt_sample(rtt);
                                                    if adaptive_keepalive.on_pong(pong.probe_id, now) {
                                                        consecutive_losses = 0;
                                                        let confirmed_sec =
                                                            adaptive_keepalive.confirmed_interval().as_secs();
                                                        self.metrics.record_confirmed_keepalive(confirmed_sec);
                                                        if self.config.keepalive_mode == KeepaliveMode::PowerSave {
                                                            powersave_deadline = tokio::time::Instant::now()
                                                                + adaptive_keepalive.current_interval();
                                                            powersave_sleep.as_mut().reset(powersave_deadline);
                                                        }
                                                        trace!(
                                                            "Client received Pong #{} (RTT: {} ms), confirmed keepalive {}s, next probe in {}s",
                                                            pong.probe_id,
                                                            rtt,
                                                            confirmed_sec,
                                                            adaptive_keepalive.current_interval().as_secs()
                                                        );
                                                    } else {
                                                        trace!(
                                                            "Client received Pong #{} (RTT: {} ms)",
                                                            pong.probe_id, rtt
                                                        );
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

                            if let Some(target) = wg_peer_addr {
                                if let Some(window) = self.config.coalesce_window {
                                    if pending_wg_frames.len() >= BATCH_SIZE {
                                        let pkts: Vec<TransmitPacket> = pending_wg_frames.iter().map(|b| TransmitPacket {
                                            buf: b,
                                            addr: target,
                                            gso_segment_size: None,
                                        }).collect();
                                        let _ = batched_wg.send_batch(&pkts).await;
                                        pending_wg_frames.clear();
                                        coalesce_wg_deadline = None;
                                    } else if !pending_wg_frames.is_empty() && coalesce_wg_deadline.is_none() {
                                        let d = tokio::time::Instant::now() + window;
                                        coalesce_wg_deadline = Some(d);
                                        coalesce_wg_sleep.as_mut().reset(d);
                                    }
                                } else if !pending_wg_frames.is_empty() {
                                    trace!("TunnelClient forwarding {} packets to WG target {}", pending_wg_frames.len(), target);
                                    let pkts: Vec<TransmitPacket> = pending_wg_frames.iter().map(|b| TransmitPacket {
                                        buf: b,
                                        addr: target,
                                        gso_segment_size: None,
                                    }).collect();
                                    let _ = batched_wg.send_batch(&pkts).await;
                                    pending_wg_frames.clear();
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

    async fn run_stream_with_notify(
        &mut self,
        mut cancel_rx: watch::Receiver<bool>,
        on_allocated: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), TunnelError> {
        info!(
            "Starting TunnelClient (Stream mode {:?}): relaying to {} via TURN {}",
            self.config.turn_transport,
            self.config.server_relayed_addr,
            self.config.turn_server_addr
        );

        let wg_socket = Arc::new(bind_tuned_udp_socket(self.config.wg_listen_addr)?);
        info!("WireGuard bridge listening on {}", wg_socket.local_addr()?);

        let stream_cfg = StreamClientConfig {
            server_addr: self.config.turn_server_addr,
            peer_addr: self.config.server_relayed_addr,
            username: self.config.turn_username.clone(),
            password: self.config.turn_password.clone(),
            channel_number: 0x4000,
            lifetime_sec: 600,
            transport: self.config.turn_transport,
            sni: self.config.turn_sni.clone(),
            custom_ca_der: self.config.custom_ca_der.clone(),
            bind_interface: self.config.bind_interface.clone(),
            tx_queue_capacity: 1024,
        };

        let mut stream_client = StreamTurnClient::connect(stream_cfg).await?;
        let my_relayed = stream_client.allocate_relay().await?;
        info!("Client allocated relay address over stream: {my_relayed}");

        stream_client
            .bind_peer(self.config.server_relayed_addr)
            .await?;
        info!("Client bound peer {}", self.config.server_relayed_addr);

        let mut alloc_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + stream_client.allocation_refresh_interval(),
            stream_client.allocation_refresh_interval(),
        );
        let mut perm_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + stream_client.permission_refresh_interval(),
            stream_client.permission_refresh_interval(),
        );
        let mut chan_bind_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + stream_client.channel_bind_refresh_interval(),
            stream_client.channel_bind_refresh_interval(),
        );

        let knock_key = derive_pre_auth_knock_key(&Psk::from_bytes(self.config.psk));
        let auth = KnockAuthenticator::new(knock_key, DEFAULT_MAX_CLOCK_SKEW_SEC);
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
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
        stream_client.send_channel_data(&knock_frame).await?;
        info!("Pre-Auth knock sent to server over stream");

        if let Some(tx) = on_allocated {
            let _ = tx.send(my_relayed);
        }

        let batched_wg = BatchedUdpSocket::new(wg_socket.clone());
        let mut resequencer = WgResequencer::new(4096, Duration::from_millis(15));
        let mut wg_peer_addr: Option<SocketAddr> = None;
        let mut seq_tx: u16 = 0;

        const BATCH_SIZE: usize = 16;
        let mut wg_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut wg_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        let mut tick_timer = interval(RESEQUENCER_TICK_INTERVAL);
        let mut adaptive_keepalive =
            AdaptiveKeepalive::new(AdaptiveKeepaliveConfig::default(), Instant::now());
        let mut powersave_deadline =
            tokio::time::Instant::now() + adaptive_keepalive.current_interval();
        let powersave_sleep = tokio::time::sleep_until(powersave_deadline);
        tokio::pin!(powersave_sleep);

        loop {
            tokio::select! {
                biased;

                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        info!("TunnelClient stream shutting down via cancel signal");
                        break;
                    }
                }

                _ = alloc_refresh_timer.tick() => {
                    let requested_sec = stream_client.negotiated_lifetime();
                    trace!("Stream TURN allocation refreshing ({requested_sec}s)");
                    if let Err(e) = stream_client.refresh_allocation(requested_sec).await {
                        warn!("Failed to refresh stream TURN allocation: {e}");
                    }
                }

                _ = perm_refresh_timer.tick() => {
                    trace!("Stream TURN permission refreshing");
                    if let Err(e) = stream_client.refresh_permission().await {
                        warn!("Failed to refresh stream TURN permission: {e}");
                    }
                }

                _ = chan_bind_refresh_timer.tick() => {
                    trace!("Stream TURN channel bind refreshing");
                    if let Err(e) = stream_client.refresh_channel_bind().await {
                        warn!("Failed to refresh stream TURN channel bind: {e}");
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

                () = &mut powersave_sleep, if self.config.keepalive_mode == KeepaliveMode::PowerSave => {
                    let now = Instant::now();
                    if adaptive_keepalive.has_pending_probe() {
                        adaptive_keepalive.on_loss(now);
                        powersave_deadline = tokio::time::Instant::now() + adaptive_keepalive.current_interval();
                        powersave_sleep.as_mut().reset(powersave_deadline);
                    } else {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let probe_id = seq_tx;
                        let ping = PingPayload {
                            timestamp: now_ms,
                            probe_id,
                        };
                        let mut pbuf = [0u8; PingPayload::LEN];
                        ping.encode(&mut pbuf);
                        let mut ping_frame = BytesMut::new();
                        encode_frame(
                            FrameType::Ping,
                            0,
                            0,
                            probe_id,
                            &pbuf,
                            &mut ping_frame,
                        );
                        seq_tx = seq_tx.wrapping_add(1);
                        if let Err(e) = stream_client.send_channel_data(&ping_frame).await {
                            warn!("Failed to send Keepalive Ping over stream: {e}");
                            adaptive_keepalive.on_loss(now);
                        } else {
                            self.metrics.record_ping_tx();
                            adaptive_keepalive.record_probe_sent(probe_id, now);
                        }
                        powersave_deadline = tokio::time::Instant::now() + adaptive_keepalive.current_interval();
                        powersave_sleep.as_mut().reset(powersave_deadline);
                    }
                }

                // Packets from WireGuard -> send over stream
                wg_batch_res = batched_wg.recv_batch(&mut wg_batch_bufs, &mut wg_batch_metas) => {
                    match wg_batch_res {
                        Ok(count) => {
                            self.metrics.record_batch_rx(count);
                            for i in 0..count {
                                let meta = wg_batch_metas[i];
                                wg_peer_addr = Some(meta.addr);
                                let payload = &wg_batch_bufs[i][..meta.len];

                                let mut frame = BytesMut::new();
                                encode_frame(FrameType::Data, 0, 0, seq_tx, payload, &mut frame);
                                seq_tx = seq_tx.wrapping_add(1);

                                if let Err(e) = stream_client.send_channel_data(&frame).await {
                                    warn!("Failed to send ChannelData over stream: {e}");
                                } else {
                                    self.metrics.record_tx(meta.len);
                                }
                            }
                        }
                        Err(e) => {
                            trace!("WG recv_batch error: {e}");
                        }
                    }
                }

                // Incoming frames from stream -> forward to WireGuard
                stream_msg_res = stream_client.recv_frame() => {
                    match stream_msg_res {
                        Ok(turn_incoming) => {
                            let payload = match turn_incoming {
                                TurnIncoming::ChannelData { payload, .. } => payload,
                                TurnIncoming::DataIndication { payload, .. } => payload,
                                _ => bytes::Bytes::new(),
                            };

                            if payload.is_empty() {
                                continue;
                            }

                            if let Ok((view, _)) = FrameView::decode(&payload) {
                                match view.header.frame_type {
                                    FrameType::Data => {
                                        let data_payload = view.payload;
                                        adaptive_keepalive.on_rx_data(Instant::now());
                                        self.metrics.record_rx(data_payload.len());

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
                                                if let Some(target) = wg_peer_addr {
                                                    for pkt in ordered {
                                                        let _ = wg_socket.send_to(&pkt, target).await;
                                                    }
                                                }
                                            } else if let Some(target) = wg_peer_addr {
                                                let _ = wg_socket.send_to(data_payload, target).await;
                                            }
                                        } else if let Some(target) = wg_peer_addr {
                                            let _ = wg_socket.send_to(data_payload, target).await;
                                        }
                                    }
                                    FrameType::Pong => {
                                        if let Ok(pong) = PongPayload::decode(view.payload) {
                                            let now = Instant::now();
                                            let now_ms = SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_millis() as u64;
                                            let rtt = now_ms.saturating_sub(pong.echo_timestamp);
                                            self.metrics.record_rtt_sample(rtt);
                                            if adaptive_keepalive.on_pong(pong.probe_id, now) {
                                                let confirmed_sec =
                                                    adaptive_keepalive.confirmed_interval().as_secs();
                                                self.metrics.record_confirmed_keepalive(confirmed_sec);
                                            }
                                        }
                                    }
                                    FrameType::HandshakeResp => {
                                        info!("Pre-Auth handshake confirmed by server over stream!");
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(e) => {
                            error!("StreamTurnClient error: {e}");
                            return Err(TunnelError::Turn(e));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the client datapath with a real TUN device and in-process WireGuard.
    ///
    /// The TUN interface carries plain IP packets; [`WgEngine`] encrypts them
    /// and the resulting datagrams ride the same TURN transport as the UDP
    /// bridge mode. Requires `tun_name`, `wg_private_key` and
    /// `wg_peer_public_key` in the config.
    async fn run_tun_with_notify(
        &mut self,
        cancel_rx: watch::Receiver<bool>,
        on_allocated: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), TunnelError> {
        let tun_name = self
            .config
            .tun_name
            .clone()
            .ok_or_else(|| TunnelError::Timeout("tun_name missing".into()))?;
        let private = self
            .config
            .wg_private_key
            .clone()
            .ok_or_else(|| TunnelError::Timeout("wg_private_key missing".into()))?;
        let peer = self
            .config
            .wg_peer_public_key
            .clone()
            .ok_or_else(|| TunnelError::Timeout("wg_peer_public_key missing".into()))?;

        let engine = wdtt_tun::WgEngine::from_base64(
            &private,
            &peer,
            self.config.wg_preshared_key.as_deref(),
            self.config.wg_keepalive,
            1,
        )?;

        info!(
            "Starting TunnelClient (TUN mode): {} <-> WG <-> TURN {}",
            tun_name, self.config.turn_server_addr
        );

        let stream_cfg = StreamClientConfig {
            server_addr: self.config.turn_server_addr,
            peer_addr: self.config.server_relayed_addr,
            username: self.config.turn_username.clone(),
            password: self.config.turn_password.clone(),
            channel_number: 0x4000,
            lifetime_sec: 600,
            transport: self.config.turn_transport,
            sni: self.config.turn_sni.clone(),
            custom_ca_der: self.config.custom_ca_der.clone(),
            bind_interface: self.config.bind_interface.clone(),
            tx_queue_capacity: 1024,
        };

        let mut stream_client = StreamTurnClient::connect(stream_cfg).await?;
        let my_relayed = stream_client.allocate_relay().await?;
        info!("Client allocated relay address over stream: {my_relayed}");

        stream_client
            .bind_peer(self.config.server_relayed_addr)
            .await?;
        info!("Client bound peer {}", self.config.server_relayed_addr);

        let knock_key = derive_pre_auth_knock_key(&Psk::from_bytes(self.config.psk));
        let auth = KnockAuthenticator::new(knock_key, DEFAULT_MAX_CLOCK_SKEW_SEC);
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
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
        stream_client.send_channel_data(&knock_frame).await?;
        info!("Pre-Auth knock sent to server over stream");

        if let Some(tx) = on_allocated {
            let _ = tx.send(my_relayed);
        }

        let mut alloc_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + stream_client.allocation_refresh_interval(),
            stream_client.allocation_refresh_interval(),
        );
        let mut perm_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + stream_client.permission_refresh_interval(),
            stream_client.permission_refresh_interval(),
        );
        let mut chan_bind_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + stream_client.channel_bind_refresh_interval(),
            stream_client.channel_bind_refresh_interval(),
        );

        let (wg_tx, mut wg_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);
        let mut seq_tx: u16 = 0;

        let send_wg = move |datagram: Vec<u8>| -> crate::tun_datapath::BoxFut<'static, Result<(), TunnelError>> {
            let tx = wg_tx.clone();
            Box::pin(async move {
                tx.send(datagram)
                    .await
                    .map_err(|_| TunnelError::Timeout("WG queue closed".into()))
            })
        };
        let in_rx = Arc::new(tokio::sync::Mutex::new(in_rx));
        let recv_wg = move || -> crate::tun_datapath::BoxFut<'static, Option<Vec<u8>>> {
            let rx = in_rx.clone();
            Box::pin(async move { rx.lock().await.recv().await })
        };

        let dp_cfg = crate::tun_datapath::TunDatapathConfig {
            tun_name,
            tun_mtu: self.config.tun_mtu,
            persistent_keepalive: self.config.wg_keepalive,
        };
        let dp_cancel = cancel_rx.clone();
        let datapath = tokio::spawn(async move {
            crate::tun_datapath::run_tun_datapath(dp_cfg, engine, send_wg, recv_wg, dp_cancel).await
        });

        let mut cancel_rx = cancel_rx;
        let result = loop {
            tokio::select! {
                biased;

                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        info!("TunnelClient TUN shutting down via cancel signal");
                        break Ok(());
                    }
                }

                _ = alloc_refresh_timer.tick() => {
                    let requested_sec = stream_client.negotiated_lifetime();
                    if let Err(e) = stream_client.refresh_allocation(requested_sec).await {
                        warn!("Failed to refresh stream TURN allocation: {e}");
                    }
                }

                _ = perm_refresh_timer.tick() => {
                    if let Err(e) = stream_client.refresh_permission().await {
                        warn!("Failed to refresh stream TURN permission: {e}");
                    }
                }

                _ = chan_bind_refresh_timer.tick() => {
                    if let Err(e) = stream_client.refresh_channel_bind().await {
                        warn!("Failed to refresh stream TURN channel bind: {e}");
                    }
                }

                Some(datagram) = wg_rx.recv() => {
                    let mut frame = BytesMut::new();
                    encode_frame(FrameType::Data, 0, 0, seq_tx, &datagram, &mut frame);
                    seq_tx = seq_tx.wrapping_add(1);
                    if let Err(e) = stream_client.send_channel_data(&frame).await {
                        warn!("Failed to send ChannelData over stream: {e}");
                    } else {
                        self.metrics.record_tx(datagram.len());
                    }
                }

                stream_msg_res = stream_client.recv_frame() => {
                    match stream_msg_res {
                        Ok(turn_incoming) => {
                            let payload = match turn_incoming {
                                TurnIncoming::ChannelData { payload, .. } => payload,
                                TurnIncoming::DataIndication { payload, .. } => payload,
                                _ => Bytes::new(),
                            };
                            if payload.is_empty() {
                                continue;
                            }
                            if let Ok((view, _)) = FrameView::decode(&payload) {
                                match view.header.frame_type {
                                    FrameType::Data => {
                                        self.metrics.record_rx(view.payload.len());
                                        if in_tx.send(view.payload.to_vec()).await.is_err() {
                                            warn!("TUN datapath closed, stopping");
                                            break Ok(());
                                        }
                                    }
                                    FrameType::HandshakeResp => {
                                        info!("Pre-Auth handshake confirmed by server over stream!");
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(e) => {
                            error!("StreamTurnClient error: {e}");
                            break Err(TunnelError::Turn(e));
                        }
                    }
                }
            }
        };

        let _ = cancel_rx; // keep the receiver alive until shutdown
        datapath.abort();
        result
    }

    /// Run the client datapath until cancellation signal is received.
    pub async fn run(&mut self, cancel_rx: watch::Receiver<bool>) -> Result<(), TunnelError> {
        self.run_with_notify(cancel_rx, None).await
    }
}

/// Worker task managing a single client session on the server.
///
/// Session Affinity: All datagrams for this client session are processed strictly
/// sequentially by this single async worker task, preventing any packet reordering
/// across Tokio threads and eliminating spurious TCP SACK retransmits.
pub struct SessionWorker {
    /// Relayed client address on the TURN server.
    pub relayed_peer: SocketAddr,
    /// 16-byte unique session ID from knock.
    pub session_id: [u8; 16],
    /// WireGuard backend endpoint address.
    pub wg_endpoint_addr: SocketAddr,
    /// TURN relay server address.
    pub turn_server_addr: SocketAddr,
    /// Shared batched socket handle to TURN relay.
    pub batched_turn: Arc<BatchedUdpSocket>,
    /// Negotiated or allocated TURN channel number for this peer.
    pub turn_channel_number: u16,
    /// Server metrics collector handle.
    pub metrics: Arc<TunnelMetrics>,
    /// Optional transmit coalescing window duration.
    pub coalesce_window: Option<Duration>,
    /// Inbound frame queue from TURN dispatcher.
    pub inbound_rx: mpsc::Receiver<BytesMut>,
}

impl SessionWorker {
    /// Run the session worker datapath until cancelled.
    pub async fn run(mut self, mut cancel_rx: watch::Receiver<bool>) -> Result<(), TunnelError> {
        let wg_socket = Arc::new(bind_tuned_udp_socket("0.0.0.0:0".parse().unwrap())?);
        let batched_wg = BatchedUdpSocket::new(wg_socket.clone());

        const BATCH_SIZE: usize = 16;
        let mut wg_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut wg_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        let mut pending_turn_frames: Vec<BytesMut> = Vec::with_capacity(BATCH_SIZE);
        let mut coalesce_turn_deadline: Option<tokio::time::Instant> = None;
        let coalesce_turn_sleep = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(coalesce_turn_sleep);

        let mut pending_wg_frames: Vec<BytesMut> = Vec::with_capacity(BATCH_SIZE);
        let mut coalesce_wg_deadline: Option<tokio::time::Instant> = None;
        let coalesce_wg_sleep = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(coalesce_wg_sleep);

        let mut adaptive_coalescer = AdaptiveCoalescer::new(self.coalesce_window);
        let mut seq_tx: u16 = 0;
        let mut last_activity = Instant::now();
        let mut inactivity_timer = interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                biased;

                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        trace!("SessionWorker for {} shutting down via cancel signal", self.relayed_peer);
                        break;
                    }
                }

                _ = inactivity_timer.tick() => {
                    if last_activity.elapsed() >= DEFAULT_SESSION_TTL {
                        info!("SessionWorker for {} timed out after {:?}", self.relayed_peer, DEFAULT_SESSION_TTL);
                        break;
                    }
                }

                () = &mut coalesce_turn_sleep, if coalesce_turn_deadline.is_some() => {
                    if !pending_turn_frames.is_empty() {
                        let pkts: Vec<TransmitPacket> = pending_turn_frames.iter().map(|b| TransmitPacket {
                            buf: b,
                            addr: self.turn_server_addr,
                            gso_segment_size: None,
                        }).collect();
                        let _ = self.batched_turn.send_batch(&pkts).await;
                        pending_turn_frames.clear();
                    }
                    coalesce_turn_deadline = None;
                }

                () = &mut coalesce_wg_sleep, if coalesce_wg_deadline.is_some() => {
                    if !pending_wg_frames.is_empty() {
                        let pkts: Vec<TransmitPacket> = pending_wg_frames.iter().map(|b| TransmitPacket {
                            buf: b,
                            addr: self.wg_endpoint_addr,
                            gso_segment_size: None,
                        }).collect();
                        let _ = batched_wg.send_batch(&pkts).await;
                        pending_wg_frames.clear();
                    }
                    coalesce_wg_deadline = None;
                }

                // Inbound frames from TURN dispatcher for this specific session
                Some(payload) = self.inbound_rx.recv() => {
                    last_activity = Instant::now();
                    if let Ok((view, _)) = FrameView::decode(&payload) {
                        let is_ctrl = is_control_frame(view.header.frame_type);
                        match view.header.frame_type {
                            FrameType::Data => {
                                self.metrics.record_rx(view.payload.len());
                                let mut b = BytesMut::new();
                                b.extend_from_slice(view.payload);
                                pending_wg_frames.push(b);
                            }
                            FrameType::Ping => {
                                self.metrics.record_ping_rx();
                                let echo_ts = PingPayload::decode(view.payload)
                                    .map(|p| p.timestamp)
                                    .unwrap_or(0);
                                let now_ms = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64;
                                let pong = PongPayload {
                                    echo_timestamp: echo_ts,
                                    probe_id: view.header.seq,
                                    receive_timestamp: now_ms,
                                };
                                let mut pbuf = [0u8; PongPayload::LEN];
                                pong.encode(&mut pbuf);

                                let mut resp_frame = BytesMut::new();
                                encode_frame(
                                    FrameType::Pong,
                                    0,
                                    0,
                                    seq_tx,
                                    &pbuf,
                                    &mut resp_frame,
                                );
                                seq_tx = seq_tx.wrapping_add(1);

                                let mut chan_buf = BytesMut::new();
                                if encode_channel_data(self.turn_channel_number, &resp_frame, false, &mut chan_buf).is_ok() {
                                    // Control frames bypass the coalescing buffer and flush immediately
                                    let mut pkts: Vec<TransmitPacket> = pending_turn_frames.iter().map(|b| TransmitPacket {
                                        buf: b,
                                        addr: self.turn_server_addr,
                                        gso_segment_size: None,
                                    }).collect();
                                    pkts.push(TransmitPacket {
                                        buf: &chan_buf,
                                        addr: self.turn_server_addr,
                                        gso_segment_size: None,
                                    });
                                    let _ = self.batched_turn.send_batch(&pkts).await;
                                    pending_turn_frames.clear();
                                    coalesce_turn_deadline = None;
                                }
                            }
                            _ => {}
                        }

                        // Flush or buffer WireGuard-bound frames
                        if !pending_wg_frames.is_empty() {
                            if is_ctrl || !adaptive_coalescer.is_coalescing_active() || pending_wg_frames.len() >= BATCH_SIZE {
                                let pkts: Vec<TransmitPacket> = pending_wg_frames.iter().map(|b| TransmitPacket {
                                    buf: b,
                                    addr: self.wg_endpoint_addr,
                                    gso_segment_size: None,
                                }).collect();
                                trace!("SessionWorker forwarding {} packets to WG endpoint {}", pkts.len(), self.wg_endpoint_addr);
                                let _ = batched_wg.send_batch(&pkts).await;
                                pending_wg_frames.clear();
                                coalesce_wg_deadline = None;
                            } else if coalesce_wg_deadline.is_none()
                                && let Some(window) = adaptive_coalescer.window()
                            {
                                let d = tokio::time::Instant::now() + window;
                                coalesce_wg_deadline = Some(d);
                                coalesce_wg_sleep.as_mut().reset(d);
                            }
                        }
                    }
                }

                // Packets from WireGuard backend -> send to client over TURN
                wg_batch_res = batched_wg.recv_batch(&mut wg_batch_bufs, &mut wg_batch_metas) => {
                    match wg_batch_res {
                        Ok(count) => {
                            self.metrics.record_batch_rx(count);
                            adaptive_coalescer.on_wakeup_batch(count);
                            trace!("SessionWorker received {} packets from WG backend", count);

                            for i in 0..count {
                                let meta = wg_batch_metas[i];
                                let payload = &wg_batch_bufs[i][..meta.len];
                                let mut frame = BytesMut::new();
                                encode_frame(FrameType::Data, 0, 0, seq_tx, payload, &mut frame);
                                seq_tx = seq_tx.wrapping_add(1);

                                let mut chan_buf = BytesMut::new();
                                if encode_channel_data(self.turn_channel_number, &frame, false, &mut chan_buf).is_ok() {
                                    pending_turn_frames.push(chan_buf);
                                    self.metrics.record_tx(meta.len);
                                }
                            }

                            if !pending_turn_frames.is_empty() {
                                if !adaptive_coalescer.is_coalescing_active() || pending_turn_frames.len() >= BATCH_SIZE {
                                    let pkts: Vec<TransmitPacket> = pending_turn_frames.iter().map(|b| TransmitPacket {
                                        buf: b,
                                        addr: self.turn_server_addr,
                                        gso_segment_size: None,
                                    }).collect();
                                    let _ = self.batched_turn.send_batch(&pkts).await;
                                    pending_turn_frames.clear();
                                    coalesce_turn_deadline = None;
                                } else if coalesce_turn_deadline.is_none()
                                    && let Some(window) = adaptive_coalescer.window()
                                {
                                    let d = tokio::time::Instant::now() + window;
                                    coalesce_turn_deadline = Some(d);
                                    coalesce_turn_sleep.as_mut().reset(d);
                                }
                            }
                        }
                        Err(e) => {
                            trace!("WG recv error in SessionWorker: {e}");
                        }
                    }
                }
            }
        }

        // Flush any remaining buffered packets before exit
        if !pending_turn_frames.is_empty() {
            let pkts: Vec<TransmitPacket> = pending_turn_frames
                .iter()
                .map(|b| TransmitPacket {
                    buf: b,
                    addr: self.turn_server_addr,
                    gso_segment_size: None,
                })
                .collect();
            let _ = self.batched_turn.send_batch(&pkts).await;
        }

        Ok(())
    }
}

/// Worker task managing a single client session in direct UDP / VK listen mode.
pub struct DirectSessionWorker {
    /// Shared current peer address (updated if client switches address or multi-streams).
    pub relayed_peer: Arc<std::sync::RwLock<SocketAddr>>,
    /// 16-byte session identifier from knock.
    pub session_id: [u8; 16],
    /// Local WireGuard endpoint (e.g. 127.0.0.1:51820).
    pub wg_endpoint_addr: SocketAddr,
    /// Shared batched UDP socket listening on the server's public UDP port.
    pub batched_sock: Arc<BatchedUdpSocket>,
    /// Server metrics collector.
    pub metrics: Arc<TunnelMetrics>,
    /// Optional transmit coalescing window duration.
    pub coalesce_window: Option<Duration>,
    /// Inbound frame queue from server dispatcher for this session.
    pub inbound_rx: mpsc::Receiver<BytesMut>,
}

impl DirectSessionWorker {
    /// Run the direct session worker datapath until cancelled.
    pub async fn run(mut self, mut cancel_rx: watch::Receiver<bool>) -> Result<(), TunnelError> {
        let wg_socket = Arc::new(bind_tuned_udp_socket("0.0.0.0:0".parse().unwrap())?);
        let batched_wg = BatchedUdpSocket::new(wg_socket.clone());

        const BATCH_SIZE: usize = 16;
        let mut wg_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut wg_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        let mut pending_client_frames: Vec<BytesMut> = Vec::with_capacity(BATCH_SIZE);
        let mut coalesce_client_deadline: Option<tokio::time::Instant> = None;
        let coalesce_client_sleep = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(coalesce_client_sleep);

        let mut pending_wg_frames: Vec<BytesMut> = Vec::with_capacity(BATCH_SIZE);
        let mut coalesce_wg_deadline: Option<tokio::time::Instant> = None;
        let coalesce_wg_sleep = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(coalesce_wg_sleep);

        let mut adaptive_coalescer = AdaptiveCoalescer::new(self.coalesce_window);
        let mut seq_tx: u16 = 0;
        let mut last_activity = Instant::now();
        let mut inactivity_timer = interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                biased;

                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        trace!("DirectSessionWorker {:?} shutting down via cancel signal", &self.session_id[..4]);
                        break;
                    }
                }

                _ = inactivity_timer.tick() => {
                    if last_activity.elapsed() >= DEFAULT_SESSION_TTL {
                        info!("DirectSessionWorker {:?} timed out after {:?}", &self.session_id[..4], DEFAULT_SESSION_TTL);
                        break;
                    }
                }

                () = &mut coalesce_client_sleep, if coalesce_client_deadline.is_some() => {
                    if !pending_client_frames.is_empty() {
                        let peer = *self.relayed_peer.read().unwrap();
                        let pkts: Vec<TransmitPacket> = pending_client_frames.iter().map(|b| TransmitPacket {
                            buf: b,
                            addr: peer,
                            gso_segment_size: None,
                        }).collect();
                        let _ = self.batched_sock.send_batch(&pkts).await;
                        pending_client_frames.clear();
                    }
                    coalesce_client_deadline = None;
                }

                () = &mut coalesce_wg_sleep, if coalesce_wg_deadline.is_some() => {
                    if !pending_wg_frames.is_empty() {
                        let pkts: Vec<TransmitPacket> = pending_wg_frames.iter().map(|b| TransmitPacket {
                            buf: b,
                            addr: self.wg_endpoint_addr,
                            gso_segment_size: None,
                        }).collect();
                        let _ = batched_wg.send_batch(&pkts).await;
                        pending_wg_frames.clear();
                    }
                    coalesce_wg_deadline = None;
                }

                // Inbound frames from dispatcher for this session
                Some(payload) = self.inbound_rx.recv() => {
                    last_activity = Instant::now();
                    if let Ok((view, _)) = FrameView::decode(&payload) {
                        let is_ctrl = is_control_frame(view.header.frame_type);
                        match view.header.frame_type {
                            FrameType::Data => {
                                self.metrics.record_rx(view.payload.len());
                                let mut b = BytesMut::new();
                                b.extend_from_slice(view.payload);
                                pending_wg_frames.push(b);
                            }
                            FrameType::Ping => {
                                self.metrics.record_ping_rx();
                                let echo_ts = PingPayload::decode(view.payload)
                                    .map(|p| p.timestamp)
                                    .unwrap_or(0);
                                let now_ms = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64;
                                let pong = PongPayload {
                                    echo_timestamp: echo_ts,
                                    probe_id: view.header.seq,
                                    receive_timestamp: now_ms,
                                };
                                let mut pbuf = [0u8; PongPayload::LEN];
                                pong.encode(&mut pbuf);
                                let mut pong_frame = BytesMut::new();
                                encode_frame(
                                    FrameType::Pong,
                                    0,
                                    0,
                                    seq_tx,
                                    &pbuf,
                                    &mut pong_frame,
                                );
                                seq_tx = seq_tx.wrapping_add(1);
                                let peer = *self.relayed_peer.read().unwrap();
                                let pkt = TransmitPacket {
                                    buf: &pong_frame,
                                    addr: peer,
                                    gso_segment_size: None,
                                };
                                let _ = self.batched_sock.send_batch(&[pkt]).await;
                                self.metrics.record_ping_tx();
                            }
                            FrameType::Pong => {
                                self.metrics.record_ping_rx();
                            }
                            _ => {}
                        }

                        // Flush or coalesce to WG
                        if !pending_wg_frames.is_empty() {
                            let should_flush = is_ctrl || !adaptive_coalescer.is_coalescing_active() || pending_wg_frames.len() >= BATCH_SIZE;
                            if should_flush {
                                let pkts: Vec<TransmitPacket> = pending_wg_frames.iter().map(|b| TransmitPacket {
                                    buf: b,
                                    addr: self.wg_endpoint_addr,
                                    gso_segment_size: None,
                                }).collect();
                                let _ = batched_wg.send_batch(&pkts).await;
                                pending_wg_frames.clear();
                                coalesce_wg_deadline = None;
                            } else if coalesce_wg_deadline.is_none()
                                && let Some(window) = adaptive_coalescer.window()
                            {
                                let d = tokio::time::Instant::now() + window;
                                coalesce_wg_deadline = Some(d);
                                coalesce_wg_sleep.as_mut().reset(d);
                            }
                        }
                    }
                }

                // Inbound frames from WireGuard backend
                wg_batch_res = batched_wg.recv_batch(&mut wg_batch_bufs, &mut wg_batch_metas) => {
                    match wg_batch_res {
                        Ok(count) => {
                            last_activity = Instant::now();
                            adaptive_coalescer.on_wakeup_batch(count);
                            for i in 0..count {
                                let meta = wg_batch_metas[i];
                                let slice = &wg_batch_bufs[i][..meta.len];
                                let is_ctrl = inspect_wg_packet(slice)
                                    .map(|h| h.is_handshake())
                                    .unwrap_or(false);

                                let mut frame = BytesMut::new();
                                encode_frame(
                                    FrameType::Data,
                                    0,
                                    0,
                                    seq_tx,
                                    slice,
                                    &mut frame,
                                );
                                seq_tx = seq_tx.wrapping_add(1);
                                self.metrics.record_tx(meta.len);

                                if is_ctrl {
                                    let peer = *self.relayed_peer.read().unwrap();
                                    let pkt = TransmitPacket {
                                        buf: &frame,
                                        addr: peer,
                                        gso_segment_size: None,
                                    };
                                    let _ = self.batched_sock.send_batch(&[pkt]).await;
                                } else {
                                    pending_client_frames.push(frame);
                                }
                            }

                            if !pending_client_frames.is_empty() {
                                let should_flush = !adaptive_coalescer.is_coalescing_active() || pending_client_frames.len() >= BATCH_SIZE;
                                if should_flush {
                                    let peer = *self.relayed_peer.read().unwrap();
                                    let pkts: Vec<TransmitPacket> = pending_client_frames.iter().map(|b| TransmitPacket {
                                        buf: b,
                                        addr: peer,
                                        gso_segment_size: None,
                                    }).collect();
                                    let _ = self.batched_sock.send_batch(&pkts).await;
                                    pending_client_frames.clear();
                                    coalesce_client_deadline = None;
                                } else if coalesce_client_deadline.is_none()
                                    && let Some(window) = adaptive_coalescer.window()
                                {
                                    let d = tokio::time::Instant::now() + window;
                                    coalesce_client_deadline = Some(d);
                                    coalesce_client_sleep.as_mut().reset(d);
                                }
                            }
                        }
                        Err(e) => {
                            trace!("WG recv error in DirectSessionWorker: {e}");
                        }
                    }
                }
            }
        }

        // Flush any remaining buffered packets before exit
        if !pending_client_frames.is_empty() {
            let peer = *self.relayed_peer.read().unwrap();
            let pkts: Vec<TransmitPacket> = pending_client_frames
                .iter()
                .map(|b| TransmitPacket {
                    buf: b,
                    addr: peer,
                    gso_segment_size: None,
                })
                .collect();
            let _ = self.batched_sock.send_batch(&pkts).await;
        }

        Ok(())
    }
}

/// Per-session worker for stream (TCP/TLS) mode: relays ChannelData payloads
/// between the stream connection and the WireGuard UDP endpoint.
pub struct StreamSessionWorker {
    /// 16-byte unique session ID from knock.
    pub session_id: [u8; 16],
    /// WireGuard backend endpoint address.
    pub wg_endpoint_addr: SocketAddr,
    /// Outbound queue of the owning stream connection (pre-framed ChannelData).
    pub tx: mpsc::Sender<Bytes>,
    /// Server metrics collector handle.
    pub metrics: Arc<TunnelMetrics>,
    /// Optional transmit coalescing window duration.
    pub coalesce_window: Option<Duration>,
    /// Inbound frame queue from the stream dispatcher.
    pub inbound_rx: mpsc::Receiver<BytesMut>,
}

impl StreamSessionWorker {
    /// Run the stream session worker datapath until cancelled.
    pub async fn run(mut self, mut cancel_rx: watch::Receiver<bool>) -> Result<(), TunnelError> {
        let wg_socket = Arc::new(bind_tuned_udp_socket("0.0.0.0:0".parse().unwrap())?);
        let batched_wg = BatchedUdpSocket::new(wg_socket.clone());

        const BATCH_SIZE: usize = 16;
        let mut wg_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut wg_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        let mut pending_wg_frames: Vec<BytesMut> = Vec::with_capacity(BATCH_SIZE);
        let mut coalesce_wg_sleep = Box::pin(tokio::time::sleep(Duration::from_secs(3600)));
        let mut coalesce_wg_deadline: Option<tokio::time::Instant> = None;

        let mut adaptive_coalescer = AdaptiveCoalescer::new(self.coalesce_window);
        let mut seq_tx: u16 = 0;
        let mut last_activity = Instant::now();
        let mut inactivity_timer = interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                biased;

                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        break;
                    }
                }

                _ = inactivity_timer.tick() => {
                    if last_activity.elapsed() > DEFAULT_SESSION_TTL {
                        debug!(
                            "Stream session {:02X?} idle timeout",
                            &self.session_id[..4]
                        );
                        break;
                    }
                }

                _ = &mut coalesce_wg_sleep, if coalesce_wg_deadline.is_some() => {
                    coalesce_wg_deadline = None;
                    if !pending_wg_frames.is_empty() {
                        let pkts: Vec<TransmitPacket> = pending_wg_frames
                            .iter()
                            .map(|b| TransmitPacket {
                                buf: b,
                                addr: self.wg_endpoint_addr,
                                gso_segment_size: None,
                            })
                            .collect();
                        if let Err(e) = batched_wg.send_batch(&pkts).await {
                            warn!("Stream worker WG send error: {e}");
                        }
                        pending_wg_frames.clear();
                    }
                }

                inbound = self.inbound_rx.recv() => {
                    let frame = match inbound {
                        Some(f) => f,
                        None => break,
                    };
                    last_activity = Instant::now();

                    let (view, _) = match FrameView::decode(&frame) {
                        Ok(v) => v,
                        Err(e) => {
                            debug!("Stream worker invalid frame: {e}");
                            continue;
                        }
                    };
                    let is_ctrl = is_control_frame(view.header.frame_type);

                    match view.header.frame_type {
                        FrameType::Data => {
                            self.metrics.record_rx(view.payload.len());
                            pending_wg_frames.push(BytesMut::from(view.payload));
                        }
                        FrameType::Ping => {
                            self.metrics.record_ping_rx();
                            let echo_ts = PingPayload::decode(view.payload)
                                .map(|p| p.timestamp)
                                .unwrap_or(0);
                            let now_ms = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;
                            let pong = PongPayload {
                                echo_timestamp: echo_ts,
                                probe_id: view.header.seq,
                                receive_timestamp: now_ms,
                            };
                            let mut pbuf = [0u8; PongPayload::LEN];
                            pong.encode(&mut pbuf);
                            let mut resp_frame = BytesMut::new();
                            encode_frame(FrameType::Pong, 0, 0, seq_tx, &pbuf, &mut resp_frame);
                            seq_tx = seq_tx.wrapping_add(1);
                            let mut chan_buf = BytesMut::new();
                            encode_tcp_channel_data(0x4000, &resp_frame, &mut chan_buf);
                            let _ = self.tx.send(chan_buf.freeze()).await;
                        }
                        FrameType::Pong => {
                            self.metrics.record_ping_rx();
                        }
                        _ => {}
                    }

                    if is_ctrl
                        || !adaptive_coalescer.is_coalescing_active()
                        || pending_wg_frames.len() >= BATCH_SIZE
                    {
                        if !pending_wg_frames.is_empty() {
                            let pkts: Vec<TransmitPacket> = pending_wg_frames
                                .iter()
                                .map(|b| TransmitPacket {
                                    buf: b,
                                    addr: self.wg_endpoint_addr,
                                    gso_segment_size: None,
                                })
                                .collect();
                            if let Err(e) = batched_wg.send_batch(&pkts).await {
                                warn!("Stream worker WG send error: {e}");
                            }
                            pending_wg_frames.clear();
                        }
                        coalesce_wg_deadline = None;
                    } else if coalesce_wg_deadline.is_none()
                        && let Some(window) = adaptive_coalescer.window()
                    {
                        let deadline = tokio::time::Instant::now() + window;
                        coalesce_wg_sleep.as_mut().reset(deadline);
                        coalesce_wg_deadline = Some(deadline);
                    }
                }

                wg_res = batched_wg.recv_batch(&mut wg_batch_bufs, &mut wg_batch_metas) => {
                    let count = match wg_res {
                        Ok(c) => c,
                        Err(e) => {
                            trace!("Stream worker WG recv error: {e}");
                            continue;
                        }
                    };
                    self.metrics.record_batch_rx(count);
                    adaptive_coalescer.on_wakeup_batch(count);
                    last_activity = Instant::now();

                    for i in 0..count {
                        let meta = wg_batch_metas[i];
                        let slice = &wg_batch_bufs[i][..meta.len];
                        let mut frame = BytesMut::new();
                        encode_frame(FrameType::Data, 0, 0, seq_tx, slice, &mut frame);
                        seq_tx = seq_tx.wrapping_add(1);
                        let mut chan_buf = BytesMut::new();
                        encode_tcp_channel_data(0x4000, &frame, &mut chan_buf);
                        self.metrics.record_tx(meta.len);
                        if self.tx.send(chan_buf.freeze()).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        Ok(())
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
        if let Some(listen_addr) = self.config.direct_listen_addr {
            return self
                .run_direct_with_notify(listen_addr, cancel_rx, on_allocated)
                .await;
        }

        if let Some(listen_addr) = self.config.stream_listen_addr {
            return self
                .run_stream_server_with_notify(listen_addr, cancel_rx, on_allocated)
                .await;
        }

        info!(
            "Starting TunnelServer (TURN mode): connecting to TURN {} forwarding to WG {}",
            self.config.turn_server_addr, self.config.wg_endpoint_addr
        );

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
        let mut alloc_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + turn_client.allocation_refresh_interval(),
            turn_client.allocation_refresh_interval(),
        );
        let mut perm_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + turn_client.permission_refresh_interval(),
            turn_client.permission_refresh_interval(),
        );
        let mut chan_bind_refresh_timer = tokio::time::interval_at(
            tokio::time::Instant::now() + turn_client.channel_bind_refresh_interval(),
            turn_client.channel_bind_refresh_interval(),
        );

        let batched_turn = Arc::new(BatchedUdpSocket::new(turn_client.socket().clone()));

        let knock_key = derive_pre_auth_knock_key(&Psk::from_bytes(self.config.psk));
        let mut auth = KnockAuthenticator::new(knock_key, DEFAULT_MAX_CLOCK_SKEW_SEC);

        let mut active_sessions: HashMap<[u8; 16], mpsc::Sender<BytesMut>> = HashMap::new();
        let mut endpoint_to_session: HashMap<SocketAddr, [u8; 16]> = HashMap::new();
        let mut channel_to_peer: HashMap<u16, SocketAddr> = HashMap::new();
        let mut peer_to_channel: HashMap<SocketAddr, u16> = HashMap::new();
        let mut next_channel_number: u16 = 0x4000;

        const BATCH_SIZE: usize = 16;
        let mut turn_batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut turn_batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        loop {
            tokio::select! {
                biased;

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
                    if !active_sessions.is_empty() {
                        trace!("TunnelServer dynamically refreshing TURN permission");
                        if let Err(e) = turn_client.refresh_permission().await {
                            warn!("Failed to refresh TURN permission: {e}");
                        }
                    }
                }

                _ = chan_bind_refresh_timer.tick() => {
                    if !active_sessions.is_empty() {
                        trace!("TunnelServer dynamically refreshing TURN channel bind");
                        if let Err(e) = turn_client.refresh_channel_bind().await {
                            warn!("Failed to refresh TURN channel bind: {e}");
                        }
                    }
                }

                // Packets from TURN relay -> validate knock or dispatch to session worker (batched)
                turn_batch_res = batched_turn.recv_batch(&mut turn_batch_bufs, &mut turn_batch_metas) => {
                    match turn_batch_res {
                        Ok(count) => {
                            self.metrics.record_batch_rx(count);
                            for i in 0..count {
                                let meta = turn_batch_metas[i];
                                let slice = &turn_batch_bufs[i][..meta.len];
                                if let Ok(Some(turn_msg)) = turn_client.parse_incoming(slice, meta.addr) {
                                    let (peer_from_turn, payload) = match turn_msg {
                                        TurnIncoming::DataIndication { peer_addr, payload } => (Some(peer_addr), payload),
                                        TurnIncoming::ChannelData { channel, payload } => {
                                            let peer = channel_to_peer.get(&channel).copied();
                                            (peer, payload)
                                        }
                                        _ => (None, bytes::Bytes::new()),
                                    };

                                    if payload.is_empty() {
                                        continue;
                                    }

                                    // 1. Check for Pre-Auth Knock (HandshakeInit)
                                    if let Ok((view, _)) = FrameView::decode(&payload)
                                        && view.header.frame_type == FrameType::HandshakeInit
                                    {
                                        let now_sec = SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();

                                        match auth.verify_knock_packet(now_sec, view.payload) {
                                            Ok(knock_payload) => {
                                                if let Some(peer) = peer_from_turn {
                                                    let session_id = knock_payload.session_id;
                                                    info!(
                                                        "Pre-Auth Knock verified for peer {} (session {:?})!",
                                                        peer, session_id
                                                    );

                                                    let assigned_channel = if let Some(chan) = peer_to_channel.get(&peer) {
                                                        *chan
                                                    } else {
                                                        let chan = next_channel_number;
                                                        next_channel_number = next_channel_number.saturating_add(1);
                                                        peer_to_channel.insert(peer, chan);
                                                        channel_to_peer.insert(chan, peer);
                                                        chan
                                                    };

                                                    // Re-bind peer on TURN with dedicated channel
                                                    if let Err(e) = turn_client.bind_peer_channel(peer, assigned_channel).await {
                                                        warn!("Failed to bind peer {peer} on TURN channel 0x{assigned_channel:04X}: {e}");
                                                    }

                                                    endpoint_to_session.insert(peer, session_id);
                                                    let is_new = !active_sessions.contains_key(&session_id)
                                                        || active_sessions.get(&session_id).unwrap().is_closed();

                                                    if is_new {
                                                        let (session_tx, session_rx) = mpsc::channel(2048);
                                                        let worker = SessionWorker {
                                                            relayed_peer: peer,
                                                            session_id,
                                                            wg_endpoint_addr: self.config.wg_endpoint_addr,
                                                            turn_server_addr: self.config.turn_server_addr,
                                                            batched_turn: batched_turn.clone(),
                                                            turn_channel_number: assigned_channel,
                                                            metrics: self.metrics.clone(),
                                                            coalesce_window: self.config.coalesce_window,
                                                            inbound_rx: session_rx,
                                                        };
                                                        let worker_cancel = cancel_rx.clone();
                                                        tokio::spawn(async move {
                                                            if let Err(e) = worker.run(worker_cancel).await {
                                                                warn!("SessionWorker terminated with error: {e}");
                                                            }
                                                        });
                                                        active_sessions.insert(session_id, session_tx);
                                                    }

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
                                                    let _ = turn_client.send_channel_data_to(assigned_channel, &resp_frame).await;
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

                                    // 2. Dispatch data/control datagram to session worker by session_id
                                    if let Some(peer) = peer_from_turn {
                                        if let Some(session_id) = endpoint_to_session.get(&peer) {
                                            if let Some(tx) = active_sessions.get(session_id) {
                                                trace!("TunnelServer dispatching {} bytes to worker for session {:?}", payload.len(), session_id);
                                                let mut b = BytesMut::new();
                                                b.extend_from_slice(&payload);
                                                if let Err(e) = tx.try_send(b) {
                                                    warn!("Failed to dispatch to session worker for {peer}: {e}");
                                                }
                                            }
                                        } else {
                                            trace!("Unauthenticated data packet for {peer} dropped silently");
                                        }
                                    }
                                }
                            }

                            // Prune closed session channels
                            active_sessions.retain(|_, tx| !tx.is_closed());
                            endpoint_to_session.retain(|_, id| active_sessions.contains_key(id));
                        }
                        Err(e) => {
                            trace!("TURN incoming batch error: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the server in stream (TCP/TLS) mode: accept TURN stream connections,
    /// verify the pre-auth knock, and relay ChannelData to the WireGuard endpoint.
    async fn run_stream_server_with_notify(
        &mut self,
        listen_addr: SocketAddr,
        mut cancel_rx: watch::Receiver<bool>,
        on_allocated: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), TunnelError> {
        info!(
            "Starting TunnelServer in stream mode: listening on {listen_addr}, forwarding to WG {}",
            self.config.wg_endpoint_addr
        );

        let server_cfg = StreamServerConfig {
            listen_addr,
            username: self.config.turn_username.clone(),
            password: self.config.turn_password.clone(),
            realm: self.config.turn_realm.clone(),
            channel_number: 0x4000,
            lifetime_sec: 600,
            tls_cert_der: self.config.tls_cert_der.clone(),
            tls_key_der: self.config.tls_key_der.clone(),
        };
        let server = StreamTurnServer::bind(server_cfg).await?;
        let bound = server.local_addr()?;
        self.relayed_addr = Some(bound);
        if let Some(tx) = on_allocated {
            let _ = tx.send(bound);
        }

        let knock_key = derive_pre_auth_knock_key(&Psk::from_bytes(self.config.psk));
        let mut auth = KnockAuthenticator::new(knock_key, DEFAULT_MAX_CLOCK_SKEW_SEC);

        struct StreamSessionEntry {
            sender: mpsc::Sender<BytesMut>,
            tx: mpsc::Sender<Bytes>,
        }

        let mut sessions_by_id: HashMap<[u8; 16], StreamSessionEntry> = HashMap::new();
        let mut conn_to_session: HashMap<SocketAddr, [u8; 16]> = HashMap::new();

        loop {
            tokio::select! {
                biased;

                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        info!("TunnelServer stream shutting down via cancel signal");
                        break;
                    }
                }

                accepted = server.accept() => {
                    let mut handle = match accepted {
                        Ok(h) => h,
                        Err(e) => {
                            warn!("Stream accept failed: {e}");
                            continue;
                        }
                    };
                    let peer = handle.peer_addr;
                    debug!("Accepted stream TURN connection from {peer}");

                    let mut session_id: Option<[u8; 16]> = None;

                    loop {
                        tokio::select! {
                            biased;

                            _ = cancel_rx.changed() => {
                                if *cancel_rx.borrow() {
                                    return Ok(());
                                }
                            }

                            ctl = handle.control_rx.recv() => {
                                match ctl {
                                    Some(resp) => {
                                        if handle.tx.send(resp).await.is_err() {
                                            break;
                                        }
                                    }
                                    None => break,
                                }
                            }

                            inbound = handle.rx.recv() => {
                                let payload = match inbound {
                                    Some(p) => p,
                                    None => break,
                                };

                                if let Ok((view, _)) = FrameView::decode(&payload)
                                    && view.header.frame_type == FrameType::HandshakeInit
                                {
                                    let now_sec = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    match auth.verify_knock_packet(now_sec, view.payload) {
                                        Ok(knock_payload) => {
                                            let sid = knock_payload.session_id;
                                            info!(
                                                "Pre-Auth Knock verified over stream for peer {peer} (session {:02X?})",
                                                &sid[..4]
                                            );

                                            let is_new = !sessions_by_id.contains_key(&sid)
                                                || sessions_by_id.get(&sid).unwrap().sender.is_closed();

                                            if is_new {
                                                let (session_tx, session_rx) = mpsc::channel(2048);
                                                let worker = StreamSessionWorker {
                                                    session_id: sid,
                                                    wg_endpoint_addr: self.config.wg_endpoint_addr,
                                                    tx: handle.tx.clone(),
                                                    metrics: self.metrics.clone(),
                                                    coalesce_window: self.config.coalesce_window,
                                                    inbound_rx: session_rx,
                                                };
                                                let worker_cancel = cancel_rx.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = worker.run(worker_cancel).await {
                                                        warn!("StreamSessionWorker terminated: {e}");
                                                    }
                                                });
                                                sessions_by_id.insert(
                                                    sid,
                                                    StreamSessionEntry {
                                                        sender: session_tx,
                                                        tx: handle.tx.clone(),
                                                    },
                                                );
                                            }

                                            conn_to_session.insert(peer, sid);
                                            session_id = Some(sid);

                                            let mut resp_frame = BytesMut::new();
                                            encode_frame(
                                                FrameType::HandshakeResp,
                                                0,
                                                0,
                                                0,
                                                b"WDTT2-OK",
                                                &mut resp_frame,
                                            );
                                            let mut framed = BytesMut::new();
                                            encode_tcp_channel_data(0x4000, &resp_frame, &mut framed);
                                            if handle.tx.send(framed.freeze()).await.is_err() {
                                                break;
                                            }
                                            continue;
                                        }
                                        Err(e) => {
                                            debug!("Invalid knock over stream from {peer}: {e}");
                                            continue;
                                        }
                                    }
                                }

                                let sid = match session_id {
                                    Some(s) => s,
                                    None => {
                                        trace!("Unauthenticated stream payload from {peer} dropped");
                                        continue;
                                    }
                                };
                                if let Some(entry) = sessions_by_id.get(&sid)
                                    && !entry.sender.is_closed()
                                {
                                    let mut b = BytesMut::new();
                                    b.extend_from_slice(&payload);
                                    if let Err(e) = entry.sender.try_send(b) {
                                        warn!("Dispatch to stream session queue full: {e}");
                                    }
                                }
                            }
                        }
                    }

                    if let Some(sid) = session_id {
                        conn_to_session.remove(&peer);
                        if let Some(entry) = sessions_by_id.get(&sid)
                            && entry.tx.same_channel(&handle.tx)
                        {
                            sessions_by_id.remove(&sid);
                        }
                    }
                    debug!("Stream TURN connection from {peer} closed");
                    sessions_by_id.retain(|_, entry| !entry.sender.is_closed());
                    conn_to_session.retain(|_, id| sessions_by_id.contains_key(id));
                }
            }
        }

        Ok(())
    }

    async fn run_direct_with_notify(
        &mut self,
        listen_addr: SocketAddr,
        mut cancel_rx: watch::Receiver<bool>,
        on_allocated: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), TunnelError> {
        info!(
            "Starting TunnelServer in direct UDP / VK mode: listening on {listen_addr}, forwarding to WG {}",
            self.config.wg_endpoint_addr
        );

        let socket = Arc::new(bind_tuned_udp_socket(listen_addr)?);
        self.relayed_addr = Some(listen_addr);
        if let Some(tx) = on_allocated {
            let _ = tx.send(listen_addr);
        }

        let batched_sock = Arc::new(BatchedUdpSocket::new(socket.clone()));
        let knock_key = derive_pre_auth_knock_key(&Psk::from_bytes(self.config.psk));
        let mut auth = KnockAuthenticator::new(knock_key, DEFAULT_MAX_CLOCK_SKEW_SEC);

        struct DirectSessionEntry {
            sender: mpsc::Sender<BytesMut>,
            peer_addr: Arc<std::sync::RwLock<SocketAddr>>,
        }

        let mut sessions_by_id: HashMap<[u8; 16], DirectSessionEntry> = HashMap::new();
        let mut endpoint_to_session: HashMap<SocketAddr, [u8; 16]> = HashMap::new();

        const BATCH_SIZE: usize = 16;
        let mut batch_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET_LEN]).collect();
        let mut batch_metas: Vec<RecvMeta> = vec![RecvMeta::default(); BATCH_SIZE];

        loop {
            tokio::select! {
                biased;

                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        info!("TunnelServer direct shutting down via cancel signal");
                        break;
                    }
                }

                batch_res = batched_sock.recv_batch(&mut batch_bufs, &mut batch_metas) => {
                    match batch_res {
                        Ok(count) => {
                            self.metrics.record_batch_rx(count);
                            for i in 0..count {
                                let meta = batch_metas[i];
                                let slice = &batch_bufs[i][..meta.len];
                                let src_addr = meta.addr;

                                // 1. Check for Pre-Auth Knock (HandshakeInit)
                                if let Ok((view, _)) = FrameView::decode(slice)
                                    && view.header.frame_type == FrameType::HandshakeInit
                                {
                                    let now_sec = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();

                                    match auth.verify_knock_packet(now_sec, view.payload) {
                                        Ok(knock_payload) => {
                                            let session_id = knock_payload.session_id;
                                            info!(
                                                "Pre-Auth Knock verified for peer {} (session {:02X?})",
                                                src_addr, &session_id[..4]
                                            );

                                            let is_new = !sessions_by_id.contains_key(&session_id)
                                                || sessions_by_id.get(&session_id).unwrap().sender.is_closed();

                                            if is_new {
                                                let peer_addr_shared = Arc::new(std::sync::RwLock::new(src_addr));
                                                let (session_tx, session_rx) = mpsc::channel(2048);
                                                let worker = DirectSessionWorker {
                                                    relayed_peer: peer_addr_shared.clone(),
                                                    session_id,
                                                    wg_endpoint_addr: self.config.wg_endpoint_addr,
                                                    batched_sock: batched_sock.clone(),
                                                    metrics: self.metrics.clone(),
                                                    coalesce_window: self.config.coalesce_window,
                                                    inbound_rx: session_rx,
                                                };
                                                let worker_cancel = cancel_rx.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = worker.run(worker_cancel).await {
                                                        warn!("DirectSessionWorker terminated: {e}");
                                                    }
                                                });
                                                sessions_by_id.insert(
                                                    session_id,
                                                    DirectSessionEntry {
                                                        sender: session_tx,
                                                        peer_addr: peer_addr_shared,
                                                    },
                                                );
                                            } else {
                                                let entry = sessions_by_id.get_mut(&session_id).unwrap();
                                                if let Ok(mut lock) = entry.peer_addr.write() {
                                                    *lock = src_addr;
                                                }
                                            }

                                            endpoint_to_session.insert(src_addr, session_id);

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
                                            let _ = socket.send_to(&resp_frame, src_addr).await;
                                            continue;
                                        }
                                        Err(e) => {
                                            debug!("Invalid knock from {src_addr} rejected: {e}");
                                            continue;
                                        }
                                    }
                                }

                                // 2. Dispatch data/control datagram to session worker by session_id lookup
                                if let Some(session_id) = endpoint_to_session.get(&src_addr)
                                    && let Some(entry) = sessions_by_id.get(session_id)
                                    && !entry.sender.is_closed()
                                {
                                    let mut b = BytesMut::new();
                                    b.extend_from_slice(slice);
                                    if let Err(e) = entry.sender.try_send(b) {
                                        warn!("Dispatch to session worker queue full: {e}");
                                    }
                                    continue;
                                }

                                // 3. Silent drop of unauthenticated packets
                                trace!("Unauthenticated packet from {src_addr} dropped silently");
                            }

                            // Prune closed sessions
                            sessions_by_id.retain(|_, entry| !entry.sender.is_closed());
                            endpoint_to_session.retain(|_, id| sessions_by_id.contains_key(id));
                        }
                        Err(e) => {
                            trace!("Direct UDP recv error: {e}");
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
