use crate::channel::{decode_channel_data, encode_channel_data, is_channel_data};
use crate::error::TurnError;
use crate::stun::*;
use bytes::{Bytes, BytesMut};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

const TIMEOUT_DURATION: Duration = Duration::from_secs(3);

/// Config for connecting to and allocating on a TURN server.
#[derive(Debug, Clone)]
pub struct TurnClientConfig {
    pub server_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub username: String,
    pub password: String,
    pub channel_number: u16,
    pub lifetime_sec: u32,
}

impl Default for TurnClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:3478".parse().unwrap(),
            peer_addr: "127.0.0.1:51820".parse().unwrap(),
            username: String::new(),
            password: String::new(),
            channel_number: 0x4000,
            lifetime_sec: 600,
        }
    }
}

/// Incoming multiplexed packet received from a TURN server.
#[derive(Debug, Clone)]
pub enum TurnIncoming {
    /// ChannelData payload received on a bound channel.
    ChannelData {
        /// Channel number (e.g. 0x4000).
        channel: u16,
        /// Payload data.
        payload: Bytes,
    },
    /// DataIndication (RFC 5766 Section 10) before channel binding is established.
    DataIndication {
        /// Peer socket address sending the data.
        peer_addr: SocketAddr,
        /// Payload data.
        payload: Bytes,
    },
    /// Other STUN message (e.g. keepalive/binding).
    Stun(StunMessage),
}

/// Asynchronous TURN Client with automatic 438 Stale Nonce recovery and keepalive lifecycle management.
pub struct TurnClient {
    socket: Arc<UdpSocket>,
    config: TurnClientConfig,
    relayed_addr: Option<SocketAddr>,
    realm: String,
    nonce: String,
    key: [u8; 16],
    allocated: Arc<AtomicBool>,
    negotiated_lifetime_sec: u32,
}

impl TurnClient {
    /// Create a new TURN client bound to an ephemeral local UDP port with tuned socket buffers.
    pub async fn bind(local_bind: SocketAddr, config: TurnClientConfig) -> Result<Self, TurnError> {
        let domain = match local_bind {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let sock2 =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        sock2.set_nonblocking(true)?;
        let _ = sock2.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = sock2.set_send_buffer_size(4 * 1024 * 1024);
        sock2.bind(&local_bind.into())?;
        let std_socket: std::net::UdpSocket = sock2.into();
        let socket = UdpSocket::from_std(std_socket)?;
        let lifetime = config.lifetime_sec;
        Ok(Self {
            socket: Arc::new(socket),
            config,
            relayed_addr: None,
            realm: String::new(),
            nonce: String::new(),
            key: [0u8; 16],
            allocated: Arc::new(AtomicBool::new(false)),
            negotiated_lifetime_sec: lifetime,
        })
    }

    /// Return negotiated allocation lifetime in seconds received from TURN server.
    pub fn negotiated_lifetime(&self) -> u32 {
        self.negotiated_lifetime_sec
    }

    /// Return dynamic refresh interval for allocation (75% of server lifetime).
    pub fn allocation_refresh_interval(&self) -> Duration {
        let sec = (self.negotiated_lifetime_sec as u64 * 3) / 4;
        Duration::from_secs(sec.max(10))
    }

    /// Return dynamic refresh interval for permissions (RFC 5766 Sec 8: 75% of min(300, lifetime)).
    pub fn permission_refresh_interval(&self) -> Duration {
        let sec = 300.min(self.negotiated_lifetime_sec as u64);
        Duration::from_secs(((sec * 3) / 4).max(10))
    }

    /// Return dynamic refresh interval for channel binding (RFC 5766 Sec 11: 75% of min(600, lifetime)).
    pub fn channel_bind_refresh_interval(&self) -> Duration {
        let sec = 600.min(self.negotiated_lifetime_sec as u64);
        Duration::from_secs(((sec * 3) / 4).max(10))
    }

    /// Retrieve the allocated relayed address, if allocation succeeded.
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed_addr
    }

    /// Update target peer address before creating permissions or channel binding.
    pub fn set_peer_addr(&mut self, peer_addr: SocketAddr) {
        self.config.peer_addr = peer_addr;
    }

    /// Update target peer and establish permission and channel binding.
    pub async fn bind_peer(&mut self, peer_addr: SocketAddr) -> Result<(), TurnError> {
        self.config.peer_addr = peer_addr;
        self.create_permission_internal().await?;
        self.channel_bind_internal().await?;
        Ok(())
    }

    /// Perform TURN allocation only, obtaining the relayed address without establishing peer bindings.
    pub async fn allocate_relay(&mut self) -> Result<SocketAddr, TurnError> {
        info!(
            "Initiating TURN allocation to {} (relay-only)",
            self.config.server_addr
        );

        // 1. Initial unauthenticated Allocate to get 401 challenge
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let initial_req = StunMessage::new(ALLOCATE_REQUEST, tx_id)
            .with_attribute(StunAttribute::RequestedTransport(17)); // UDP

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
            "TURN allocation granted: relayed addr = {relayed_addr}, lifetime = {}s",
            self.negotiated_lifetime_sec
        );

        self.allocated.store(true, Ordering::SeqCst);
        Ok(relayed_addr)
    }

    /// Perform full TURN allocation, permission grant, and channel binding.
    pub async fn allocate(&mut self) -> Result<SocketAddr, TurnError> {
        let relayed_addr = self.allocate_relay().await?;

        // 3. Create Permission for peer
        self.create_permission_internal().await?;

        // 4. ChannelBind peer to channel number
        self.channel_bind_internal().await?;

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
        debug!("TURN Refresh granted lifetime: {granted}s");
        Ok(granted)
    }

    /// Refresh permission for target peer before 300s expiration (RFC 5766 Section 8).
    pub async fn refresh_permission(&mut self) -> Result<(), TurnError> {
        self.create_permission_internal().await
    }

    /// Explicitly grant permission for an IP address (RFC 5766 Section 8).
    pub async fn create_permission(&mut self, peer_addr: SocketAddr) -> Result<(), TurnError> {
        self.config.peer_addr = peer_addr;
        self.create_permission_internal().await
    }

    /// Refresh channel binding before 10-minute expiration (RFC 5766 Section 11).
    pub async fn refresh_channel_bind(&mut self) -> Result<(), TurnError> {
        self.channel_bind_internal().await
    }

    /// Send a data packet encapsulated in a TURN ChannelData message to the relay.
    pub async fn send_channel_data(&self, payload: &[u8]) -> Result<(), TurnError> {
        let mut buf = BytesMut::new();
        encode_channel_data(self.config.channel_number, payload, false, &mut buf)?;
        self.socket.send_to(&buf, self.config.server_addr).await?;
        Ok(())
    }

    /// Receive a ChannelData packet or STUN message from the socket.
    ///
    /// If incoming packet is ChannelData for our bound channel, returns `Ok(Some(payload))`.
    /// Otherwise (STUN keepalive or other channel), returns `Ok(None)`.
    pub async fn recv_channel_data(&self, buf: &mut [u8]) -> Result<Option<Bytes>, TurnError> {
        let (len, src) = self.socket.recv_from(buf).await?;
        if src != self.config.server_addr {
            return Ok(None);
        }

        let slice = &buf[..len];
        if is_channel_data(slice) {
            let (chan, payload, _) = decode_channel_data(slice)?;
            if chan == self.config.channel_number {
                return Ok(Some(payload));
            }
        }
        Ok(None)
    }

    /// Receive an incoming packet from the TURN socket, parsing ChannelData or STUN DataIndication.
    pub async fn recv_incoming(&self, buf: &mut [u8]) -> Result<Option<TurnIncoming>, TurnError> {
        let (len, src) = self.socket.recv_from(buf).await?;
        if src != self.config.server_addr {
            return Ok(None);
        }

        let slice = &buf[..len];
        if is_channel_data(slice) {
            let (channel, payload, _) = decode_channel_data(slice)?;
            return Ok(Some(TurnIncoming::ChannelData { channel, payload }));
        }

        if let Ok(msg) = StunMessage::decode(slice) {
            if msg.message_type == DATA_INDICATION
                && let Some(peer_addr) = msg.peer_address()
                && let Some(data) = msg.data()
            {
                return Ok(Some(TurnIncoming::DataIndication {
                    peer_addr,
                    payload: data.clone(),
                }));
            }
            return Ok(Some(TurnIncoming::Stun(msg)));
        }

        Ok(None)
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

        let resp = self.send_authenticated_request(req, &tx_id).await?;
        if let Some((code, reason)) = resp.error_code() {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: reason.to_string(),
            });
        }
        Ok(resp)
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
            "TURN CreatePermission succeeded for {}",
            self.config.peer_addr
        );
        Ok(())
    }

    async fn channel_bind_internal(&mut self) -> Result<(), TurnError> {
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let req = StunMessage::new(CHANNEL_BIND_REQUEST, tx_id)
            .with_attribute(StunAttribute::ChannelNumber(self.config.channel_number))
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
        info!(
            "TURN ChannelBind succeeded: channel 0x{:04X} -> {}",
            self.config.channel_number, self.config.peer_addr
        );
        Ok(())
    }

    /// Send authenticated request with automatic 438 Stale Nonce recovery.
    async fn send_authenticated_request(
        &mut self,
        mut req: StunMessage,
        tx_id: &[u8; 12],
    ) -> Result<StunMessage, TurnError> {
        let resp = self.send_stun_packet(&req, tx_id, Some(&self.key)).await?;

        // RFC 5389 Section 10.2: If 438 Stale Nonce, update nonce and retry once
        if let Some((code, _)) = resp.error_code()
            && code == CODE_STALE_NONCE
            && let Some(new_nonce) = resp.nonce()
        {
            warn!("Received 438 Stale Nonce. Updating nonce to {new_nonce} and retrying...");
            self.nonce = new_nonce.to_string();
            self.key =
                compute_long_term_key(&self.config.username, &self.realm, &self.config.password);

            // Re-populate nonce in request attributes
            for attr in &mut req.attributes {
                if let StunAttribute::Nonce(n) = attr {
                    *n = self.nonce.clone();
                }
            }

            return self.send_stun_packet(&req, tx_id, Some(&self.key)).await;
        }

        Ok(resp)
    }

    /// Send raw STUN packet with retries.
    async fn send_stun_packet(
        &self,
        req: &StunMessage,
        tx_id: &[u8; 12],
        key: Option<&[u8]>,
    ) -> Result<StunMessage, TurnError> {
        let encoded = match key {
            Some(k) => req.encode_with_integrity(k),
            None => req.encode(),
        };

        for _ in 0..3 {
            self.socket
                .send_to(&encoded, self.config.server_addr)
                .await?;

            let mut recv_buf = [0u8; 2048];
            let res = timeout(TIMEOUT_DURATION, async {
                loop {
                    let (len, src) = self.socket.recv_from(&mut recv_buf).await?;
                    if src == self.config.server_addr
                        && let Ok(msg) = StunMessage::decode(&recv_buf[..len])
                        && msg.transaction_id == *tx_id
                    {
                        return Ok::<StunMessage, TurnError>(msg);
                    }
                }
            })
            .await;

            match res {
                Ok(Ok(msg)) => return Ok(msg),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    warn!("STUN request timed out, retrying...");
                }
            }
        }

        Err(TurnError::Timeout)
    }
}
