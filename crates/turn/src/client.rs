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

/// Asynchronous TURN Client.
pub struct TurnClient {
    socket: Arc<UdpSocket>,
    config: TurnClientConfig,
    relayed_addr: Option<SocketAddr>,
    realm: String,
    nonce: String,
    key: [u8; 16],
    allocated: Arc<AtomicBool>,
}

impl TurnClient {
    /// Create a new TURN client bound to an ephemeral local UDP port.
    pub async fn bind(local_bind: SocketAddr, config: TurnClientConfig) -> Result<Self, TurnError> {
        let socket = UdpSocket::bind(local_bind).await?;
        Ok(Self {
            socket: Arc::new(socket),
            config,
            relayed_addr: None,
            realm: String::new(),
            nonce: String::new(),
            key: [0u8; 16],
            allocated: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Retrieve the allocated relayed address, if allocation succeeded.
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed_addr
    }

    /// Perform full TURN allocation, permission grant, and channel binding.
    pub async fn allocate(&mut self) -> Result<SocketAddr, TurnError> {
        info!(
            "Initiating TURN allocation to {} for peer {}",
            self.config.server_addr, self.config.peer_addr
        );

        // 1. Initial unauthenticated Allocate to get 401 challenge
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let initial_req = StunMessage::new(ALLOCATE_REQUEST, tx_id)
            .with_attribute(StunAttribute::RequestedTransport(17)); // UDP

        let resp = self.send_stun_request(&initial_req, &tx_id, None).await?;

        // Expect 401 Unauthorized
        if let Some((code, _)) = resp.error_code()
            && code != 401
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
        rand::rng().fill_bytes(&mut tx_id);
        let auth_alloc = StunMessage::new(ALLOCATE_REQUEST, tx_id)
            .with_attribute(StunAttribute::RequestedTransport(17))
            .with_attribute(StunAttribute::Lifetime(self.config.lifetime_sec))
            .with_attribute(StunAttribute::Username(self.config.username.clone()))
            .with_attribute(StunAttribute::Realm(self.realm.clone()))
            .with_attribute(StunAttribute::Nonce(self.nonce.clone()));

        let alloc_resp = self
            .send_stun_request(&auth_alloc, &tx_id, Some(&self.key))
            .await?;

        if let Some((code, reason)) = alloc_resp.error_code() {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: reason.to_string(),
            });
        }

        let relayed_addr = alloc_resp
            .relayed_address()
            .ok_or(TurnError::MissingAttribute("XOR-RELAYED-ADDRESS"))?;
        self.relayed_addr = Some(relayed_addr);
        info!("TURN allocation granted: relayed addr = {relayed_addr}");

        // 3. Create Permission for peer
        rand::rng().fill_bytes(&mut tx_id);
        let perm_req = StunMessage::new(CREATE_PERMISSION_REQUEST, tx_id)
            .with_attribute(StunAttribute::XorPeerAddress(self.config.peer_addr))
            .with_attribute(StunAttribute::Username(self.config.username.clone()))
            .with_attribute(StunAttribute::Realm(self.realm.clone()))
            .with_attribute(StunAttribute::Nonce(self.nonce.clone()));

        let perm_resp = self
            .send_stun_request(&perm_req, &tx_id, Some(&self.key))
            .await?;

        if let Some((code, reason)) = perm_resp.error_code() {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: reason.to_string(),
            });
        }
        debug!(
            "TURN CreatePermission succeeded for {}",
            self.config.peer_addr
        );

        // 4. ChannelBind peer to channel number
        rand::rng().fill_bytes(&mut tx_id);
        let chan_req = StunMessage::new(CHANNEL_BIND_REQUEST, tx_id)
            .with_attribute(StunAttribute::ChannelNumber(self.config.channel_number))
            .with_attribute(StunAttribute::XorPeerAddress(self.config.peer_addr))
            .with_attribute(StunAttribute::Username(self.config.username.clone()))
            .with_attribute(StunAttribute::Realm(self.realm.clone()))
            .with_attribute(StunAttribute::Nonce(self.nonce.clone()));

        let chan_resp = self
            .send_stun_request(&chan_req, &tx_id, Some(&self.key))
            .await?;

        if let Some((code, reason)) = chan_resp.error_code() {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: reason.to_string(),
            });
        }
        info!(
            "TURN ChannelBind succeeded: channel 0x{:04X} -> {}",
            self.config.channel_number, self.config.peer_addr
        );

        self.allocated.store(true, Ordering::SeqCst);
        Ok(relayed_addr)
    }

    /// Refresh allocation lifetime.
    pub async fn refresh(&mut self, lifetime_sec: u32) -> Result<u32, TurnError> {
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);

        let req = StunMessage::new(REFRESH_REQUEST, tx_id)
            .with_attribute(StunAttribute::Lifetime(lifetime_sec))
            .with_attribute(StunAttribute::Username(self.config.username.clone()))
            .with_attribute(StunAttribute::Realm(self.realm.clone()))
            .with_attribute(StunAttribute::Nonce(self.nonce.clone()));

        let resp = self
            .send_stun_request(&req, &tx_id, Some(&self.key))
            .await?;
        if let Some((code, reason)) = resp.error_code() {
            return Err(TurnError::StunErrorResponse {
                code,
                reason: reason.to_string(),
            });
        }

        let granted = resp.lifetime().unwrap_or(lifetime_sec);
        debug!("TURN Refresh granted lifetime: {granted}s");
        Ok(granted)
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

    /// Helper to send a STUN request and await matching response with timeout.
    async fn send_stun_request(
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
