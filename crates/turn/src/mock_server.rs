use crate::channel::{decode_channel_data, encode_channel_data, is_channel_data};
use crate::error::TurnError;
use crate::stun::*;
use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

pub struct MockTurnServer {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

impl MockTurnServer {
    /// Start a mock TURN server on 127.0.0.1 with ephemeral port.
    pub async fn start(expected_user: &str, expected_pass: &str) -> Result<Self, TurnError> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let local_addr = socket.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));

        let user = expected_user.to_string();
        let pass = expected_pass.to_string();
        let realm = "mock.turn.local".to_string();
        let nonce = "mock-nonce-12345".to_string();
        let key = compute_long_term_key(&user, &realm, &pass);

        let s_sock = socket.clone();
        let s_shutdown = shutdown.clone();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while !s_shutdown.load(Ordering::Relaxed) {
                let (len, client_addr) = match s_sock.recv_from(&mut buf).await {
                    Ok(res) => res,
                    Err(_) => break,
                };

                let slice = &buf[..len];

                // 1. ChannelData Echo
                if is_channel_data(slice) {
                    if let Ok((chan, payload, _)) = decode_channel_data(slice) {
                        let mut resp = BytesMut::new();
                        let _ = encode_channel_data(chan, &payload, false, &mut resp);
                        let _ = s_sock.send_to(&resp, client_addr).await;
                    }
                    continue;
                }

                // 2. STUN Message
                if let Ok(msg) = StunMessage::decode(slice) {
                    match msg.message_type {
                        ALLOCATE_REQUEST => {
                            // Check if message has credentials
                            if msg.realm().is_none() || msg.nonce().is_none() {
                                // Reply 401 Unauthorized
                                let err_resp =
                                    StunMessage::new(ALLOCATE_ERROR_RESPONSE, msg.transaction_id)
                                        .with_attribute(StunAttribute::ErrorCode {
                                            code: 401,
                                            reason: "Unauthorized".into(),
                                        })
                                        .with_attribute(StunAttribute::Realm(realm.clone()))
                                        .with_attribute(StunAttribute::Nonce(nonce.clone()));
                                let encoded = err_resp.encode();
                                let _ = s_sock.send_to(&encoded, client_addr).await;
                            } else {
                                // Authenticated allocate -> 200 OK
                                let relayed: SocketAddr = "127.0.0.1:49152".parse().unwrap();
                                let resp = StunMessage::new(ALLOCATE_RESPONSE, msg.transaction_id)
                                    .with_attribute(StunAttribute::XorRelayedAddress(relayed))
                                    .with_attribute(StunAttribute::Lifetime(600));
                                let encoded = resp.encode_with_integrity(&key);
                                let _ = s_sock.send_to(&encoded, client_addr).await;
                            }
                        }
                        CREATE_PERMISSION_REQUEST => {
                            let resp =
                                StunMessage::new(CREATE_PERMISSION_RESPONSE, msg.transaction_id);
                            let encoded = resp.encode_with_integrity(&key);
                            let _ = s_sock.send_to(&encoded, client_addr).await;
                        }
                        CHANNEL_BIND_REQUEST => {
                            let resp = StunMessage::new(CHANNEL_BIND_RESPONSE, msg.transaction_id);
                            let encoded = resp.encode_with_integrity(&key);
                            let _ = s_sock.send_to(&encoded, client_addr).await;
                        }
                        REFRESH_REQUEST => {
                            let resp = StunMessage::new(REFRESH_RESPONSE, msg.transaction_id)
                                .with_attribute(StunAttribute::Lifetime(600));
                            let encoded = resp.encode_with_integrity(&key);
                            let _ = s_sock.send_to(&encoded, client_addr).await;
                        }
                        BINDING_REQUEST => {
                            let resp = StunMessage::new(BINDING_RESPONSE, msg.transaction_id)
                                .with_attribute(StunAttribute::XorMappedAddress(client_addr));
                            let encoded = resp.encode();
                            let _ = s_sock.send_to(&encoded, client_addr).await;
                        }
                        _ => {}
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            shutdown,
            handle,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.abort();
    }
}
