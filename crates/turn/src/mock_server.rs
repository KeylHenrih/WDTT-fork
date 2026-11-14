use crate::channel::{decode_channel_data, encode_channel_data, is_channel_data};
use crate::error::TurnError;
use crate::stun::*;
use bytes::BytesMut;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

#[allow(dead_code)]
struct ClientSession {
    relayed_addr: SocketAddr,
    channel: Option<u16>,
}

pub struct MockTurnServer {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    pub stale_nonce_trigger: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

impl MockTurnServer {
    /// Start a mock TURN server on 127.0.0.1 with ephemeral port.
    pub async fn start(expected_user: &str, expected_pass: &str) -> Result<Self, TurnError> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let local_addr = socket.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let stale_nonce_trigger = Arc::new(AtomicBool::new(false));

        let user = expected_user.to_string();
        let pass = expected_pass.to_string();
        let realm = "mock.turn.local".to_string();
        let initial_nonce = "mock-nonce-12345".to_string();
        let fresh_nonce = "mock-nonce-fresh-67890".to_string();
        let key = compute_long_term_key(&user, &realm, &pass);

        let s_sock = socket.clone();
        let s_shutdown = shutdown.clone();
        let s_stale = stale_nonce_trigger.clone();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let mut sessions: HashMap<SocketAddr, ClientSession> = HashMap::new();
            let mut next_port = 49152u16;

            while !s_shutdown.load(Ordering::Relaxed) {
                let (len, client_addr) = match s_sock.recv_from(&mut buf).await {
                    Ok(res) => res,
                    Err(_) => break,
                };

                let slice = &buf[..len];

                // 1. ChannelData Relay Routing
                if is_channel_data(slice) {
                    if let Ok((chan, payload, _)) = decode_channel_data(slice) {
                        // Find other client to relay to, otherwise echo
                        let other_client =
                            sessions.keys().copied().find(|addr| *addr != client_addr);
                        let dest = other_client.unwrap_or(client_addr);
                        let mut resp = BytesMut::new();
                        let _ = encode_channel_data(chan, &payload, false, &mut resp);
                        let _ = s_sock.send_to(&resp, dest).await;
                    }
                    continue;
                }

                // 2. STUN Message Handling
                if let Ok(msg) = StunMessage::decode(slice) {
                    // Check username for error code testing
                    let username = msg.attributes.iter().find_map(|a| {
                        if let StunAttribute::Username(u) = a {
                            Some(u.as_str())
                        } else {
                            None
                        }
                    });

                    if let Some(u) = username {
                        if u == "quota" {
                            let resp =
                                StunMessage::new(ALLOCATE_ERROR_RESPONSE, msg.transaction_id)
                                    .with_attribute(StunAttribute::ErrorCode {
                                        code: CODE_ALLOCATION_QUOTA_REACHED,
                                        reason: "Allocation Quota Reached".into(),
                                    });
                            let encoded = resp.encode();
                            let _ = s_sock.send_to(&encoded, client_addr).await;
                            continue;
                        } else if u == "forbidden" {
                            let resp =
                                StunMessage::new(ALLOCATE_ERROR_RESPONSE, msg.transaction_id)
                                    .with_attribute(StunAttribute::ErrorCode {
                                        code: CODE_FORBIDDEN,
                                        reason: "Forbidden".into(),
                                    });
                            let encoded = resp.encode();
                            let _ = s_sock.send_to(&encoded, client_addr).await;
                            continue;
                        } else if u == "server_err" {
                            let resp =
                                StunMessage::new(ALLOCATE_ERROR_RESPONSE, msg.transaction_id)
                                    .with_attribute(StunAttribute::ErrorCode {
                                        code: CODE_SERVER_ERROR,
                                        reason: "Server Error".into(),
                                    });
                            let encoded = resp.encode();
                            let _ = s_sock.send_to(&encoded, client_addr).await;
                            continue;
                        }
                    }

                    match msg.message_type {
                        ALLOCATE_REQUEST => {
                            if msg.realm().is_none() || msg.nonce().is_none() {
                                // 401 Challenge
                                let err_resp =
                                    StunMessage::new(ALLOCATE_ERROR_RESPONSE, msg.transaction_id)
                                        .with_attribute(StunAttribute::ErrorCode {
                                            code: CODE_UNAUTHORIZED,
                                            reason: "Unauthorized".into(),
                                        })
                                        .with_attribute(StunAttribute::Realm(realm.clone()))
                                        .with_attribute(StunAttribute::Nonce(
                                            initial_nonce.clone(),
                                        ));
                                let encoded = err_resp.encode();
                                let _ = s_sock.send_to(&encoded, client_addr).await;
                            } else if s_stale.swap(false, Ordering::SeqCst) {
                                // Simulate 438 Stale Nonce
                                let err_resp =
                                    StunMessage::new(ALLOCATE_ERROR_RESPONSE, msg.transaction_id)
                                        .with_attribute(StunAttribute::ErrorCode {
                                            code: CODE_STALE_NONCE,
                                            reason: "Stale Nonce".into(),
                                        })
                                        .with_attribute(StunAttribute::Realm(realm.clone()))
                                        .with_attribute(StunAttribute::Nonce(fresh_nonce.clone()));
                                let encoded = err_resp.encode();
                                let _ = s_sock.send_to(&encoded, client_addr).await;
                            } else {
                                // Authenticated 200 OK
                                let relayed: SocketAddr =
                                    format!("127.0.0.1:{next_port}").parse().unwrap();
                                next_port = next_port.saturating_add(1);
                                sessions.insert(
                                    client_addr,
                                    ClientSession {
                                        relayed_addr: relayed,
                                        channel: None,
                                    },
                                );

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
                            let chan = msg.attributes.iter().find_map(|a| {
                                if let StunAttribute::ChannelNumber(c) = a {
                                    Some(*c)
                                } else {
                                    None
                                }
                            });
                            if let Some(entry) = sessions.get_mut(&client_addr) {
                                entry.channel = chan;
                            }

                            let resp = StunMessage::new(CHANNEL_BIND_RESPONSE, msg.transaction_id);
                            let encoded = resp.encode_with_integrity(&key);
                            let _ = s_sock.send_to(&encoded, client_addr).await;
                        }
                        REFRESH_REQUEST => {
                            let requested_life = msg.lifetime().unwrap_or(600);
                            let resp = StunMessage::new(REFRESH_RESPONSE, msg.transaction_id)
                                .with_attribute(StunAttribute::Lifetime(requested_life));
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
            stale_nonce_trigger,
            handle,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn trigger_stale_nonce(&self) {
        self.stale_nonce_trigger.store(true, Ordering::SeqCst);
    }

    pub fn stop(self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.abort();
    }
}
