use bytes::BytesMut;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use wdtt_turn::stun::*;
use wdtt_turn::transport::{TurnTransportMode, decode_tcp_frame, encode_tcp_channel_data};
use wdtt_turn::{StreamClientConfig, StreamTurnClient, TurnIncoming};

#[tokio::test]
async fn test_stream_turn_client_tcp_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let user = "testuser";
    let pass = "testpassword";
    let realm = "testrealm";
    let nonce = "testnonce123";
    let key = compute_long_term_key(user, realm, pass);

    // Spawn mock TCP server
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut read_buf = BytesMut::new();
        let mut chunk = [0u8; 4096];

        loop {
            let n = match socket.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            read_buf.extend_from_slice(&chunk[..n]);

            while let Ok(Some(incoming)) = decode_tcp_frame(&mut read_buf) {
                match incoming {
                    TurnIncoming::Stun(req) => match req.message_type {
                        ALLOCATE_REQUEST => {
                            let has_user = req
                                .attributes
                                .iter()
                                .any(|a| matches!(a, StunAttribute::Username(_)));
                            if !has_user {
                                let resp = StunMessage::new(ALLOCATE_RESPONSE, req.transaction_id)
                                    .with_attribute(StunAttribute::ErrorCode {
                                        code: CODE_UNAUTHORIZED,
                                        reason: "Unauthorized".into(),
                                    })
                                    .with_attribute(StunAttribute::Realm(realm.into()))
                                    .with_attribute(StunAttribute::Nonce(nonce.into()));
                                let enc = resp.encode();
                                socket.write_all(&enc).await.unwrap();
                            } else {
                                let relayed: SocketAddr = "127.0.0.1:49999".parse().unwrap();
                                let resp = StunMessage::new(ALLOCATE_RESPONSE, req.transaction_id)
                                    .with_attribute(StunAttribute::XorRelayedAddress(relayed))
                                    .with_attribute(StunAttribute::Lifetime(600));
                                let enc = resp.encode_with_integrity(&key);
                                socket.write_all(&enc).await.unwrap();
                            }
                        }
                        CREATE_PERMISSION_REQUEST => {
                            let resp =
                                StunMessage::new(CREATE_PERMISSION_RESPONSE, req.transaction_id);
                            let enc = resp.encode_with_integrity(&key);
                            socket.write_all(&enc).await.unwrap();
                        }
                        CHANNEL_BIND_REQUEST => {
                            let resp = StunMessage::new(CHANNEL_BIND_RESPONSE, req.transaction_id);
                            let enc = resp.encode_with_integrity(&key);
                            socket.write_all(&enc).await.unwrap();
                        }
                        _ => {}
                    },
                    TurnIncoming::ChannelData { channel, payload } => {
                        let mut echo_buf = BytesMut::new();
                        let mut echo_payload = Vec::new();
                        echo_payload.extend_from_slice(b"ECHO: ");
                        echo_payload.extend_from_slice(&payload);
                        encode_tcp_channel_data(channel, &echo_payload, &mut echo_buf);
                        socket.write_all(&echo_buf).await.unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let config = StreamClientConfig {
        server_addr,
        peer_addr: "10.0.0.2:51820".parse().unwrap(),
        username: user.into(),
        password: pass.into(),
        channel_number: 0x4000,
        lifetime_sec: 600,
        transport: TurnTransportMode::Tcp,
        sni: None,
        custom_ca_der: None,
        bind_interface: None,
        tx_queue_capacity: 256,
    };

    let mut client = StreamTurnClient::connect(config).await.expect("connect");
    let relayed = client.allocate_relay().await.expect("allocate_relay");
    assert_eq!(relayed, "127.0.0.1:49999".parse().unwrap());

    client
        .bind_peer("10.0.0.2:51820".parse().unwrap())
        .await
        .expect("bind_peer");

    client
        .send_channel_data(b"ping from stream client")
        .await
        .expect("send_channel_data");

    let received = tokio::time::timeout(Duration::from_secs(2), client.recv_frame())
        .await
        .expect("timeout")
        .expect("recv_frame");

    if let TurnIncoming::ChannelData { channel, payload } = received {
        assert_eq!(channel, 0x4000);
        assert_eq!(&payload[..], b"ECHO: ping from stream client");
    } else {
        panic!("expected ChannelData echo");
    }
}

#[tokio::test]
async fn test_stream_turn_client_tls_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let ca_cert_der = include_bytes!("fixtures/ca_cert.der").to_vec();
    let server_cert_der = include_bytes!("fixtures/server_cert.der").to_vec();
    let server_key_der = include_bytes!("fixtures/server_key.der").to_vec();
    let certs = vec![CertificateDer::from(server_cert_der)];
    let key = PrivateKeyDer::Pkcs8(server_key_der.into());
    let server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let user = "tlsuser";
    let pass = "tlspassword";
    let realm = "tlsrealm";
    let nonce = "tlsnonce456";
    let key = compute_long_term_key(user, realm, pass);

    // Spawn mock TLS server
    tokio::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(tcp_stream).await.unwrap();
        let mut read_buf = BytesMut::new();
        let mut chunk = [0u8; 4096];

        loop {
            let n = match socket.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            read_buf.extend_from_slice(&chunk[..n]);

            while let Ok(Some(incoming)) = decode_tcp_frame(&mut read_buf) {
                match incoming {
                    TurnIncoming::Stun(req) => match req.message_type {
                        ALLOCATE_REQUEST => {
                            let has_user = req
                                .attributes
                                .iter()
                                .any(|a| matches!(a, StunAttribute::Username(_)));
                            if !has_user {
                                let resp = StunMessage::new(ALLOCATE_RESPONSE, req.transaction_id)
                                    .with_attribute(StunAttribute::ErrorCode {
                                        code: CODE_UNAUTHORIZED,
                                        reason: "Unauthorized".into(),
                                    })
                                    .with_attribute(StunAttribute::Realm(realm.into()))
                                    .with_attribute(StunAttribute::Nonce(nonce.into()));
                                let enc = resp.encode();
                                socket.write_all(&enc).await.unwrap();
                            } else {
                                let relayed: SocketAddr = "127.0.0.1:49998".parse().unwrap();
                                let resp = StunMessage::new(ALLOCATE_RESPONSE, req.transaction_id)
                                    .with_attribute(StunAttribute::XorRelayedAddress(relayed))
                                    .with_attribute(StunAttribute::Lifetime(600));
                                let enc = resp.encode_with_integrity(&key);
                                socket.write_all(&enc).await.unwrap();
                            }
                        }
                        CREATE_PERMISSION_REQUEST => {
                            let resp =
                                StunMessage::new(CREATE_PERMISSION_RESPONSE, req.transaction_id);
                            let enc = resp.encode_with_integrity(&key);
                            socket.write_all(&enc).await.unwrap();
                        }
                        CHANNEL_BIND_REQUEST => {
                            let resp = StunMessage::new(CHANNEL_BIND_RESPONSE, req.transaction_id);
                            let enc = resp.encode_with_integrity(&key);
                            socket.write_all(&enc).await.unwrap();
                        }
                        _ => {}
                    },
                    TurnIncoming::ChannelData { channel, payload } => {
                        let mut echo_buf = BytesMut::new();
                        let mut echo_payload = Vec::new();
                        echo_payload.extend_from_slice(b"TLS_ECHO: ");
                        echo_payload.extend_from_slice(&payload);
                        encode_tcp_channel_data(channel, &echo_payload, &mut echo_buf);
                        socket.write_all(&echo_buf).await.unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let config = StreamClientConfig {
        server_addr,
        peer_addr: "10.0.0.2:51820".parse().unwrap(),
        username: user.into(),
        password: pass.into(),
        channel_number: 0x4000,
        lifetime_sec: 600,
        transport: TurnTransportMode::Tls,
        sni: Some("localhost".into()),
        custom_ca_der: Some(ca_cert_der),
        bind_interface: None,
        tx_queue_capacity: 256,
    };

    let mut client = StreamTurnClient::connect(config)
        .await
        .expect("connect tls");
    let relayed = client.allocate_relay().await.expect("allocate_relay tls");
    assert_eq!(relayed, "127.0.0.1:49998".parse().unwrap());

    client
        .bind_peer("10.0.0.2:51820".parse().unwrap())
        .await
        .expect("bind_peer tls");

    client
        .send_channel_data(b"ping from tls stream client")
        .await
        .expect("send_channel_data tls");

    let received = tokio::time::timeout(Duration::from_secs(2), client.recv_frame())
        .await
        .expect("timeout")
        .expect("recv_frame");

    if let TurnIncoming::ChannelData { channel, payload } = received {
        assert_eq!(channel, 0x4000);
        assert_eq!(&payload[..], b"TLS_ECHO: ping from tls stream client");
    } else {
        panic!("expected TLS ChannelData echo");
    }
}
