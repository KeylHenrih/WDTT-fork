//! Integration tests for the server-side stream TURN listener.
//!
//! Each test drives the real `StreamTurnServer` with the real `StreamTurnClient`
//! over both plain TCP and TLS, exercising the 401 challenge, MessageIntegrity
//! verification, ChannelBind and bidirectional ChannelData relay.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use wdtt_turn::transport::TurnTransportMode;
use wdtt_turn::{
    StreamClientConfig, StreamServerConfig, StreamTurnClient, StreamTurnServer, TurnIncoming,
};

const USER: &str = "streamuser";
const PASS: &str = "streampass";
const REALM: &str = "streamrealm";
const CHANNEL: u16 = 0x4000;

fn server_config(addr: SocketAddr, tls: Option<(Vec<u8>, Vec<u8>)>) -> StreamServerConfig {
    let (cert, key) = match tls {
        Some((c, k)) => (Some(c), Some(k)),
        None => (None, None),
    };
    StreamServerConfig {
        listen_addr: addr,
        username: USER.into(),
        password: PASS.into(),
        realm: REALM.into(),
        channel_number: CHANNEL,
        lifetime_sec: 600,
        tls_cert_der: cert,
        tls_key_der: key,
    }
}

fn client_config(
    server_addr: SocketAddr,
    transport: TurnTransportMode,
    ca: Option<Vec<u8>>,
) -> StreamClientConfig {
    StreamClientConfig {
        server_addr,
        peer_addr: "10.0.0.2:51820".parse().unwrap(),
        username: USER.into(),
        password: PASS.into(),
        channel_number: CHANNEL,
        lifetime_sec: 600,
        transport,
        sni: ca.as_ref().map(|_| "localhost".to_string()),
        custom_ca_der: ca,
        bind_interface: None,
        tx_queue_capacity: 256,
    }
}

/// Drive one accepted connection: echo every inbound ChannelData payload back
/// through the connection's outbound queue.
async fn echo_connection(handle: wdtt_turn::StreamConnectionHandle) {
    let tx = handle.tx.clone();
    let mut control = handle.control_rx;
    let mut inbound = handle.rx;
    loop {
        tokio::select! {
            ctl = control.recv() => {
                match ctl {
                    Some(frame) => {
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            data = inbound.recv() => {
                match data {
                    Some(payload) => {
                        let mut echo = Vec::with_capacity(payload.len() + 5);
                        echo.extend_from_slice(b"ECHO:");
                        echo.extend_from_slice(&payload);
                        let frame = wdtt_turn::stream_server::encode_outbound(CHANNEL, &echo);
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

async fn run_roundtrip(server: StreamTurnServer, client_cfg: StreamClientConfig, tag: &[u8]) {
    let (done_tx, mut done_rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        let handle = server.accept().await.expect("accept");
        echo_connection(handle).await;
        let _ = done_tx.send(()).await;
    });

    let mut client = StreamTurnClient::connect(client_cfg)
        .await
        .expect("client connect");
    let relayed = client.allocate_relay().await.expect("allocate_relay");
    assert_eq!(relayed.port(), 0, "relayed address mirrors the listen addr");

    client
        .bind_peer("10.0.0.2:51820".parse().unwrap())
        .await
        .expect("bind_peer");

    client
        .send_channel_data(tag)
        .await
        .expect("send_channel_data");

    let received = tokio::time::timeout(Duration::from_secs(3), client.recv_frame())
        .await
        .expect("timeout waiting for echo")
        .expect("recv_frame");

    match received {
        TurnIncoming::ChannelData { channel, payload } => {
            assert_eq!(channel, CHANNEL);
            let mut expected = b"ECHO:".to_vec();
            expected.extend_from_slice(tag);
            assert_eq!(&payload[..], expected.as_slice());
        }
        other => panic!("expected ChannelData echo, got {other:?}"),
    }

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), done_rx.recv()).await;
}

#[tokio::test]
async fn test_stream_server_tcp_roundtrip() {
    let server = StreamTurnServer::bind(server_config("127.0.0.1:0".parse().unwrap(), None))
        .await
        .expect("bind tcp server");
    let addr = server.local_addr().unwrap();
    let cfg = client_config(addr, TurnTransportMode::Tcp, None);
    run_roundtrip(server, cfg, b"tcp-payload").await;
}

#[tokio::test]
async fn test_stream_server_tls_roundtrip() {
    let cert = include_bytes!("fixtures/server_cert.der").to_vec();
    let key = include_bytes!("fixtures/server_key.der").to_vec();
    let ca = include_bytes!("fixtures/ca_cert.der").to_vec();

    let server = StreamTurnServer::bind(server_config(
        "127.0.0.1:0".parse().unwrap(),
        Some((cert, key)),
    ))
    .await
    .expect("bind tls server");
    let addr = server.local_addr().unwrap();
    let cfg = client_config(addr, TurnTransportMode::Tls, Some(ca));
    run_roundtrip(server, cfg, b"tls-payload").await;
}

#[tokio::test]
async fn test_stream_server_rejects_bad_credentials() {
    let server = StreamTurnServer::bind(server_config("127.0.0.1:0".parse().unwrap(), None))
        .await
        .expect("bind server");
    let addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        let mut handle = server.accept().await.expect("accept");
        // Drain control frames so the connection task does not block on a full queue.
        while handle.control_rx.recv().await.is_some() {}
    });

    let mut cfg = client_config(addr, TurnTransportMode::Tcp, None);
    cfg.password = "wrong-password".into();

    let mut client = StreamTurnClient::connect(cfg).await.expect("connect");
    let err = client.allocate_relay().await;
    assert!(err.is_err(), "allocation must fail with bad credentials");
}

#[tokio::test]
async fn test_stream_server_requires_cert_and_key_together() {
    let mut cfg = server_config("127.0.0.1:0".parse().unwrap(), None);
    cfg.tls_cert_der = Some(include_bytes!("fixtures/server_cert.der").to_vec());
    let err = StreamTurnServer::bind(cfg).await;
    assert!(err.is_err(), "cert without key must be rejected");
}
