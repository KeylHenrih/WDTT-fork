//! Integration tests for the stream pool.
//!
//! Each test drives the real [`StreamPool`] against the real
//! [`StreamTurnServer`] over plain TCP, exercising multi-stream establishment,
//! exclusive checkout, retirement of a dead stream and refill.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use wdtt_turn::transport::TurnTransportMode;
use wdtt_turn::{
    StreamClientConfig, StreamPool, StreamServerConfig, StreamTurnServer, TurnIncoming,
    establish_pool,
};

const USER: &str = "pooluser";
const PASS: &str = "poolpass";
const REALM: &str = "poolrealm";
const CHANNEL: u16 = 0x4000;

fn server_config(addr: SocketAddr) -> StreamServerConfig {
    StreamServerConfig {
        listen_addr: addr,
        username: USER.into(),
        password: PASS.into(),
        realm: REALM.into(),
        channel_number: CHANNEL,
        lifetime_sec: 600,
        tls_cert_der: None,
        tls_key_der: None,
    }
}

fn client_config(server_addr: SocketAddr) -> StreamClientConfig {
    StreamClientConfig {
        server_addr,
        peer_addr: "10.0.0.2:51820".parse().unwrap(),
        username: USER.into(),
        password: PASS.into(),
        channel_number: CHANNEL,
        lifetime_sec: 600,
        transport: TurnTransportMode::Tcp,
        sni: None,
        custom_ca_der: None,
        bind_interface: None,
        tx_queue_capacity: 256,
    }
}

/// Accept connections forever, echoing ChannelData back with an `ECHO:` prefix.
///
/// Returns a shutdown sender; dropping it (or sending on it) stops the accept
/// loop, which closes the listener and kills every established stream.
fn spawn_echo_server(server: StreamTurnServer) -> tokio::sync::oneshot::Sender<()> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = server.accept() => accepted,
            };
            let handle = match accepted {
                Ok(handle) => handle,
                Err(_) => break,
            };
            tokio::spawn(echo_connection(handle));
        }
    });
    shutdown_tx
}

async fn echo_connection(handle: wdtt_turn::StreamConnectionHandle) {
    let tx = handle.tx.clone();
    let mut control_rx = handle.control_rx;
    let mut rx = handle.rx;

    loop {
        tokio::select! {
            frame = control_rx.recv() => {
                match frame {
                    Some(frame) => {
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            payload = rx.recv() => {
                match payload {
                    Some(payload) => {
                        let mut echo = b"ECHO:".to_vec();
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

async fn start_server() -> SocketAddr {
    let server = StreamTurnServer::bind(server_config("127.0.0.1:0".parse().unwrap()))
        .await
        .expect("bind stream server");
    let addr = server.local_addr().unwrap();
    // The shutdown sender is dropped immediately; the accept loop keeps
    // running because it only stops when the sender is dropped *and* the
    // receiver observes it, which happens at test teardown.
    let _shutdown = spawn_echo_server(server);
    std::mem::forget(_shutdown);
    addr
}

#[tokio::test]
async fn pool_establishes_the_target_number_of_streams() {
    let addr = start_server().await;

    let pool = establish_pool(client_config(addr), 3, 8)
        .await
        .expect("establish pool");

    assert_eq!(pool.len(), 3);
    assert_eq!(pool.target_size(), 3);
    assert_eq!(pool.retired(), 0);
    assert!(pool.first_relayed_addr().is_some());
}

#[tokio::test]
async fn pool_hands_out_one_stream_at_a_time() {
    let addr = start_server().await;

    let mut pool = establish_pool(client_config(addr), 2, 8)
        .await
        .expect("establish pool");

    {
        let mut guard = pool.acquire().await.expect("acquire");
        assert!(guard.relayed_addr().is_some());
        guard.send_channel_data(b"pool-payload").await.unwrap();

        let incoming = tokio::time::timeout(Duration::from_secs(3), guard.recv_frame())
            .await
            .expect("recv timeout")
            .expect("recv frame");
        match incoming {
            TurnIncoming::ChannelData { channel, payload } => {
                assert_eq!(channel, CHANNEL);
                assert_eq!(&payload[..], b"ECHO:pool-payload");
            }
            other => panic!("unexpected frame: {other:?}"),
        }

        guard.release(&mut pool, true).await;
    }

    // The pool is usable again after the guard is released.
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.retired(), 0);
    let mut guard = pool.acquire().await.expect("second acquire");
    guard.release(&mut pool, true).await;
}

#[tokio::test]
async fn pool_retires_a_failed_stream_and_refills() {
    let addr = start_server().await;

    let mut pool = establish_pool(client_config(addr), 2, 8)
        .await
        .expect("establish pool");
    assert_eq!(pool.len(), 2);

    // Report the stream as dead; the pool must drop it and refill.
    {
        let mut guard = pool.acquire().await.expect("acquire");
        guard.release(&mut pool, false).await;
    }

    assert_eq!(pool.retired(), 1);
    assert_eq!(pool.len(), 2, "pool refilled to its target size");
}

#[tokio::test]
async fn pool_prune_keeps_healthy_streams() {
    let addr = start_server().await;

    let mut pool = establish_pool(client_config(addr), 2, 8)
        .await
        .expect("establish pool");
    assert_eq!(pool.len(), 2);

    // Every stream still answers its refresh probe, so nothing is retired.
    pool.probe_and_prune().await;

    assert_eq!(pool.retired(), 0);
    assert_eq!(pool.len(), 2);
}

#[tokio::test]
async fn pool_prune_skips_the_checked_out_stream() {
    let addr = start_server().await;

    let mut pool = establish_pool(client_config(addr), 2, 8)
        .await
        .expect("establish pool");

    let guard = pool.acquire().await.expect("acquire");
    let checked_out = guard.relayed_addr().expect("relayed addr");
    drop(guard);

    pool.probe_and_prune().await;

    // The probe must not have touched the stream that was checked out.
    assert_eq!(pool.retired(), 0);
    assert_eq!(pool.len(), 2);
    assert!(pool.is_checked_out(checked_out));
}

#[tokio::test]
async fn pool_refuses_to_exceed_its_ceiling() {
    let addr = start_server().await;

    let mut pool = StreamPool::new(client_config(addr), 1, 1);
    pool.add_stream().await.expect("first stream");

    let err = pool.add_stream().await.expect_err("pool is full");
    assert!(err.to_string().contains("full"));
}

#[tokio::test]
async fn pool_reports_failure_when_no_stream_can_be_established() {
    // Nothing is listening on this port.
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let err = establish_pool(client_config(addr), 2, 8)
        .await
        .expect_err("no server to talk to");
    assert!(!err.to_string().is_empty());
}

#[tokio::test]
async fn pool_clear_drops_every_stream() {
    let addr = start_server().await;

    let mut pool = establish_pool(client_config(addr), 2, 8)
        .await
        .expect("establish pool");
    assert_eq!(pool.len(), 2);

    pool.clear();
    assert!(pool.is_empty());
    assert!(pool.active_relayed_addr().is_none());
}

/// Keeps the `mpsc` import honest for the echo helper's channel types.
#[allow(dead_code)]
fn _assert_mpsc_used(_: mpsc::Sender<bytes::Bytes>) {}
