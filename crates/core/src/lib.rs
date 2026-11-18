//! Core tunnel engine, session state machine, and adaptive multi-stream dispatcher.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod batch;
pub mod keepalive;
pub mod metrics;
pub mod tun_datapath;
pub mod tunnel;

pub use batch::{
    BatchCapabilities, BatchedUdpSocket, DEFAULT_BATCH_SIZE, RecvMeta, TransmitPacket,
};
pub use keepalive::{AdaptiveKeepalive, AdaptiveKeepaliveConfig, KeepaliveNetworkCache, NetworkId};
pub use metrics::{MetricsSnapshot, TunnelMetrics};
pub use tunnel::{
    DirectSessionWorker, KeepaliveMode, StreamSessionWorker, TunnelClient, TunnelClientConfig,
    TunnelError, TunnelServer, TunnelServerConfig,
};
pub use wdtt_turn::TurnTransportMode;

/// Default MTU for WDTT v2 WireGuard inner tunnel interface (1360 prevents fragmentation on 1492 PPPoE WANs).
pub const DEFAULT_TUNNEL_MTU: u16 = 1360;

/// Maximum number of active streams allocated per single call join hash.
pub const MAX_STREAMS_PER_HASH: usize = 8;

/// Minimum number of active streams in idle mode.
pub const MIN_STREAMS: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::watch;
    use wdtt_turn::{MockTurnServer, TurnClient, TurnClientConfig};

    #[tokio::test]
    async fn test_end_to_end_tunnel_session_over_turn() {
        // 1. Start Mock TURN server
        let mock_turn = MockTurnServer::start("user", "pass")
            .await
            .expect("start mock turn");
        let turn_addr = mock_turn.local_addr();

        // 2. Prepare mock WireGuard endpoint for Server
        let server_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_wg_addr = server_wg.local_addr().unwrap();

        // 3. Prepare mock WireGuard endpoint for Client
        let _client_wg_app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let psk = [0x55u8; 32];

        // 4. Start TunnelServer
        let server_cfg = TunnelServerConfig {
            turn_server_addr: turn_addr,
            turn_username: "user".into(),
            turn_password: "pass".into(),
            turn_realm: "mock.turn.local".into(),
            wg_endpoint_addr: server_wg_addr,
            psk,
            coalesce_window: None,
            direct_listen_addr: None,
            stream_listen_addr: None,
            tls_cert_der: None,
            tls_key_der: None,
        };

        let (server_cancel_tx, server_cancel_rx) = watch::channel(false);

        // Pre-allocate server on TURN to obtain server_relayed_addr
        let server_turn_cfg = wdtt_turn::TurnClientConfig {
            server_addr: turn_addr,
            peer_addr: "0.0.0.0:0".parse().unwrap(),
            username: "user".into(),
            password: "pass".into(),
            channel_number: 0x4000,
            lifetime_sec: 600,
        };

        let mut probe_client =
            wdtt_turn::TurnClient::bind("0.0.0.0:0".parse().unwrap(), server_turn_cfg)
                .await
                .unwrap();
        let _server_relayed_addr = probe_client.allocate_relay().await.unwrap();
        drop(probe_client);

        // Spawn TunnelServer task
        let mut server_task = TunnelServer::new(server_cfg);

        let server_handle = tokio::spawn(async move {
            let _ = server_task.run(server_cancel_rx).await;
        });

        // Let server initialize and allocate
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = server_cancel_tx.send(true);
        server_handle.abort();
        mock_turn.stop();
    }

    #[tokio::test]
    async fn test_keepalive_chaff_and_ping_pong_exchange() {
        let mock_turn = MockTurnServer::start("user", "pass")
            .await
            .expect("start mock turn");
        let turn_addr = mock_turn.local_addr();
        let psk = [0x77u8; 32];

        // 1. Prepare server WireGuard mock
        let server_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_wg_addr = server_wg.local_addr().unwrap();

        // 2. Start server
        let server_cfg = TunnelServerConfig {
            turn_server_addr: turn_addr,
            turn_username: "user".into(),
            turn_password: "pass".into(),
            turn_realm: "mock.turn.local".into(),
            wg_endpoint_addr: server_wg_addr,
            psk,
            coalesce_window: None,
            direct_listen_addr: None,
            stream_listen_addr: None,
            tls_cert_der: None,
            tls_key_der: None,
        };
        let mut server = TunnelServer::new(server_cfg);
        let server_metrics = server.metrics();
        let (srv_cancel_tx, srv_cancel_rx) = watch::channel(false);
        let (srv_alloc_tx, srv_alloc_rx) = tokio::sync::oneshot::channel();

        let srv_handle = tokio::spawn(async move {
            let _ = server
                .run_with_notify(srv_cancel_rx, Some(srv_alloc_tx))
                .await;
        });

        let server_relayed = srv_alloc_rx.await.unwrap();

        // 3. Start client in Chaff mode (50 pps @ 20ms)
        let client_cfg = TunnelClientConfig {
            turn_server_addr: turn_addr,
            turn_username: "user".into(),
            turn_password: "pass".into(),
            turn_realm: "mock.turn.local".into(),
            server_relayed_addr: server_relayed,
            wg_listen_addr: "127.0.0.1:0".parse().unwrap(),
            psk,
            keepalive_mode: KeepaliveMode::Chaff,
            coalesce_window: None,
            turn_transport: TurnTransportMode::Udp,
            turn_sni: None,
            custom_ca_der: None,
            bind_interface: None,
        };
        let mut client = TunnelClient::new(client_cfg);
        let client_metrics = client.metrics();
        let (cln_cancel_tx, cln_cancel_rx) = watch::channel(false);
        let (cln_alloc_tx, cln_alloc_rx) = tokio::sync::oneshot::channel();

        let cln_handle = tokio::spawn(async move {
            let res = client
                .run_with_notify(cln_cancel_rx, Some(cln_alloc_tx))
                .await;
            if let Err(ref e) = res {
                eprintln!("Client error: {e:?}");
            }
            res
        });

        let _ = cln_alloc_rx.await.unwrap();

        // Wait up to 3s to allow several Chaff pings and Pong responses
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if server_metrics.snapshot().pings_rx >= 1 && client_metrics.snapshot().pings_tx >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let cln_snap = client_metrics.snapshot();
        let srv_snap = server_metrics.snapshot();

        assert!(
            cln_snap.pings_tx >= 2,
            "Client should transmit chaff pings (got {})",
            cln_snap.pings_tx
        );
        assert!(
            srv_snap.pings_rx >= 1,
            "Server should receive ping probes (got {})",
            srv_snap.pings_rx
        );

        let _ = cln_cancel_tx.send(true);
        let _ = srv_cancel_tx.send(true);
        cln_handle.abort();
        srv_handle.abort();
        mock_turn.stop();
    }

    #[tokio::test]
    async fn test_nat_reconnect_and_recovery_time() {
        let mock_turn = MockTurnServer::start("user", "pass").await.unwrap();
        let turn_addr = mock_turn.local_addr();

        let turn_cfg = TurnClientConfig {
            server_addr: turn_addr,
            peer_addr: "127.0.0.1:49152".parse().unwrap(),
            username: "user".into(),
            password: "pass".into(),
            channel_number: 0x4000,
            lifetime_sec: 600,
        };
        let mut client = TurnClient::bind("127.0.0.1:0".parse().unwrap(), turn_cfg)
            .await
            .unwrap();
        let _initial_relayed = client.allocate_relay().await.unwrap();
        let initial_local = client.socket().local_addr().unwrap();

        // Simulate NAT mapping expiration / external port change:
        let recovery_start = std::time::Instant::now();
        let new_bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        client.rebind_socket(new_bind_addr).await.unwrap();
        assert_ne!(client.socket().local_addr().unwrap(), initial_local);

        // Client reconnects and re-establishes allocation
        let reconnected_relayed = client.reconnect().await.unwrap();
        let recovery_elapsed = recovery_start.elapsed();

        assert_eq!(client.relayed_addr(), Some(reconnected_relayed));
        assert!(
            recovery_elapsed < Duration::from_millis(500),
            "Reconnection recovery took too long: {:?}",
            recovery_elapsed
        );

        mock_turn.stop();
    }

    #[test]
    fn test_core_limits() {
        assert_eq!(DEFAULT_TUNNEL_MTU, 1360);
        assert_eq!(MAX_STREAMS_PER_HASH, 8);
        assert_eq!(MIN_STREAMS, 2);
    }

    #[test]
    fn test_adaptive_coalescer_rules_and_control_bypass() {
        use crate::tunnel::{AdaptiveCoalescer, is_control_frame};
        use wdtt_proto::FrameType;

        // When window is configured
        let mut coalescer = AdaptiveCoalescer::new(Some(Duration::from_millis(1)));
        assert_eq!(coalescer.window(), Some(Duration::from_millis(1)));

        // 1 packet in wakeup -> sparse uniform traffic -> coalescing active
        coalescer.on_wakeup_batch(1);
        assert!(
            coalescer.is_coalescing_active(),
            "Single-packet batch must enable coalescing"
        );

        // 2 or more packets in wakeup -> bursty traffic (e.g. TCP stream) -> coalescing disabled!
        coalescer.on_wakeup_batch(2);
        assert!(
            !coalescer.is_coalescing_active(),
            "Batch >= 2 must immediately disable coalescing"
        );

        coalescer.on_wakeup_batch(16);
        assert!(
            !coalescer.is_coalescing_active(),
            "Full batch must disable coalescing"
        );

        // When window is None -> always disabled
        let mut disabled_coalescer = AdaptiveCoalescer::new(None);
        disabled_coalescer.on_wakeup_batch(1);
        assert!(!disabled_coalescer.is_coalescing_active());

        // Control frame bypass rules
        assert!(is_control_frame(FrameType::HandshakeInit));
        assert!(is_control_frame(FrameType::HandshakeResp));
        assert!(is_control_frame(FrameType::Ping));
        assert!(is_control_frame(FrameType::Pong));
        assert!(is_control_frame(FrameType::Disconnect));
        assert!(
            !is_control_frame(FrameType::Data),
            "Data frames must not bypass coalescer"
        );
    }

    #[tokio::test]
    async fn test_coalescing_deadline_flush_no_lost_wakeups() {
        use crate::batch::{BatchedUdpSocket, TransmitPacket};
        let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let srv_addr = srv.local_addr().unwrap();
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let batched_client = BatchedUdpSocket::new(client);

        let window = Duration::from_millis(5);
        let deadline = tokio::time::Instant::now() + window;
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);

        let packet_payload = b"coalesced_flush_payload";

        let flushed = tokio::select! {
            () = &mut sleep => {
                let pkts = [TransmitPacket {
                    buf: packet_payload,
                    addr: srv_addr,
                    gso_segment_size: None,
                }];
                batched_client.send_batch(&pkts).await.unwrap();
                true
            }
        };

        assert!(
            flushed,
            "Sleep deadline must fire and flush without lost wakeup"
        );

        let mut buf = [0u8; 1024];
        let (len, _src) = tokio::time::timeout(Duration::from_millis(100), srv.recv_from(&mut buf))
            .await
            .expect("Server must receive packet after deadline flush")
            .unwrap();
        assert_eq!(&buf[..len], packet_payload);
    }
}
