//! Core tunnel engine, session state machine, and adaptive multi-stream dispatcher.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod batch;
pub mod metrics;
pub mod tunnel;

pub use batch::{
    BatchCapabilities, BatchedUdpSocket, DEFAULT_BATCH_SIZE, RecvMeta, TransmitPacket,
};
pub use metrics::{MetricsSnapshot, TunnelMetrics};
pub use tunnel::{TunnelClient, TunnelClientConfig, TunnelError, TunnelServer, TunnelServerConfig};

/// Default MTU for WDTT v2 WireGuard inner tunnel interface.
pub const DEFAULT_TUNNEL_MTU: u16 = 1200;

/// Maximum number of active streams allocated per single call join hash.
pub const MAX_STREAMS_PER_HASH: usize = 8;

/// Minimum number of active streams in idle mode.
pub const MIN_STREAMS: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::watch;
    use wdtt_turn::MockTurnServer;

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

    #[test]
    fn test_core_limits() {
        assert_eq!(DEFAULT_TUNNEL_MTU, 1200);
        assert_eq!(MAX_STREAMS_PER_HASH, 8);
        assert_eq!(MIN_STREAMS, 2);
    }
}
