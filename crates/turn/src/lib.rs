#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod channel;
pub mod client;
pub mod error;
pub mod mock_server;
pub mod pool;
pub mod stream_client;
pub mod stream_server;
pub mod stun;
pub mod transport;

pub use channel::{
    CHANNEL_DATA_HEADER_LEN, CHANNEL_MAX, CHANNEL_MIN, decode_channel_data, encode_channel_data,
    is_channel_data,
};
pub use client::{TurnClient, TurnClientConfig, TurnIncoming};
pub use error::TurnError;
pub use mock_server::MockTurnServer;
pub use pool::{
    DEFAULT_MAX_STREAMS, DEFAULT_POOL_SIZE, DEFAULT_PROBE_TIMEOUT, StreamGuard, StreamPool,
    establish_pool,
};
pub use stream_client::{StreamClientConfig, StreamTurnClient};
pub use stream_server::{StreamConnectionHandle, StreamServerConfig, StreamTurnServer};
pub use stun::{
    ALLOCATE_REQUEST, ALLOCATE_RESPONSE, BINDING_REQUEST, BINDING_RESPONSE, CHANNEL_BIND_REQUEST,
    CHANNEL_BIND_RESPONSE, CODE_ALLOCATION_MISMATCH, CODE_ALLOCATION_QUOTA_REACHED,
    CODE_BAD_REQUEST, CODE_FORBIDDEN, CODE_SERVER_ERROR, CODE_STALE_NONCE, CODE_UNAUTHORIZED,
    CREATE_PERMISSION_REQUEST, CREATE_PERMISSION_RESPONSE, REFRESH_REQUEST, REFRESH_RESPONSE,
    STUN_MAGIC_COOKIE, StunAttribute, StunMessage, compute_long_term_key,
};
pub use transport::{BoundedTxQueue, TurnTransportMode, decode_tcp_frame, encode_tcp_channel_data};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_turn_client_single_allocation_flow() {
        let user = "alice";
        let pass = "secret123";

        let server = MockTurnServer::start(user, pass)
            .await
            .expect("start mock server");
        let server_addr = server.local_addr();

        let config = TurnClientConfig {
            server_addr,
            peer_addr: "10.0.0.1:51820".parse().unwrap(),
            username: user.into(),
            password: pass.into(),
            channel_number: 0x4000,
            lifetime_sec: 600,
        };

        let mut client = TurnClient::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .expect("bind turn client");

        let relayed_addr = client.allocate().await.expect("allocate on turn server");
        assert_eq!(relayed_addr, "127.0.0.1:49152".parse().unwrap());
        assert_eq!(client.relayed_addr(), Some(relayed_addr));

        // Test ChannelData echo
        let test_payload = b"Encapsulated WireGuard payload test!";
        client
            .send_channel_data(test_payload)
            .await
            .expect("send channel data");

        let mut recv_buf = [0u8; 2048];
        let received = client
            .recv_channel_data(&mut recv_buf)
            .await
            .expect("recv channel data");

        assert!(received.is_some());
        assert_eq!(received.unwrap(), Bytes::from_static(test_payload));

        // Test keepalive refreshes
        let refreshed = client
            .refresh_allocation(300)
            .await
            .expect("refresh turn allocation");
        assert_eq!(refreshed, 300);

        client
            .refresh_permission()
            .await
            .expect("refresh permission");
        client
            .refresh_channel_bind()
            .await
            .expect("refresh channel bind");

        server.stop();
    }

    #[tokio::test]
    async fn test_end_to_end_relay_two_clients() {
        let user = "relay_pair";
        let pass = "pass456";

        let server = MockTurnServer::start(user, pass)
            .await
            .expect("start mock server");
        let server_addr = server.local_addr();

        // 1. Client A allocates
        let mut client_a = TurnClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            TurnClientConfig {
                server_addr,
                peer_addr: "127.0.0.1:49153".parse().unwrap(), // will be updated with B's relayed
                username: user.into(),
                password: pass.into(),
                channel_number: 0x4000,
                lifetime_sec: 600,
            },
        )
        .await
        .unwrap();

        let relayed_a = client_a.allocate().await.unwrap();

        // 2. Client B allocates
        let mut client_b = TurnClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            TurnClientConfig {
                server_addr,
                peer_addr: relayed_a,
                username: user.into(),
                password: pass.into(),
                channel_number: 0x4000,
                lifetime_sec: 600,
            },
        )
        .await
        .unwrap();

        let relayed_b = client_b.allocate().await.unwrap();

        // Rebind A's peer to B's relayed address
        client_a.set_peer_addr(relayed_b);
        client_a.refresh_permission().await.unwrap();
        client_a.refresh_channel_bind().await.unwrap();

        // 3. Client A -> Relay -> Client B
        let msg_a_to_b = b"WireGuard Handshake Initiation from A to B";
        client_a.send_channel_data(msg_a_to_b).await.unwrap();

        let mut buf_b = [0u8; 2048];
        let received_b = client_b.recv_channel_data(&mut buf_b).await.unwrap();
        assert_eq!(received_b, Some(Bytes::from_static(msg_a_to_b)));

        // 4. Client B -> Relay -> Client A
        let msg_b_to_a = b"WireGuard Handshake Response from B to A";
        client_b.send_channel_data(msg_b_to_a).await.unwrap();

        let mut buf_a = [0u8; 2048];
        let received_a = client_a.recv_channel_data(&mut buf_a).await.unwrap();
        assert_eq!(received_a, Some(Bytes::from_static(msg_b_to_a)));

        server.stop();
    }

    #[tokio::test]
    async fn test_stale_nonce_recovery_438() {
        let user = "stale_user";
        let pass = "stale_pass";

        let server = MockTurnServer::start(user, pass)
            .await
            .expect("start mock server");
        let server_addr = server.local_addr();

        // Enable 438 trigger on first authenticated request
        server.trigger_stale_nonce();

        let mut client = TurnClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            TurnClientConfig {
                server_addr,
                peer_addr: "10.0.0.1:51820".parse().unwrap(),
                username: user.into(),
                password: pass.into(),
                channel_number: 0x4000,
                lifetime_sec: 600,
            },
        )
        .await
        .unwrap();

        // Allocation must succeed transparently despite 438 Stale Nonce on first try!
        let relayed = client.allocate().await.expect("allocate with 438 recovery");
        assert!(client.relayed_addr().is_some());
        assert_eq!(client.relayed_addr(), Some(relayed));

        server.stop();
    }

    #[tokio::test]
    async fn test_error_responses_4xx_5xx() {
        let server = MockTurnServer::start("any", "any")
            .await
            .expect("start mock server");
        let server_addr = server.local_addr();

        // 1. Quota Reached (486)
        let mut client_quota = TurnClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            TurnClientConfig {
                server_addr,
                peer_addr: "10.0.0.1:51820".parse().unwrap(),
                username: "quota".into(),
                password: "p".into(),
                channel_number: 0x4000,
                lifetime_sec: 600,
            },
        )
        .await
        .unwrap();

        let res = client_quota.allocate().await;
        assert!(matches!(
            res,
            Err(TurnError::StunErrorResponse {
                code: CODE_ALLOCATION_QUOTA_REACHED,
                ..
            })
        ));

        // 2. Forbidden (403)
        let mut client_forbidden = TurnClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            TurnClientConfig {
                server_addr,
                peer_addr: "10.0.0.1:51820".parse().unwrap(),
                username: "forbidden".into(),
                password: "p".into(),
                channel_number: 0x4000,
                lifetime_sec: 600,
            },
        )
        .await
        .unwrap();

        let res = client_forbidden.allocate().await;
        assert!(matches!(
            res,
            Err(TurnError::StunErrorResponse {
                code: CODE_FORBIDDEN,
                ..
            })
        ));

        // 3. Server Error (500)
        let mut client_err = TurnClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            TurnClientConfig {
                server_addr,
                peer_addr: "10.0.0.1:51820".parse().unwrap(),
                username: "server_err".into(),
                password: "p".into(),
                channel_number: 0x4000,
                lifetime_sec: 600,
            },
        )
        .await
        .unwrap();

        let res = client_err.allocate().await;
        assert!(matches!(
            res,
            Err(TurnError::StunErrorResponse {
                code: CODE_SERVER_ERROR,
                ..
            })
        ));

        server.stop();
    }
}
