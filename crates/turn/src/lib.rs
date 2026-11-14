#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod channel;
pub mod client;
pub mod error;
pub mod mock_server;
pub mod stun;

pub use channel::{
    CHANNEL_DATA_HEADER_LEN, CHANNEL_MAX, CHANNEL_MIN, decode_channel_data, encode_channel_data,
    is_channel_data,
};
pub use client::{TurnClient, TurnClientConfig};
pub use error::TurnError;
pub use mock_server::MockTurnServer;
pub use stun::{
    ALLOCATE_REQUEST, ALLOCATE_RESPONSE, BINDING_REQUEST, BINDING_RESPONSE, CHANNEL_BIND_REQUEST,
    CHANNEL_BIND_RESPONSE, CREATE_PERMISSION_REQUEST, CREATE_PERMISSION_RESPONSE, REFRESH_REQUEST,
    REFRESH_RESPONSE, STUN_MAGIC_COOKIE, StunAttribute, StunMessage, compute_long_term_key,
};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_turn_client_with_mock_server_flow() {
        let user = "testuser";
        let pass = "testpassword123";

        // 1. Start embedded mock TURN server
        let server = MockTurnServer::start(user, pass)
            .await
            .expect("start mock server");
        let server_addr = server.local_addr();

        // 2. Initialize TURN client
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

        // 3. Perform Allocate -> CreatePermission -> ChannelBind
        let relayed_addr = client.allocate().await.expect("allocate on turn server");
        assert_eq!(relayed_addr, "127.0.0.1:49152".parse().unwrap());
        assert_eq!(client.relayed_addr(), Some(relayed_addr));

        // 4. Send and receive ChannelData
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

        // 5. Test Refresh
        let refreshed = client.refresh(300).await.expect("refresh turn allocation");
        assert_eq!(refreshed, 600);

        server.stop();
    }
}
