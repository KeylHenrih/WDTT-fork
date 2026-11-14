use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use wdtt_turn::{TurnClient, TurnClientConfig};

#[tokio::test]
async fn test_coturn_live_if_available() {
    let coturn_addr: SocketAddr = "127.0.0.1:3478".parse().unwrap();

    // Check if coturn is reachable by sending a quick probe
    let socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(_) => return,
    };

    // STUN binding probe
    let probe = wdtt_turn::StunMessage::new(wdtt_turn::BINDING_REQUEST, [0xEE; 12]).encode();
    if socket.send_to(&probe, coturn_addr).await.is_err() {
        eprintln!("Local coturn server not running on 127.0.0.1:3478; skipping live coturn test.");
        return;
    }

    let mut buf = [0u8; 1024];
    let is_live = match timeout(Duration::from_millis(300), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => len >= 20,
        _ => false,
    };

    if !is_live {
        eprintln!(
            "Local coturn server not responding on 127.0.0.1:3478; skipping live coturn test."
        );
        return;
    }

    eprintln!(
        "Live coturn detected on 127.0.0.1:3478! Executing full allocation and keepalive tests..."
    );
    let config = TurnClientConfig {
        server_addr: coturn_addr,
        peer_addr: "10.0.0.2:51820".parse().unwrap(),
        username: "testuser".into(),
        password: "testpassword123".into(),
        channel_number: 0x4000,
        lifetime_sec: 600,
    };

    let mut client = TurnClient::bind("127.0.0.1:0".parse().unwrap(), config)
        .await
        .expect("bind turn client");

    let relayed = client.allocate().await.expect("allocate on live coturn");
    eprintln!("Successfully allocated on live coturn: {relayed}");
    assert!(client.relayed_addr().is_some());

    // Test refresh allocation on live coturn
    let refreshed = client
        .refresh_allocation(300)
        .await
        .expect("refresh on live coturn");
    eprintln!("Refreshed lifetime on live coturn: {refreshed}s");
    assert!(refreshed > 0);

    // Test refresh permission on live coturn
    client
        .refresh_permission()
        .await
        .expect("refresh permission on live coturn");

    // Test refresh channel bind on live coturn
    client
        .refresh_channel_bind()
        .await
        .expect("refresh channel bind on live coturn");
}
