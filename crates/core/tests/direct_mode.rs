use bytes::BytesMut;
use rand::RngCore;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use wdtt_core::{TunnelServer, TunnelServerConfig};
use wdtt_crypto::{DEFAULT_MAX_CLOCK_SKEW_SEC, KnockAuthenticator, Psk, derive_pre_auth_knock_key};
use wdtt_proto::{FrameType, FrameView, encode_frame};

#[tokio::test]
async fn test_direct_udp_mode_session_demux_and_silent_drop() {
    let psk = [0x42u8; 32];

    // 1. Mock WireGuard endpoint on server
    let server_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_wg_addr = server_wg.local_addr().unwrap();

    // 2. Start TunnelServer in direct UDP listen mode on dynamic port
    let srv_listen_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_listen_addr = srv_listen_sock.local_addr().unwrap();
    drop(srv_listen_sock);

    let server_cfg = TunnelServerConfig {
        turn_server_addr: "0.0.0.0:0".parse().unwrap(),
        turn_username: String::new(),
        turn_password: String::new(),
        turn_realm: String::new(),
        wg_endpoint_addr: server_wg_addr,
        psk,
        coalesce_window: None,
        direct_listen_addr: Some(srv_listen_addr),
        stream_listen_addr: None,
        tls_cert_der: None,
        tls_key_der: None,
    };

    let mut server = TunnelServer::new(server_cfg);
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (alloc_tx, alloc_rx) = tokio::sync::oneshot::channel();

    let srv_task =
        tokio::spawn(async move { server.run_with_notify(cancel_rx, Some(alloc_tx)).await });

    let bound_addr = alloc_rx.await.expect("allocated direct address");
    assert_eq!(bound_addr, srv_listen_addr);

    // 3. Test unauthenticated packet silent drop (no session, no knock)
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let unauth_payload = b"MALICIOUS_SCANNER_PAYLOAD";
    client_sock
        .send_to(unauth_payload, bound_addr)
        .await
        .unwrap();

    // Verify server did NOT forward unauthenticated packet to WG endpoint
    let mut wg_buf = [0u8; 1024];
    let res =
        tokio::time::timeout(Duration::from_millis(100), server_wg.recv_from(&mut wg_buf)).await;
    assert!(
        res.is_err(),
        "unauthenticated packet must be silently dropped"
    );

    // 4. Test invalid knock silent drop
    let mut bad_knock_frame = BytesMut::new();
    encode_frame(
        FrameType::HandshakeInit,
        0,
        0,
        0,
        b"CORRUPTED_KNOCK",
        &mut bad_knock_frame,
    );
    client_sock
        .send_to(&bad_knock_frame, bound_addr)
        .await
        .unwrap();

    let mut resp_buf = [0u8; 1024];
    let res = tokio::time::timeout(
        Duration::from_millis(100),
        client_sock.recv_from(&mut resp_buf),
    )
    .await;
    assert!(
        res.is_err(),
        "invalid knock must be silently dropped without response"
    );

    // 5. Test valid Pre-Auth Knock
    let knock_key = derive_pre_auth_knock_key(&Psk::from_bytes(psk));
    let auth = KnockAuthenticator::new(knock_key, DEFAULT_MAX_CLOCK_SKEW_SEC);
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut client_nonce = [0u8; 16];
    let session_id = [0xAAu8; 16];
    rand::rng().fill_bytes(&mut client_nonce);

    let knock_wire = auth.generate_knock_packet(now_sec, &client_nonce, &session_id, 32);
    let mut knock_frame = BytesMut::new();
    encode_frame(
        FrameType::HandshakeInit,
        0,
        0,
        0,
        &knock_wire,
        &mut knock_frame,
    );
    client_sock.send_to(&knock_frame, bound_addr).await.unwrap();

    // Server must respond with HandshakeResp
    let (n, resp_addr) = tokio::time::timeout(
        Duration::from_millis(500),
        client_sock.recv_from(&mut resp_buf),
    )
    .await
    .expect("timely handshake response")
    .unwrap();
    assert_eq!(resp_addr, bound_addr);
    let (view, _) = FrameView::decode(&resp_buf[..n]).unwrap();
    assert_eq!(view.header.frame_type, FrameType::HandshakeResp);

    // 6. Send authenticated Data frame through client_sock
    let test_data = b"WIREGUARD_DATA_PACKET_CONTENT";
    let mut data_frame = BytesMut::new();
    encode_frame(FrameType::Data, 0, 0, 1, test_data, &mut data_frame);
    client_sock.send_to(&data_frame, bound_addr).await.unwrap();

    // Server WG backend must receive the data!
    let (n_wg, _) =
        tokio::time::timeout(Duration::from_millis(500), server_wg.recv_from(&mut wg_buf))
            .await
            .expect("timely WG forward")
            .unwrap();
    assert_eq!(&wg_buf[..n_wg], test_data);

    // 7. Server WG replies -> client_sock receives it
    let wg_reply = b"WIREGUARD_SERVER_RESPONSE";
    server_wg.send_to(wg_reply, bound_addr).await.unwrap();

    // 8. Connect second client socket with SAME session_id (simulating multi-stream stream 2)
    let stream2_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut nonce2 = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce2);
    let knock2_wire = auth.generate_knock_packet(now_sec, &nonce2, &session_id, 32);
    let mut knock2_frame = BytesMut::new();
    encode_frame(
        FrameType::HandshakeInit,
        1,
        0,
        0,
        &knock2_wire,
        &mut knock2_frame,
    );
    stream2_sock
        .send_to(&knock2_frame, bound_addr)
        .await
        .unwrap();

    let (n2, _) = tokio::time::timeout(
        Duration::from_millis(500),
        stream2_sock.recv_from(&mut resp_buf),
    )
    .await
    .expect("timely handshake response for stream 2")
    .unwrap();
    let (view2, _) = FrameView::decode(&resp_buf[..n2]).unwrap();
    assert_eq!(view2.header.frame_type, FrameType::HandshakeResp);

    // Send data from stream 2 -> verify it forwards to the SAME session on server_wg!
    let test_data2 = b"STREAM_2_WIREGUARD_PACKET";
    let mut data2_frame = BytesMut::new();
    encode_frame(FrameType::Data, 1, 0, 1, test_data2, &mut data2_frame);
    stream2_sock
        .send_to(&data2_frame, bound_addr)
        .await
        .unwrap();

    let (n_wg2, _) =
        tokio::time::timeout(Duration::from_millis(500), server_wg.recv_from(&mut wg_buf))
            .await
            .expect("stream 2 data forwarded to WG")
            .unwrap();
    assert_eq!(&wg_buf[..n_wg2], test_data2);

    // Clean up
    let _ = cancel_tx.send(true);
    let _ = srv_task.await;
}
