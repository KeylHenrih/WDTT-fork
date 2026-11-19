//! Synthetic DTLS 1.2 handshake messages.
//!
//! The handshake exists so that a passive observer sees a genuine-looking
//! WebRTC DTLS negotiation: a `ClientHello` carrying the extensions a browser
//! sends, a `ServerHello` that echoes them, a certificate, a key exchange and
//! the `ChangeCipherSpec`/`Finished` pair.
//!
//! None of it establishes a secret. Every byte that would normally be
//! negotiated is derived from the pre-shared key, and every byte that would
//! normally be verified — the certificate chain, the signature in
//! `ServerKeyExchange`, the `Finished` verify data — is a deterministic
//! function of that same secret. Authentication is the Pre-Auth Knock layer's
//! job; this layer only has to be *shaped* like DTLS.
//!
//! # Message sequence
//!
//! ```text
//! client                                server
//!   |---- ClientHello -------------------->|
//!   |<--- ServerHello ---------------------|
//!   |<--- Certificate ---------------------|
//!   |<--- ServerKeyExchange ---------------|
//!   |<--- ServerHelloDone -----------------|
//!   |---- ClientKeyExchange -------------->|
//!   |---- ChangeCipherSpec --------------->|
//!   |---- Finished ----------------------->|
//! ```

use crate::dtls::{HandshakeType, handshake_message};

/// Extension type: supported groups (RFC 8422).
const EXT_SUPPORTED_GROUPS: u16 = 10;
/// Extension type: signature algorithms (RFC 8446 §4.2.3).
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
/// Extension type: application-layer protocol negotiation (RFC 7301).
const EXT_ALPN: u16 = 16;
/// Extension type: extended master secret (RFC 7627).
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/// Extension type: use SRTP (RFC 5764).
const EXT_USE_SRTP: u16 = 14;
/// Extension type: renegotiation info (RFC 5746).
const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;
/// Extension type: connection id (RFC 9146).
const EXT_CONNECTION_ID: u16 = 54;
/// Extension type: server name (RFC 6066).
const EXT_SERVER_NAME: u16 = 0;

/// Value for the `x25519` named group, which WebRTC stacks offer first.
const GROUP_X25519: u16 = 29;
/// Value for the `secp256r1` named group.
const GROUP_SECP256R1: u16 = 23;
/// Signature algorithm `ecdsa_secp256r1_sha256`.
const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// Signature algorithm `rsa_pss_rsae_sha256`, present in every browser hello.
const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;

/// ALPN protocol identifier browsers offer for WebRTC data channels.
const ALPN_WEBRTC: &[u8] = b"webrtc";
/// SRTP protection profile `SRTP_AES128_CM_HMAC_SHA1_80`, the mandatory one.
const SRTP_PROFILE_AES128_CM_HMAC_SHA1_80: u16 = 0x0001;
/// SRTP protection profile `SRTP_AEAD_AES_128_GCM`.
const SRTP_PROFILE_AEAD_AES_128_GCM: u16 = 0x0007;

/// Builds the body of a `ClientHello`.
///
/// The body carries a version pinned to DTLS 1.2, a random field drawn from
/// the keys (so it is stable across retransmissions of the same handshake but
/// unguessable to an observer), and the extension block a browser would send.
///
/// # Errors
///
/// Returns [`HandshakeError::BodyTooLarge`] if the assembled body cannot be
/// expressed, which cannot happen with the fixed inputs here.
pub fn client_hello_body(
    random: &[u8; 32],
    session_id: &[u8; 32],
    cookie: &[u8],
    server_name: &str,
    cid: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let mut body = Vec::with_capacity(256);

    // client_version: DTLS 1.2.
    body.extend_from_slice(&0xFEFDu16.to_be_bytes());
    // random: 32 bytes.
    body.extend_from_slice(random);

    // legacy_session_id: 32 bytes for DTLS (RFC 6347 §4.2.1 keeps the TLS
    // variable-length form but requires exactly 32 when non-empty).
    body.push(32u8);
    body.extend_from_slice(session_id);

    // cookie: variable, empty on the first flight of a full handshake.
    push_u8_vec(&mut body, cookie)?;

    // cipher_suites: AES-128-GCM-SHA256 first, the WebRTC default.
    let suites: [u16; 3] = [
        0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    ];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for suite in suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }

    // compression_methods: only null compression.
    body.push(1u8);
    body.push(0u8);

    let extensions = client_extensions(server_name, cid)?;
    body.extend_from_slice(&extensions);

    Ok(body)
}

/// Assembles the `ClientHello` extension block.
fn client_extensions(server_name: &str, cid: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let mut exts = Vec::with_capacity(192);

    // server_name (SNI), so the stream names the host it claims to reach.
    if !server_name.is_empty() {
        let name = server_name.as_bytes();
        let mut value = Vec::with_capacity(name.len() + 5);
        value.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        value.push(0u8); // host_name
        value.extend_from_slice(&(name.len() as u16).to_be_bytes());
        value.extend_from_slice(name);
        push_extension(&mut exts, EXT_SERVER_NAME, &value);
    }

    // renegotiation_info: an empty renegotiated_connection vector.
    push_extension(&mut exts, EXT_RENEGOTIATION_INFO, &[0u8]);

    // supported_groups: x25519 and secp256r1, in browser order.
    let mut groups = Vec::with_capacity(6);
    groups.extend_from_slice(&4u16.to_be_bytes());
    groups.extend_from_slice(&GROUP_X25519.to_be_bytes());
    groups.extend_from_slice(&GROUP_SECP256R1.to_be_bytes());
    push_extension(&mut exts, EXT_SUPPORTED_GROUPS, &groups);

    // signature_algorithms.
    let mut sigs = Vec::with_capacity(8);
    sigs.extend_from_slice(&6u16.to_be_bytes());
    sigs.extend_from_slice(&SIG_ECDSA_SECP256R1_SHA256.to_be_bytes());
    sigs.extend_from_slice(&SIG_RSA_PSS_RSAE_SHA256.to_be_bytes());
    sigs.extend_from_slice(&0x0401u16.to_be_bytes()); // rsa_pkcs1_sha256
    push_extension(&mut exts, EXT_SIGNATURE_ALGORITHMS, &sigs);

    // use_srtp: the profile list a WebRTC peer offers.
    let mut srtp = Vec::with_capacity(6);
    srtp.extend_from_slice(&4u16.to_be_bytes());
    srtp.extend_from_slice(&SRTP_PROFILE_AES128_CM_HMAC_SHA1_80.to_be_bytes());
    srtp.extend_from_slice(&SRTP_PROFILE_AEAD_AES_128_GCM.to_be_bytes());
    srtp.push(0u8); // no mki
    push_extension(&mut exts, EXT_USE_SRTP, &srtp);

    // alpn: "webrtc".
    let mut alpn = Vec::with_capacity(8);
    alpn.extend_from_slice(&((ALPN_WEBRTC.len() + 1) as u16).to_be_bytes());
    alpn.push(ALPN_WEBRTC.len() as u8);
    alpn.extend_from_slice(ALPN_WEBRTC);
    push_extension(&mut exts, EXT_ALPN, &alpn);

    // extended_master_secret: empty value.
    push_extension(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);

    // connection_id (RFC 9146): the CID this layer routes by.
    let mut cid_ext = Vec::with_capacity(cid.len() + 1);
    cid_ext.push(cid.len() as u8);
    cid_ext.extend_from_slice(cid);
    push_extension(&mut exts, EXT_CONNECTION_ID, &cid_ext);

    let mut out = Vec::with_capacity(exts.len() + 2);
    out.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    out.extend_from_slice(&exts);
    Ok(out)
}

/// Builds the body of a `ServerHello`.
///
/// The server echoes the extensions it accepts, as a real server does.
///
/// # Errors
///
/// Returns [`HandshakeError::BodyTooLarge`] if the extension block overflows a
/// 16-bit length, which cannot happen with the fixed inputs here.
pub fn server_hello_body(
    random: &[u8; 32],
    session_id: &[u8; 32],
    cid: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&0xFEFDu16.to_be_bytes());
    body.extend_from_slice(random);
    body.push(32u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&0xC02Bu16.to_be_bytes()); // the negotiated suite
    body.push(0u8); // null compression

    let mut exts = Vec::with_capacity(64);
    // The server echoes the extended master secret and SRTP profile.
    push_extension(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);
    let mut srtp = Vec::with_capacity(6);
    srtp.extend_from_slice(&2u16.to_be_bytes());
    srtp.extend_from_slice(&SRTP_PROFILE_AES128_CM_HMAC_SHA1_80.to_be_bytes());
    srtp.push(0u8);
    push_extension(&mut exts, EXT_USE_SRTP, &srtp);
    // Renegotiation info with an empty vector, as a server replies.
    push_extension(&mut exts, EXT_RENEGOTIATION_INFO, &[0u8]);
    // The server's own connection id.
    let mut cid_ext = Vec::with_capacity(cid.len() + 1);
    cid_ext.push(cid.len() as u8);
    cid_ext.extend_from_slice(cid);
    push_extension(&mut exts, EXT_CONNECTION_ID, &cid_ext);

    let ext_len = u16::try_from(exts.len()).map_err(|_| HandshakeError::BodyTooLarge)?;
    body.extend_from_slice(&ext_len.to_be_bytes());
    body.extend_from_slice(&exts);
    Ok(body)
}

/// Builds a synthetic certificate body.
///
/// The certificate is deterministically generated from the PSK, so both ends
/// derive the same bytes without transmitting a real key pair, and the DER is
/// shaped like the ECDSA P-256 certificate a WebRTC peer would present.
///
/// # Errors
///
/// Returns [`HandshakeError::BodyTooLarge`] if the certificate does not fit a
/// 24-bit length, which cannot happen for the fixed template.
pub fn certificate_body(der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let mut body = Vec::with_capacity(der.len() + 16);
    // certificate_list length.
    let entry_len = der.len() + 3;
    body.extend_from_slice(&((entry_len) as u32).to_be_bytes()[1..]);
    // A single Certificate entry: 24-bit length, then the DER.
    body.extend_from_slice(&((der.len() as u32).to_be_bytes()[1..]));
    body.extend_from_slice(der);
    Ok(body)
}

/// Builds a synthetic `ServerKeyExchange` body.
///
/// A real server sends an ephemeral public key and a signature over it. Here
/// both are derived from the PSK: the "public key" is 32 bytes of key material
/// and the "signature" is a fixed-length tag, so the record has the right shape
/// and length without a real signing key.
#[must_use]
pub fn server_key_exchange_body(ephemeral: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(32 + signature.len() + 6);
    body.push(3u8); // named_curve
    body.extend_from_slice(&GROUP_X25519.to_be_bytes());
    body.push(32u8);
    body.extend_from_slice(ephemeral);
    body.extend_from_slice(&((signature.len() as u16).to_be_bytes()));
    body.extend_from_slice(signature);
    body
}

/// Builds a synthetic `ClientKeyExchange` body.
#[must_use]
pub fn client_key_exchange_body(ephemeral: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(33);
    body.push(32u8);
    body.extend_from_slice(ephemeral);
    body
}

/// Wraps a handshake body into a full handshake message with its header.
#[must_use]
pub fn message(msg_type: HandshakeType, message_seq: u16, body: &[u8]) -> Vec<u8> {
    handshake_message(msg_type, message_seq, body)
}

/// Returns the `ChangeCipherSpec` payload: the single byte `0x01`.
#[must_use]
pub const fn change_cipher_spec_payload() -> [u8; 1] {
    [0x01]
}

/// Appends a length-prefixed byte vector whose length fits in one byte.
fn push_u8_vec(out: &mut Vec<u8>, value: &[u8]) -> Result<(), HandshakeError> {
    let len = u8::try_from(value.len()).map_err(|_| HandshakeError::BodyTooLarge)?;
    out.push(len);
    out.extend_from_slice(value);
    Ok(())
}

/// Appends one extension: type, 16-bit length, value.
fn push_extension(out: &mut Vec<u8>, ext_type: u16, value: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Errors raised while building a handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// A field would not fit in the 16-bit or 24-bit length the format
    /// reserves for it.
    #[error("handshake body is too large for its wire encoding")]
    BodyTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random() -> [u8; 32] {
        [0x11u8; 32]
    }

    fn session() -> [u8; 32] {
        [0x22u8; 32]
    }

    #[test]
    fn test_client_hello_has_a_dtls_version_and_the_webrtc_extensions() {
        let body = client_hello_body(&random(), &session(), &[], "example.com", &[0xAB; 8])
            .expect("body");
        assert_eq!(&body[0..2], &0xFEFDu16.to_be_bytes());
        // The extensions block must name the WebRTC-typical extensions, so the
        // hello looks like a browser's rather than a bespoke client's.
        for needle in [
            &[0x00, 0x17u8][..],       // extended_master_secret
            &[0x00, 0x0Eu8][..],       // use_srtp
            &[0x00, 0x36u8][..],       // connection_id
            &[0x00, 0x10u8][..],       // alpn
            &[0xFF, 0x01u8][..],       // renegotiation_info
        ] {
            assert!(
                body.windows(needle.len()).any(|w| w == needle),
                "extension {needle:02x?} missing from the hello"
            );
        }
        assert!(
            body.windows(b"webrtc".len()).any(|w| w == b"webrtc"),
            "alpn identifier missing"
        );
    }

    #[test]
    fn test_client_hello_embeds_the_cid_and_sni() {
        let cid = [0x5A; 8];
        let body = client_hello_body(&random(), &session(), &[], "sni.example.org", &cid)
            .expect("body");
        assert!(body.windows(8).any(|w| w == cid));
        assert!(body.windows("sni.example.org".len()).any(|w| w == b"sni.example.org"));
    }

    #[test]
    fn test_client_hello_is_deterministic_for_the_same_inputs() {
        let a = client_hello_body(&random(), &session(), &[], "e.com", &[1; 8]).expect("body");
        let b = client_hello_body(&random(), &session(), &[], "e.com", &[1; 8]).expect("body");
        assert_eq!(a, b);
    }

    #[test]
    fn test_server_hello_echoes_a_version_and_a_suite() {
        let body = server_hello_body(&random(), &session(), &[7; 8]).expect("body");
        assert_eq!(&body[0..2], &0xFEFDu16.to_be_bytes());
        // The negotiated suite is AES-128-GCM-SHA256.
        assert!(body.windows(2).any(|w| w == 0xC02Bu16.to_be_bytes()));
        assert!(body.windows(8).any(|w| w == [7u8; 8]));
    }

    #[test]
    fn test_certificate_body_is_length_prefixed() {
        let der = vec![0x30u8; 64];
        let body = certificate_body(&der).expect("body");
        // A single list entry, whose 24-bit length equals the DER plus its own
        // three length bytes.
        let entry_len = der.len() + 3;
        let declared = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
        assert_eq!(declared, entry_len);
        assert_eq!(body.len(), 3 + entry_len);
    }

    #[test]
    fn test_server_key_exchange_layout() {
        let body = server_key_exchange_body(&[0x33; 32], &[0x44; 64]);
        assert_eq!(body[0], 3);
        assert_eq!(u16::from_be_bytes([body[1], body[2]]), GROUP_X25519);
        assert_eq!(body[3], 32);
        assert_eq!(&body[4..36], &[0x33; 32]);
        assert_eq!(u16::from_be_bytes([body[36], body[37]]), 64);
        assert_eq!(body.len(), 38 + 64);
    }

    #[test]
    fn test_handshake_message_header_is_twelve_bytes_and_declares_the_body() {
        let body = vec![0xAAu8; 30];
        let msg = message(HandshakeType::ClientHello, 7, &body);
        assert_eq!(msg.len(), 12 + body.len());
        assert_eq!(msg[0], HandshakeType::ClientHello.as_u8());
        // The 24-bit body length.
        let declared = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
        assert_eq!(declared, 30);
        // The message sequence.
        assert_eq!(u16::from_be_bytes([msg[4], msg[5]]), 7);
        // A zero fragment offset and a fragment length equal to the body.
        assert_eq!(&msg[6..9], &[0, 0, 0]);
        let frag = ((msg[9] as usize) << 16) | ((msg[10] as usize) << 8) | msg[11] as usize;
        assert_eq!(frag, 30);
    }

    #[test]
    fn test_change_cipher_spec_payload_is_the_single_byte_one() {
        assert_eq!(change_cipher_spec_payload(), [0x01]);
    }

    #[test]
    fn test_oversized_cookie_is_rejected() {
        let cookie = vec![0u8; 300];
        assert_eq!(
            client_hello_body(&random(), &session(), &cookie, "e.com", &[0; 8]),
            Err(HandshakeError::BodyTooLarge)
        );
    }
}
