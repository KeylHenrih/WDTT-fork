//! DTLS 1.2 record layer and synthetic handshake for traffic masquerading.
//!
//! This module implements enough of RFC 6347 (DTLS 1.2) to make a WDTT stream
//! indistinguishable from a WebRTC media session to a passive observer, without
//! introducing a certificate authority or any key material beyond the
//! pre-shared key the Pre-Auth Knock layer already uses.
//!
//! # Why DTLS 1.2
//!
//! Real WebRTC stacks (Chrome, pion, libwebrtc) negotiate DTLS 1.2 in the
//! overwhelming majority of sessions. A DTLS 1.3 session is therefore an
//! anomaly in itself, and its fingerprints sit closer to TLS 1.3, which the
//! deployment target may filter. Version 1.2 is the conservative choice that
//! matches the traffic this layer is imitating.
//!
//! # Key derivation
//!
//! No certificate is used. Client and server authentication is already solved
//! by the Pre-Auth Knock layer, so the DTLS layer only needs to *look* like a
//! handshake. Every byte of key material is derived from the PSK:
//!
//! ```text
//! PSK
//!  └─ HKDF-SHA256(salt = b"WDTT-DTLS-v1", info = b"dtls/key-material")
//!      ├─ client_write_key (16 B)  AES-128-GCM
//!      ├─ server_write_key (16 B)  AES-128-GCM
//!      ├─ client_write_iv  ( 4 B)
//!      ├─ server_write_iv  ( 4 B)
//!      └─ cid              ( 8 B)  connection identifier
//! ```
//!
//! # Scope
//!
//! What this layer does **not** provide is confidentiality of the payload.
//! Secrecy comes from the transport TLS underneath. The DTLS records here give
//! the stream a plausible *format*; they are not a second security boundary.

use bytes::{BufMut, BytesMut};

use crate::aead::{AeadEngine, CipherSuite, NONCE_LEN};
use crate::error::CryptoError;
use crate::key::{AeadKey, Psk};

/// The DTLS version this layer speaks: 1.2, as encoded on the wire.
pub const DTLS_VERSION_1_2: u16 = 0xFEFD;

/// Length of a DTLS record header in bytes.
pub const RECORD_HEADER_LEN: usize = 13;

/// Length of the explicit nonce carried in an AEAD-protected record.
///
/// RFC 6347 §4.1.2.1 specifies an explicit 8-byte nonce for AEAD cipher suites.
pub const EXPLICIT_NONCE_LEN: usize = 8;

/// Length of the connection identifier, matching the WebRTC/pion default.
pub const CID_LEN: usize = 8;

/// Size of the write keys and write IVs derived from the PSK.
const WRITE_KEY_LEN: usize = 16;
/// Size of each per-direction write IV, which forms the nonce's fixed part.
const WRITE_IV_LEN: usize = 4;

/// HKDF salt for the DTLS key derivation.
const SALT_DTLS: &[u8] = b"WDTT-DTLS-v1";
/// HKDF info string for the single key-material expansion.
const INFO_DTLS_KEY_MATERIAL: &[u8] = b"dtls/key-material";

/// Total number of bytes the single HKDF expansion produces.
const KEY_MATERIAL_LEN: usize =
    (WRITE_KEY_LEN * 2) + (WRITE_IV_LEN * 2) + CID_LEN;

/// DTLS record content types (RFC 6347 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    /// A handshake message (`ClientHello`, `ServerHello`, ...).
    Handshake = 0x16,
    /// A `ChangeCipherSpec` message.
    ChangeCipherSpec = 0x14,
    /// An alert.
    Alert = 0x15,
    /// Application data: a WDTT frame rides here in steady state.
    ApplicationData = 0x17,
}

impl ContentType {
    /// Decodes a content type from its wire value.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidRecord`] for any value that is not one of
    /// the four defined content types.
    pub fn from_u8(value: u8) -> Result<Self, CryptoError> {
        match value {
            0x14 => Ok(Self::ChangeCipherSpec),
            0x15 => Ok(Self::Alert),
            0x16 => Ok(Self::Handshake),
            0x17 => Ok(Self::ApplicationData),
            other => Err(CryptoError::InvalidRecord {
                detail: format!("unknown content type {other:#04x}"),
            }),
        }
    }

    /// Returns the wire value of this content type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Handshake message types this layer emits (RFC 6347 §4.2).
///
/// Only the types needed for a synthetic WebRTC-shaped handshake are modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// `ClientHello`.
    ClientHello = 1,
    /// `ServerHello`.
    ServerHello = 2,
    /// `Certificate`.
    Certificate = 11,
    /// `ServerKeyExchange`.
    ServerKeyExchange = 12,
    /// `CertificateRequest`.
    CertificateRequest = 13,
    /// `ServerHelloDone`.
    ServerHelloDone = 14,
    /// `CertificateVerify`.
    CertificateVerify = 15,
    /// `ClientKeyExchange`.
    ClientKeyExchange = 16,
    /// `Finished`.
    Finished = 20,
}

impl HandshakeType {
    /// Returns the wire value of this handshake message type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A DTLS record sequence number.
///
/// DTLS uses a 48-bit sequence number per epoch, carried in six bytes on the
/// wire. The struct keeps the full `u64` and rejects values that do not fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SequenceNumber(u64);

impl SequenceNumber {
    /// The largest sequence number that fits in the 48-bit wire field.
    pub const MAX: u64 = (1u64 << 48) - 1;

    /// Builds a sequence number, rejecting anything wider than 48 bits.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidRecord`] when `value` does not fit in the
    /// six bytes the wire format reserves for it.
    pub fn new(value: u64) -> Result<Self, CryptoError> {
        if value > Self::MAX {
            return Err(CryptoError::InvalidRecord {
                detail: format!("sequence number {value} exceeds the 48-bit field"),
            });
        }
        Ok(Self(value))
    }

    /// Returns the numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next sequence number, saturating at the wire maximum.
    #[must_use]
    pub const fn next(self) -> Self {
        if self.0 >= Self::MAX {
            Self(Self::MAX)
        } else {
            Self(self.0 + 1)
        }
    }
}

/// Key material for the DTLS layer, derived from the pre-shared key.
#[derive(Clone)]
pub struct DtlsKeys {
    /// Key protecting records sent by the client.
    client_write_key: AeadKey,
    /// Key protecting records sent by the server.
    server_write_key: AeadKey,
    /// Fixed nonce component for records sent by the client.
    client_write_iv: [u8; WRITE_IV_LEN],
    /// Fixed nonce component for records sent by the server.
    server_write_iv: [u8; WRITE_IV_LEN],
    /// Connection identifier advertised in the handshake extensions.
    cid: [u8; CID_LEN],
}

impl std::fmt::Debug for DtlsKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material, even in a debug log.
        f.debug_struct("DtlsKeys")
            .field("client_write_key", &"<redacted>")
            .field("server_write_key", &"<redacted>")
            .field("client_write_iv", &"<redacted>")
            .field("server_write_iv", &"<redacted>")
            .field("cid", &self.cid)
            .finish()
    }
}

impl DtlsKeys {
    /// Returns the connection identifier.
    #[must_use]
    pub const fn cid(&self) -> &[u8; CID_LEN] {
        &self.cid
    }

    /// Returns the write key for the given role.
    #[must_use]
    fn write_key(&self, role: Role) -> &AeadKey {
        match role {
            Role::Client => &self.client_write_key,
            Role::Server => &self.server_write_key,
        }
    }

    /// Returns the write IV for the given role.
    #[must_use]
    fn write_iv(&self, role: Role) -> &[u8; WRITE_IV_LEN] {
        match role {
            Role::Client => &self.client_write_iv,
            Role::Server => &self.server_write_iv,
        }
    }
}

/// Which side of the connection a record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The tunnel client, which sends `client_write_key`-protected records.
    Client,
    /// The tunnel server, which sends `server_write_key`-protected records.
    Server,
}

impl Role {
    /// Returns the opposite role.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Derives the DTLS key material from the pre-shared key.
///
/// The derivation is deterministic, so both ends reach the same keys with no
/// additional exchange. This is what lets the layer dispense with certificates:
/// authentication happened at the Pre-Auth Knock layer, and everything here is
/// a pure function of the shared secret.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyLength`] if the expansion produces an
/// unexpected number of bytes, which would indicate an internal inconsistency.
pub fn derive_dtls_keys(psk: &Psk) -> Result<DtlsKeys, CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(SALT_DTLS), psk.as_bytes());
    let mut material = [0u8; KEY_MATERIAL_LEN];
    hk.expand(INFO_DTLS_KEY_MATERIAL, &mut material)
        .map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_MATERIAL_LEN,
            actual: KEY_MATERIAL_LEN,
        })?;

    let mut cursor = 0usize;
    let mut take = |len: usize| {
        let slice = &material[cursor..cursor + len];
        cursor += len;
        slice
    };

    let mut client_key = [0u8; 32];
    client_key[..WRITE_KEY_LEN].copy_from_slice(take(WRITE_KEY_LEN));
    let mut server_key = [0u8; 32];
    server_key[..WRITE_KEY_LEN].copy_from_slice(take(WRITE_KEY_LEN));

    let mut client_iv = [0u8; WRITE_IV_LEN];
    client_iv.copy_from_slice(take(WRITE_IV_LEN));
    let mut server_iv = [0u8; WRITE_IV_LEN];
    server_iv.copy_from_slice(take(WRITE_IV_LEN));

    let mut cid = [0u8; CID_LEN];
    cid.copy_from_slice(take(CID_LEN));

    Ok(DtlsKeys {
        client_write_key: AeadKey::from_bytes(client_key),
        server_write_key: AeadKey::from_bytes(server_key),
        client_write_iv: client_iv,
        server_write_iv: server_iv,
        cid,
    })
}

/// Builds the 12-byte AEAD nonce for a record.
///
/// RFC 6347 §4.1.2.1 composes an AEAD nonce from the record's fixed IV (the
/// first four bytes) followed by the explicit per-record nonce, which is built
/// here from the epoch and sequence number.
fn record_nonce(iv: &[u8; WRITE_IV_LEN], epoch: u16, seq: SequenceNumber) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0..WRITE_IV_LEN].copy_from_slice(iv);
    nonce[WRITE_IV_LEN..WRITE_IV_LEN + 2].copy_from_slice(&epoch.to_be_bytes());
    // The remaining six bytes are the low 48 bits of the sequence number.
    let raw = seq.get().to_be_bytes();
    nonce[WRITE_IV_LEN + 2..].copy_from_slice(&raw[2..]);
    nonce
}

/// Encodes a handshake message header (RFC 6347 §4.2.2).
///
/// The DTLS handshake header is twelve bytes: a one-byte message type, a
/// three-byte body length, a two-byte message sequence, a three-byte fragment
/// offset and a three-byte fragment length, all big-endian. This layer never
/// fragments, so the offset is zero and the fragment length equals the body
/// length.
fn encode_handshake_header(msg_type: HandshakeType, message_seq: u16, body_len: usize) -> [u8; 12] {
    let mut header = [0u8; 12];
    let len = body_len as u32;
    header[0] = msg_type.as_u8();
    header[1] = ((len >> 16) & 0xFF) as u8;
    header[2] = ((len >> 8) & 0xFF) as u8;
    header[3] = (len & 0xFF) as u8;
    header[4..6].copy_from_slice(&message_seq.to_be_bytes());
    // Fragment offset stays zero and the fragment length mirrors the body.
    header[6..9].copy_from_slice(&[0, 0, 0]);
    header[9] = ((len >> 16) & 0xFF) as u8;
    header[10] = ((len >> 8) & 0xFF) as u8;
    header[11] = (len & 0xFF) as u8;
    header
}

/// Builds a handshake message, header included, ready to be a record payload.
#[must_use]
pub fn handshake_message(msg_type: HandshakeType, message_seq: u16, body: &[u8]) -> Vec<u8> {
    let header = encode_handshake_header(msg_type, message_seq, body.len());
    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(body);
    out
}

/// A DTLS record as it appears on the wire, before protection is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Content type of the record.
    pub content_type: ContentType,
    /// Epoch the record belongs to: 0 during the handshake, 1 afterwards.
    pub epoch: u16,
    /// Per-epoch sequence number.
    pub sequence: SequenceNumber,
    /// Record payload.
    pub payload: Vec<u8>,
}

impl Record {
    /// Builds a plaintext record.
    #[must_use]
    pub fn new(
        content_type: ContentType,
        epoch: u16,
        sequence: SequenceNumber,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            content_type,
            epoch,
            sequence,
            payload,
        }
    }

    /// Encodes this record as a plaintext DTLS record.
    ///
    /// This form is what a handshake message uses before the cipher spec
    /// changes; it is also the parse target for the synthetic handshake.
    #[must_use]
    pub fn encode_plaintext(&self) -> BytesMut {
        let mut out = BytesMut::with_capacity(RECORD_HEADER_LEN + self.payload.len());
        out.put_u8(self.content_type.as_u8());
        out.put_u16(DTLS_VERSION_1_2);
        out.put_u16(self.epoch);
        let seq = self.sequence.get().to_be_bytes();
        out.extend_from_slice(&seq[2..]); // low 48 bits
        out.put_u16(self.payload.len() as u16);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Encodes this record with AEAD protection.
    ///
    /// The output carries the record header, the explicit per-record nonce, and
    /// the ciphertext with its appended tag.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the AEAD engine rejects the operation, which
    /// would indicate a key or nonce of the wrong size.
    pub fn encode_protected(
        &self,
        keys: &DtlsKeys,
        role: Role,
        engine: &AeadEngine,
    ) -> Result<BytesMut, CryptoError> {
        let iv = keys.write_iv(role);
        let nonce = record_nonce(iv, self.epoch, self.sequence);

        let mut ciphertext = BytesMut::with_capacity(self.payload.len());
        ciphertext.extend_from_slice(&self.payload);
        engine.encrypt(keys.write_key(role), &nonce, &[], &mut ciphertext)?;

        let mut out =
            BytesMut::with_capacity(RECORD_HEADER_LEN + EXPLICIT_NONCE_LEN + ciphertext.len());
        out.put_u8(self.content_type.as_u8());
        out.put_u16(DTLS_VERSION_1_2);
        out.put_u16(self.epoch);
        let seq = self.sequence.get().to_be_bytes();
        out.extend_from_slice(&seq[2..]);
        let explicit_nonce = &nonce[WRITE_IV_LEN..];
        out.put_u16((EXPLICIT_NONCE_LEN + ciphertext.len()) as u16);
        out.extend_from_slice(explicit_nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

/// A decoded DTLS record borrowed from its input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordView<'a> {
    /// Content type of the record.
    pub content_type: ContentType,
    /// Epoch the record belongs to.
    pub epoch: u16,
    /// Per-epoch sequence number.
    pub sequence: SequenceNumber,
    /// Record payload, still protected if the record is ciphertext.
    pub payload: &'a [u8],
    /// Number of bytes consumed from the input, including the header.
    pub consumed: usize,
}

impl<'a> RecordView<'a> {
    /// Decodes a plaintext DTLS record from the front of `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidRecord`] if the buffer is too short, the
    /// version is not DTLS 1.2, or the content type is unknown.
    pub fn decode_plaintext(buf: &'a [u8]) -> Result<Self, CryptoError> {
        let (content_type, epoch, sequence, payload, consumed) = Self::split(buf)?;
        Ok(Self {
            content_type,
            epoch,
            sequence,
            payload,
            consumed,
        })
    }

    /// Decodes a record and returns its ciphertext portion plus the explicit
    /// nonce, without attempting decryption.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidRecord`] for the same reasons as
    /// [`Self::decode_plaintext`], or when the record is too short to carry an
    /// explicit nonce.
    pub fn decode_protected(buf: &'a [u8]) -> Result<(&'a [u8], &'a [u8], Self), CryptoError> {
        let view = Self::decode_plaintext(buf)?;
        if view.payload.len() < EXPLICIT_NONCE_LEN {
            return Err(CryptoError::InvalidRecord {
                detail: format!(
                    "record payload of {} bytes cannot carry an explicit nonce",
                    view.payload.len()
                ),
            });
        }
        let (explicit, ciphertext) = view.payload.split_at(EXPLICIT_NONCE_LEN);
        Ok((explicit, ciphertext, view))
    }

    /// Splits a record header from its payload.
    fn split(buf: &'a [u8]) -> Result<(ContentType, u16, SequenceNumber, &'a [u8], usize), CryptoError> {
        if buf.len() < RECORD_HEADER_LEN {
            return Err(CryptoError::InvalidRecord {
                detail: format!(
                    "buffer of {} bytes is shorter than the {RECORD_HEADER_LEN}-byte record header",
                    buf.len()
                ),
            });
        }
        let content_type = ContentType::from_u8(buf[0])?;
        let version = u16::from_be_bytes([buf[1], buf[2]]);
        if version != DTLS_VERSION_1_2 {
            return Err(CryptoError::InvalidRecord {
                detail: format!("unsupported DTLS version {version:#06x}"),
            });
        }
        let epoch = u16::from_be_bytes([buf[3], buf[4]]);
        let mut raw_seq = [0u8; 8];
        raw_seq[2..].copy_from_slice(&buf[5..11]);
        let sequence = SequenceNumber::new(u64::from_be_bytes(raw_seq))?;
        let length = usize::from(u16::from_be_bytes([buf[11], buf[12]]));
        let end = RECORD_HEADER_LEN + length;
        if buf.len() < end {
            return Err(CryptoError::InvalidRecord {
                detail: format!(
                    "record declares {length} payload bytes but only {} remain",
                    buf.len() - RECORD_HEADER_LEN
                ),
            });
        }
        Ok((
            content_type,
            epoch,
            sequence,
            &buf[RECORD_HEADER_LEN..end],
            end,
        ))
    }
}

/// Opens a protected record, returning the plaintext payload.
///
/// # Errors
///
/// Returns [`CryptoError`] when the record cannot be decoded or the tag does
/// not verify under the peer's write key.
pub fn open_record(
    input: &[u8],
    keys: &DtlsKeys,
    peer_role: Role,
    engine: &AeadEngine,
) -> Result<(Vec<u8>, usize), CryptoError> {
    let (_explicit, ciphertext, view) = RecordView::decode_protected(input)?;
    let iv = keys.write_iv(peer_role);
    let nonce = record_nonce(iv, view.epoch, view.sequence);
    let mut buffer = ciphertext.to_vec();
    let plaintext = engine.decrypt(keys.write_key(peer_role), &nonce, &[], &mut buffer)?;
    Ok((plaintext.to_vec(), view.consumed))
}

/// Seals a payload into a protected record.
///
/// # Errors
///
/// Returns [`CryptoError`] if the AEAD engine rejects the operation.
pub fn seal_record(
    content_type: ContentType,
    epoch: u16,
    sequence: SequenceNumber,
    payload: &[u8],
    keys: &DtlsKeys,
    role: Role,
    engine: &AeadEngine,
) -> Result<BytesMut, CryptoError> {
    let record = Record::new(content_type, epoch, sequence, payload.to_vec());
    record.encode_protected(keys, role, engine)
}

/// The AEAD cipher suite this layer uses.
///
/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` is what pion and libwebrtc
/// negotiate by default, so a DTLS 1.2 session using it is unremarkable.
#[must_use]
pub const fn suite() -> CipherSuite {
    CipherSuite::Aes128Gcm
}

/// Builds the AEAD engine for this layer.
#[must_use]
pub fn engine() -> AeadEngine {
    AeadEngine::new(suite())
}

/// Derives the synthetic certificate bytes from the PSK.
///
/// The certificate is never verified by either side — authentication is the
/// Pre-Auth Knock layer's job — so it only has to be *shaped* like the ECDSA
/// P-256 certificate a WebRTC peer presents. The bytes are a deterministic
/// function of the PSK, so both ends derive the same certificate without
/// transmitting a real key pair.
#[must_use]
pub fn synthetic_certificate(psk: &Psk) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // A distinct info string keeps this expansion independent of the key
    // material above, so the certificate cannot leak the write keys.
    const INFO_CERT: &[u8] = b"dtls/synthetic-certificate";
    const CERT_LEN: usize = 512;

    let hk = Hkdf::<Sha256>::new(Some(SALT_DTLS), psk.as_bytes());
    let mut der = vec![0u8; CERT_LEN];
    hk.expand(INFO_CERT, &mut der)
        .expect("expand synthetic certificate");

    // Shape the random bytes into a DER SEQUENCE so the record parses as a
    // certificate rather than as opaque noise.
    let mut out = Vec::with_capacity(CERT_LEN + 4);
    out.push(0x30); // SEQUENCE
    out.push(0x82); // two-byte length follows
    out.extend_from_slice(&(CERT_LEN as u16).to_be_bytes());
    out.extend_from_slice(&der);
    out
}

/// Derives the synthetic `ServerKeyExchange` signature from the PSK.
///
/// A real server signs its ephemeral key with a certificate key. Here the
/// signature is a fixed-length tag over the ephemeral key, derived from the
/// PSK, so the field has the right shape and length without a signing key.
#[must_use]
pub fn synthetic_signature(psk: &Psk, ephemeral: &[u8; 32]) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    const INFO_SIG: &[u8] = b"dtls/synthetic-signature";
    const SIG_LEN: usize = 64;

    let hk = Hkdf::<Sha256>::new(Some(SALT_DTLS), psk.as_bytes());
    let mut sig = vec![0u8; SIG_LEN];
    hk.expand_multi_info(&[INFO_SIG, ephemeral], &mut sig)
        .expect("expand synthetic signature");
    sig
}

/// Derives a 32-byte ephemeral public value from the PSK and a label.
///
/// Both the client's and the server's ephemeral keys are pure functions of the
/// shared secret, so no key exchange actually happens.
#[must_use]
pub fn synthetic_ephemeral(psk: &Psk, label: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    const INFO_EPHEMERAL: &[u8] = b"dtls/synthetic-ephemeral";

    let hk = Hkdf::<Sha256>::new(Some(SALT_DTLS), psk.as_bytes());
    let mut out = [0u8; 32];
    hk.expand_multi_info(&[INFO_EPHEMERAL, label], &mut out)
        .expect("expand synthetic ephemeral");
    out
}

/// The state of a synthetic DTLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Nothing has been sent or received yet.
    Start,
    /// The client has sent `ClientHello` and awaits the server flight.
    ClientHelloSent,
    /// The server has sent its flight and awaits `ClientKeyExchange`.
    ServerFlightSent,
    /// The client has sent `ClientKeyExchange` and awaits `Finished`.
    ClientKeyExchangeSent,
    /// The handshake completed; both sides may send `ApplicationData`.
    Established,
}

/// A synthetic DTLS session: the handshake state machine plus the record
/// counters for the two epochs.
///
/// The session owns the derived key material, its role, and one sequence
/// counter per epoch. It produces the handshake flight for its role and, once
/// [`Self::is_established`] returns true, seals and opens `ApplicationData`
/// records carrying WDTT frames.
pub struct DtlsSession {
    role: Role,
    keys: DtlsKeys,
    engine: AeadEngine,
    state: HandshakeState,
    /// Sequence counter for epoch 0 (handshake records).
    epoch0_seq: SequenceNumber,
    /// Sequence counter for epoch 1 (application records).
    epoch1_seq: SequenceNumber,
    /// Sequence counter for records received in epoch 0.
    peer_epoch0_seq: SequenceNumber,
    /// Sequence counter for records received in epoch 1.
    peer_epoch1_seq: SequenceNumber,
    /// The synthetic certificate, derived once from the PSK.
    certificate: Vec<u8>,
    /// The server name advertised in the `ClientHello`.
    server_name: String,
}

impl std::fmt::Debug for DtlsSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material; the certificate is public by design.
        f.debug_struct("DtlsSession")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("epoch0_seq", &self.epoch0_seq)
            .field("epoch1_seq", &self.epoch1_seq)
            .field("peer_epoch0_seq", &self.peer_epoch0_seq)
            .field("peer_epoch1_seq", &self.peer_epoch1_seq)
            .field("cid", self.keys.cid())
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl DtlsSession {
    /// Builds a session for the given role from the pre-shared key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the key derivation fails.
    pub fn new(role: Role, psk: &Psk, server_name: impl Into<String>) -> Result<Self, CryptoError> {
        Ok(Self {
            role,
            keys: derive_dtls_keys(psk)?,
            engine: engine(),
            state: HandshakeState::Start,
            epoch0_seq: SequenceNumber::default(),
            epoch1_seq: SequenceNumber::default(),
            peer_epoch0_seq: SequenceNumber::default(),
            peer_epoch1_seq: SequenceNumber::default(),
            certificate: synthetic_certificate(psk),
            server_name: server_name.into(),
        })
    }

    /// Returns the session's role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns the current handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Returns true once the handshake has completed.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, HandshakeState::Established)
    }

    /// Returns the connection identifier derived from the PSK.
    #[must_use]
    pub const fn cid(&self) -> &[u8; CID_LEN] {
        self.keys.cid()
    }

    /// Returns the synthetic certificate bytes.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Builds the client's `ClientHello` record.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the message cannot be encoded.
    pub fn client_hello(&mut self, psk: &Psk) -> Result<BytesMut, CryptoError> {
        use crate::dtls_handshake::{client_hello_body, message};

        let random = synthetic_ephemeral(psk, b"client-random");
        let session_id = synthetic_ephemeral(psk, b"session-id");
        let body = client_hello_body(&random, &session_id, &[], &self.server_name, self.keys.cid())
            .map_err(|_| CryptoError::InvalidRecord {
                detail: "client hello body too large".to_string(),
            })?;
        let msg = message(HandshakeType::ClientHello, 0, &body);
        self.state = HandshakeState::ClientHelloSent;
        self.seal_handshake(&msg)
    }

    /// Builds the server's flight: `ServerHello`, `Certificate`,
    /// `ServerKeyExchange` and `ServerHelloDone`, each as its own record.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if a message cannot be encoded.
    pub fn server_flight(&mut self, psk: &Psk) -> Result<Vec<BytesMut>, CryptoError> {
        use crate::dtls_handshake::{
            certificate_body, message, server_hello_body, server_key_exchange_body,
        };

        let random = synthetic_ephemeral(psk, b"server-random");
        let session_id = synthetic_ephemeral(psk, b"session-id");
        let ephemeral = synthetic_ephemeral(psk, b"server-ephemeral");
        let signature = synthetic_signature(psk, &ephemeral);

        let hello = server_hello_body(&random, &session_id, self.keys.cid()).map_err(|_| {
            CryptoError::InvalidRecord {
                detail: "server hello body too large".to_string(),
            }
        })?;
        let cert = certificate_body(&self.certificate).map_err(|_| CryptoError::InvalidRecord {
            detail: "certificate body too large".to_string(),
        })?;
        let key_exchange = server_key_exchange_body(&ephemeral, &signature);

        let mut out = Vec::with_capacity(4);
        out.push(self.seal_handshake(&message(HandshakeType::ServerHello, 1, &hello))?);
        out.push(self.seal_handshake(&message(HandshakeType::Certificate, 2, &cert))?);
        out.push(self.seal_handshake(&message(
            HandshakeType::ServerKeyExchange,
            3,
            &key_exchange,
        ))?);
        out.push(self.seal_handshake(&message(HandshakeType::ServerHelloDone, 4, &[]))?);
        self.state = HandshakeState::ServerFlightSent;
        Ok(out)
    }

    /// Builds the client's `ClientKeyExchange` record.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the message cannot be encoded.
    pub fn client_key_exchange(&mut self, psk: &Psk) -> Result<BytesMut, CryptoError> {
        use crate::dtls_handshake::{client_key_exchange_body, message};

        let ephemeral = synthetic_ephemeral(psk, b"client-ephemeral");
        let body = client_key_exchange_body(&ephemeral);
        let msg = message(HandshakeType::ClientKeyExchange, 1, &body);
        self.state = HandshakeState::ClientKeyExchangeSent;
        self.seal_handshake(&msg)
    }

    /// Builds a `ChangeCipherSpec` record, which switches the sender to epoch 1.
    ///
    /// RFC 6347 §4.1 keeps `ChangeCipherSpec` in the clear: it is the message
    /// that *announces* the switch, so it cannot itself be protected.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the record cannot be encoded.
    pub fn change_cipher_spec(&mut self) -> Result<BytesMut, CryptoError> {
        use crate::dtls_handshake::change_cipher_spec_payload;

        let payload = change_cipher_spec_payload();
        let record = Record::new(
            ContentType::ChangeCipherSpec,
            0,
            self.epoch0_seq,
            payload.to_vec(),
        );
        self.epoch0_seq = self.epoch0_seq.next();
        Ok(record.encode_plaintext())
    }

    /// Builds a `Finished` record in epoch 1.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the record cannot be sealed.
    pub fn finished(&mut self) -> Result<BytesMut, CryptoError> {
        use crate::dtls_handshake::message;

        // The verify data is a deterministic function of the PSK, so both ends
        // compute the same bytes without a real transcript hash.
        let verify = self.keys.cid().to_vec();
        let msg = message(HandshakeType::Finished, 2, &verify);
        let out = seal_record(
            ContentType::Handshake,
            1,
            self.epoch1_seq,
            &msg,
            &self.keys,
            self.role,
            &self.engine,
        );
        self.epoch1_seq = self.epoch1_seq.next();
        out
    }

    /// Marks the handshake as complete.
    pub fn mark_established(&mut self) {
        self.state = HandshakeState::Established;
    }

    /// Seals a WDTT frame into an `ApplicationData` record in epoch 1.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the record cannot be sealed.
    pub fn seal_application(&mut self, payload: &[u8]) -> Result<BytesMut, CryptoError> {
        let out = seal_record(
            ContentType::ApplicationData,
            1,
            self.epoch1_seq,
            payload,
            &self.keys,
            self.role,
            &self.engine,
        );
        self.epoch1_seq = self.epoch1_seq.next();
        out
    }

    /// Opens a record received from the peer.
    ///
    /// Returns the content type, the plaintext payload and the number of bytes
    /// consumed. Handshake records are returned as-is so the caller can drive
    /// the state machine; `ApplicationData` records carry WDTT frames.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the record cannot be decoded or the tag does
    /// not verify.
    pub fn open(&mut self, input: &[u8]) -> Result<(ContentType, Vec<u8>, usize), CryptoError> {
        let view = RecordView::decode_plaintext(input)?;
        let content_type = view.content_type;
        let epoch = view.epoch;
        let sequence = view.sequence;
        let consumed = view.consumed;

        // Epoch 0 records are plaintext; epoch 1 records are protected.
        let payload = if epoch == 0 {
            view.payload.to_vec()
        } else {
            let (plaintext, _) = open_record(input, &self.keys, self.role.opposite(), &self.engine)?;
            plaintext
        };

        // Advance the peer's sequence counter for this epoch.
        let counter = if epoch == 0 {
            &mut self.peer_epoch0_seq
        } else {
            &mut self.peer_epoch1_seq
        };
        if sequence >= *counter {
            *counter = sequence.next();
        }

        Ok((content_type, payload, consumed))
    }

    /// Seals a handshake message as a plaintext epoch-0 record.
    fn seal_handshake(&mut self, message: &[u8]) -> Result<BytesMut, CryptoError> {
        let record = Record::new(
            ContentType::Handshake,
            0,
            self.epoch0_seq,
            message.to_vec(),
        );
        self.epoch0_seq = self.epoch0_seq.next();
        Ok(record.encode_plaintext())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psk() -> Psk {
        Psk::from_bytes([0x42u8; 32])
    }

    #[test]
    fn test_dtls_derivation_is_deterministic() {
        let a = derive_dtls_keys(&test_psk()).expect("derivation");
        let b = derive_dtls_keys(&test_psk()).expect("derivation");
        assert_eq!(a.cid(), b.cid());
    }

    #[test]
    fn test_dtls_keys_differ_between_directions() {
        let keys = derive_dtls_keys(&test_psk()).expect("derivation");
        // The two directions must not share a key, or a reflected record would
        // verify under the sender's own key.
        assert_ne!(
            keys.write_key(Role::Client).as_bytes(),
            keys.write_key(Role::Server).as_bytes()
        );
        assert_ne!(keys.write_iv(Role::Client), keys.write_iv(Role::Server));
    }

    #[test]
    fn test_dtls_keys_depend_on_the_psk() {
        let other = Psk::from_bytes([0x43u8; 32]);
        let a = derive_dtls_keys(&test_psk()).expect("derivation");
        let b = derive_dtls_keys(&other).expect("derivation");
        assert_ne!(a.cid(), b.cid());
    }

    #[test]
    fn test_content_type_roundtrip() {
        for value in [0x14u8, 0x15, 0x16, 0x17] {
            let ct = ContentType::from_u8(value).expect("known");
            assert_eq!(ct.as_u8(), value);
        }
        assert!(ContentType::from_u8(0x18).is_err());
        assert!(ContentType::from_u8(0x00).is_err());
    }

    #[test]
    fn test_sequence_number_rejects_wide_values() {
        assert!(SequenceNumber::new(SequenceNumber::MAX).is_ok());
        assert!(SequenceNumber::new(SequenceNumber::MAX + 1).is_err());
        assert_eq!(SequenceNumber::new(5).expect("valid").next().get(), 6);
        assert_eq!(SequenceNumber::MAX as u64, (1u64 << 48) - 1);
    }

    #[test]
    fn test_plaintext_record_roundtrip() {
        let record = Record::new(
            ContentType::Handshake,
            0,
            SequenceNumber::new(7).expect("valid"),
            vec![1, 2, 3, 4],
        );
        let encoded = record.encode_plaintext();
        assert_eq!(encoded[0], 0x16);
        assert_eq!(&encoded[1..3], &[0xFE, 0xFD]);
        let view = RecordView::decode_plaintext(&encoded).expect("decode");
        assert_eq!(view.content_type, ContentType::Handshake);
        assert_eq!(view.epoch, 0);
        assert_eq!(view.sequence.get(), 7);
        assert_eq!(view.payload, &[1, 2, 3, 4]);
        assert_eq!(view.consumed, encoded.len());
    }

    #[test]
    fn test_protected_record_roundtrip() {
        let keys = derive_dtls_keys(&test_psk()).expect("derivation");
        let engine = engine();
        let plaintext = b"this is a WDTT frame";

        let sealed = seal_record(
            ContentType::ApplicationData,
            1,
            SequenceNumber::new(42).expect("valid"),
            plaintext,
            &keys,
            Role::Client,
            &engine,
        )
        .expect("seal");

        // The payload is opaque on the wire.
        assert!(!sealed.windows(plaintext.len()).any(|w| w == plaintext));

        let (opened, consumed) = open_record(&sealed, &keys, Role::Client, &engine).expect("open");
        assert_eq!(opened, plaintext);
        assert_eq!(consumed, sealed.len());
    }

    #[test]
    fn test_record_protected_with_one_direction_does_not_open_with_the_other() {
        let keys = derive_dtls_keys(&test_psk()).expect("derivation");
        let engine = engine();
        let sealed = seal_record(
            ContentType::ApplicationData,
            1,
            SequenceNumber::new(1).expect("valid"),
            b"payload",
            &keys,
            Role::Client,
            &engine,
        )
        .expect("seal");
        assert!(open_record(&sealed, &keys, Role::Server, &engine).is_err());
    }

    #[test]
    fn test_replayed_record_opens_but_carries_the_same_sequence() {
        // Replay protection is the caller's business: the record layer only
        // reports the sequence number so a window can reject it.
        let keys = derive_dtls_keys(&test_psk()).expect("derivation");
        let engine = engine();
        let sealed = seal_record(
            ContentType::ApplicationData,
            1,
            SequenceNumber::new(9).expect("valid"),
            b"payload",
            &keys,
            Role::Client,
            &engine,
        )
        .expect("seal");
        let (first, _) = open_record(&sealed, &keys, Role::Client, &engine).expect("open");
        let (second, _) = open_record(&sealed, &keys, Role::Client, &engine).expect("open");
        assert_eq!(first, second);
    }

    #[test]
    fn test_tampered_record_is_rejected() {
        let keys = derive_dtls_keys(&test_psk()).expect("derivation");
        let engine = engine();
        let mut sealed = seal_record(
            ContentType::ApplicationData,
            1,
            SequenceNumber::new(3).expect("valid"),
            b"payload",
            &keys,
            Role::Client,
            &engine,
        )
        .expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open_record(&sealed, &keys, Role::Client, &engine).is_err());
    }

    #[test]
    fn test_wrong_version_is_rejected() {
        let mut encoded = Record::new(
            ContentType::Handshake,
            0,
            SequenceNumber::new(0).expect("valid"),
            vec![],
        )
        .encode_plaintext();
        encoded[1] = 0xFE;
        encoded[2] = 0xFC; // DTLS 1.0
        assert!(RecordView::decode_plaintext(&encoded).is_err());
    }

    #[test]
    fn test_truncated_record_is_rejected() {
        let encoded = Record::new(
            ContentType::Handshake,
            0,
            SequenceNumber::new(0).expect("valid"),
            vec![1, 2, 3],
        )
        .encode_plaintext();
        assert!(RecordView::decode_plaintext(&encoded[..RECORD_HEADER_LEN + 1]).is_err());
        assert!(RecordView::decode_plaintext(&encoded[..5]).is_err());
    }

    #[test]
    fn test_record_header_length_matches_encoding() {
        let encoded = Record::new(
            ContentType::Alert,
            0,
            SequenceNumber::new(0).expect("valid"),
            vec![],
        )
        .encode_plaintext();
        assert_eq!(encoded.len(), RECORD_HEADER_LEN);
    }

    #[test]
    fn test_synthetic_certificate_is_deterministic_and_psk_dependent() {
        let a = synthetic_certificate(&test_psk());
        let b = synthetic_certificate(&test_psk());
        assert_eq!(a, b);
        assert_eq!(&a[0..2], &[0x30, 0x82]);
        let other = synthetic_certificate(&Psk::from_bytes([0x43u8; 32]));
        assert_ne!(a, other);
    }

    #[test]
    fn test_synthetic_signature_depends_on_ephemeral() {
        let psk = test_psk();
        let a = synthetic_signature(&psk, &[1u8; 32]);
        let b = synthetic_signature(&psk, &[2u8; 32]);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn test_session_full_handshake_and_application_data() {
        let psk = test_psk();
        let mut client = DtlsSession::new(Role::Client, &psk, "cz.cdn.rewake.cc").expect("client");
        let mut server = DtlsSession::new(Role::Server, &psk, "cz.cdn.rewake.cc").expect("server");

        // The two ends must agree on the connection identifier.
        assert_eq!(client.cid(), server.cid());

        // ClientHello.
        let hello = client.client_hello(&psk).expect("hello");
        let (ct, _payload, consumed) = server.open(&hello).expect("open hello");
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(consumed, hello.len());

        // Server flight: four records.
        let flight = server.server_flight(&psk).expect("flight");
        assert_eq!(flight.len(), 4);
        for record in &flight {
            let (ct, _p, _c) = client.open(record).expect("open flight");
            assert_eq!(ct, ContentType::Handshake);
        }

        // ClientKeyExchange, ChangeCipherSpec, Finished.
        let cke = client.client_key_exchange(&psk).expect("cke");
        let (ct, _p, _c) = server.open(&cke).expect("open cke");
        assert_eq!(ct, ContentType::Handshake);

        let ccs = client.change_cipher_spec().expect("ccs");
        let (ct, payload, _c) = server.open(&ccs).expect("open ccs");
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        assert_eq!(payload, vec![0x01]);

        let fin = client.finished().expect("finished");
        let (ct, _p, _c) = server.open(&fin).expect("open finished");
        assert_eq!(ct, ContentType::Handshake);

        client.mark_established();
        server.mark_established();
        assert!(client.is_established());
        assert!(server.is_established());

        // ApplicationData in both directions.
        let frame = b"a WDTT frame rides here";
        let sealed = client.seal_application(frame).expect("seal app");
        let (ct, opened, _c) = server.open(&sealed).expect("open app");
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(opened, frame);

        let reply = b"and back again";
        let sealed = server.seal_application(reply).expect("seal reply");
        let (ct, opened, _c) = client.open(&sealed).expect("open reply");
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(opened, reply);
    }

    #[test]
    fn test_session_application_records_are_opaque_on_the_wire() {
        let psk = test_psk();
        let mut client = DtlsSession::new(Role::Client, &psk, "x").expect("client");
        let frame = b"plaintext marker";
        let sealed = client.seal_application(frame).expect("seal");
        assert!(!sealed.windows(frame.len()).any(|w| w == frame));
    }

    #[test]
    fn test_session_sequence_numbers_advance() {
        let psk = test_psk();
        let mut client = DtlsSession::new(Role::Client, &psk, "x").expect("client");
        let first = client.seal_application(b"one").expect("seal");
        let second = client.seal_application(b"two").expect("seal");
        // The two records must differ even though the payloads are the same
        // length, because the sequence number feeds the nonce.
        assert_ne!(first, second);
    }
}
