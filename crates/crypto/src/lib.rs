#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod aead;
pub mod anti_replay;
pub mod dtls;
pub mod dtls_handshake;
pub mod error;
pub mod kdf;
pub mod key;
pub mod knock;

pub use aead::{AeadEngine, CipherSuite, NONCE_LEN, TAG_LEN, make_nonce};
pub use anti_replay::{AntiReplayWindow, REPLAY_WINDOW_SIZE, REPLAY_WINDOW_WORDS};
pub use dtls::{
    CID_LEN, ContentType, DTLS_VERSION_1_2, DtlsKeys, EXPLICIT_NONCE_LEN, HandshakeType, RECORD_HEADER_LEN,
    Record, RecordView, Role, SequenceNumber, derive_dtls_keys, engine, handshake_message,
    open_record, seal_record, suite,
};
pub use error::CryptoError;
pub use dtls_handshake::{
    HandshakeError, change_cipher_spec_payload, certificate_body, client_hello_body,
    client_key_exchange_body, message, server_hello_body, server_key_exchange_body,
};
pub use kdf::{derive_pre_auth_knock_key, derive_session_keys};
pub use key::{AeadKey, KnockKey, Psk, SessionKeys};
pub use knock::{
    DEFAULT_MAX_CLOCK_SKEW_SEC, KnockAuthenticator, KnockPayload, MAX_NONCE_CACHE_ENTRIES,
    MIN_KNOCK_WIRE_LEN, NonceReplayCache,
};
