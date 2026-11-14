#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod aead;
pub mod anti_replay;
pub mod error;
pub mod kdf;
pub mod key;
pub mod knock;

pub use aead::{AeadEngine, CipherSuite, NONCE_LEN, TAG_LEN, make_nonce};
pub use anti_replay::{AntiReplayWindow, REPLAY_WINDOW_SIZE, REPLAY_WINDOW_WORDS};
pub use error::CryptoError;
pub use kdf::derive_session_keys;
pub use key::{AeadKey, KnockKey, Psk, SessionKeys};
pub use knock::{DEFAULT_MAX_CLOCK_SKEW_SEC, KNOCK_TAG_LEN, KnockAuthenticator};
