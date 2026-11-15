use thiserror::Error;

/// Errors arising during protocol serialization, deserialization, parsing, or sequencing.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ProtoError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("missing required field in URL: {0}")]
    MissingField(&'static str),

    #[error("invalid port: {0}")]
    InvalidPort(String),

    #[error("invalid worker count: {0} (must be between 1 and 255)")]
    InvalidWorkerCount(u32),

    #[error("buffer too short: expected at least {expected} bytes, got {actual}")]
    BufferTooShort { expected: usize, actual: usize },

    #[error("invalid magic byte: expected 0x{expected:02X}, got 0x{actual:02X}")]
    InvalidMagic { expected: u8, actual: u8 },

    #[error("invalid frame type: 0x{0:02X}")]
    InvalidFrameType(u8),

    #[error(
        "payload length mismatch: header specified {header_len} bytes, buffer has {actual_len}"
    )]
    PayloadLengthMismatch {
        header_len: usize,
        actual_len: usize,
    },

    #[error("invalid WireGuard packet: {0}")]
    InvalidWireGuardPacket(String),

    #[error("resequencer window overflow: packet counter {counter} is beyond window capacity")]
    ResequencerOverflow { counter: u64 },
}
