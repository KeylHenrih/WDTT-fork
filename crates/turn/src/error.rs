use thiserror::Error;

/// TURN protocol and client errors.
#[derive(Debug, Error)]
pub enum TurnError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("buffer too short: expected at least {expected} bytes, got {actual}")]
    BufferTooShort { expected: usize, actual: usize },

    #[error("invalid STUN magic cookie: expected 0x2112A442, got 0x{0:08X}")]
    InvalidMagicCookie(u32),

    #[error("unknown STUN message type: 0x{0:04X}")]
    UnknownMessageType(u16),

    #[error("unknown STUN attribute type: 0x{0:04X}")]
    UnknownAttribute(u16),

    #[error("STUN error response: code {code}, reason: {reason}")]
    StunErrorResponse { code: u16, reason: String },

    #[error("missing required STUN attribute: {0}")]
    MissingAttribute(&'static str),

    #[error("transaction ID mismatch: expected {expected:?}, got {actual:?}")]
    TransactionMismatch {
        expected: [u8; 12],
        actual: [u8; 12],
    },

    #[error("STUN message integrity verification failed")]
    IntegrityVerificationFailed,

    #[error("allocation failed: maximum retry attempts exceeded")]
    AllocationFailed,

    #[error("channel number 0x{0:04X} outside valid range 0x4000..=0x7FFF")]
    InvalidChannelNumber(u16),

    #[error("timeout waiting for TURN response")]
    Timeout,
}
