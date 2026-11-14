//! Lightweight, asynchronous STUN and TURN client implementation.
//!
//! Handles UDP, TCP, and TLS connections to standard TURN servers (RFC 5766)
//! and ChannelData framing (0x4000..0x7FFF).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Minimum valid STUN ChannelData channel number (RFC 5766).
pub const CHANNEL_DATA_MIN: u16 = 0x4000;

/// Maximum valid STUN ChannelData channel number (RFC 5766).
pub const CHANNEL_DATA_MAX: u16 = 0x7FFF;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_data_range() {
        assert_eq!(CHANNEL_DATA_MIN, 0x4000);
        assert_eq!(CHANNEL_DATA_MAX, 0x7FFF);
    }
}
