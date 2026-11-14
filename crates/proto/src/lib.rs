//! WDTT v2 wire protocol frames, URL parser, and version definitions.
//!
//! This crate contains pure protocol definitions and data transformations
//! without any network I/O.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Magic identifier for WDTT v2 frames (`0xD2`).
pub const WDTT_V2_MAGIC: u8 = 0xD2;

/// Frame types supported by WDTT v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Full WireGuard or IP packet.
    Data = 0x01,
    /// Fragmented packet.
    DataFrag = 0x02,
    /// Handshake initiation from client.
    HandshakeInit = 0x10,
    /// Handshake response from server.
    HandshakeResp = 0x11,
    /// RTT path probe / keepalive.
    Ping = 0x20,
    /// Keepalive echo response.
    Pong = 0x21,
    /// Stream flow metrics and congestion feedback.
    StreamFeedback = 0x30,
    /// Orderly session termination.
    Disconnect = 0xFF,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_constant() {
        assert_eq!(WDTT_V2_MAGIC, 0xD2);
    }
}
