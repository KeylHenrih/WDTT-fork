//! Core tunnel engine, session state machine, and adaptive multi-stream dispatcher.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Default MTU for WDTT v2 WireGuard inner tunnel interface.
pub const DEFAULT_TUNNEL_MTU: u16 = 1200;

/// Maximum number of active streams allocated per single call join hash.
pub const MAX_STREAMS_PER_HASH: usize = 8;

/// Minimum number of active streams in idle mode.
pub const MIN_STREAMS: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_limits() {
        assert_eq!(DEFAULT_TUNNEL_MTU, 1200);
        assert_eq!(MAX_STREAMS_PER_HASH, 8);
        assert_eq!(MIN_STREAMS, 2);
    }
}
