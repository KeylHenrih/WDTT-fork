//! Cross-platform TUN device abstraction (Linux netlink/ioctl, Windows wintun, macOS utun, Android fd).
//!
//! Any unsafe code interacting with OS device descriptors is strictly isolated
//! with comprehensive safety rationale comments.

#![deny(missing_docs)]

/// Virtual packet buffer type for TUN payload exchange.
pub type TunPacket = bytes::Bytes;

/// Errors produced during TUN device initialization or frame processing.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// Device I/O failure.
    #[error("TUN device I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Common configuration parameters for creating a virtual TUN interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Interface name (e.g. `wdtt0` or empty for OS-assigned).
    pub name: String,
    /// Interface MTU (default 1200).
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "wdtt0".into(),
            mtu: 1200,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_default_config() {
        let cfg = TunConfig::default();
        assert_eq!(cfg.name, "wdtt0");
        assert_eq!(cfg.mtu, 1200);
    }
}
