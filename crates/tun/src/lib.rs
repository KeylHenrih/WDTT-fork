//! Cross-platform TUN device abstraction (Linux netlink/ioctl, Windows wintun, macOS utun, Android fd).
//!
//! Any unsafe code interacting with OS device descriptors is strictly isolated
//! with comprehensive safety rationale comments.

#![deny(missing_docs)]

pub mod dns;
pub mod geo;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub mod netcfg;
#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod nft;
pub mod resolver;
pub mod routing;
pub mod wg;

pub use dns::{DnsServer, DnsServerConfig, ResolverBackend, ResolverError, SystemResolver};
#[cfg(target_os = "linux")]
pub use linux::TunDevice;
#[cfg(target_os = "linux")]
pub use netcfg::{RouteSpec, WDTT_FWMARK, WDTT_ROUTE_TABLE, WDTT_RULE_PRIORITY};
#[cfg(target_os = "linux")]
pub use netlink::{NlRouteSpec, RuleSpec};
pub use routing::{
    ConnectionInfo, Outbound, Routing, RoutingError, RoutingTable, Rule, RuleMatcher,
};
pub use wg::{DATA_OVERHEAD_SZ, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ, WgEngine, WgError, WgOutput};

/// Virtual packet buffer type for TUN payload exchange.
pub type TunPacket = bytes::Bytes;

/// Errors produced during TUN device initialization or frame processing.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// Device I/O failure.
    #[error("TUN device I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The requested platform is not supported by this build.
    #[error("TUN devices are not supported on this platform")]
    Unsupported,
    /// Interface name is invalid (too long or contains a NUL byte).
    #[error("invalid interface name {0:?}")]
    InvalidName(String),
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
