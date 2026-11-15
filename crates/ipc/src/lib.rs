//! Inter-process communication protocol between `wdttd` daemon and GUI applications.
//!
//! Uses compact binary framing via `postcard` over local Unix domain sockets or Windows named pipes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Requests sent from the GUI client to the `wdttd` system daemon.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum IpcRequest {
    /// Query current daemon status and active connection metrics.
    GetStatus,
    /// Connect using the specified configuration string.
    Connect {
        /// Raw configuration string (wdtt2://, qwdtt://, or wdtt://).
        config_uri: String,
    },
    /// Disconnect the active tunnel session.
    Disconnect,
}

/// Responses sent from `wdttd` to the GUI client.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum IpcResponse {
    /// Current tunnel status.
    Status {
        /// Whether the tunnel is currently connected and active.
        connected: bool,
        /// Current upload bytes per second.
        tx_bytes_per_sec: u64,
        /// Current download bytes per second.
        rx_bytes_per_sec: u64,
        /// Smoothed round-trip time in milliseconds.
        rtt_ms: u32,
    },
    /// Operation completed successfully.
    Ok,
    /// An error occurred during request processing.
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_postcard_serde() {
        let req = IpcRequest::GetStatus;
        let serialized = postcard::to_allocvec(&req).expect("serialize");
        let deserialized: IpcRequest = postcard::from_bytes(&serialized).expect("deserialize");
        assert_eq!(req, deserialized);
    }
}
