//! Android UniFFI and JNI bindings for the WDTT Rust core.

#![deny(missing_docs)]

/// Connection parameters passed across the FFI boundary from Kotlin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidConnectConfig {
    /// Server endpoint address (IP:port).
    pub endpoint: String,
    /// Shared authentication secret.
    pub secret: String,
    /// Virtual TUN file descriptor passed directly from Android VpnService.
    pub tun_fd: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_config() {
        let cfg = AndroidConnectConfig {
            endpoint: "1.2.3.4:56000".into(),
            secret: "secret".into(),
            tun_fd: 42,
        };
        assert_eq!(cfg.tun_fd, 42);
    }
}
