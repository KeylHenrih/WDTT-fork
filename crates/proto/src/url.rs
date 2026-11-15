use crate::error::ProtoError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use url::Url;

/// Default number of concurrent TURN streams in pool.
pub const DEFAULT_WORKERS: u8 = 4;

/// Architectural upper bound estimate of concurrent TURN streams before STUN 486
/// (ADR-0002 / ADR-0006 architectural estimate, pending external server quota measurement).
pub const MAX_WORKERS_ESTIMATE: u8 = 8;

/// Tunnel transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    /// Disguised inside WebRTC DTLS ApplicationData (default).
    #[default]
    Dtls,
    /// Direct RTP without DTLS encryption.
    DirectRtp,
}

impl FromStr for TunnelMode {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "dtls" | "tls" => Ok(Self::Dtls),
            "direct" | "notls" | "directrtp" => Ok(Self::DirectRtp),
            other => Err(ProtoError::InvalidUrl(format!("unknown mode: {other}"))),
        }
    }
}

impl fmt::Display for TunnelMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dtls => write!(f, "dtls"),
            Self::DirectRtp => write!(f, "direct"),
        }
    }
}

/// Scheduling strategy for multi-stream packet distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SprayMode {
    /// 5-tuple flow hashing: all packets of a TCP flow stick to 1 stream.
    #[default]
    FlowHash,
    /// Hybrid spray: dominant heavy flow is sprayed across streams with resequencer.
    HybridSpray,
    /// Direct round-robin across all streams (requires resequencer).
    DirectRoundRobin,
}

impl FromStr for SprayMode {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "flow" | "flow_hash" | "flowhash" => Ok(Self::FlowHash),
            "hybrid" | "hybrid_spray" | "hybridspray" => Ok(Self::HybridSpray),
            "rr" | "round_robin" | "roundrobin" => Ok(Self::DirectRoundRobin),
            other => Err(ProtoError::InvalidUrl(format!(
                "unknown spray mode: {other}"
            ))),
        }
    }
}

impl fmt::Display for SprayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FlowHash => write!(f, "flow_hash"),
            Self::HybridSpray => write!(f, "hybrid_spray"),
            Self::DirectRoundRobin => write!(f, "round_robin"),
        }
    }
}

/// Normalized tunnel connection configuration.
///
/// Implements custom `Debug` and `Display` to guarantee passwords and hashes
/// are NEVER printed to logs or standard outputs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Optional human-readable connection name.
    pub name: Option<String>,
    /// Server IP address or domain name.
    pub host: String,
    /// DTLS listening port on server.
    pub dtls_port: u16,
    /// WireGuard listening port on server.
    pub wg_port: u16,
    /// Client-side local bind port (0 for ephemeral).
    pub local_port: u16,
    /// Tunnel pre-shared password / secret.
    pub password: String,
    /// Pool of TURN allocation hashes (e.g. VK call hashes).
    pub hashes: Vec<String>,
    /// Configured stream count requested in URL (default: `DEFAULT_WORKERS`).
    pub workers: u8,
    /// Transport mode (DTLS or Direct RTP).
    pub mode: TunnelMode,
    /// Resequencer window capacity (default: 4096 slots).
    pub reseq_window: u32,
    /// Multi-stream packet scheduler strategy.
    pub spray_mode: SprayMode,
}

impl fmt::Debug for TunnelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConfig")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("dtls_port", &self.dtls_port)
            .field("wg_port", &self.wg_port)
            .field("local_port", &self.local_port)
            .field("password", &"[REDACTED]")
            .field(
                "hashes",
                &format!("[REDACTED; count={}]", self.hashes.len()),
            )
            .field("workers", &self.workers)
            .field("mode", &self.mode)
            .field("reseq_window", &self.reseq_window)
            .field("spray_mode", &self.spray_mode)
            .finish()
    }
}

impl fmt::Display for TunnelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TunnelConfig(name={:?}, endpoint={}:{}, wg={}, local={}, mode={}, workers={}, spray={})",
            self.name,
            self.host,
            self.dtls_port,
            self.wg_port,
            self.local_port,
            self.mode,
            self.workers,
            self.spray_mode
        )
    }
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            name: None,
            host: String::new(),
            dtls_port: 56000,
            wg_port: 56001,
            local_port: 0,
            password: String::new(),
            hashes: Vec::new(),
            workers: DEFAULT_WORKERS,
            mode: TunnelMode::Dtls,
            reseq_window: 4096,
            spray_mode: SprayMode::FlowHash,
        }
    }
}

impl TunnelConfig {
    /// Calculate effective worker count clamped to an upper bound (e.g. `MAX_WORKERS_ESTIMATE`).
    pub fn effective_workers(&self, max_allowed: u8) -> u8 {
        self.workers.clamp(1, max_allowed)
    }

    /// Parse any supported tunnel URL format:
    /// - `wdtt2://`
    /// - `qwdtt://config?...`
    /// - `wdtt://connect?v=1...`
    /// - Positional legacy `wdtt://host:dtls:wg:proxy:password:hashes#name`
    pub fn parse(input: &str) -> Result<Self, ProtoError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ProtoError::InvalidUrl("empty URL".into()));
        }

        if trimmed.starts_with("wdtt2://") {
            Self::parse_wdtt2(trimmed)
        } else if trimmed.starts_with("qwdtt://config?") || trimmed.starts_with("qwdtt://") {
            Self::parse_qwdtt(trimmed)
        } else if trimmed.starts_with("wdtt://connect?") {
            Self::parse_wdtt_connect(trimmed)
        } else if trimmed.starts_with("wdtt://") {
            Self::parse_legacy_wdtt(trimmed)
        } else {
            Err(ProtoError::InvalidUrl(format!(
                "unsupported scheme in URL: {trimmed}"
            )))
        }
    }

    /// Parse `wdtt2://host:dtls_port?wg=...&pass=...`
    fn parse_wdtt2(input: &str) -> Result<Self, ProtoError> {
        let parsed = Url::parse(input).map_err(|e| ProtoError::InvalidUrl(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or(ProtoError::MissingField("host"))?
            .to_string();
        let dtls_port = parsed.port().ok_or(ProtoError::MissingField("dtls_port"))?;

        let name = parsed.fragment().map(|f| f.to_string());

        let mut wg_port = dtls_port.saturating_add(1);
        let mut local_port = 0u16;
        let mut password = String::new();
        let mut hashes = Vec::new();
        let mut workers = DEFAULT_WORKERS;
        let mut mode = TunnelMode::Dtls;
        let mut reseq_window = 4096u32;
        let mut spray_mode = SprayMode::FlowHash;

        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "wg" => {
                    wg_port = v
                        .parse::<u16>()
                        .map_err(|_| ProtoError::InvalidPort(v.to_string()))?;
                }
                "local" | "port" => {
                    local_port = v
                        .parse::<u16>()
                        .map_err(|_| ProtoError::InvalidPort(v.to_string()))?;
                }
                "pass" | "password" => {
                    password = v.to_string();
                }
                "hashes" | "hash" => {
                    hashes = v
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "workers" | "n" => {
                    if let Ok(w) = v.parse::<u32>() {
                        workers = if w > 0 {
                            w.min(255) as u8
                        } else {
                            DEFAULT_WORKERS
                        };
                    }
                }
                "mode" => {
                    mode = TunnelMode::from_str(&v)?;
                }
                "reseq" | "window" => {
                    reseq_window = v
                        .parse::<u32>()
                        .map_err(|_| ProtoError::InvalidUrl("invalid reseq window".into()))?;
                }
                "spray" => {
                    spray_mode = SprayMode::from_str(&v)?;
                }
                _ => {}
            }
        }

        if password.is_empty() {
            return Err(ProtoError::MissingField("password"));
        }

        Ok(Self {
            name,
            host,
            dtls_port,
            wg_port,
            local_port,
            password,
            hashes,
            workers,
            mode,
            reseq_window,
            spray_mode,
        })
    }

    /// Parse `qwdtt://config?peer=host:port&pass=...&hashes=...&workers=...&port=...&name=...`
    fn parse_qwdtt(input: &str) -> Result<Self, ProtoError> {
        let parsed = Url::parse(input).map_err(|e| ProtoError::InvalidUrl(e.to_string()))?;

        let mut name = None;
        let mut host = String::new();
        let mut dtls_port = 0u16;
        let mut wg_port = 0u16;
        let mut local_port = 0u16;
        let mut password = String::new();
        let mut hashes = Vec::new();
        let mut workers = DEFAULT_WORKERS;

        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "name" => {
                    if !v.is_empty() {
                        name = Some(v.to_string());
                    }
                }
                "peer" => {
                    let parts: Vec<&str> = v.split(':').collect();
                    if parts.len() != 2 {
                        return Err(ProtoError::InvalidUrl(format!("invalid peer: {v}")));
                    }
                    host = parts[0].to_string();
                    dtls_port = parts[1]
                        .parse::<u16>()
                        .map_err(|_| ProtoError::InvalidPort(parts[1].to_string()))?;
                }
                "pass" | "password" => {
                    password = v.to_string();
                }
                "hashes" => {
                    hashes = v
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "workers" => {
                    if let Ok(w) = v.parse::<u32>() {
                        workers = if w > 0 {
                            w.min(255) as u8
                        } else {
                            DEFAULT_WORKERS
                        };
                    }
                }
                "port" | "local" => {
                    local_port = v
                        .parse::<u16>()
                        .map_err(|_| ProtoError::InvalidPort(v.to_string()))?;
                }
                "wg" => {
                    wg_port = v
                        .parse::<u16>()
                        .map_err(|_| ProtoError::InvalidPort(v.to_string()))?;
                }
                _ => {}
            }
        }

        if host.is_empty() {
            return Err(ProtoError::MissingField("peer"));
        }
        if password.is_empty() {
            return Err(ProtoError::MissingField("pass"));
        }
        if wg_port == 0 {
            wg_port = dtls_port.saturating_add(1);
        }

        Ok(Self {
            name,
            host,
            dtls_port,
            wg_port,
            local_port,
            password,
            hashes,
            workers,
            mode: TunnelMode::Dtls,
            reseq_window: 4096,
            spray_mode: SprayMode::FlowHash,
        })
    }

    /// Parse `wdtt://connect?v=1&host=...&dtls=...&wg=...&local=...&password=...&hashes=...`
    fn parse_wdtt_connect(input: &str) -> Result<Self, ProtoError> {
        let parsed = Url::parse(input).map_err(|e| ProtoError::InvalidUrl(e.to_string()))?;

        let mut name = parsed.fragment().map(|f| f.to_string());
        let mut host = String::new();
        let mut dtls_port = 0u16;
        let mut wg_port = 0u16;
        let mut local_port = 0u16;
        let mut password = String::new();
        let mut hashes = Vec::new();
        let mut workers = DEFAULT_WORKERS;

        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "name" => {
                    if !v.is_empty() {
                        name = Some(v.to_string());
                    }
                }
                "host" => {
                    host = v.to_string();
                }
                "dtls" => {
                    dtls_port = v
                        .parse::<u16>()
                        .map_err(|_| ProtoError::InvalidPort(v.to_string()))?;
                }
                "wg" => {
                    wg_port = v
                        .parse::<u16>()
                        .map_err(|_| ProtoError::InvalidPort(v.to_string()))?;
                }
                "local" | "port" => {
                    local_port = v
                        .parse::<u16>()
                        .map_err(|_| ProtoError::InvalidPort(v.to_string()))?;
                }
                "password" | "pass" => {
                    password = v.to_string();
                }
                "hashes" => {
                    hashes = v
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "workers" => {
                    if let Ok(w) = v.parse::<u32>() {
                        workers = if w > 0 {
                            w.min(255) as u8
                        } else {
                            DEFAULT_WORKERS
                        };
                    }
                }
                _ => {}
            }
        }

        if host.is_empty() {
            return Err(ProtoError::MissingField("host"));
        }
        if dtls_port == 0 {
            return Err(ProtoError::MissingField("dtls"));
        }
        if wg_port == 0 {
            wg_port = dtls_port.saturating_add(1);
        }
        if password.is_empty() {
            return Err(ProtoError::MissingField("password"));
        }

        Ok(Self {
            name,
            host,
            dtls_port,
            wg_port,
            local_port,
            password,
            hashes,
            workers,
            mode: TunnelMode::Dtls,
            reseq_window: 4096,
            spray_mode: SprayMode::FlowHash,
        })
    }

    /// Parse legacy positional `wdtt://host:dtls:wg:proxy:password[:hashes][#name]`
    fn parse_legacy_wdtt(input: &str) -> Result<Self, ProtoError> {
        let without_scheme = input
            .strip_prefix("wdtt://")
            .ok_or_else(|| ProtoError::InvalidUrl("missing wdtt:// scheme".into()))?;

        // Split off #fragment
        let (body, fragment) = match without_scheme.split_once('#') {
            Some((b, f)) => (b, Some(f.to_string())),
            None => (without_scheme, None),
        };

        let parts: Vec<&str> = body.split(':').collect();
        if parts.len() < 5 {
            return Err(ProtoError::InvalidUrl(format!(
                "legacy wdtt:// requires at least 5 colon-separated fields, got {}",
                parts.len()
            )));
        }

        let host = parts[0].to_string();
        if host.is_empty() {
            return Err(ProtoError::MissingField("host"));
        }

        let dtls_port = parts[1]
            .parse::<u16>()
            .map_err(|_| ProtoError::InvalidPort(parts[1].to_string()))?;
        let wg_port = parts[2]
            .parse::<u16>()
            .map_err(|_| ProtoError::InvalidPort(parts[2].to_string()))?;
        let local_port = parts[3]
            .parse::<u16>()
            .map_err(|_| ProtoError::InvalidPort(parts[3].to_string()))?;
        let password = parts[4].to_string();
        if password.is_empty() {
            return Err(ProtoError::MissingField("password"));
        }

        let hashes = if parts.len() >= 6 {
            parts[5]
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            Vec::new()
        };

        Ok(Self {
            name: fragment,
            host,
            dtls_port,
            wg_port,
            local_port,
            password,
            hashes,
            workers: DEFAULT_WORKERS,
            mode: TunnelMode::Dtls,
            reseq_window: 4096,
            spray_mode: SprayMode::FlowHash,
        })
    }

    /// Format as canonical `wdtt2://` URL.
    pub fn to_wdtt2_url(&self) -> String {
        let hashes_str = self.hashes.join(",");
        let mut s = format!(
            "wdtt2://{}:{}/?wg={}&local={}&pass={}&workers={}&mode={}&reseq={}&spray={}",
            self.host,
            self.dtls_port,
            self.wg_port,
            self.local_port,
            urlencoding::encode(&self.password),
            self.workers,
            self.mode,
            self.reseq_window,
            self.spray_mode
        );
        if !hashes_str.is_empty() {
            s.push_str(&format!("&hashes={}", urlencoding::encode(&hashes_str)));
        }
        if let Some(ref name) = self.name {
            s.push('#');
            s.push_str(&urlencoding::encode(name));
        }
        s
    }

    /// Format as standard `qwdtt://config?` URL.
    pub fn to_qwdtt_url(&self) -> String {
        let hashes_str = self.hashes.join(",");
        let mut s = format!(
            "qwdtt://config?peer={}:{}&pass={}&workers={}&port={}&wg={}",
            self.host,
            self.dtls_port,
            urlencoding::encode(&self.password),
            self.workers,
            self.local_port,
            self.wg_port
        );
        if !hashes_str.is_empty() {
            s.push_str(&format!("&hashes={}", urlencoding::encode(&hashes_str)));
        }
        if let Some(ref name) = self.name {
            s.push_str(&format!("&name={}", urlencoding::encode(name)));
        }
        s
    }

    /// Format as legacy positional `wdtt://` URL.
    pub fn to_legacy_wdtt_url(&self) -> String {
        let hashes_str = self.hashes.join(",");
        let mut s = format!(
            "wdtt://{}:{}:{}:{}:{}:{}",
            self.host, self.dtls_port, self.wg_port, self.local_port, self.password, hashes_str
        );
        if let Some(ref name) = self.name {
            s.push('#');
            s.push_str(name);
        }
        s
    }
}

/// Simple percent-encoding helper for URLs without pulling heavy extra deps.
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_legacy_wdtt() {
        let url = "wdtt://198.51.100.1:56000:56001:0:SecretPass:hash1,hash2#HomeServer";
        let cfg = TunnelConfig::parse(url).expect("parse legacy URL");
        assert_eq!(cfg.host, "198.51.100.1");
        assert_eq!(cfg.dtls_port, 56000);
        assert_eq!(cfg.wg_port, 56001);
        assert_eq!(cfg.local_port, 0);
        assert_eq!(cfg.password, "SecretPass");
        assert_eq!(cfg.hashes, vec!["hash1", "hash2"]);
        assert_eq!(cfg.name.as_deref(), Some("HomeServer"));
    }

    #[test]
    fn test_parse_qwdtt() {
        let url = "qwdtt://config?name=MyServer&peer=198.51.100.1:5555&pass=secret123&hashes=h1,h2,h3&workers=8&port=9000";
        let cfg = TunnelConfig::parse(url).expect("parse qwdtt URL");
        assert_eq!(cfg.host, "198.51.100.1");
        assert_eq!(cfg.dtls_port, 5555);
        assert_eq!(cfg.wg_port, 5556); // default dtls+1
        assert_eq!(cfg.local_port, 9000);
        assert_eq!(cfg.password, "secret123");
        assert_eq!(cfg.hashes, vec!["h1", "h2", "h3"]);
        assert_eq!(cfg.workers, 8);
        assert_eq!(cfg.name.as_deref(), Some("MyServer"));
    }

    #[test]
    fn test_parse_wdtt_connect() {
        let url = "wdtt://connect?v=1&host=vpn.example.com&dtls=56000&wg=56001&local=9000&password=secret&hashes=h1,h2#MyServer";
        let cfg = TunnelConfig::parse(url).expect("parse wdtt connect URL");
        assert_eq!(cfg.host, "vpn.example.com");
        assert_eq!(cfg.dtls_port, 56000);
        assert_eq!(cfg.wg_port, 56001);
        assert_eq!(cfg.local_port, 9000);
        assert_eq!(cfg.password, "secret");
        assert_eq!(cfg.hashes, vec!["h1", "h2"]);
        assert_eq!(cfg.name.as_deref(), Some("MyServer"));
    }

    #[test]
    fn test_parse_and_roundtrip_wdtt2() {
        let original = TunnelConfig {
            name: Some("FastV2".into()),
            host: "10.0.0.1".into(),
            dtls_port: 443,
            wg_port: 51820,
            local_port: 9000,
            password: "super_secret_key".into(),
            hashes: vec!["vk_hash_1".into(), "vk_hash_2".into()],
            workers: 8,
            mode: TunnelMode::Dtls,
            reseq_window: 16384,
            spray_mode: SprayMode::HybridSpray,
        };

        let url_str = original.to_wdtt2_url();
        let parsed = TunnelConfig::parse(&url_str).expect("parse generated wdtt2 url");

        assert_eq!(parsed.name, original.name);
        assert_eq!(parsed.host, original.host);
        assert_eq!(parsed.dtls_port, original.dtls_port);
        assert_eq!(parsed.wg_port, original.wg_port);
        assert_eq!(parsed.local_port, original.local_port);
        assert_eq!(parsed.password, original.password);
        assert_eq!(parsed.hashes, original.hashes);
        assert_eq!(parsed.workers, original.workers);
        assert_eq!(parsed.mode, original.mode);
        assert_eq!(parsed.reseq_window, original.reseq_window);
        assert_eq!(parsed.spray_mode, original.spray_mode);
    }

    #[test]
    fn test_empty_and_malformed_urls() {
        assert!(TunnelConfig::parse("").is_err());
        assert!(TunnelConfig::parse("   ").is_err());
        assert!(TunnelConfig::parse("ftp://example.com").is_err());
        assert!(TunnelConfig::parse("wdtt://short").is_err());
        assert!(TunnelConfig::parse("wdtt://1.2.3.4:5555").is_err());
    }

    #[test]
    fn test_debug_and_display_redact_secrets() {
        let cfg = TunnelConfig {
            name: Some("SecretTunnel".into()),
            host: "192.168.1.1".into(),
            dtls_port: 56000,
            wg_port: 56001,
            local_port: 9000,
            password: "EXTREMELY_CONFIDENTIAL_PASSWORD".into(),
            hashes: vec!["SECRET_VK_HASH_A".into(), "SECRET_VK_HASH_B".into()],
            workers: 4,
            mode: TunnelMode::Dtls,
            reseq_window: 4096,
            spray_mode: SprayMode::FlowHash,
        };

        let debug_str = format!("{cfg:?}");
        assert!(!debug_str.contains("EXTREMELY_CONFIDENTIAL_PASSWORD"));
        assert!(!debug_str.contains("SECRET_VK_HASH_A"));
        assert!(!debug_str.contains("SECRET_VK_HASH_B"));
        assert!(debug_str.contains("[REDACTED]"));

        let display_str = format!("{cfg}");
        assert!(!display_str.contains("EXTREMELY_CONFIDENTIAL_PASSWORD"));
        assert!(!display_str.contains("SECRET_VK_HASH_A"));
        assert!(!display_str.contains("SECRET_VK_HASH_B"));
        assert!(display_str.contains("endpoint=192.168.1.1:56000"));
    }

    #[test]
    fn test_workers_configuration_and_clamping() {
        let cfg =
            TunnelConfig::parse("qwdtt://config?peer=1.2.3.4:5000&pass=p&workers=16").unwrap();
        assert_eq!(cfg.workers, 16);
        // Clamped by ADR-0002/0006 estimate (8)
        assert_eq!(cfg.effective_workers(MAX_WORKERS_ESTIMATE), 8);
        assert_eq!(cfg.effective_workers(32), 16);

        let cfg_default = TunnelConfig::parse("qwdtt://config?peer=1.2.3.4:5000&pass=p").unwrap();
        assert_eq!(cfg_default.workers, DEFAULT_WORKERS);
    }
}
