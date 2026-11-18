//! Provider selection and construction.
//!
//! The daemon needs to build a [`TurnProvider`] from configuration without
//! knowing which implementation it is talking to. This module owns that
//! decision: it parses a provider name, validates the options that provider
//! requires, and returns a boxed trait object.
//!
//! Adding a provider means adding a variant to [`ProviderKind`], a match arm
//! in [`ProviderKind::from_name`], and a branch in [`build_provider`]. Nothing
//! outside this module needs to change.

use std::path::PathBuf;

use crate::vk::{CaptchaMode, VkTurnProvider};
use crate::{ProviderError, StaticTurnProvider, TurnCredentials, TurnProvider};

/// The provider implementations the daemon can construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// VK Calls: credentials are derived from a call join link.
    Vk,
    /// A fixed relay server, configured entirely on the command line.
    Static,
}

impl ProviderKind {
    /// Parses a provider name as accepted by `--provider`.
    ///
    /// Names are matched case-insensitively. `vk` also accepts the aliases
    /// `vk-calls` and `calls`, since the call link is what the user actually
    /// has in hand.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "vk" | "vk-calls" | "calls" => Some(Self::Vk),
            "static" | "coturn" => Some(Self::Static),
            _ => None,
        }
    }

    /// The canonical name of this provider, as printed in help and errors.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Vk => "vk",
            Self::Static => "static",
        }
    }

    /// Every provider name accepted by [`ProviderKind::from_name`].
    #[must_use]
    pub fn all_names() -> &'static [&'static str] {
        &["vk", "static"]
    }
}

/// Configuration for building a provider.
///
/// Every field is optional because which ones are required depends on the
/// selected [`ProviderKind`]; [`build_provider`] reports the missing ones.
#[derive(Debug, Clone, Default)]
pub struct ProviderConfig {
    /// Which implementation to build.
    pub kind: Option<ProviderKind>,
    /// VK call join link or bare call hash.
    pub vk_hash: Option<String>,
    /// Where the VK provider caches tokens and relay endpoints.
    pub vk_cache_path: Option<PathBuf>,
    /// Refuse to start a VK call before this UNIX timestamp.
    pub earliest_time_secs: Option<u64>,
    /// How to answer a captcha challenge.
    pub captcha_mode: Option<CaptchaMode>,
    /// Interface to bind outbound provider requests to.
    pub bind_interface: Option<String>,
    /// Fixed relay credentials, for [`ProviderKind::Static`].
    pub static_credentials: Option<TurnCredentials>,
}

impl ProviderConfig {
    /// Creates an empty configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the provider kind.
    #[must_use]
    pub fn with_kind(mut self, kind: ProviderKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Sets the VK call link or hash.
    #[must_use]
    pub fn with_vk_hash(mut self, hash: impl Into<String>) -> Self {
        self.vk_hash = Some(hash.into());
        self
    }

    /// Sets the VK credential cache path.
    #[must_use]
    pub fn with_vk_cache_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.vk_cache_path = Some(path.into());
        self
    }

    /// Sets the earliest permitted call start time.
    #[must_use]
    pub fn with_earliest_time(mut self, secs: u64) -> Self {
        self.earliest_time_secs = Some(secs);
        self
    }

    /// Sets the captcha handling mode.
    #[must_use]
    pub fn with_captcha_mode(mut self, mode: CaptchaMode) -> Self {
        self.captcha_mode = Some(mode);
        self
    }

    /// Sets the interface outbound provider requests bind to.
    #[must_use]
    pub fn with_bind_interface(mut self, iface: impl Into<String>) -> Self {
        self.bind_interface = Some(iface.into());
        self
    }

    /// Sets fixed relay credentials for the static provider.
    #[must_use]
    pub fn with_static_credentials(mut self, creds: TurnCredentials) -> Self {
        self.static_credentials = Some(creds);
        self
    }
}

/// Builds a provider from configuration.
///
/// # Errors
///
/// Returns [`ProviderError::Other`] when the configuration is incomplete for
/// the selected provider — for example a VK provider with no call link, or a
/// static provider with no relay address. The message names the missing
/// option so the user can fix the command line.
pub fn build_provider(config: &ProviderConfig) -> Result<Box<dyn TurnProvider>, ProviderError> {
    let kind = config.kind.ok_or_else(|| {
        ProviderError::Other(format!(
            "no provider selected; pass --provider <{}>",
            ProviderKind::all_names().join("|")
        ))
    })?;

    match kind {
        ProviderKind::Vk => build_vk(config),
        ProviderKind::Static => build_static(config),
    }
}

fn build_vk(config: &ProviderConfig) -> Result<Box<dyn TurnProvider>, ProviderError> {
    let hash = config
        .vk_hash
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            ProviderError::Other(
                "the vk provider needs a call link; pass --vk-link <URL|PATH> or --vk-hash <HASH>"
                    .to_owned(),
            )
        })?;

    let cache_path = config.vk_cache_path.clone().ok_or_else(|| {
        ProviderError::Other("the vk provider needs a credential cache path".to_owned())
    })?;

    let provider = VkTurnProvider::new(hash, cache_path, config.earliest_time_secs.unwrap_or(0))
        .with_bind_interface(config.bind_interface.clone())
        .with_captcha_mode(config.captcha_mode.unwrap_or_default());

    Ok(Box::new(provider))
}

fn build_static(config: &ProviderConfig) -> Result<Box<dyn TurnProvider>, ProviderError> {
    let creds = config.static_credentials.clone().ok_or_else(|| {
        ProviderError::Other(
            "the static provider needs a relay address; pass --turn-server <ADDR:PORT>".to_owned(),
        )
    })?;

    if creds.host.trim().is_empty() {
        return Err(ProviderError::Other(
            "the static provider needs a non-empty relay host".to_owned(),
        ));
    }

    Ok(Box::new(StaticTurnProvider::new(creds)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn static_creds() -> TurnCredentials {
        TurnCredentials {
            username: "u".into(),
            password: "p".into(),
            host: "127.0.0.1".into(),
            port: 3478,
            realm: "r".into(),
            use_udp: true,
            expires_at: 0,
        }
    }

    #[test]
    fn parses_provider_names_case_insensitively() {
        assert_eq!(ProviderKind::from_name("VK"), Some(ProviderKind::Vk));
        assert_eq!(
            ProviderKind::from_name(" vk-calls "),
            Some(ProviderKind::Vk)
        );
        assert_eq!(ProviderKind::from_name("Calls"), Some(ProviderKind::Vk));
        assert_eq!(
            ProviderKind::from_name("Static"),
            Some(ProviderKind::Static)
        );
        assert_eq!(
            ProviderKind::from_name("coturn"),
            Some(ProviderKind::Static)
        );
        assert_eq!(ProviderKind::from_name("wireguard"), None);
        assert_eq!(ProviderKind::from_name(""), None);
    }

    #[test]
    fn every_advertised_name_parses() {
        for name in ProviderKind::all_names() {
            assert!(
                ProviderKind::from_name(name).is_some(),
                "advertised name {name} does not parse"
            );
        }
    }

    #[test]
    fn missing_kind_is_reported() {
        let Err(err) = build_provider(&ProviderConfig::new()) else {
            panic!("a provider was built without a kind");
        };
        let msg = err.to_string();
        assert!(msg.contains("--provider"), "unhelpful error: {msg}");
        assert!(msg.contains("vk"), "unhelpful error: {msg}");
    }

    #[test]
    fn vk_without_a_link_is_reported() {
        let config = ProviderConfig::new()
            .with_kind(ProviderKind::Vk)
            .with_vk_cache_path("/tmp/x.json");
        let Err(err) = build_provider(&config) else {
            panic!("a vk provider was built without a link");
        };
        assert!(
            err.to_string().contains("--vk-link"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn vk_with_a_blank_link_is_reported() {
        let config = ProviderConfig::new()
            .with_kind(ProviderKind::Vk)
            .with_vk_hash("   ")
            .with_vk_cache_path("/tmp/x.json");
        assert!(build_provider(&config).is_err());
    }

    #[test]
    fn vk_without_a_cache_path_is_reported() {
        let config = ProviderConfig::new()
            .with_kind(ProviderKind::Vk)
            .with_vk_hash("somehash");
        let Err(err) = build_provider(&config) else {
            panic!("a vk provider was built without a cache path");
        };
        assert!(err.to_string().contains("cache"), "unhelpful error: {err}");
    }

    #[test]
    fn vk_builds_with_a_link_and_a_cache_path() {
        let config = ProviderConfig::new()
            .with_kind(ProviderKind::Vk)
            .with_vk_hash("somehash")
            .with_vk_cache_path("/tmp/x.json");
        assert!(build_provider(&config).is_ok());
    }

    #[test]
    fn static_without_credentials_is_reported() {
        let config = ProviderConfig::new().with_kind(ProviderKind::Static);
        let Err(err) = build_provider(&config) else {
            panic!("a static provider was built without credentials");
        };
        assert!(
            err.to_string().contains("--turn-server"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn static_with_a_blank_host_is_reported() {
        let mut creds = static_creds();
        creds.host = "  ".into();
        let config = ProviderConfig::new()
            .with_kind(ProviderKind::Static)
            .with_static_credentials(creds);
        assert!(build_provider(&config).is_err());
    }

    #[tokio::test]
    async fn static_provider_returns_the_configured_credentials() {
        let creds = static_creds();
        let config = ProviderConfig::new()
            .with_kind(ProviderKind::Static)
            .with_static_credentials(creds.clone());
        let provider = build_provider(&config).unwrap();
        assert_eq!(provider.acquire_credentials().await.unwrap(), creds);
    }
}
