//! Trait definitions and implementations for TURN credential providers.
//!
//! Abstracts static coturn configurations, REST-based credential endpoints,
//! and future dynamic call relay providers.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cache;
pub mod factory;
pub mod vk;

pub use cache::{
    CachedTurnEndpoint, CachedVkCredentials, VkRequestCounter, load_cached_credentials,
    load_raw_cached_credentials, save_cached_credentials,
};
pub use factory::{ProviderConfig, ProviderKind, build_provider};
pub use vk::{CaptchaMode, VkTurnProvider};

use async_trait::async_trait;

/// Error type returned by TURN credential providers.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ProviderError {
    /// Network or I/O failure during credential acquisition.
    #[error("network error: {0}")]
    Network(String),

    /// Authentication failure against credential service.
    #[error("authentication failed: {0}")]
    Authentication(String),

    /// Credentials have permanently expired and cannot be refreshed.
    #[error("credentials expired")]
    Expired,

    /// Provider hit rate limit; retry after the specified seconds.
    #[error("rate limited; retry after {retry_after_secs}s")]
    RateLimited {
        /// Suggested retry interval in seconds.
        retry_after_secs: u32,
    },

    /// Challenge requiring user interaction (e.g. captcha).
    #[error("user interaction required: {challenge_url}")]
    NeedsUserInteraction {
        /// URL of the challenge.
        challenge_url: String,
        /// Optional session token.
        session_token: String,
    },

    /// Other provider-specific error.
    #[error("provider error: {0}")]
    Other(String),
}

/// Active TURN server credentials acquired by a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredentials {
    /// Relay server username.
    pub username: String,
    /// Relay server password / credential token.
    pub password: String,
    /// Relay server host address (domain or IP).
    pub host: String,
    /// Relay server port (default 3478 / 443).
    pub port: u16,
    /// Relay server realm (default "coturn" or similar).
    pub realm: String,
    /// Whether the relay connection should use UDP or TCP/TLS.
    pub use_udp: bool,
    /// Expiration timestamp in seconds since UNIX epoch (0 = indefinite).
    pub expires_at: u64,
}

impl TurnCredentials {
    /// Checks whether credentials have expired at the given timestamp.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        self.expires_at > 0 && now_secs >= self.expires_at
    }
}

/// Abstract trait for acquiring and refreshing TURN server credentials.
#[async_trait]
pub trait TurnProvider: Send + Sync {
    /// Acquired new credentials from the provider.
    async fn acquire_credentials(&self) -> Result<TurnCredentials, ProviderError>;

    /// Refreshes existing credentials before expiration.
    async fn refresh_credentials(
        &self,
        current: &TurnCredentials,
    ) -> Result<TurnCredentials, ProviderError>;
}

/// Static provider supplying fixed TURN credentials (e.g. for dedicated coturn deployments).
#[derive(Debug, Clone)]
pub struct StaticTurnProvider {
    creds: TurnCredentials,
}

impl StaticTurnProvider {
    /// Creates a new static TURN credentials provider.
    pub fn new(creds: TurnCredentials) -> Self {
        Self { creds }
    }
}

#[async_trait]
impl TurnProvider for StaticTurnProvider {
    async fn acquire_credentials(&self) -> Result<TurnCredentials, ProviderError> {
        Ok(self.creds.clone())
    }

    async fn refresh_credentials(
        &self,
        _current: &TurnCredentials,
    ) -> Result<TurnCredentials, ProviderError> {
        // Static credentials do not change on refresh
        Ok(self.creds.clone())
    }
}

/// Events emitted by credential providers, including user interaction challenges.
#[derive(Debug, Clone)]
pub enum ProviderEvent {
    /// Provider encountered a challenge requiring user interaction (e.g. captcha).
    NeedsUserInteraction {
        /// Challenge description or redirect URL.
        challenge_url: String,
        /// Session token associated with the challenge.
        session_token: String,
    },
    /// Credentials were successfully refreshed for the stream.
    CredentialsRefreshed {
        /// Stream ID refreshed.
        stream_id: u8,
        /// Expiration timestamp in seconds.
        expires_at: u64,
    },
    /// Rate limit encountered from external API.
    RateLimited {
        /// Suggested retry interval in seconds.
        retry_after_secs: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_turn_provider() {
        let creds = TurnCredentials {
            username: "turnuser".into(),
            password: "turnpassword".into(),
            host: "127.0.0.1".into(),
            port: 3478,
            realm: "wdtt-test".into(),
            use_udp: true,
            expires_at: 0,
        };

        let provider = StaticTurnProvider::new(creds.clone());
        let acquired = provider.acquire_credentials().await.unwrap();
        assert_eq!(acquired, creds);
        assert!(!acquired.is_expired(9999999999));

        let refreshed = provider.refresh_credentials(&acquired).await.unwrap();
        assert_eq!(refreshed, creds);
    }

    #[test]
    fn test_credentials_expiration() {
        let creds = TurnCredentials {
            username: "u".into(),
            password: "p".into(),
            host: "127.0.0.1".into(),
            port: 3478,
            realm: "r".into(),
            use_udp: true,
            expires_at: 1000,
        };
        assert!(!creds.is_expired(999));
        assert!(creds.is_expired(1000));
        assert!(creds.is_expired(1001));
    }
}
