//! Trait definitions and implementations for TURN credential providers.
//!
//! Abstracts VK Calls anonymous credential generation, static coturn configurations,
//! and REST-based credential endpoints.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Active TURN server credentials acquired by a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredentials {
    /// Relay server username.
    pub username: String,
    /// Relay server password / credential token.
    pub password: String,
    /// Relay server host address (domain or IP).
    pub host: String,
    /// Relay server port (default 443).
    pub port: u16,
    /// Whether the relay connection should use UDP or TCP/TLS.
    pub use_udp: bool,
    /// Expiration timestamp in seconds since UNIX epoch.
    pub expires_at: u64,
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

    #[test]
    fn test_credentials_struct() {
        let creds = TurnCredentials {
            username: "user".into(),
            password: "pass".into(),
            host: "turn.example.com".into(),
            port: 443,
            use_udp: false,
            expires_at: 1893456000,
        };
        assert_eq!(creds.port, 443);
    }
}
