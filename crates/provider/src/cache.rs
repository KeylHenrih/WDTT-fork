//! Secure credential caching and rate-limiting counters for VK credentials.
//!
//! Stores session keys and TURN tokens in ~/.config/wdtt-dev/ with strict 0600 permissions,
//! preventing unnecessary calls to VK Calls API.

use crate::ProviderError;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{info, warn};

/// Cached VK Session and TURN credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedVkCredentials {
    /// Token 1 from VK Calls API.
    pub token1: String,
    /// Token 2 from VK Calls API.
    pub token2: String,
    /// Session key from VK Calls API.
    pub session_key: String,
    /// TURN servers list returned by VK.
    pub turn_servers: Vec<CachedTurnEndpoint>,
    /// Expiration timestamp in seconds since UNIX epoch.
    pub expires_at: u64,
    /// Timestamp when credentials were saved/refreshed.
    pub refreshed_at: u64,
}

impl CachedVkCredentials {
    /// Checks whether credentials are still valid at the given timestamp.
    pub fn is_valid(&self, now_secs: u64) -> bool {
        // Consider expired if within 60 seconds of expiration
        self.expires_at > now_secs + 60
    }
}

/// TURN server endpoint cached from provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedTurnEndpoint {
    /// Full URL, e.g. "turns:turn.voip.vk.com:443?transport=tcp"
    pub url: String,
    /// Username for TURN allocation.
    pub username: String,
    /// Credential / password token.
    pub credential: String,
    /// Whether this is a TLS endpoint.
    pub is_tls: bool,
}

/// Load cached credentials from disk if present and not expired.
pub fn load_cached_credentials(
    path: &Path,
    now_secs: u64,
) -> Result<Option<CachedVkCredentials>, ProviderError> {
    if let Some(creds) = load_raw_cached_credentials(path)? {
        if creds.is_valid(now_secs) {
            info!(
                "Loaded cached VK credentials (valid for {}s more)",
                creds.expires_at.saturating_sub(now_secs)
            );
            Ok(Some(creds))
        } else {
            info!(
                "Cached VK credentials have expired (expires_at={})",
                creds.expires_at
            );
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// Load cached credentials from disk regardless of expiration timestamp.
pub fn load_raw_cached_credentials(
    path: &Path,
) -> Result<Option<CachedVkCredentials>, ProviderError> {
    if !path.exists() {
        return Ok(None);
    }

    let mut file = File::open(path).map_err(|e| ProviderError::Network(e.to_string()))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| ProviderError::Network(e.to_string()))?;

    let creds: CachedVkCredentials =
        serde_json::from_str(&contents).map_err(|e| ProviderError::Other(e.to_string()))?;

    Ok(Some(creds))
}

/// Save credentials to disk with strict 0600 file permissions.
pub fn save_cached_credentials(
    path: &Path,
    creds: &CachedVkCredentials,
) -> Result<(), ProviderError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ProviderError::Network(e.to_string()))?;
    }

    let json =
        serde_json::to_string_pretty(creds).map_err(|e| ProviderError::Other(e.to_string()))?;

    let tmp_path = path.with_extension("tmp");
    {
        let mut file =
            File::create(&tmp_path).map_err(|e| ProviderError::Network(e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file
                .metadata()
                .map_err(|e| ProviderError::Network(e.to_string()))?
                .permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)
                .map_err(|e| ProviderError::Network(e.to_string()))?;
        }

        file.write_all(json.as_bytes())
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        file.flush()
            .map_err(|e| ProviderError::Network(e.to_string()))?;
    }

    std::fs::rename(&tmp_path, path).map_err(|e| ProviderError::Network(e.to_string()))?;
    info!("Saved VK credentials to cache with mode 0600");
    Ok(())
}

/// Thread-safe request counter enforcing hard limits on external VK API calls.
#[derive(Debug, Clone)]
pub struct VkRequestCounter {
    count: Arc<AtomicU32>,
    max_limit: u32,
}

impl VkRequestCounter {
    /// Create a new counter with specified max request budget.
    pub fn new(max_limit: u32) -> Self {
        Self {
            count: Arc::new(AtomicU32::new(0)),
            max_limit,
        }
    }

    /// Increment counter and return current request number, or error if limit exceeded.
    pub fn next_request(&self) -> Result<u32, ProviderError> {
        let prev = self.count.fetch_add(1, Ordering::SeqCst);
        let curr = prev + 1;
        if curr > self.max_limit {
            warn!("VK API request limit reached ({curr}/{})", self.max_limit);
            return Err(ProviderError::RateLimited {
                retry_after_secs: 3600,
            });
        }
        info!("VK API request #{}/{}", curr, self.max_limit);
        Ok(curr)
    }

    /// Current request count.
    pub fn current(&self) -> u32 {
        self.count.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_cache_save_and_load() {
        let cache_file = std::env::temp_dir().join(format!(
            "wdtt_test_creds_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let creds = CachedVkCredentials {
            token1: "tok1_secret".into(),
            token2: "tok2_secret".into(),
            session_key: "sess_key".into(),
            turn_servers: vec![CachedTurnEndpoint {
                url: "turns:turn.example.com:443?transport=tcp".into(),
                username: "u123".into(),
                credential: "p123".into(),
                is_tls: true,
            }],
            expires_at: 10000,
            refreshed_at: 5000,
        };

        save_cached_credentials(&cache_file, &creds).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&cache_file).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        // Test loading valid
        let loaded = load_cached_credentials(&cache_file, 8000).unwrap();
        assert_eq!(loaded, Some(creds.clone()));

        // Test loading expired (within 60s or past)
        let expired = load_cached_credentials(&cache_file, 9950).unwrap();
        assert_eq!(expired, None);

        let _ = std::fs::remove_file(&cache_file);
    }

    #[test]
    fn test_vk_request_counter_budget() {
        let counter = VkRequestCounter::new(3);
        assert_eq!(counter.next_request().unwrap(), 1);
        assert_eq!(counter.next_request().unwrap(), 2);
        assert_eq!(counter.next_request().unwrap(), 3);
        assert!(counter.next_request().is_err());
        assert_eq!(counter.current(), 4);
    }
}
