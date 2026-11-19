//! VK Calls TURN credential provider.
//!
//! Implements automated acquisition of temporary TURN credentials from the VK Calls / OK CDN
//! infrastructure with multi-layer caching, strict rate-limiting, and decoupled WebKit captcha resolution.

use crate::cache::{
    CachedTurnEndpoint, CachedVkCredentials, VkRequestCounter, load_cached_credentials,
    load_raw_cached_credentials, save_cached_credentials,
};
use crate::{ProviderError, TurnCredentials, TurnProvider};
use async_trait::async_trait;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

const VK_CLIENT_ID: &str = "8202606";
const VK_CLIENT_SECRET: &str = "lMRsTiMCyPnp5vfoldmn";
const OK_APP_KEY: &str = "CGMMEJLGDIHBABABA";

/// Parsed TURN allocation credentials from OK CDN response.
struct TurnAllocationInfo {
    username: String,
    credential: String,
    endpoints: Vec<String>,
}

/// Captcha resolution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaptchaMode {
    /// Automatic WebKit window via wdtt-captcha-helper.
    #[default]
    Helper,
    /// Manual prompt in console with hidden no-echo token entry.
    Manual,
}

/// VK Calls TURN Provider.
#[derive(Debug, Clone)]
pub struct VkTurnProvider {
    /// 43-character VK Calls join hash or full URL.
    hash: String,
    /// Local cache path (e.g. ~/.config/wdtt-dev/vk_creds.json).
    cache_path: PathBuf,
    /// Bounded request counter preventing API flooding.
    counter: VkRequestCounter,
    /// Earliest timestamp (UNIX epoch) when external network requests to VK are permitted.
    earliest_time_secs: u64,
    /// Path to wdtt-captcha-helper executable, if available.
    captcha_helper_bin: Option<PathBuf>,
    /// Optional custom base URL for OK CDN (for testing). Defaults to https://calls.okcdn.ru.
    ok_base_url: Option<String>,
    /// Optional custom base URL for VK API (for testing). Defaults to https://api.vk.com.
    vk_base_url: Option<String>,
    /// Optional network interface name for SO_BINDTODEVICE.
    bind_interface: Option<String>,
    /// Captcha resolution mode (Helper window or Manual console).
    captcha_mode: CaptchaMode,
}

impl VkTurnProvider {
    /// Creates a new VK Calls TURN credential provider.
    pub fn new(hash: impl Into<String>, cache_path: PathBuf, earliest_time_secs: u64) -> Self {
        let mut raw_hash = hash.into();
        // If full join URL was provided, extract the trailing hash
        if let Some(pos) = raw_hash.rfind("/join/") {
            raw_hash = raw_hash[(pos + 6)..].to_string();
        }

        // Look for wdtt-captcha-helper binary in standard locations
        let helper_bin = find_captcha_helper();

        Self {
            hash: raw_hash,
            cache_path,
            counter: VkRequestCounter::new(15),
            earliest_time_secs,
            captcha_helper_bin: helper_bin,
            ok_base_url: None,
            vk_base_url: None,
            bind_interface: None,
            captcha_mode: CaptchaMode::Helper,
        }
    }

    /// Sets the captcha resolution mode.
    pub fn with_captcha_mode(mut self, mode: CaptchaMode) -> Self {
        self.captcha_mode = mode;
        self
    }

    /// Sets a custom path to the captcha helper binary.
    pub fn with_captcha_helper(mut self, path: PathBuf) -> Self {
        self.captcha_helper_bin = Some(path);
        self
    }

    /// Sets custom base URLs for OK CDN and VK API endpoints (useful for hermetic tests).
    pub fn with_base_urls(mut self, ok_base: Option<String>, vk_base: Option<String>) -> Self {
        self.ok_base_url = ok_base;
        self.vk_base_url = vk_base;
        self
    }

    /// Sets network interface name for binding all outgoing HTTP sockets via SO_BINDTODEVICE.
    pub fn with_bind_interface(mut self, iface: Option<String>) -> Self {
        self.bind_interface = iface;
        self
    }

    /// Extracts host, port, realm, and transport mode from a TURN URI.
    pub fn parse_turn_uri(uri: &str) -> Option<(String, u16, String, bool)> {
        let trimmed = uri.trim();
        let (is_turns, rest) = if let Some(rest) = trimmed.strip_prefix("turns:") {
            (true, rest)
        } else if let Some(rest) = trimmed.strip_prefix("turn:") {
            (false, rest)
        } else {
            (false, trimmed)
        };

        let (endpoint, _query) = rest.split_once('?').unwrap_or((rest, ""));
        let default_port = if is_turns { 443 } else { 3478 };

        let (host, port) = if let Some((h, p)) = endpoint.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
        } else {
            (endpoint.to_string(), default_port)
        };

        // Determine if connection is TLS or UDP
        let use_udp = !is_turns && !uri.contains("transport=tcp");
        Some((host, port, "okcdn.ru".into(), use_udp))
    }

    /// Executes the full VK Calls acquisition sequence.
    async fn acquire_from_vk(&self) -> Result<TurnCredentials, ProviderError> {
        let now = now_secs();
        if now < self.earliest_time_secs {
            let wait_secs = self.earliest_time_secs - now;
            return Err(ProviderError::Other(format!(
                "VK API requests blocked until safety window expires in {wait_secs}s"
            )));
        }

        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        if let Some(ref iface) = self.bind_interface {
            builder = builder.interface(iface);
        }
        let client = builder
            .build()
            .map_err(|e| ProviderError::Network(e.to_string()))?;

        // Step 1: Anonymous Access Token (token1)
        self.counter.next_request()?;
        info!("[VK Calls] Request 1/5: Fetching anonymous access token...");
        let step1_resp = client
            .post("https://login.vk.ru/?act=get_anonym_token")
            .form(&[
                ("client_id", VK_CLIENT_ID),
                ("token_type", "messages"),
                ("client_secret", VK_CLIENT_SECRET),
                ("version", "1"),
                ("app_id", VK_CLIENT_ID),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Network(format!("token1 request failed: {e}")))?;

        let step1_json: Value = step1_resp
            .json()
            .await
            .map_err(|e| ProviderError::Network(format!("token1 parse failed: {e}")))?;

        let token1 = step1_json
            .get("data")
            .and_then(|d| d.get("access_token"))
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Authentication("token1 not found in response".into()))?
            .to_string();

        // Step 2: Call Preview
        self.counter.next_request()?;
        info!("[VK Calls] Request 2/5: Fetching call preview...");
        let join_url = format!("https://vk.com/call/join/{}", self.hash);
        let preview_url = format!(
            "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id={VK_CLIENT_ID}"
        );
        let _ = client
            .post(&preview_url)
            .form(&[
                ("vk_join_link", join_url.as_str()),
                ("fields", "photo_200"),
                ("access_token", token1.as_str()),
            ])
            .send()
            .await;

        // Step 3: Anonymous Call Token (token2)
        self.counter.next_request()?;
        info!("[VK Calls] Request 3/5: Fetching anonymous call token...");
        let anon_url = format!(
            "https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id={VK_CLIENT_ID}"
        );
        let pseudorandom_name = crate::namegen::generate_name();

        let step3_resp = client
            .post(&anon_url)
            .form(&[
                ("vk_join_link", join_url.as_str()),
                ("name", pseudorandom_name.as_str()),
                ("access_token", token1.as_str()),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Network(format!("token2 request failed: {e}")))?;

        let step3_json: Value = step3_resp
            .json()
            .await
            .map_err(|e| ProviderError::Network(format!("token2 parse failed: {e}")))?;

        let token2 = if let Some(tok) = step3_json
            .get("response")
            .and_then(|r| r.get("token"))
            .and_then(Value::as_str)
        {
            tok.to_string()
        } else if let Some(err_obj) = step3_json.get("error") {
            let error_code = err_obj
                .get("error_code")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if error_code == 14 {
                // Captcha challenge encountered
                let redirect_uri = err_obj
                    .get("redirect_uri")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let captcha_sid = err_obj
                    .get("captcha_sid")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let captcha_ts = err_obj
                    .get("captcha_ts")
                    .and_then(Value::as_str)
                    .unwrap_or("");

                warn!("[VK Calls] Captcha challenged (code 14, sid={captcha_sid}).");

                let success_token = self.resolve_captcha(redirect_uri)?;

                // Retry Step 3 ONCE with solved captcha
                self.counter.next_request()?;
                info!("[VK Calls] Retrying anonymous call token with captcha solution...");
                let retry_resp = client
                    .post(&anon_url)
                    .form(&[
                        ("vk_join_link", join_url.as_str()),
                        ("name", pseudorandom_name.as_str()),
                        ("captcha_key", ""),
                        ("captcha_sid", captcha_sid),
                        ("is_sound_captcha", "0"),
                        ("success_token", success_token.as_str()),
                        ("captcha_ts", captcha_ts),
                        ("captcha_attempt", "1"),
                        ("access_token", token1.as_str()),
                    ])
                    .send()
                    .await
                    .map_err(|e| ProviderError::Network(format!("captcha retry failed: {e}")))?;

                let retry_json: Value = retry_resp.json().await.map_err(|e| {
                    ProviderError::Network(format!("captcha retry parse failed: {e}"))
                })?;

                retry_json
                    .get("response")
                    .and_then(|r| r.get("token"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        error!("[VK Calls] Captcha resolution failed or rejected by server");
                        ProviderError::Authentication("VK captcha challenge rejected".into())
                    })?
                    .to_string()
            } else {
                let err_msg = err_obj
                    .get("error_msg")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                return Err(ProviderError::Authentication(format!(
                    "VK API error {error_code}: {err_msg}"
                )));
            }
        } else {
            return Err(ProviderError::Authentication(
                "unexpected token2 response format".into(),
            ));
        };

        // Step 4: OK CDN Session Login
        info!("[VK Calls] Request 4/5: Logging into OK CDN calls session...");
        let session_key = self.exec_step4(&client).await?;

        // Step 5: Join Conversation & Retrieve TURN Server
        info!("[VK Calls] Request 5/5: Joining conversation to retrieve TURN allocation creds...");
        let turn_info = self.exec_step5(&client, &token2, &session_key).await?;

        let mut cached = CachedVkCredentials {
            token1,
            token2,
            session_key,
            turn_servers: Vec::new(),
            expires_at: 0,
            refreshed_at: 0,
        };

        self.commit_and_return_credentials(&mut cached, turn_info, now)
    }

    /// Fast-path acquisition: skips steps 1–3 and attempts Step 5 directly with cached token2 and session_key.
    /// If session_key is expired, executes Step 4 ONCE to refresh session_key and retries Step 5 ONCE.
    pub async fn try_fast_path(
        &self,
        cached: &mut CachedVkCredentials,
        now: u64,
    ) -> Result<TurnCredentials, ProviderError> {
        if now < self.earliest_time_secs {
            let wait_secs = self.earliest_time_secs - now;
            return Err(ProviderError::Other(format!(
                "VK API requests blocked until safety window expires in {wait_secs}s"
            )));
        }

        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));
        if let Some(ref iface) = self.bind_interface {
            builder = builder.interface(iface);
        }
        let client = builder
            .build()
            .map_err(|e| ProviderError::Network(e.to_string()))?;

        info!(
            "[VK Calls Fast-Path] Request 1: Attempting joinConversationByLink with cached tokens..."
        );
        match self
            .exec_step5(&client, &cached.token2, &cached.session_key)
            .await
        {
            Ok(turn_info) => {
                info!(
                    "[VK Calls Fast-Path] Successfully refreshed TURN credentials with 1 request!"
                );
                return self.commit_and_return_credentials(cached, turn_info, now);
            }
            Err(e) => {
                info!(
                    "[VK Calls Fast-Path] Initial joinConversation failed ({e}). Attempting session re-login (Step 4)..."
                );
            }
        }

        // Session expired: execute Step 4 ONCE to get fresh session_key
        info!("[VK Calls Fast-Path] Request 2: Re-logging into OK CDN (Step 4)...");
        let new_session_key = self.exec_step4(&client).await?;
        cached.session_key = new_session_key;

        // Retry Step 5 ONCE
        info!(
            "[VK Calls Fast-Path] Request 3: Retrying joinConversationByLink with new session_key..."
        );
        let turn_info = self
            .exec_step5(&client, &cached.token2, &cached.session_key)
            .await?;

        info!("[VK Calls Fast-Path] Successfully acquired TURN credentials on retry!");
        self.commit_and_return_credentials(cached, turn_info, now)
    }

    /// Step 4: OK CDN Session Login (auth.anonymLogin).
    async fn exec_step4(&self, client: &reqwest::Client) -> Result<String, ProviderError> {
        self.counter.next_request()?;
        let ok_base = self
            .ok_base_url
            .as_deref()
            .unwrap_or("https://calls.okcdn.ru");
        let url = format!("{ok_base}/fb.do");

        let device_id = uuid::Uuid::new_v4().to_string();
        let session_data = format!(
            r#"{{"version":2,"device_id":"{device_id}","client_version":1.1,"client_type":"SDK_JS"}}"#
        );

        let step4_resp = client
            .post(&url)
            .form(&[
                ("session_data", session_data.as_str()),
                ("method", "auth.anonymLogin"),
                ("format", "JSON"),
                ("application_key", OK_APP_KEY),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Network(format!("OK anonymLogin failed: {e}")))?;

        let step4_json: Value = step4_resp
            .json()
            .await
            .map_err(|e| ProviderError::Network(format!("OK anonymLogin parse failed: {e}")))?;

        let session_key = step4_json
            .get("session_key")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::Authentication("session_key missing from OK login".into())
            })?
            .to_string();

        Ok(session_key)
    }

    /// Step 5: Join Conversation & Retrieve TURN Server (vchat.joinConversationByLink).
    async fn exec_step5(
        &self,
        client: &reqwest::Client,
        token2: &str,
        session_key: &str,
    ) -> Result<TurnAllocationInfo, ProviderError> {
        self.counter.next_request()?;
        let ok_base = self
            .ok_base_url
            .as_deref()
            .unwrap_or("https://calls.okcdn.ru");
        let url = format!("{ok_base}/fb.do");

        let step5_resp = client
            .post(&url)
            .form(&[
                ("joinLink", self.hash.as_str()),
                ("isVideo", "false"),
                ("protocolVersion", "5"),
                ("capabilities", "2F7F"),
                ("anonymToken", token2),
                ("method", "vchat.joinConversationByLink"),
                ("format", "JSON"),
                ("application_key", OK_APP_KEY),
                ("session_key", session_key),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Network(format!("OK joinConversation failed: {e}")))?;

        let step5_json: Value = step5_resp.json().await.map_err(|e| {
            ProviderError::Network(format!("OK joinConversation parse failed: {e}"))
        })?;

        if let Some(err_code) = step5_json.get("error_code") {
            let err_msg = step5_json
                .get("error_msg")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            return Err(ProviderError::Authentication(format!(
                "OK joinConversation returned error {err_code}: {err_msg}"
            )));
        }

        let turn = step5_json
            .get("turn_server")
            .or_else(|| {
                step5_json
                    .get("turn_servers")
                    .and_then(Value::as_array)
                    .and_then(|s| s.first())
            })
            .ok_or_else(|| {
                ProviderError::Authentication("missing turn_server in OK response".into())
            })?;

        let username = turn
            .get("username")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Authentication("missing turn username".into()))?
            .to_string();

        let credential = turn
            .get("credential")
            .or_else(|| turn.get("password"))
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Authentication("missing turn credential".into()))?
            .to_string();

        let mut turn_endpoints = Vec::new();
        if let Some(urls) = turn.get("urls").and_then(Value::as_array) {
            for u in urls.iter().filter_map(Value::as_str) {
                turn_endpoints.push(u.to_string());
            }
        } else if let Some(u) = turn.get("urls").and_then(Value::as_str) {
            turn_endpoints.push(u.to_string());
        }

        if turn_endpoints.is_empty() {
            return Err(ProviderError::Authentication(
                "no TURN URLs provided by VK".into(),
            ));
        }

        Ok(TurnAllocationInfo {
            username,
            credential,
            endpoints: turn_endpoints,
        })
    }

    /// Commits freshly acquired TURN credentials to disk cache and returns `TurnCredentials`.
    fn commit_and_return_credentials(
        &self,
        cached: &mut CachedVkCredentials,
        turn_info: TurnAllocationInfo,
        now: u64,
    ) -> Result<TurnCredentials, ProviderError> {
        let preferred_url = turn_info
            .endpoints
            .iter()
            .find(|u| u.starts_with("turns:"))
            .cloned()
            .unwrap_or_else(|| turn_info.endpoints[0].clone());

        let (host, port, realm, use_udp) =
            Self::parse_turn_uri(&preferred_url).ok_or_else(|| {
                ProviderError::Other(format!("unparseable TURN URL: {preferred_url}"))
            })?;

        let expires_at = now + 86400;
        cached.expires_at = expires_at;
        cached.refreshed_at = now;
        cached.turn_servers = turn_info
            .endpoints
            .into_iter()
            .map(|url| {
                let is_tls = url.starts_with("turns:");
                CachedTurnEndpoint {
                    url,
                    username: turn_info.username.clone(),
                    credential: turn_info.credential.clone(),
                    is_tls,
                }
            })
            .collect();

        if let Err(e) = save_cached_credentials(&self.cache_path, cached) {
            warn!("[VK Calls] Failed to save credentials to cache: {e}");
        }

        info!(
            "[VK Calls] Successfully acquired TURN credentials for host {host}:{port} (expires in 24h)"
        );

        Ok(TurnCredentials {
            username: turn_info.username,
            password: turn_info.credential,
            host,
            port,
            realm,
            use_udp,
            expires_at,
        })
    }

    /// Resolves captcha challenge via wry helper binary or interactive user prompt.
    fn resolve_captcha(&self, redirect_uri: &str) -> Result<String, ProviderError> {
        if redirect_uri.is_empty() {
            return Err(ProviderError::Authentication(
                "empty captcha redirect URI".into(),
            ));
        }

        if self.captcha_mode == CaptchaMode::Helper
            && let Some(ref helper) = self.captcha_helper_bin
        {
            info!("[VK Calls] Spawning WebKit captcha resolution window...");
            let output = Command::new(helper)
                .args(["--url", redirect_uri])
                .output()
                .map_err(|e| ProviderError::Other(format!("failed to run captcha helper: {e}")))?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(tok) = line.trim().strip_prefix("SUCCESS_TOKEN:") {
                        info!("[VK Calls] Captcha successfully resolved in WebKit window");
                        return Ok(tok.trim().to_string());
                    }
                }
            }
        }

        // Manual console mode
        use std::io::Write;
        eprintln!("\n========================================================================");
        eprintln!("VK CAPTCHA CHALLENGE REQUIRED (Manual Mode)");
        eprintln!("1. Open this URL in any browser:");
        eprintln!("{redirect_uri}");
        eprintln!("2. Complete the puzzle/check.");
        eprintln!("3. Paste the redirect URL or success_token below.");
        eprintln!("========================================================================");
        eprint!("Enter token (input hidden): ");
        std::io::stderr().flush().ok();

        let _ = Command::new("stty").arg("-echo").status();
        let mut input = String::new();
        let read_res = std::io::stdin().read_line(&mut input);
        let _ = Command::new("stty").arg("echo").status();
        eprintln!();

        read_res.map_err(|e| ProviderError::Other(format!("failed to read manual token: {e}")))?;
        let raw = input.trim();

        let token = if let Some(pos) = raw.find("success_token=") {
            let sub = &raw[(pos + 14)..];
            let end = sub.find('&').unwrap_or(sub.len());
            sub[..end].to_string()
        } else if let Some(pos) = raw.find("token=") {
            let sub = &raw[(pos + 6)..];
            let end = sub.find('&').unwrap_or(sub.len());
            sub[..end].to_string()
        } else {
            raw.to_string()
        };

        if token.is_empty() {
            return Err(ProviderError::Authentication(
                "empty captcha token provided".into(),
            ));
        }

        Ok(token)
    }
}

#[async_trait]
impl TurnProvider for VkTurnProvider {
    async fn acquire_credentials(&self) -> Result<TurnCredentials, ProviderError> {
        let now = now_secs();

        // 1. Try loading cached credentials first
        if let Ok(Some(cached)) = load_cached_credentials(&self.cache_path, now)
            && let Some((endpoint, (host, port, realm, use_udp))) = cached
                .turn_servers
                .first()
                .and_then(|ep| Self::parse_turn_uri(&ep.url).map(|parsed| (ep, parsed)))
        {
            info!("[VK Calls] Reusing valid cached TURN credentials for host {host}:{port}");
            return Ok(TurnCredentials {
                username: endpoint.username.clone(),
                password: endpoint.credential.clone(),
                host,
                port,
                realm,
                use_udp,
                expires_at: cached.expires_at,
            });
        }

        // 2. Fast-path: if raw cached credentials exist, attempt refresh using cached token2 / session_key
        if let Ok(Some(mut raw_cached)) = load_raw_cached_credentials(&self.cache_path)
            && !raw_cached.token2.is_empty()
        {
            info!("[VK Calls] Found existing raw cached tokens. Attempting fast-path refresh...");
            match self.try_fast_path(&mut raw_cached, now).await {
                Ok(creds) => return Ok(creds),
                Err(e) => {
                    warn!(
                        "[VK Calls] Fast-path refresh failed: {e}. Falling back to full acquisition."
                    );
                }
            }
        }

        // 3. Fallback to full acquisition from VK Calls (steps 1–5)
        self.acquire_from_vk().await
    }

    async fn refresh_credentials(
        &self,
        current: &TurnCredentials,
    ) -> Result<TurnCredentials, ProviderError> {
        let now = now_secs();
        if !current.is_expired(now) {
            return Ok(current.clone());
        }
        self.acquire_credentials().await
    }
}

/// Discovers the path to wdtt-captcha-helper executable.
fn find_captcha_helper() -> Option<PathBuf> {
    // 1. Next to current executable
    if let Some(candidate) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.join("wdtt-captcha-helper")))
        .filter(|p| p.exists())
    {
        return Some(candidate);
    }

    // 2. Explicit override via environment
    if let Some(path) = std::env::var_os("WDTT_CAPTCHA_HELPER") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // 3. Search PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for p in std::env::split_paths(&path_var) {
            let candidate = p.join("wdtt-captcha-helper");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique suffix for per-test cache filenames.
    fn rand_num() -> u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        1000 + (nanos % 9000)
    }

    #[test]
    fn test_parse_turn_uri() {
        let (host, port, realm, use_udp) =
            VkTurnProvider::parse_turn_uri("turns:turn-msk-1.okcdn.ru:443?transport=tcp").unwrap();
        assert_eq!(host, "turn-msk-1.okcdn.ru");
        assert_eq!(port, 443);
        assert_eq!(realm, "okcdn.ru");
        assert!(!use_udp);

        let (host, port, _, use_udp) =
            VkTurnProvider::parse_turn_uri("turn:turn-msk-2.okcdn.ru:3478").unwrap();
        assert_eq!(host, "turn-msk-2.okcdn.ru");
        assert_eq!(port, 3478);
        assert!(use_udp);
    }

    #[test]
    fn test_safety_window_block() {
        let provider = VkTurnProvider::new(
            "dummy_hash",
            PathBuf::from("/tmp/dummy_creds.json"),
            u64::MAX, // Safety window far in the future
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let res = provider.acquire_credentials().await;
            assert!(res.is_err());
            let err_str = res.unwrap_err().to_string();
            assert!(err_str.contains("blocked until safety window"));
        });
    }

    #[tokio::test]
    async fn test_fast_path_one_request_on_expired_turn() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ok_base = format!("http://{addr}");

        let req_count = Arc::new(AtomicUsize::new(0));
        let req_count_srv = req_count.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let body = String::from_utf8_lossy(&buf[..n]);
                req_count_srv.fetch_add(1, Ordering::SeqCst);

                // Must call joinConversationByLink directly
                assert!(body.contains("vchat.joinConversationByLink"));
                assert!(!body.contains("auth.anonymLogin"));

                let response_body = serde_json::json!({
                    "turn_server": {
                        "username": "fast_user_1",
                        "password": "fast_pass_1",
                        "urls": ["turns:turn-fast.okcdn.ru:443?transport=tcp"]
                    }
                })
                .to_string();

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let temp_dir = std::env::temp_dir();
        let cache_file = temp_dir.join(format!("test_cache_{}.json", rand_num()));

        // Write expired cache to disk (expires_at = 100, now is ~1.7e9)
        let old_creds = CachedVkCredentials {
            token1: "cached_tok1".into(),
            token2: "cached_tok2".into(),
            session_key: "cached_sess_key".into(),
            turn_servers: vec![CachedTurnEndpoint {
                url: "turns:old.okcdn.ru:443".into(),
                username: "old".into(),
                credential: "old".into(),
                is_tls: true,
            }],
            expires_at: 100, // expired!
            refreshed_at: 50,
        };
        save_cached_credentials(&cache_file, &old_creds).unwrap();

        let provider = VkTurnProvider::new("test_hash", cache_file.clone(), 0)
            .with_base_urls(Some(ok_base), None);

        let creds = provider.acquire_credentials().await.unwrap();
        assert_eq!(creds.username, "fast_user_1");
        assert_eq!(creds.password, "fast_pass_1");
        assert_eq!(creds.host, "turn-fast.okcdn.ru");
        assert_eq!(creds.port, 443);

        // Verification: EXACTLY ONE request sent to joinConversationByLink!
        assert_eq!(req_count.load(Ordering::SeqCst), 1);

        let _ = std::fs::remove_file(cache_file);
    }

    #[tokio::test]
    async fn test_fast_path_expired_session_retries_once() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ok_base = format!("http://{addr}");

        let req_count = Arc::new(AtomicUsize::new(0));
        let req_count_srv = req_count.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let body = String::from_utf8_lossy(&buf[..n]);
                let count = req_count_srv.fetch_add(1, Ordering::SeqCst);

                let resp_body = match count {
                    0 => {
                        // Request 1: initial vchat.joinConversationByLink fails due to expired session
                        assert!(body.contains("vchat.joinConversationByLink"));
                        assert!(body.contains("session_key=expired_session_key"));
                        serde_json::json!({
                            "error_code": 102,
                            "error_msg": "PARAM_SESSION_EXPIRED"
                        })
                        .to_string()
                    }
                    1 => {
                        // Request 2: step 4 auth.anonymLogin called ONCE
                        assert!(body.contains("auth.anonymLogin"));
                        serde_json::json!({
                            "session_key": "fresh_session_key_777"
                        })
                        .to_string()
                    }
                    2 => {
                        // Request 3: retry vchat.joinConversationByLink with fresh session_key
                        assert!(body.contains("vchat.joinConversationByLink"));
                        assert!(body.contains("session_key=fresh_session_key_777"));
                        serde_json::json!({
                            "turn_server": {
                                "username": "retried_user_2",
                                "password": "retried_pass_2",
                                "urls": ["turns:turn-retry.okcdn.ru:443?transport=tcp"]
                            }
                        })
                        .to_string()
                    }
                    _ => panic!("Unexpected request count: {}", count),
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let temp_dir = std::env::temp_dir();
        let cache_file = temp_dir.join(format!("test_cache_{}.json", rand_num()));

        let old_creds = CachedVkCredentials {
            token1: "cached_tok1".into(),
            token2: "cached_tok2".into(),
            session_key: "expired_session_key".into(),
            turn_servers: vec![],
            expires_at: 100, // expired!
            refreshed_at: 50,
        };
        save_cached_credentials(&cache_file, &old_creds).unwrap();

        let provider = VkTurnProvider::new("test_hash", cache_file.clone(), 0)
            .with_base_urls(Some(ok_base), None);

        let creds = provider.acquire_credentials().await.unwrap();
        assert_eq!(creds.username, "retried_user_2");
        assert_eq!(creds.password, "retried_pass_2");

        // Verification: Exactly 3 requests total: (1) join fail -> (2) anonymLogin once -> (3) join retry
        assert_eq!(req_count.load(Ordering::SeqCst), 3);

        let _ = std::fs::remove_file(cache_file);
    }
}
