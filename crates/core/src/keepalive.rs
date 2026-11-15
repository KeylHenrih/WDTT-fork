//! Adaptive keepalive controller with Pong feedback for NAT mapping maintenance.

#![forbid(unsafe_code)]

use siphasher::sip::SipHasher13;
use std::collections::HashMap;
use std::hash::Hasher;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration parameters for adaptive keepalive probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveKeepaliveConfig {
    /// Safe lower floor interval (e.g. 10s).
    pub min_interval: Duration,
    /// Starting interval (must be <= 20-25s, e.g. 20s).
    pub initial_interval: Duration,
    /// Maximum ceiling (must not exceed 25s to guarantee safe margin within standard 30s NAT timeout).
    pub max_interval: Duration,
    /// Step to increment upon receiving a valid Pong (e.g. 2s).
    pub step: Duration,
    /// Probe response timeout before marking lost and rolling back (e.g. 3s).
    pub probe_timeout: Duration,
}

impl Default for AdaptiveKeepaliveConfig {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(10),
            initial_interval: Duration::from_secs(20),
            max_interval: Duration::from_secs(25),
            step: Duration::from_secs(2),
            probe_timeout: Duration::from_secs(3),
        }
    }
}

/// Non-personal network descriptor identifying network type and hashed identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkId {
    /// Network type (e.g. "wifi", "cellular", "ethernet", "unknown").
    pub net_type: String,
    /// 64-bit non-reversible hash of the network interface/SSID identifier.
    pub identifier_hash: u64,
}

impl NetworkId {
    /// Create a new NetworkId with SipHash-1-3 over the identifier string to prevent storing plain text.
    pub fn new(net_type: impl Into<String>, raw_identifier: &str) -> Self {
        let mut hasher = SipHasher13::new_with_keys(0x1337_cafe_babe_dead, 0x0123_4567_89ab_cdef);
        hasher.write(raw_identifier.as_bytes());
        Self {
            net_type: net_type.into(),
            identifier_hash: hasher.finish(),
        }
    }
}

/// In-memory cache of confirmed keepalive intervals per network.
#[derive(Debug, Default)]
pub struct KeepaliveNetworkCache {
    entries: Mutex<HashMap<NetworkId, Duration>>,
}

impl KeepaliveNetworkCache {
    /// Create a new empty network cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lookup previously confirmed keepalive interval for a network.
    pub fn get(&self, net_id: &NetworkId) -> Option<Duration> {
        self.entries.lock().ok()?.get(net_id).copied()
    }

    /// Store confirmed keepalive interval for a network.
    pub fn store(&self, net_id: NetworkId, interval: Duration) {
        if let Ok(mut lock) = self.entries.lock() {
            lock.insert(net_id, interval);
        }
    }
}

/// Adaptive keepalive state machine tracking probe health and confirmed NAT lifetime.
#[derive(Debug)]
pub struct AdaptiveKeepalive {
    config: AdaptiveKeepaliveConfig,
    current_interval: Duration,
    confirmed_interval: Duration,
    last_tx: Instant,
    last_rx: Instant,
    pending_probe: Option<(u16, Instant)>,
    network_binding: Option<(NetworkId, Arc<KeepaliveNetworkCache>)>,
}

impl AdaptiveKeepalive {
    /// Create a new adaptive keepalive tracker with custom or default configuration.
    pub fn new(config: AdaptiveKeepaliveConfig, now: Instant) -> Self {
        assert!(config.min_interval <= config.initial_interval);
        assert!(config.initial_interval <= config.max_interval);
        assert!(
            config.max_interval <= Duration::from_secs(25),
            "Keepalive max interval must never exceed 25s for safe margin within UDP NAT"
        );

        Self {
            current_interval: config.initial_interval,
            confirmed_interval: config.min_interval,
            last_tx: now,
            last_rx: now,
            pending_probe: None,
            network_binding: None,
            config,
        }
    }

    /// Bind a network identifier and cache to restore/persist confirmed keepalive intervals.
    ///
    /// When reconnecting to a known network, starts with (cached - 2s) to ensure safe margin.
    pub fn with_network(mut self, net_id: NetworkId, cache: Arc<KeepaliveNetworkCache>) -> Self {
        if let Some(cached) = cache.get(&net_id) {
            let restored = cached
                .saturating_sub(Duration::from_secs(2))
                .clamp(self.config.min_interval, self.config.max_interval);
            self.confirmed_interval = restored;
            self.current_interval = restored;
        }
        self.network_binding = Some((net_id, cache));
        self
    }

    /// Return probe timeout duration.
    pub fn probe_timeout(&self) -> Duration {
        self.config.probe_timeout
    }

    /// Currently active probing interval.
    pub fn current_interval(&self) -> Duration {
        self.current_interval
    }

    /// Highest confirmed interval that received a successful Pong response.
    pub fn confirmed_interval(&self) -> Duration {
        self.confirmed_interval
    }

    /// Whether a probe is currently pending response.
    pub fn has_pending_probe(&self) -> bool {
        self.pending_probe.is_some()
    }

    /// Compute the next instant when an action (probe send or probe timeout check) must occur.
    pub fn next_deadline(&self) -> Instant {
        if let Some((_, sent_at)) = self.pending_probe {
            sent_at + self.config.probe_timeout
        } else {
            self.last_tx + self.current_interval
        }
    }

    /// Register outbound traffic transmission (resets idle interval timer).
    pub fn on_tx(&mut self, now: Instant) {
        self.last_tx = now;
    }

    /// Register inbound traffic reception (data packet received from peer).
    pub fn on_rx_data(&mut self, now: Instant) {
        self.last_rx = now;
    }

    /// Check whether a keepalive Ping probe should be transmitted now.
    ///
    /// If an active probe has timed out, this immediately rolls back to the safe floor.
    pub fn should_probe(&mut self, now: Instant) -> bool {
        // Check pending probe timeout
        if let Some((_probe_id, sent_at)) = self.pending_probe {
            if now.saturating_duration_since(sent_at) >= self.config.probe_timeout {
                // Probe timed out! Loss detected. Roll back immediately to safe floor.
                self.current_interval = self.config.min_interval;
                self.pending_probe = None;
                self.last_tx = now;
                return true;
            }
            // Probe is still awaiting Pong response, do not send duplicate
            return false;
        }

        // Check if idle time exceeds current_interval
        now.saturating_duration_since(self.last_tx) >= self.current_interval
    }

    /// Record sending a probe with the given sequence ID.
    pub fn record_probe_sent(&mut self, probe_id: u16, now: Instant) {
        self.pending_probe = Some((probe_id, now));
        self.last_tx = now;
    }

    /// Process received Pong response. Returns true if matching probe was confirmed.
    pub fn on_pong(&mut self, probe_id: u16, now: Instant) -> bool {
        if let Some((pending_id, _sent_at)) = self.pending_probe {
            if pending_id == probe_id {
                self.pending_probe = None;
                self.last_rx = now;
                // Confirm current interval
                self.confirmed_interval = self.current_interval;
                // Grow interval up to maximum ceiling
                self.current_interval =
                    (self.current_interval + self.config.step).min(self.config.max_interval);

                // Persist confirmed interval to network cache if bound
                if let Some((ref net_id, ref cache)) = self.network_binding {
                    cache.store(net_id.clone(), self.confirmed_interval);
                }
                return true;
            }
        }
        false
    }

    /// Explicitly report packet loss or error, triggering immediate rollback to safe floor.
    pub fn on_loss(&mut self, now: Instant) {
        self.current_interval = self.config.min_interval;
        self.pending_probe = None;
        self.last_tx = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_keepalive_initial_and_growth_to_25s_ceiling() {
        let t0 = Instant::now();
        let cfg = AdaptiveKeepaliveConfig::default();
        let mut ak = AdaptiveKeepalive::new(cfg, t0);

        assert_eq!(ak.current_interval(), Duration::from_secs(20));
        assert_eq!(ak.confirmed_interval(), Duration::from_secs(10));

        // Before 20s, should not probe
        assert!(!ak.should_probe(t0 + Duration::from_secs(19)));

        // At 20s, should probe
        let t1 = t0 + Duration::from_secs(20);
        assert!(ak.should_probe(t1));

        ak.record_probe_sent(101, t1);
        assert!(ak.has_pending_probe());
        assert!(!ak.should_probe(t1 + Duration::from_secs(1))); // pending, no duplicate

        // Receive Pong for probe 101 at 50ms later
        let t2 = t1 + Duration::from_millis(50);
        assert!(ak.on_pong(101, t2));
        assert!(!ak.has_pending_probe());

        // Confirmed is now 20s, next interval grew to 22s
        assert_eq!(ak.confirmed_interval(), Duration::from_secs(20));
        assert_eq!(ak.current_interval(), Duration::from_secs(22));

        // Step up successively: 22 -> 24 -> 25 -> capped at 25s
        let mut cur_t = t2;
        let mut pid = 102;
        for expected in [24, 25, 25] {
            cur_t += ak.current_interval();
            assert!(ak.should_probe(cur_t));
            ak.record_probe_sent(pid, cur_t);
            assert!(ak.on_pong(pid, cur_t + Duration::from_millis(10)));
            assert_eq!(ak.current_interval(), Duration::from_secs(expected));
            pid += 1;
        }

        assert_eq!(ak.confirmed_interval(), Duration::from_secs(25));
    }

    #[test]
    fn test_adaptive_keepalive_network_cache() {
        let cache = Arc::new(KeepaliveNetworkCache::new());
        let net_id = NetworkId::new("wifi", "wlan0-office-net");

        let t0 = Instant::now();
        let mut ak1 = AdaptiveKeepalive::new(AdaptiveKeepaliveConfig::default(), t0)
            .with_network(net_id.clone(), cache.clone());

        // Probe and Pong to grow interval to 24s
        let t1 = t0 + Duration::from_secs(20);
        ak1.record_probe_sent(1, t1);
        ak1.on_pong(1, t1 + Duration::from_millis(10));
        let t2 = t1 + Duration::from_secs(22);
        ak1.record_probe_sent(2, t2);
        ak1.on_pong(2, t2 + Duration::from_millis(10));
        assert_eq!(ak1.confirmed_interval(), Duration::from_secs(22));

        // Create new session on same network -> restores (cached - 2s) = 22s - 2s = 20s
        let ak2 = AdaptiveKeepalive::new(AdaptiveKeepaliveConfig::default(), Instant::now())
            .with_network(net_id, cache);
        assert_eq!(ak2.current_interval(), Duration::from_secs(20));
        assert_eq!(ak2.confirmed_interval(), Duration::from_secs(20));
    }

    #[test]
    fn test_adaptive_keepalive_timeout_rollback() {
        let t0 = Instant::now();
        let cfg = AdaptiveKeepaliveConfig::default();
        let mut ak = AdaptiveKeepalive::new(cfg, t0);

        // Advance to probe at 20s
        let t1 = t0 + Duration::from_secs(20);
        assert!(ak.should_probe(t1));
        ak.record_probe_sent(1, t1);

        // Before 3s timeout, no probe
        assert!(!ak.should_probe(t1 + Duration::from_secs(2)));

        // At 3s timeout: should_probe detects timeout, rolls back to safe floor (10s), returns true
        let t_to = t1 + Duration::from_secs(3);
        assert!(ak.should_probe(t_to));
        assert_eq!(ak.current_interval(), Duration::from_secs(10));
        assert!(!ak.has_pending_probe());
    }

    #[test]
    fn test_adaptive_keepalive_explicit_loss_rollback() {
        let t0 = Instant::now();
        let cfg = AdaptiveKeepaliveConfig::default();
        let mut ak = AdaptiveKeepalive::new(cfg, t0);

        // Grow to 22s
        let t1 = t0 + Duration::from_secs(20);
        ak.record_probe_sent(1, t1);
        ak.on_pong(1, t1 + Duration::from_millis(10));
        assert_eq!(ak.current_interval(), Duration::from_secs(22));

        // Signal loss
        ak.on_loss(t1 + Duration::from_secs(5));
        assert_eq!(ak.current_interval(), Duration::from_secs(10));
    }

    #[test]
    #[should_panic(expected = "Keepalive max interval must never exceed 25s for safe margin within UDP NAT")]
    fn test_adaptive_keepalive_rejects_unsafe_ceiling() {
        let cfg = AdaptiveKeepaliveConfig {
            max_interval: Duration::from_secs(28),
            ..AdaptiveKeepaliveConfig::default()
        };
        let _ = AdaptiveKeepalive::new(cfg, Instant::now());
    }
}
