//! Resolution of rule domains into addresses.
//!
//! nftables matches packets, not names, so a rule that selects traffic by
//! domain can only be projected once its domains have been resolved to
//! addresses. This module performs that resolution before the tunnel comes up
//! and hands the result to [`crate::nft::compile_ruleset`].
//!
//! Not every pattern is resolvable. `full:` and `domain:` name concrete hosts
//! and can be looked up; `keyword:` and `regexp:` describe a *shape* of name
//! and have no single address, so they are reported as unresolvable and the
//! caller decides what to do with the rule.
//!
//! Resolution is bounded in three ways, because a `geosite:` category can hold
//! hundreds of thousands of patterns and an unbounded lookup would stall
//! startup indefinitely:
//!
//! * a per-rule cap on how many names are looked up;
//! * a global cap across all rules;
//! * a concurrency limit, so the resolver does not flood the system resolver.
//!
//! Results are cached on disk keyed by name, with a configurable TTL, so a
//! restart does not repeat the work.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::routing::RoutingTable;
use crate::routing::matcher::DomainPattern;

/// Default cap on names resolved for a single rule.
pub const DEFAULT_PER_RULE_LIMIT: usize = 256;

/// Default cap on names resolved across all rules.
pub const DEFAULT_TOTAL_LIMIT: usize = 4096;

/// Default number of concurrent lookups.
pub const DEFAULT_CONCURRENCY: usize = 16;

/// Default lifetime of a cached resolution.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Errors raised while resolving rule domains.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The cache file could not be read or written.
    #[error("resolution cache I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The cache file was not valid JSON.
    #[error("resolution cache is malformed: {0}")]
    Cache(#[from] serde_json::Error),
}

/// Why a rule's domains could not be fully resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unresolvable {
    /// The pattern describes a shape of name, not a concrete host.
    Pattern {
        /// The offending pattern, rendered for display.
        pattern: String,
        /// Why it cannot be resolved.
        reason: &'static str,
    },
    /// The rule exceeded the per-rule lookup cap.
    PerRuleLimit {
        /// The cap that was hit.
        limit: usize,
    },
    /// The global lookup budget was exhausted before this rule was reached.
    TotalLimit {
        /// The cap that was hit.
        limit: usize,
    },
}

/// The outcome of resolving one rule.
#[derive(Debug, Clone, Default)]
pub struct RuleResolution {
    /// Addresses the rule's domains resolved to.
    pub addresses: Vec<IpAddr>,
    /// Patterns that could not be resolved.
    pub unresolvable: Vec<Unresolvable>,
}

/// The outcome of resolving a whole routing table.
#[derive(Debug, Clone, Default)]
pub struct ResolutionReport {
    /// Per-rule results, keyed by rule index.
    pub rules: HashMap<usize, RuleResolution>,
    /// Total number of names looked up.
    pub looked_up: usize,
    /// Number of names served from cache.
    pub cache_hits: usize,
}

impl ResolutionReport {
    /// Returns the address map expected by [`crate::nft::compile_ruleset`].
    #[must_use]
    pub fn address_map(&self) -> HashMap<usize, Vec<IpAddr>> {
        self.rules
            .iter()
            .filter(|(_, r)| !r.addresses.is_empty())
            .map(|(index, r)| (*index, r.addresses.clone()))
            .collect()
    }

    /// Returns true when every rule resolved without complaint.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.rules.values().all(|r| r.unresolvable.is_empty())
    }
}

/// A cached resolution entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    resolved_at: u64,
}

/// On-disk cache of resolved names.
#[derive(Debug, Clone)]
pub struct ResolutionCache {
    path: PathBuf,
    ttl: Duration,
    entries: HashMap<String, CacheEntry>,
}

impl ResolutionCache {
    /// Loads a cache from `path`, treating a missing or malformed file as empty.
    #[must_use]
    pub fn load(path: impl Into<PathBuf>, ttl: Duration) -> Self {
        let path = path.into();
        let entries = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<HashMap<String, CacheEntry>>(&bytes).ok())
            .unwrap_or_default();
        Self { path, ttl, entries }
    }

    /// Returns the cached addresses for `name`, if fresh.
    fn get(&self, name: &str, now: u64) -> Option<&Vec<IpAddr>> {
        let entry = self.entries.get(name)?;
        let age = now.saturating_sub(entry.resolved_at);
        if age > self.ttl.as_secs() {
            return None;
        }
        Some(&entry.addresses)
    }

    /// Records a resolution.
    fn insert(&mut self, name: &str, addresses: Vec<IpAddr>, now: u64) {
        self.entries.insert(
            name.to_owned(),
            CacheEntry {
                addresses,
                resolved_at: now,
            },
        );
    }

    /// Writes the cache back to disk.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::Io`] when the file cannot be written and
    /// [`ResolveError::Cache`] when serialization fails.
    pub fn save(&self) -> Result<(), ResolveError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec(&self.entries)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Returns the number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Configuration for [`DomainResolver`].
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Cap on names resolved for a single rule.
    pub per_rule_limit: usize,
    /// Cap on names resolved across all rules.
    pub total_limit: usize,
    /// Number of concurrent lookups.
    pub concurrency: usize,
    /// Cache lifetime.
    pub cache_ttl: Duration,
    /// Cache file location; `None` disables caching.
    pub cache_path: Option<PathBuf>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            per_rule_limit: DEFAULT_PER_RULE_LIMIT,
            total_limit: DEFAULT_TOTAL_LIMIT,
            concurrency: DEFAULT_CONCURRENCY,
            cache_ttl: DEFAULT_CACHE_TTL,
            cache_path: None,
        }
    }
}

/// Resolves rule domains into addresses.
#[derive(Debug)]
pub struct DomainResolver {
    config: ResolverConfig,
    cache: Option<ResolutionCache>,
}

impl DomainResolver {
    /// Builds a resolver, loading the cache when one is configured.
    #[must_use]
    pub fn new(config: ResolverConfig) -> Self {
        let cache = config
            .cache_path
            .clone()
            .map(|path| ResolutionCache::load(path, config.cache_ttl));
        Self { config, cache }
    }

    /// Resolves every tunnelled rule's domains.
    ///
    /// Rules that are not tunnelled are skipped: their domains never need to
    /// reach nftables.
    pub async fn resolve(&mut self, table: &RoutingTable) -> ResolutionReport {
        let now = unix_now();
        let mut report = ResolutionReport::default();
        let mut budget = self.config.total_limit;
        let semaphore = std::sync::Arc::new(Semaphore::new(self.config.concurrency.max(1)));

        for rule in table.rules() {
            if !rule.outbound.is_tunnelled() || rule.matcher.domain.is_empty() {
                continue;
            }

            let mut resolution = RuleResolution::default();
            let mut names: Vec<String> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();

            for pattern in rule.matcher.domain.patterns() {
                match resolvable_name(pattern) {
                    Some(name) => {
                        if seen.insert(name.clone()) {
                            names.push(name);
                        }
                    }
                    None => resolution.unresolvable.push(Unresolvable::Pattern {
                        pattern: render_pattern(pattern),
                        reason: "pattern describes a name shape, not a concrete host",
                    }),
                }
            }

            if names.len() > self.config.per_rule_limit {
                resolution.unresolvable.push(Unresolvable::PerRuleLimit {
                    limit: self.config.per_rule_limit,
                });
                names.truncate(self.config.per_rule_limit);
            }

            if names.len() > budget {
                resolution.unresolvable.push(Unresolvable::TotalLimit {
                    limit: self.config.total_limit,
                });
                names.truncate(budget);
            }
            budget = budget.saturating_sub(names.len());

            let mut addresses: Vec<IpAddr> = Vec::new();
            let mut pending: Vec<String> = Vec::new();

            for name in &names {
                match self.cache.as_ref().and_then(|c| c.get(name, now)) {
                    Some(cached) => {
                        report.cache_hits += 1;
                        addresses.extend(cached.iter().copied());
                    }
                    None => pending.push(name.clone()),
                }
            }

            let resolved = resolve_many(&pending, semaphore.clone()).await;
            report.looked_up += resolved.len();

            if let Some(cache) = self.cache.as_mut() {
                for (name, addrs) in &resolved {
                    cache.insert(name, addrs.clone(), now);
                }
            }

            for addrs in resolved.values() {
                addresses.extend(addrs.iter().copied());
            }

            addresses.sort();
            addresses.dedup();
            resolution.addresses = addresses;
            report.rules.insert(rule.index, resolution);
        }

        if let Some(cache) = self.cache.as_ref()
            && let Err(error) = cache.save()
        {
            tracing::warn!("could not persist the resolution cache: {error}");
        }

        report
    }
}

/// Returns the name to look up for a pattern, or `None` when the pattern has
/// no single address.
fn resolvable_name(pattern: &DomainPattern) -> Option<String> {
    match pattern {
        DomainPattern::Full(name) => Some(name.clone()),
        DomainPattern::Suffix(name) => Some(name.clone()),
        DomainPattern::Keyword(_) | DomainPattern::Regexp(_) => None,
    }
}

fn render_pattern(pattern: &DomainPattern) -> String {
    match pattern {
        DomainPattern::Full(name) => format!("full:{name}"),
        DomainPattern::Suffix(name) => format!("domain:{name}"),
        DomainPattern::Keyword(text) => format!("keyword:{text}"),
        DomainPattern::Regexp(text) => format!("regexp:{text}"),
    }
}

async fn resolve_many(
    names: &[String],
    semaphore: std::sync::Arc<Semaphore>,
) -> HashMap<String, Vec<IpAddr>> {
    let mut tasks = Vec::with_capacity(names.len());
    for name in names {
        let name = name.clone();
        let permit = semaphore.clone().acquire_owned().await;
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let addrs = lookup(&name).await;
            (name, addrs)
        }));
    }

    let mut out = HashMap::new();
    for task in tasks {
        if let Ok((name, addrs)) = task.await
            && !addrs.is_empty()
        {
            out.insert(name, addrs);
        }
    }
    out
}

async fn lookup(name: &str) -> Vec<IpAddr> {
    match tokio::net::lookup_host((name, 0)).await {
        Ok(addrs) => {
            let mut out: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
            out.sort();
            out.dedup();
            out
        }
        Err(error) => {
            tracing::debug!("could not resolve {name}: {error}");
            Vec::new()
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns the default cache path under `dir`.
#[must_use]
pub fn default_cache_path(dir: &Path) -> PathBuf {
    dir.join("resolved_domains.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingTable;
    use crate::routing::config::Routing;

    fn table_from_json(json: &str) -> RoutingTable {
        let routing: Routing = serde_json::from_str(json).expect("routing parses");
        let geo = crate::geo::GeoData::default();
        RoutingTable::compile(&routing, &geo).expect("routing compiles")
    }

    #[test]
    fn full_and_suffix_patterns_are_resolvable() {
        assert_eq!(
            resolvable_name(&DomainPattern::Full("a.example".into())),
            Some("a.example".to_owned())
        );
        assert_eq!(
            resolvable_name(&DomainPattern::Suffix("example.com".into())),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn keyword_and_regexp_patterns_are_not_resolvable() {
        assert!(resolvable_name(&DomainPattern::Keyword("ads".into())).is_none());
        assert!(resolvable_name(&DomainPattern::Regexp("^ads\\.".into())).is_none());
    }

    #[test]
    fn render_pattern_round_trips_prefixes() {
        assert_eq!(
            render_pattern(&DomainPattern::Suffix("example.com".into())),
            "domain:example.com"
        );
        assert_eq!(
            render_pattern(&DomainPattern::Keyword("ads".into())),
            "keyword:ads"
        );
    }

    #[test]
    fn cache_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("wdtt-cache-test-{}", std::process::id()));
        let path = dir.join("cache.json");
        let _ = std::fs::remove_file(&path);

        let mut cache = ResolutionCache::load(&path, DEFAULT_CACHE_TTL);
        assert!(cache.is_empty());
        cache.insert("example.com", vec!["1.2.3.4".parse().unwrap()], unix_now());
        cache.save().expect("save");

        let reloaded = ResolutionCache::load(&path, DEFAULT_CACHE_TTL);
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded.get("example.com", unix_now()),
            Some(&vec!["1.2.3.4".parse().unwrap()])
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_cache_entries_are_ignored() {
        let mut cache = ResolutionCache::load("/nonexistent/cache.json", Duration::from_secs(10));
        cache.insert("example.com", vec!["1.2.3.4".parse().unwrap()], 1000);
        assert!(cache.get("example.com", 1005).is_some());
        assert!(cache.get("example.com", 2000).is_none());
    }

    #[test]
    fn missing_cache_file_loads_empty() {
        let cache = ResolutionCache::load("/nonexistent/dir/cache.json", DEFAULT_CACHE_TTL);
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn non_tunnelled_rules_are_skipped() {
        let table =
            table_from_json(r#"{"rules":[{"domain":["example.com"],"outboundTag":"direct"}]}"#);
        let mut resolver = DomainResolver::new(ResolverConfig::default());
        let report = resolver.resolve(&table).await;
        assert!(report.rules.is_empty());
        assert_eq!(report.looked_up, 0);
    }

    #[tokio::test]
    async fn unresolvable_patterns_are_reported() {
        let table = table_from_json(
            r#"{"rules":[{"domain":["keyword:ads","regexp:^track\\."],"outboundTag":"proxy"}]}"#,
        );
        let mut resolver = DomainResolver::new(ResolverConfig::default());
        let report = resolver.resolve(&table).await;
        let resolution = report.rules.get(&0).expect("rule 0 present");
        assert_eq!(resolution.unresolvable.len(), 2);
        assert!(resolution.addresses.is_empty());
        assert!(!report.is_complete());
    }

    #[tokio::test]
    async fn per_rule_limit_is_enforced() {
        let domains: Vec<String> = (0..10).map(|i| format!("host{i}.example")).collect();
        let json = serde_json::json!({
            "rules": [{"domain": domains, "outboundTag": "proxy"}]
        })
        .to_string();
        let table = table_from_json(&json);

        let mut resolver = DomainResolver::new(ResolverConfig {
            per_rule_limit: 3,
            total_limit: 100,
            concurrency: 2,
            cache_ttl: DEFAULT_CACHE_TTL,
            cache_path: None,
        });
        let report = resolver.resolve(&table).await;
        let resolution = report.rules.get(&0).expect("rule 0 present");
        assert!(
            resolution
                .unresolvable
                .iter()
                .any(|u| matches!(u, Unresolvable::PerRuleLimit { limit: 3 }))
        );
    }

    #[tokio::test]
    async fn total_limit_is_enforced_across_rules() {
        let domains: Vec<String> = (0..10).map(|i| format!("host{i}.example")).collect();
        let json = serde_json::json!({
            "rules": [
                {"domain": domains.clone(), "outboundTag": "proxy"},
                {"domain": domains, "outboundTag": "proxy"}
            ]
        })
        .to_string();
        let table = table_from_json(&json);

        let mut resolver = DomainResolver::new(ResolverConfig {
            per_rule_limit: 100,
            total_limit: 4,
            concurrency: 2,
            cache_ttl: DEFAULT_CACHE_TTL,
            cache_path: None,
        });
        let report = resolver.resolve(&table).await;
        let second = report.rules.get(&1).expect("rule 1 present");
        assert!(
            second
                .unresolvable
                .iter()
                .any(|u| matches!(u, Unresolvable::TotalLimit { limit: 4 }))
        );
    }

    #[tokio::test]
    async fn address_map_omits_empty_rules() {
        let table =
            table_from_json(r#"{"rules":[{"domain":["keyword:ads"],"outboundTag":"proxy"}]}"#);
        let mut resolver = DomainResolver::new(ResolverConfig::default());
        let report = resolver.resolve(&table).await;
        assert!(report.address_map().is_empty());
    }

    #[test]
    fn default_cache_path_is_under_the_given_dir() {
        let path = default_cache_path(Path::new("/var/lib/wdtt"));
        assert_eq!(path, PathBuf::from("/var/lib/wdtt/resolved_domains.json"));
    }
}
