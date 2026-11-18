//! Xray-compatible routing rules.
//!
//! The module parses the `routing` section of an Xray/V2Ray JSON config,
//! compiles each rule into a [`RuleMatcher`], and evaluates a connection
//! against the ordered rule list. The first matching rule wins, exactly as in
//! Xray.
//!
//! Geo references (`geoip:` / `geosite:`) are resolved through the
//! [`crate::geo`] module, which supplies the category contents.

pub mod config;
pub mod matcher;

pub use config::{
    Balancer, DomainMatcher as DomainMatcherKind, DomainStrategy, NetworkSpec, PortRange, PortSpec,
    Routing, Rule,
};
pub use matcher::{
    Cidr, ConnectionInfo, DomainMatcher, DomainPattern, IpMatcher, MatchError, RuleMatcher,
    UserMatcher,
};

use std::collections::HashMap;

use crate::geo::GeoData;

/// Errors raised while compiling a routing configuration.
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    /// A rule pattern failed to compile.
    #[error(transparent)]
    Match(#[from] MatchError),
    /// A `geoip:` or `geosite:` reference named an unknown category.
    #[error("unknown geo category {0:?}")]
    UnknownGeoCategory(String),
    /// A rule referenced a balancer tag that is not defined.
    #[error("rule references undefined balancer {0:?}")]
    UnknownBalancer(String),
    /// A user identifier could not be resolved to a numeric id.
    #[error("cannot resolve user {0:?}")]
    UnknownUser(String),
}

/// What a matching rule selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Send the connection through the tunnel.
    Proxy,
    /// Send the connection outside the tunnel.
    Direct,
    /// Drop the connection.
    Block,
    /// A named outbound tag that is neither `proxy`, `direct` nor `block`.
    Tagged(String),
}

impl Outbound {
    /// Classifies an Xray outbound tag.
    #[must_use]
    pub fn from_tag(tag: &str) -> Self {
        match tag {
            "proxy" => Self::Proxy,
            "direct" => Self::Direct,
            "block" => Self::Block,
            other => Self::Tagged(other.to_owned()),
        }
    }

    /// Returns true when traffic selected by this outbound is tunnelled.
    #[must_use]
    pub fn is_tunnelled(&self) -> bool {
        matches!(self, Self::Proxy)
    }
}

/// A compiled rule: its criteria plus the outbound it selects.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Criteria that must all match.
    pub matcher: RuleMatcher,
    /// Outbound selected on a match.
    pub outbound: Outbound,
    /// Inbound tags this rule is restricted to; empty means "any".
    pub inbound_tags: Vec<String>,
    /// Original rule index, for diagnostics.
    pub index: usize,
}

/// A compiled routing table.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    rules: Vec<CompiledRule>,
    strategy: DomainStrategy,
    balancers: HashMap<String, Balancer>,
}

impl RoutingTable {
    /// Compiles a parsed [`Routing`] section against the loaded geo data.
    ///
    /// # Errors
    ///
    /// Returns [`RoutingError`] when a pattern, geo reference, user name or
    /// balancer reference cannot be resolved.
    pub fn compile(routing: &Routing, geo: &GeoData) -> Result<Self, RoutingError> {
        let mut rules = Vec::with_capacity(routing.rules.len());

        for (index, rule) in routing.rules.iter().enumerate() {
            let matcher = compile_rule(rule, geo)?;
            let outbound = match (&rule.outbound_tag, &rule.balancer_tag) {
                (Some(tag), _) => Outbound::from_tag(tag),
                (None, Some(balancer)) => {
                    if !routing.balancers.iter().any(|b| &b.tag == balancer) {
                        return Err(RoutingError::UnknownBalancer(balancer.clone()));
                    }
                    Outbound::Tagged(balancer.clone())
                }
                (None, None) => Outbound::Direct,
            };
            rules.push(CompiledRule {
                matcher,
                outbound,
                inbound_tags: rule.inbound_tag.clone(),
                index,
            });
        }

        let balancers = routing
            .balancers
            .iter()
            .map(|b| (b.tag.clone(), b.clone()))
            .collect();

        Ok(Self {
            rules,
            strategy: routing.domain_strategy,
            balancers,
        })
    }

    /// Returns the configured domain strategy.
    #[must_use]
    pub fn strategy(&self) -> DomainStrategy {
        self.strategy
    }

    /// Returns the compiled rules in evaluation order.
    #[must_use]
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Returns the defined balancers.
    #[must_use]
    pub fn balancers(&self) -> &HashMap<String, Balancer> {
        &self.balancers
    }

    /// Evaluates `conn` and returns the selected outbound.
    ///
    /// Returns `None` when no rule matched, which the caller treats as
    /// "direct" — the same default Xray applies.
    #[must_use]
    pub fn evaluate(&self, conn: &ConnectionInfo) -> Option<&CompiledRule> {
        self.rules.iter().find(|rule| rule.matcher.matches(conn))
    }

    /// Returns true when `conn` should be tunnelled.
    #[must_use]
    pub fn should_tunnel(&self, conn: &ConnectionInfo) -> bool {
        self.evaluate(conn)
            .is_some_and(|rule| rule.outbound.is_tunnelled())
    }
}

fn compile_rule(rule: &Rule, geo: &GeoData) -> Result<RuleMatcher, RoutingError> {
    let mut domain = DomainMatcher::default();
    for pattern in &rule.domain {
        if let Some(category) = pattern.strip_prefix("geosite:") {
            let matcher = geo
                .domain_matcher(category)
                .ok_or_else(|| RoutingError::UnknownGeoCategory(pattern.clone()))?;
            domain.extend(matcher);
        } else {
            domain.extend(&DomainMatcher::from_patterns([pattern])?);
        }
    }

    let mut ip = IpMatcher::default();
    for pattern in &rule.ip {
        if let Some(category) = pattern.strip_prefix("geoip:") {
            let matcher = geo
                .ip_matcher(category)
                .ok_or_else(|| RoutingError::UnknownGeoCategory(pattern.clone()))?;
            ip.extend(matcher);
        } else {
            ip.extend(&IpMatcher::from_cidrs([pattern])?);
        }
    }

    let mut source_ip = IpMatcher::default();
    for pattern in &rule.source_ip {
        if let Some(category) = pattern.strip_prefix("geoip:") {
            let matcher = geo
                .ip_matcher(category)
                .ok_or_else(|| RoutingError::UnknownGeoCategory(pattern.clone()))?;
            source_ip.extend(matcher);
        } else {
            source_ip.extend(&IpMatcher::from_cidrs([pattern])?);
        }
    }

    let mut user = UserMatcher::default();
    for name in &rule.user {
        let id = resolve_user(name).ok_or_else(|| RoutingError::UnknownUser(name.clone()))?;
        user = UserMatcher::from_ids(user.ids().iter().copied().chain(std::iter::once(id)));
    }

    Ok(RuleMatcher {
        domain,
        ip,
        port: rule.port.clone(),
        source_port: rule.source_port.clone(),
        network: rule.network,
        source_ip,
        user,
    })
}

/// Resolves a user identifier to a numeric uid.
///
/// Accepts a decimal number directly, or a name looked up through the system
/// user database.
#[must_use]
pub fn resolve_user(name: &str) -> Option<u32> {
    if let Ok(id) = name.trim().parse::<u32>() {
        return Some(id);
    }
    lookup_user_id(name.trim())
}

#[cfg(unix)]
fn lookup_user_id(name: &str) -> Option<u32> {
    use std::ffi::CString;

    let cname = CString::new(name).ok()?;
    // SAFETY: `getpwnam` returns a pointer into a static buffer owned by libc.
    // We copy the single field we need before any other libc call can
    // overwrite it, and never retain the pointer.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: `pw` is non-null and points at a valid `passwd` for the duration
    // of this call.
    Some(unsafe { (*pw).pw_uid })
}

#[cfg(not(unix))]
fn lookup_user_id(_name: &str) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_geo() -> GeoData {
        GeoData::default()
    }

    #[test]
    fn compiles_and_evaluates_ip_rule() {
        let json = r#"{
            "rules": [
                {"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "proxy"}
            ]
        }"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        let table = RoutingTable::compile(&routing, &empty_geo()).unwrap();

        let inside = ConnectionInfo {
            dest_ip: Some("10.1.2.3".parse().unwrap()),
            ..Default::default()
        };
        assert!(table.should_tunnel(&inside));

        let outside = ConnectionInfo {
            dest_ip: Some("8.8.8.8".parse().unwrap()),
            ..Default::default()
        };
        assert!(!table.should_tunnel(&outside));
    }

    #[test]
    fn first_matching_rule_wins() {
        let json = r#"{
            "rules": [
                {"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "direct"},
                {"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "proxy"}
            ]
        }"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        let table = RoutingTable::compile(&routing, &empty_geo()).unwrap();
        let conn = ConnectionInfo {
            dest_ip: Some("10.1.2.3".parse().unwrap()),
            ..Default::default()
        };
        let matched = table.evaluate(&conn).unwrap();
        assert_eq!(matched.outbound, Outbound::Direct);
        assert_eq!(matched.index, 0);
    }

    #[test]
    fn unmatched_connection_is_not_tunnelled() {
        let json =
            r#"{"rules": [{"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "proxy"}]}"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        let table = RoutingTable::compile(&routing, &empty_geo()).unwrap();
        assert!(!table.should_tunnel(&ConnectionInfo::default()));
    }

    #[test]
    fn unknown_geo_category_is_reported() {
        let json =
            r#"{"rules": [{"type": "field", "ip": ["geoip:nowhere"], "outboundTag": "proxy"}]}"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        let err = RoutingTable::compile(&routing, &empty_geo()).unwrap_err();
        assert!(matches!(err, RoutingError::UnknownGeoCategory(_)));
    }

    #[test]
    fn unknown_balancer_is_reported() {
        let json =
            r#"{"rules": [{"type": "field", "ip": ["10.0.0.0/8"], "balancerTag": "missing"}]}"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        let err = RoutingTable::compile(&routing, &empty_geo()).unwrap_err();
        assert!(matches!(err, RoutingError::UnknownBalancer(_)));
    }

    #[test]
    fn known_balancer_compiles() {
        let json = r#"{
            "rules": [{"type": "field", "ip": ["10.0.0.0/8"], "balancerTag": "b1"}],
            "balancers": [{"tag": "b1", "selector": ["proxy-"]}]
        }"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        let table = RoutingTable::compile(&routing, &empty_geo()).unwrap();
        assert_eq!(table.balancers().len(), 1);
    }

    #[test]
    fn numeric_user_resolves() {
        assert_eq!(resolve_user("1000"), Some(1000));
        assert_eq!(resolve_user(" 0 "), Some(0));
    }

    #[test]
    fn outbound_classification() {
        assert_eq!(Outbound::from_tag("proxy"), Outbound::Proxy);
        assert_eq!(Outbound::from_tag("direct"), Outbound::Direct);
        assert_eq!(Outbound::from_tag("block"), Outbound::Block);
        assert_eq!(
            Outbound::from_tag("custom"),
            Outbound::Tagged("custom".to_owned())
        );
        assert!(Outbound::Proxy.is_tunnelled());
        assert!(!Outbound::Direct.is_tunnelled());
    }

    #[test]
    fn domain_strategy_is_preserved() {
        let json = r#"{"domainStrategy": "IPOnDemand", "rules": []}"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        let table = RoutingTable::compile(&routing, &empty_geo()).unwrap();
        assert_eq!(table.strategy(), DomainStrategy::IpOnDemand);
    }
}
