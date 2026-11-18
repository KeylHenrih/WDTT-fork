//! Xray-compatible routing configuration model.
//!
//! The structs here mirror the `routing` section of an Xray/V2Ray JSON config
//! so that existing rule lists can be reused verbatim. Unknown fields are
//! ignored rather than rejected, which keeps the parser forward-compatible
//! with newer Xray releases.

use serde::Deserialize;

/// Strategy controlling when domain rules are resolved to addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum DomainStrategy {
    /// Never resolve domains; match on the literal destination only.
    #[default]
    #[serde(rename = "AsIs", alias = "asIs")]
    AsIs,
    /// Resolve only when no other rule matched.
    #[serde(rename = "IPIfNonMatch", alias = "ipIfNonMatch")]
    IpIfNonMatch,
    /// Resolve as soon as a domain rule is encountered.
    #[serde(rename = "IPOnDemand", alias = "ipOnDemand")]
    IpOnDemand,
}

/// Algorithm used to match domain rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum DomainMatcher {
    /// Hybrid matcher (Xray's default).
    #[default]
    #[serde(rename = "hybrid", alias = "Hybrid")]
    Hybrid,
    /// Linear scan over all rules.
    #[serde(rename = "linear", alias = "Linear")]
    Linear,
}

/// The `routing` section of an Xray configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Routing {
    /// When domain rules are resolved to addresses.
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    /// Which matcher implementation to use.
    #[serde(default)]
    pub domain_matcher: DomainMatcher,
    /// Ordered rule list; the first matching rule wins.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Load-balancer definitions referenced by `balancerTag`.
    #[serde(default)]
    pub balancers: Vec<Balancer>,
}

/// A single routing rule.
///
/// Every field is optional; a rule matches when all of its *present* criteria
/// match. An empty rule matches everything.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    /// Rule kind, e.g. `field`. Present in Xray configs but not used for
    /// matching here.
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    /// Domain patterns: `domain:`, `full:`, `regexp:`, `keyword:`, `geosite:`.
    #[serde(default)]
    pub domain: Vec<String>,
    /// Address patterns: CIDR literals or `geoip:`.
    #[serde(default)]
    pub ip: Vec<String>,
    /// Destination ports: `443`, `80,443`, `1000-2000`.
    #[serde(default)]
    pub port: PortSpec,
    /// Source ports, same syntax as `port`.
    #[serde(default)]
    pub source_port: PortSpec,
    /// Transport protocols: `tcp`, `udp`, `tcp,udp`.
    #[serde(default)]
    pub network: NetworkSpec,
    /// Source addresses: CIDR literals or `geoip:`.
    #[serde(default)]
    pub source_ip: Vec<String>,
    /// User identifiers: uid/gid as a number or a name.
    #[serde(default)]
    pub user: Vec<String>,
    /// Inbound tags this rule applies to.
    #[serde(default)]
    pub inbound_tag: Vec<String>,
    /// Outbound tag selected when the rule matches.
    #[serde(default)]
    pub outbound_tag: Option<String>,
    /// Balancer selected when the rule matches.
    #[serde(default)]
    pub balancer_tag: Option<String>,
}

/// A load-balancer definition.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Balancer {
    /// Tag referenced by a rule's `balancerTag`.
    #[serde(default)]
    pub tag: String,
    /// Outbound tag prefixes this balancer draws from.
    #[serde(default)]
    pub selector: Vec<String>,
    /// Strategy name; accepted but not interpreted.
    #[serde(default)]
    pub strategy: Option<String>,
}

/// A port list, accepted either as a string (`"80,443"`) or as a number.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortSpec(pub Vec<PortRange>);

/// An inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// First port in the range.
    pub start: u16,
    /// Last port in the range.
    pub end: u16,
}

impl PortRange {
    /// Returns true when `port` falls inside this range.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

impl PortSpec {
    /// Returns true when the spec is empty (matches any port).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns true when `port` matches any range in the spec.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|r| r.contains(port))
    }
}

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Number(u16),
            List(Vec<Raw>),
        }

        fn parse_one(text: &str) -> Result<Vec<PortRange>, String> {
            let mut out = Vec::new();
            for part in text.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((lo, hi)) = part.split_once('-') {
                    let start: u16 = lo
                        .trim()
                        .parse()
                        .map_err(|_| format!("invalid port range start {lo:?}"))?;
                    let end: u16 = hi
                        .trim()
                        .parse()
                        .map_err(|_| format!("invalid port range end {hi:?}"))?;
                    if start > end {
                        return Err(format!("inverted port range {part:?}"));
                    }
                    out.push(PortRange { start, end });
                } else {
                    let port: u16 = part.parse().map_err(|_| format!("invalid port {part:?}"))?;
                    out.push(PortRange {
                        start: port,
                        end: port,
                    });
                }
            }
            Ok(out)
        }

        fn collect(raw: Raw, out: &mut Vec<PortRange>) -> Result<(), String> {
            match raw {
                Raw::Text(text) => out.extend(parse_one(&text)?),
                Raw::Number(port) => out.push(PortRange {
                    start: port,
                    end: port,
                }),
                Raw::List(items) => {
                    for item in items {
                        collect(item, out)?;
                    }
                }
            }
            Ok(())
        }

        let raw = Raw::deserialize(deserializer)?;
        let mut out = Vec::new();
        collect(raw, &mut out).map_err(D::Error::custom)?;
        Ok(PortSpec(out))
    }
}

/// A transport-protocol list, accepted as `"tcp"`, `"tcp,udp"` or a list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkSpec {
    /// Whether TCP traffic matches.
    pub tcp: bool,
    /// Whether UDP traffic matches.
    pub udp: bool,
}

impl NetworkSpec {
    /// Returns true when the spec is empty (matches any protocol).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.tcp && !self.udp
    }

    /// Returns true when TCP traffic matches this spec.
    #[must_use]
    pub fn matches_tcp(&self) -> bool {
        self.is_empty() || self.tcp
    }

    /// Returns true when UDP traffic matches this spec.
    #[must_use]
    pub fn matches_udp(&self) -> bool {
        self.is_empty() || self.udp
    }
}

impl<'de> Deserialize<'de> for NetworkSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            List(Vec<String>),
        }

        fn apply(token: &str, spec: &mut NetworkSpec) -> Result<(), String> {
            match token.trim().to_ascii_lowercase().as_str() {
                "" => Ok(()),
                "tcp" => {
                    spec.tcp = true;
                    Ok(())
                }
                "udp" => {
                    spec.udp = true;
                    Ok(())
                }
                other => Err(format!("unknown network {other:?}")),
            }
        }

        let raw = Raw::deserialize(deserializer)?;
        let mut spec = NetworkSpec::default();
        match raw {
            Raw::Text(text) => {
                for token in text.split(',') {
                    apply(token, &mut spec).map_err(D::Error::custom)?;
                }
            }
            Raw::List(items) => {
                for item in items {
                    apply(&item, &mut spec).map_err(D::Error::custom)?;
                }
            }
        }
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port_spec_forms() {
        let spec: PortSpec = serde_json::from_str("\"80,443\"").unwrap();
        assert_eq!(spec.0.len(), 2);
        assert!(spec.contains(80));
        assert!(spec.contains(443));
        assert!(!spec.contains(8080));

        let spec: PortSpec = serde_json::from_str("443").unwrap();
        assert!(spec.contains(443));

        let spec: PortSpec = serde_json::from_str("\"1000-2000\"").unwrap();
        assert!(spec.contains(1000));
        assert!(spec.contains(1500));
        assert!(spec.contains(2000));
        assert!(!spec.contains(2001));

        let spec: PortSpec = serde_json::from_str("[\"80\", 443]").unwrap();
        assert!(spec.contains(80));
        assert!(spec.contains(443));
    }

    #[test]
    fn rejects_inverted_port_range() {
        let err = serde_json::from_str::<PortSpec>("\"2000-1000\"").unwrap_err();
        assert!(err.to_string().contains("inverted"));
    }

    #[test]
    fn parses_network_spec_forms() {
        let spec: NetworkSpec = serde_json::from_str("\"tcp\"").unwrap();
        assert!(spec.matches_tcp());
        assert!(!spec.matches_udp());

        let spec: NetworkSpec = serde_json::from_str("\"tcp,udp\"").unwrap();
        assert!(spec.matches_tcp());
        assert!(spec.matches_udp());

        let spec: NetworkSpec = serde_json::from_str("[\"udp\"]").unwrap();
        assert!(!spec.matches_tcp());
        assert!(spec.matches_udp());
    }

    #[test]
    fn empty_network_spec_matches_everything() {
        let spec = NetworkSpec::default();
        assert!(spec.is_empty());
        assert!(spec.matches_tcp());
        assert!(spec.matches_udp());
    }

    #[test]
    fn parses_full_routing_section() {
        let json = r#"{
            "domainStrategy": "IPIfNonMatch",
            "domainMatcher": "hybrid",
            "rules": [
                {"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:ru"], "outboundTag": "proxy"},
                {"type": "field", "user": ["1000"], "port": "443", "network": "tcp", "outboundTag": "proxy"}
            ],
            "balancers": [{"tag": "b1", "selector": ["proxy-"]}]
        }"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        assert_eq!(routing.domain_strategy, DomainStrategy::IpIfNonMatch);
        assert_eq!(routing.domain_matcher, DomainMatcher::Hybrid);
        assert_eq!(routing.rules.len(), 3);
        assert_eq!(routing.rules[0].outbound_tag.as_deref(), Some("direct"));
        assert_eq!(routing.rules[1].ip, vec!["geoip:ru"]);
        assert!(routing.rules[2].port.contains(443));
        assert_eq!(routing.balancers.len(), 1);
        assert_eq!(routing.balancers[0].selector, vec!["proxy-"]);
    }

    #[test]
    fn ignores_unknown_fields() {
        let json = r#"{
            "rules": [{"type": "field", "outboundTag": "proxy", "somethingNew": 42}],
            "unknownTopLevel": true
        }"#;
        let routing: Routing = serde_json::from_str(json).unwrap();
        assert_eq!(routing.rules.len(), 1);
    }

    #[test]
    fn empty_rule_matches_everything() {
        let rule = Rule::default();
        assert!(rule.domain.is_empty());
        assert!(rule.ip.is_empty());
        assert!(rule.port.is_empty());
        assert!(rule.network.is_empty());
    }
}
