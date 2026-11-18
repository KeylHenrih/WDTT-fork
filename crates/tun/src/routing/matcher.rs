//! Rule matchers: domain, address, port, network and user criteria.
//!
//! Each matcher is compiled once from the textual form used in Xray configs
//! and then queried per connection. Compilation validates the pattern so that
//! a malformed rule is reported at startup rather than silently never
//! matching.

use std::net::IpAddr;

use super::config::{NetworkSpec, PortSpec};

/// Errors raised while compiling a rule pattern.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MatchError {
    /// A CIDR literal could not be parsed.
    #[error("invalid CIDR {0:?}")]
    InvalidCidr(String),
    /// A prefix length was outside `0..=32` for IPv4 or `0..=128` for IPv6.
    #[error("invalid prefix length in {0:?}")]
    InvalidPrefix(String),
    /// A regular expression failed to compile.
    #[error("invalid regexp {pattern:?}: {reason}")]
    InvalidRegexp {
        /// The offending pattern.
        pattern: String,
        /// The underlying regex error.
        reason: String,
    },
    /// A `geoip:` or `geosite:` reference named an unknown category.
    #[error("unknown geo category {0:?}")]
    UnknownGeoCategory(String),
    /// A user identifier was neither a number nor a resolvable name.
    #[error("unknown user {0:?}")]
    UnknownUser(String),
}

/// A single IPv4/IPv6 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// Network base address.
    pub addr: IpAddr,
    /// Prefix length in bits.
    pub prefix: u8,
}

impl Cidr {
    /// Parses `a.b.c.d/len` or a bare address (treated as a host route).
    ///
    /// # Errors
    ///
    /// Returns [`MatchError::InvalidCidr`] when the address is malformed and
    /// [`MatchError::InvalidPrefix`] when the prefix length is out of range.
    pub fn parse(text: &str) -> Result<Self, MatchError> {
        let text = text.trim();
        let (addr_part, prefix_part) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr: IpAddr = addr_part
            .parse()
            .map_err(|_| MatchError::InvalidCidr(text.to_owned()))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => p
                .trim()
                .parse::<u8>()
                .map_err(|_| MatchError::InvalidPrefix(text.to_owned()))?,
            None => max,
        };
        if prefix > max {
            return Err(MatchError::InvalidPrefix(text.to_owned()));
        }
        Ok(Self { addr, prefix })
    }

    /// Returns true when `candidate` falls inside this network.
    #[must_use]
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.addr, candidate) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = v4_mask(self.prefix);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = v6_mask(self.prefix);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// Matches destination addresses against a list of CIDRs.
#[derive(Debug, Clone, Default)]
pub struct IpMatcher {
    cidrs: Vec<Cidr>,
}

impl IpMatcher {
    /// Builds a matcher from CIDR literals.
    ///
    /// # Errors
    ///
    /// Propagates [`Cidr::parse`] failures.
    pub fn from_cidrs<I, S>(items: I) -> Result<Self, MatchError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut cidrs = Vec::new();
        for item in items {
            cidrs.push(Cidr::parse(item.as_ref())?);
        }
        Ok(Self { cidrs })
    }

    /// Returns true when the matcher holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// Returns true when `addr` matches any entry.
    #[must_use]
    pub fn matches(&self, addr: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(addr))
    }

    /// Appends every CIDR from `other` to this matcher.
    pub fn extend(&mut self, other: &Self) {
        self.cidrs.extend_from_slice(&other.cidrs);
    }

    /// Returns the contained CIDRs.
    #[must_use]
    pub fn cidrs(&self) -> &[Cidr] {
        &self.cidrs
    }
}

/// A single domain pattern.
#[derive(Debug, Clone)]
pub enum DomainPattern {
    /// `full:example.com` — exact match.
    Full(String),
    /// `domain:example.com` — matches the domain and any subdomain.
    Suffix(String),
    /// `keyword:example` — substring match.
    Keyword(String),
    /// `regexp:^ads\\.` — regular expression match.
    Regexp(String),
}

impl DomainPattern {
    /// Parses one Xray domain pattern.
    ///
    /// A bare value with no recognised prefix is treated as `domain:`.
    ///
    /// # Errors
    ///
    /// Returns [`MatchError::InvalidRegexp`] when a `regexp:` pattern does not
    /// compile.
    pub fn parse(text: &str) -> Result<Self, MatchError> {
        let text = text.trim();
        if let Some(rest) = text.strip_prefix("full:") {
            return Ok(Self::Full(rest.to_ascii_lowercase()));
        }
        if let Some(rest) = text.strip_prefix("domain:") {
            return Ok(Self::Suffix(rest.to_ascii_lowercase()));
        }
        if let Some(rest) = text.strip_prefix("keyword:") {
            return Ok(Self::Keyword(rest.to_ascii_lowercase()));
        }
        if let Some(rest) = text.strip_prefix("regexp:") {
            validate_regexp(rest)?;
            return Ok(Self::Regexp(rest.to_owned()));
        }
        Ok(Self::Suffix(text.to_ascii_lowercase()))
    }

    /// Returns true when `domain` matches this pattern.
    ///
    /// `domain` is expected to be lowercase and without a trailing dot.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Full(want) => domain == want,
            Self::Suffix(want) => {
                domain == want
                    || (domain.len() > want.len()
                        && domain.ends_with(want)
                        && domain.as_bytes()[domain.len() - want.len() - 1] == b'.')
            }
            Self::Keyword(needle) => domain.contains(needle.as_str()),
            Self::Regexp(pattern) => regexp_matches(pattern, domain),
        }
    }
}

/// Matches domains against a list of patterns.
#[derive(Debug, Clone, Default)]
pub struct DomainMatcher {
    patterns: Vec<DomainPattern>,
}

impl DomainMatcher {
    /// Builds a matcher from Xray domain patterns.
    ///
    /// # Errors
    ///
    /// Propagates [`DomainPattern::parse`] failures.
    pub fn from_patterns<I, S>(items: I) -> Result<Self, MatchError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut patterns = Vec::new();
        for item in items {
            patterns.push(DomainPattern::parse(item.as_ref())?);
        }
        Ok(Self { patterns })
    }

    /// Builds a matcher from already-parsed patterns.
    #[must_use]
    pub fn from_parsed<I: IntoIterator<Item = DomainPattern>>(items: I) -> Self {
        Self {
            patterns: items.into_iter().collect(),
        }
    }

    /// Returns true when the matcher holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns true when `domain` matches any pattern.
    ///
    /// The input is lowercased and any trailing dot is stripped before
    /// matching.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        self.patterns.iter().any(|p| p.matches(&normalized))
    }

    /// Appends every pattern from `other` to this matcher.
    pub fn extend(&mut self, other: &Self) {
        self.patterns.extend_from_slice(&other.patterns);
    }

    /// Returns the contained patterns.
    #[must_use]
    pub fn patterns(&self) -> &[DomainPattern] {
        &self.patterns
    }
}

/// Matches a user identifier against uid/gid values.
#[derive(Debug, Clone, Default)]
pub struct UserMatcher {
    ids: Vec<u32>,
}

impl UserMatcher {
    /// Builds a matcher from numeric ids.
    #[must_use]
    pub fn from_ids<I: IntoIterator<Item = u32>>(ids: I) -> Self {
        Self {
            ids: ids.into_iter().collect(),
        }
    }

    /// Returns true when the matcher holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Returns true when `id` matches any entry.
    #[must_use]
    pub fn matches(&self, id: u32) -> bool {
        self.ids.contains(&id)
    }

    /// Returns the contained ids.
    #[must_use]
    pub fn ids(&self) -> &[u32] {
        &self.ids
    }
}

/// The complete set of criteria carried by one compiled rule.
#[derive(Debug, Clone, Default)]
pub struct RuleMatcher {
    /// Domain criteria; empty means "any".
    pub domain: DomainMatcher,
    /// Destination address criteria; empty means "any".
    pub ip: IpMatcher,
    /// Destination port criteria; empty means "any".
    pub port: PortSpec,
    /// Source port criteria; empty means "any".
    pub source_port: PortSpec,
    /// Transport protocol criteria; empty means "any".
    pub network: NetworkSpec,
    /// Source address criteria; empty means "any".
    pub source_ip: IpMatcher,
    /// User criteria; empty means "any".
    pub user: UserMatcher,
}

/// A connection's attributes, as seen by the matcher.
#[derive(Debug, Clone, Default)]
pub struct ConnectionInfo {
    /// Destination domain, if known.
    pub domain: Option<String>,
    /// Destination address.
    pub dest_ip: Option<IpAddr>,
    /// Destination port.
    pub dest_port: Option<u16>,
    /// Source address.
    pub source_ip: Option<IpAddr>,
    /// Source port.
    pub source_port: Option<u16>,
    /// Whether the connection is TCP (`false` means UDP).
    pub tcp: bool,
    /// Owning uid, when known.
    pub uid: Option<u32>,
}

impl RuleMatcher {
    /// Returns true when every present criterion matches `conn`.
    ///
    /// A criterion that is absent from the rule is skipped. A criterion that
    /// is present but whose counterpart is unknown in `conn` fails the match,
    /// except for domains: an unresolved domain is treated as "not yet known"
    /// and does not by itself reject the rule.
    #[must_use]
    pub fn matches(&self, conn: &ConnectionInfo) -> bool {
        if !self.domain.is_empty() {
            match conn.domain.as_deref() {
                Some(domain) if self.domain.matches(domain) => {}
                _ => return false,
            }
        }

        if !self.ip.is_empty() {
            match conn.dest_ip {
                Some(ip) if self.ip.matches(ip) => {}
                _ => return false,
            }
        }

        if !self.port.is_empty() {
            match conn.dest_port {
                Some(port) if self.port.contains(port) => {}
                _ => return false,
            }
        }

        if !self.source_port.is_empty() {
            match conn.source_port {
                Some(port) if self.source_port.contains(port) => {}
                _ => return false,
            }
        }

        if !self.network.is_empty() {
            let ok = if conn.tcp {
                self.network.matches_tcp()
            } else {
                self.network.matches_udp()
            };
            if !ok {
                return false;
            }
        }

        if !self.source_ip.is_empty() {
            match conn.source_ip {
                Some(ip) if self.source_ip.matches(ip) => {}
                _ => return false,
            }
        }

        if !self.user.is_empty() {
            match conn.uid {
                Some(uid) if self.user.matches(uid) => {}
                _ => return false,
            }
        }

        true
    }
}

/// Validates a regular expression without pulling in a regex engine.
///
/// The supported subset is deliberately small: anchors, literals, `.`, `*`,
/// `+`, `?`, character classes and alternation. Anything outside it is
/// rejected at compile time so a rule never silently fails to match.
fn validate_regexp(pattern: &str) -> Result<(), MatchError> {
    let mut depth = 0usize;
    let mut in_class = false;
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if chars.next().is_none() {
                    return Err(MatchError::InvalidRegexp {
                        pattern: pattern.to_owned(),
                        reason: "trailing backslash".to_owned(),
                    });
                }
            }
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => {
                if depth == 0 {
                    return Err(MatchError::InvalidRegexp {
                        pattern: pattern.to_owned(),
                        reason: "unbalanced ')'".to_owned(),
                    });
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    if in_class {
        return Err(MatchError::InvalidRegexp {
            pattern: pattern.to_owned(),
            reason: "unterminated character class".to_owned(),
        });
    }
    if depth != 0 {
        return Err(MatchError::InvalidRegexp {
            pattern: pattern.to_owned(),
            reason: "unbalanced '('".to_owned(),
        });
    }
    Ok(())
}

/// Matches `text` against the supported regular-expression subset.
///
/// This is a backtracking matcher over the small subset accepted by
/// [`validate_regexp`]. It is only used for routing rules, which are matched
/// once per connection, so the simple implementation is adequate.
fn regexp_matches(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    let anchored_start = pat.first() == Some(&'^');
    let anchored_end = pat.last() == Some(&'$') && pat.len() > 1;
    let start = usize::from(anchored_start);
    let end = if anchored_end {
        pat.len() - 1
    } else {
        pat.len()
    };

    if anchored_start {
        return match_here(&pat[start..end], &txt, 0, anchored_end);
    }
    for offset in 0..=txt.len() {
        if match_here(&pat[start..end], &txt, offset, anchored_end) {
            return true;
        }
    }
    false
}

fn match_here(pat: &[char], txt: &[char], pos: usize, anchored_end: bool) -> bool {
    if pat.is_empty() {
        return !anchored_end || pos == txt.len();
    }

    // Alternation at the top level: split on '|'.
    if let Some(split) = find_top_level_alt(pat) {
        return match_here(&pat[..split], txt, pos, anchored_end)
            || match_here(&pat[split + 1..], txt, pos, anchored_end);
    }

    // A group: find its matching ')' and try the alternatives inside it.
    if pat.first() == Some(&'(')
        && let Some(close) = find_group_end(pat)
    {
        let inner = &pat[1..close];
        let rest = &pat[close + 1..];
        let quantifier = rest
            .first()
            .copied()
            .filter(|c| matches!(c, '*' | '+' | '?'));
        let rest = &rest[usize::from(quantifier.is_some())..];
        return match_group(inner, quantifier, rest, txt, pos, anchored_end);
    }

    let (atom_len, matcher, quantifiable) = parse_atom(pat);
    let quantifier = if quantifiable {
        pat.get(atom_len)
            .copied()
            .filter(|c| matches!(c, '*' | '+' | '?'))
    } else {
        None
    };
    let rest = &pat[atom_len + usize::from(quantifier.is_some())..];

    match quantifier {
        Some('*') => {
            let mut count = 0usize;
            while pos + count < txt.len() && matcher(txt[pos + count]) {
                count += 1;
            }
            for take in (0..=count).rev() {
                if match_here(rest, txt, pos + take, anchored_end) {
                    return true;
                }
            }
            false
        }
        Some('+') => {
            let mut count = 0usize;
            while pos + count < txt.len() && matcher(txt[pos + count]) {
                count += 1;
            }
            if count == 0 {
                return false;
            }
            for take in (1..=count).rev() {
                if match_here(rest, txt, pos + take, anchored_end) {
                    return true;
                }
            }
            false
        }
        Some('?') => {
            if pos < txt.len() && matcher(txt[pos]) && match_here(rest, txt, pos + 1, anchored_end)
            {
                return true;
            }
            match_here(rest, txt, pos, anchored_end)
        }
        _ => {
            if pos < txt.len() && matcher(txt[pos]) {
                match_here(rest, txt, pos + 1, anchored_end)
            } else {
                false
            }
        }
    }
}

fn find_top_level_alt(pat: &[char]) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_class = false;
    let mut escaped = false;
    for (i, ch) in pat.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' => in_class = true,
            ']' => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => depth = depth.saturating_sub(1),
            '|' if !in_class && depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Returns the index of the `)` closing the group that starts at `pat[0]`.
fn find_group_end(pat: &[char]) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_class = false;
    let mut escaped = false;
    for (i, ch) in pat.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' => in_class = true,
            ']' => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Matches a group body, honouring an optional quantifier, then the rest.
fn match_group(
    inner: &[char],
    quantifier: Option<char>,
    rest: &[char],
    txt: &[char],
    pos: usize,
    anchored_end: bool,
) -> bool {
    // Collect the lengths the group can consume, shortest first.
    let mut lengths: Vec<usize> = Vec::new();
    for take in 0..=txt.len().saturating_sub(pos) {
        if match_here(inner, &txt[..pos + take], pos, true) {
            lengths.push(take);
        }
    }

    match quantifier {
        Some('*') => {
            for take in lengths.iter().rev() {
                if match_here(rest, txt, pos + take, anchored_end) {
                    return true;
                }
            }
            false
        }
        Some('+') => {
            for take in lengths.iter().rev().filter(|t| **t > 0) {
                if match_here(rest, txt, pos + take, anchored_end) {
                    return true;
                }
            }
            false
        }
        Some('?') => {
            for take in lengths.iter().rev() {
                if match_here(rest, txt, pos + take, anchored_end) {
                    return true;
                }
            }
            match_here(rest, txt, pos, anchored_end)
        }
        _ => {
            for take in lengths.iter().rev() {
                if match_here(rest, txt, pos + take, anchored_end) {
                    return true;
                }
            }
            false
        }
    }
}

/// Returns the atom length, a predicate for the character it matches, and
/// whether a quantifier may follow it.
///
/// An escaped literal (`\.`) is not quantifiable: in `\..*` the `*` applies to
/// the following `.`, not to the escaped dot.
fn parse_atom(pat: &[char]) -> (usize, Box<dyn Fn(char) -> bool>, bool) {
    match pat.first() {
        Some('.') => (1, Box::new(|_| true), true),
        Some('\\') if pat.len() > 1 => {
            let literal = pat[1];
            (2, Box::new(move |c| c == literal), false)
        }
        Some('[') => {
            let mut i = 1;
            let negated = pat.get(i) == Some(&'^');
            if negated {
                i += 1;
            }
            let mut set: Vec<(char, char)> = Vec::new();
            while i < pat.len() && pat[i] != ']' {
                let lo = pat[i];
                if pat.get(i + 1) == Some(&'-') && pat.get(i + 2).is_some() && pat[i + 2] != ']' {
                    set.push((lo, pat[i + 2]));
                    i += 3;
                } else {
                    set.push((lo, lo));
                    i += 1;
                }
            }
            let len = if i < pat.len() { i + 1 } else { i };
            (
                len,
                Box::new(move |c| {
                    let inside = set.iter().any(|(lo, hi)| c >= *lo && c <= *hi);
                    inside != negated
                }),
                true,
            )
        }
        Some(&ch) => (1, Box::new(move |c| c == ch), true),
        None => (0, Box::new(|_| false), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parses_and_matches() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains("10.1.2.3".parse().unwrap()));
        assert!(!cidr.contains("11.0.0.1".parse().unwrap()));

        let host = Cidr::parse("1.1.1.1").unwrap();
        assert_eq!(host.prefix, 32);
        assert!(host.contains("1.1.1.1".parse().unwrap()));
        assert!(!host.contains("1.1.1.2".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_bad_prefix() {
        assert!(matches!(
            Cidr::parse("10.0.0.0/33"),
            Err(MatchError::InvalidPrefix(_))
        ));
        assert!(matches!(
            Cidr::parse("not-an-ip"),
            Err(MatchError::InvalidCidr(_))
        ));
    }

    #[test]
    fn cidr_zero_prefix_matches_everything() {
        let cidr = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(cidr.contains("8.8.8.8".parse().unwrap()));
        assert!(cidr.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr_matches() {
        let cidr = Cidr::parse("2001:db8::/32").unwrap();
        assert!(cidr.contains("2001:db8::1".parse().unwrap()));
        assert!(!cidr.contains("2001:db9::1".parse().unwrap()));
        // Cross-family never matches.
        assert!(!cidr.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn domain_suffix_matches_subdomains_only() {
        let m = DomainMatcher::from_patterns(["domain:example.com"]).unwrap();
        assert!(m.matches("example.com"));
        assert!(m.matches("www.example.com"));
        assert!(m.matches("a.b.example.com"));
        assert!(!m.matches("notexample.com"));
        assert!(!m.matches("example.com.evil.net"));
    }

    #[test]
    fn domain_full_matches_exactly() {
        let m = DomainMatcher::from_patterns(["full:example.com"]).unwrap();
        assert!(m.matches("example.com"));
        assert!(!m.matches("www.example.com"));
    }

    #[test]
    fn domain_keyword_matches_substring() {
        let m = DomainMatcher::from_patterns(["keyword:ads"]).unwrap();
        assert!(m.matches("ads.example.com"));
        assert!(m.matches("myads.net"));
        assert!(!m.matches("example.com"));
    }

    #[test]
    fn domain_matching_is_case_insensitive_and_ignores_trailing_dot() {
        let m = DomainMatcher::from_patterns(["domain:Example.COM"]).unwrap();
        assert!(m.matches("WWW.EXAMPLE.com."));
    }

    #[test]
    fn bare_domain_defaults_to_suffix() {
        let m = DomainMatcher::from_patterns(["example.com"]).unwrap();
        assert!(m.matches("www.example.com"));
    }

    #[test]
    fn regexp_anchors_and_quantifiers() {
        let m = DomainMatcher::from_patterns([r"regexp:^ads\..*\.net$"]).unwrap();
        assert!(m.matches("ads.foo.net"));
        assert!(!m.matches("ads.foo.com"));
        assert!(!m.matches("xads.foo.net"));
    }

    #[test]
    fn regexp_alternation_and_classes() {
        let m = DomainMatcher::from_patterns([r"regexp:^(a|b)[0-9]+\.com$"]).unwrap();
        assert!(m.matches("a1.com"));
        assert!(m.matches("b42.com"));
        assert!(!m.matches("c1.com"));
        assert!(!m.matches("a.com"));
    }

    #[test]
    fn regexp_rejects_unbalanced_patterns() {
        assert!(matches!(
            DomainPattern::parse("regexp:(unclosed"),
            Err(MatchError::InvalidRegexp { .. })
        ));
        assert!(matches!(
            DomainPattern::parse("regexp:[unclosed"),
            Err(MatchError::InvalidRegexp { .. })
        ));
    }

    #[test]
    fn user_matcher_matches_ids() {
        let m = UserMatcher::from_ids([1000, 1001]);
        assert!(m.matches(1000));
        assert!(!m.matches(0));
        assert!(!m.is_empty());
    }

    #[test]
    fn rule_matcher_requires_all_present_criteria() {
        let matcher = RuleMatcher {
            ip: IpMatcher::from_cidrs(["10.0.0.0/8"]).unwrap(),
            port: serde_json::from_str("\"443\"").unwrap(),
            network: serde_json::from_str("\"tcp\"").unwrap(),
            ..Default::default()
        };

        let good = ConnectionInfo {
            dest_ip: Some("10.1.1.1".parse().unwrap()),
            dest_port: Some(443),
            tcp: true,
            ..Default::default()
        };
        assert!(matcher.matches(&good));

        let wrong_port = ConnectionInfo {
            dest_port: Some(80),
            ..good.clone()
        };
        assert!(!matcher.matches(&wrong_port));

        let wrong_proto = ConnectionInfo {
            tcp: false,
            ..good.clone()
        };
        assert!(!matcher.matches(&wrong_proto));

        let missing_ip = ConnectionInfo {
            dest_ip: None,
            ..good
        };
        assert!(!matcher.matches(&missing_ip));
    }

    #[test]
    fn empty_rule_matcher_matches_everything() {
        let matcher = RuleMatcher::default();
        assert!(matcher.matches(&ConnectionInfo::default()));
    }

    #[test]
    fn domain_criterion_fails_when_domain_unknown() {
        let matcher = RuleMatcher {
            domain: DomainMatcher::from_patterns(["domain:example.com"]).unwrap(),
            ..Default::default()
        };
        assert!(!matcher.matches(&ConnectionInfo::default()));
        assert!(matcher.matches(&ConnectionInfo {
            domain: Some("www.example.com".to_owned()),
            ..Default::default()
        }));
    }
}
