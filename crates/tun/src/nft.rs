//! Compilation of routing rules into an nftables ruleset.
//!
//! The routing engine in [`crate::routing`] evaluates a *connection*: it knows
//! the destination domain, the resolved address, the port and the owning uid.
//! nftables sees *packets*, and only a subset of those attributes is available
//! in the `output` hook: destination address, transport protocol, destination
//! port and socket uid. Domain names are not visible at all.
//!
//! This module therefore performs a projection, not a translation:
//!
//! * `ip` / `geoip:` criteria become address sets;
//! * `user` criteria become `meta skuid` matches;
//! * `port` and `network` criteria become `meta l4proto` plus `th dport`;
//! * `domain` / `geosite:` criteria cannot be expressed directly. They are
//!   resolved to addresses beforehand (see [`crate::routing`] callers) and the
//!   resulting addresses are folded into the same address set.
//!
//! The projection is lossy in one specific way, and the compiler reports it
//! rather than hiding it: a rule that constrains *both* a domain and an
//! address is an AND in Xray, but once the domain is resolved to addresses the
//! two conditions can only be unioned. Such rules are flagged in
//! [`CompiledRuleset::approximations`] so the caller can warn the user.
//!
//! The generated ruleset is applied by piping it to `nft -f -`, which keeps
//! the dependency surface at `libc` and a subprocess instead of linking
//! libnftnl.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;

use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::netcfg::WDTT_FWMARK;
use crate::routing::config::{NetworkSpec, PortSpec};
use crate::routing::matcher::Cidr;
use crate::routing::{CompiledRule, Outbound, RoutingTable};

/// Name of the nftables table owned by this program.
///
/// The table is created and destroyed as a unit, so it never interferes with
/// rules managed by other software on the same host.
pub const NFT_TABLE: &str = "wdtt";

/// Name of the address set holding tunnelled destinations.
pub const SET_TUNNEL_V4: &str = "tunnel_v4";

/// Name of the port set holding tunnelled destination ports.
pub const SET_TUNNEL_PORTS: &str = "tunnel_ports";

/// Name of the chain that marks packets for the policy route.
pub const CHAIN_MARK: &str = "mark_out";

/// Name of the address set holding destinations that are never tunnelled.
///
/// Only emitted in inverted mode, where it is consulted with `!=` to select
/// everything outside the white list.
pub const SET_DIRECT_V4: &str = "direct_v4";

/// Name of the nftables table holding blocked destinations.
///
/// Kept separate from [`NFT_TABLE`] so a drop decision can never be confused
/// with a routing decision, and so tearing one down leaves the other intact.
pub const NFT_BLOCK_TABLE: &str = "wdtt_block";

/// Name of the address set holding blocked destinations.
pub const SET_BLOCK_V4: &str = "block_v4";

/// Name of the chain that drops blocked packets.
pub const CHAIN_BLOCK: &str = "block_out";

/// Priority of the block chain within the `output` hook.
///
/// Matches the mark chain's `mangle` priority so both run before the host's
/// own firewall sees the packet.
pub const BLOCK_PRIORITY: i32 = -150;

/// Errors raised while compiling or applying a ruleset.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    /// The generated ruleset could not be applied.
    #[error("nft failed: {0}")]
    Apply(String),
    /// The `nft` binary could not be executed.
    #[error("cannot run nft: {0}")]
    Spawn(#[from] std::io::Error),
    /// A rule used a criterion that cannot be projected onto packets.
    #[error("rule {index} cannot be expressed in nftables: {reason}")]
    Unsupported {
        /// Index of the offending rule in the routing table.
        index: usize,
        /// Why the rule cannot be projected.
        reason: String,
    },
}

/// A rule that survived projection, in the form nftables can express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkRule {
    /// Destination networks that select this rule, if any.
    pub dest_v4: Vec<Cidr>,
    /// Destination ports that select this rule, if any.
    pub dest_ports: Vec<(u16, u16)>,
    /// Whether TCP traffic matches.
    pub tcp: bool,
    /// Whether UDP traffic matches.
    pub udp: bool,
    /// Owning uids that select this rule, if any.
    pub uids: Vec<u32>,
    /// Index of the source rule, for diagnostics.
    pub source_index: usize,
}

impl MarkRule {
    /// Returns true when the rule constrains nothing and would therefore mark
    /// every packet.
    #[must_use]
    pub fn is_catch_all(&self) -> bool {
        self.dest_v4.is_empty()
            && self.dest_ports.is_empty()
            && self.uids.is_empty()
            && self.tcp
            && self.udp
    }
}

/// A note about a rule whose projection is not exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approximation {
    /// Index of the source rule.
    pub index: usize,
    /// Human-readable description of the inexactness.
    pub detail: String,
}

/// The result of projecting a routing table onto nftables.
#[derive(Debug, Clone, Default)]
pub struct CompiledRuleset {
    /// Mark rules, in evaluation order.
    pub rules: Vec<MarkRule>,
    /// Rules that must be dropped rather than routed.
    ///
    /// These describe the same match dimensions as [`Self::rules`] but carry a
    /// terminal `drop` instead of a mark, and are rendered into their own table
    /// so a block rule can never be confused with a routing decision.
    pub block_rules: Vec<MarkRule>,
    /// Rules whose destinations must never be tunnelled.
    ///
    /// Their addresses form an *exclusion* set. When at least one such rule
    /// exists the mark chain inverts: instead of marking the addresses that
    /// must be tunnelled, it marks everything that is **not** in this set.
    pub direct_rules: Vec<MarkRule>,
    /// Rules whose projection is not exact.
    pub approximations: Vec<Approximation>,
}

impl CompiledRuleset {
    /// Returns true when no rule would mark any packet.
    ///
    /// This deliberately ignores [`Self::block_rules`] and [`Self::direct_rules`]:
    /// callers use it to decide whether the mark table has anything to install.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns true when at least one rule asks for traffic to be dropped.
    #[must_use]
    pub fn has_block_rules(&self) -> bool {
        !self.block_rules.is_empty()
    }

    /// Returns true when the ruleset asks for the marking to be inverted.
    ///
    /// An inverted ruleset tunnels everything that is not explicitly excluded,
    /// which is how "VPN by default with a white list" is expressed.
    #[must_use]
    pub fn is_inverted(&self) -> bool {
        !self.direct_rules.is_empty()
    }

    /// Returns the addresses that must never be tunnelled.
    ///
    /// These come from `direct` rules and, in inverted mode, from the local
    /// and infrastructure ranges the caller seeds in. The result is coalesced
    /// into a minimal set of non-overlapping, exactly-covering CIDR blocks:
    /// nftables rejects an interval set whose elements overlap, and the
    /// sources routinely do (a white-list category carries addresses inside
    /// the local ranges, and the relay often sits inside a white-listed
    /// range). A merged interval that is not an aligned power-of-two block is
    /// emitted as several CIDRs, since no single one denotes it.
    #[must_use]
    pub fn direct_exclusions(&self) -> Vec<Cidr> {
        let items: Vec<Cidr> = self
            .direct_rules
            .iter()
            .flat_map(|rule| rule.dest_v4.iter().cloned())
            .collect();
        coalesce_v4(&items)
    }
}

/// Merges IPv4 CIDRs into a minimal set of non-overlapping ranges.
///
/// nftables rejects an interval set whose elements overlap ("conflicting
/// intervals specified"), and the exclusion set is assembled from several
/// sources: white-list categories, the local infrastructure ranges and the
/// relay address. Those routinely overlap — `geoip:ru` carries addresses
/// inside `10.0.0.0/8`, and the relay often sits inside a white-listed range —
/// so the raw concatenation is not installable. Coalescing overlapping and
/// adjacent ranges produces the minimal equivalent set, which nft accepts and
/// which the kernel walks faster.
///
/// IPv6 entries are dropped: the rendered set is `type ipv4_addr`.
fn coalesce_v4(items: &[Cidr]) -> Vec<Cidr> {
    let mut ranges: Vec<(u32, u32)> = items
        .iter()
        .filter_map(|cidr| match cidr.addr {
            IpAddr::V4(addr) => {
                let prefix = cidr.prefix.min(32);
                let start = u32::from(addr);
                if prefix == 0 {
                    return Some((0, u32::MAX));
                }
                let mask = u32::MAX << (32 - prefix);
                let host = if prefix == 0 { u32::MAX } else { !mask };
                Some((start & mask, start | host))
            }
            IpAddr::V6(_) => None,
        })
        .collect();

    if ranges.is_empty() {
        return Vec::new();
    }

    ranges.sort_unstable();

    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            // `end + 1` would overflow when a range reaches the top of the
            // address space, so the adjacency test guards it explicitly.
            Some(last) if start <= last.1 || last.1 != u32::MAX && start == last.1 + 1 => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }

    merged
        .into_iter()
        .flat_map(|(start, end)| decompose_range(start, end))
        .collect()
}

/// Splits the inclusive address range `start..=end` into CIDR blocks.
///
/// A merged interval is not necessarily an aligned power-of-two block: two
/// adjacent CIDRs whose union has a non-power-of-two span, such as
/// `5.8.0.0/18` followed by `5.8.64.0/19`, merge into the 24576-address range
/// `5.8.0.0..=5.8.95.255`. No single CIDR denotes that range — the shortest
/// one covering it is `5.8.0.0/17`, which also spans the following addresses.
/// Emitting that wider CIDR would overlap the next element and nft would
/// reject the whole set with "conflicting intervals specified".
///
/// The range is therefore decomposed greedily: at every step take the largest
/// aligned block that starts at the current address and fits within what is
/// left, then advance past it. The blocks are exact — together they cover the
/// range with no gap and no excess.
fn decompose_range(start: u32, end: u32) -> Vec<Cidr> {
    let mut out = Vec::new();
    let mut cursor = u64::from(start);
    let last = u64::from(end);
    // The cursor is compared against the range end before any arithmetic, so a
    // block that runs past `end` still terminates the loop.
    while cursor <= last {
        // Largest power-of-two block that is aligned at `cursor`.
        let alignment = if cursor == 0 {
            1u64 << 32
        } else {
            1u64 << (cursor.trailing_zeros().min(32))
        };
        let remaining = last - cursor + 1;
        let mut size = 1u64;
        while size * 2 <= remaining && size * 2 <= alignment {
            size *= 2;
        }
        let prefix = 32 - (size.trailing_zeros() as u8);
        out.push(Cidr {
            addr: IpAddr::V4(Ipv4Addr::from(cursor as u32)),
            prefix,
        });
        cursor += size;
    }
    out
}

/// Projects a routing table onto nftables mark and drop rules.
///
/// [`Outbound::Proxy`] rules are projected as mark rules: the ruleset's job is
/// to mark packets that must take the policy route. [`Outbound::Block`] rules
/// are projected as drop rules in a separate table, so they terminate the
/// packet locally instead of routing it. [`Outbound::Direct`] rules contribute
/// their addresses to an exclusion set; as soon as at least one of them exists
/// the mark chain flips to "mark everything that is not excluded", so these
/// rules stop being inert. A named tag is left to the routing engine and
/// produces no packet-layer statement.
///
/// `resolved` supplies addresses obtained by resolving the domains referenced
/// by a rule. A rule with domain criteria and no entry in `resolved` is
/// skipped, because matching by domain is impossible at the packet layer.
#[must_use]
pub fn compile_ruleset(
    table: &RoutingTable,
    resolved: &std::collections::HashMap<usize, Vec<IpAddr>>,
) -> CompiledRuleset {
    let mut out = CompiledRuleset::default();

    for rule in table.rules() {
        let matcher = &rule.matcher;
        let outbound = rule.outbound.clone();
        if matches!(outbound, Outbound::Tagged(_)) {
            continue;
        }

        // Only IPv4 is projected: the generated set is `type ipv4_addr`, and a
        // `geoip:` category routinely carries IPv6 ranges alongside IPv4 ones.
        // Mixing them makes nft reject the whole set.
        let ipv6_dropped = matcher.ip.cidrs().iter().any(|c| c.addr.is_ipv6());
        let mut dest_v4: Vec<Cidr> = matcher
            .ip
            .cidrs()
            .iter()
            .filter(|c| c.addr.is_ipv4())
            .cloned()
            .collect();
        let has_domain = !matcher.domain.is_empty();

        if has_domain {
            match resolved.get(&rule.index) {
                Some(addrs) if !addrs.is_empty() => {
                    if addrs.iter().any(|ip| ip.is_ipv6()) {
                        out.approximations.push(Approximation {
                            index: rule.index,
                            detail: "IPv6 addresses are not tunnelled; only IPv4 is routed"
                                .to_owned(),
                        });
                    }
                    dest_v4.extend(addrs.iter().filter(|ip| ip.is_ipv4()).map(|ip| Cidr {
                        addr: *ip,
                        prefix: 32,
                    }));
                }
                _ => {
                    out.approximations.push(Approximation {
                        index: rule.index,
                        detail: "domain criteria could not be resolved; rule not applied"
                            .to_owned(),
                    });
                    continue;
                }
            }
        }

        if ipv6_dropped {
            out.approximations.push(Approximation {
                index: rule.index,
                detail: "IPv6 addresses are not tunnelled; only IPv4 is routed".to_owned(),
            });
        }

        if has_domain && !matcher.ip.is_empty() {
            out.approximations.push(Approximation {
                index: rule.index,
                detail: "rule constrains both domain and address; the two conditions are \
                         unioned instead of intersected"
                    .to_owned(),
            });
        }

        if !matcher.source_ip.is_empty() {
            out.approximations.push(Approximation {
                index: rule.index,
                detail: "source address criteria are not applied to locally generated traffic"
                    .to_owned(),
            });
        }

        if !matcher.source_port.is_empty() {
            out.approximations.push(Approximation {
                index: rule.index,
                detail: "source port criteria are not applied to locally generated traffic"
                    .to_owned(),
            });
        }

        let network = &matcher.network;
        let mark_rule = MarkRule {
            dest_v4: dedup_sorted(dest_v4),
            dest_ports: matcher.port.0.iter().map(|r| (r.start, r.end)).collect(),
            tcp: network.matches_tcp(),
            udp: network.matches_udp(),
            uids: matcher.user.ids().to_vec(),
            source_index: rule.index,
        };

        if mark_rule.is_catch_all() {
            let detail = match outbound {
                Outbound::Block => "rule matches every packet; it would block all traffic",
                Outbound::Direct => {
                    "rule matches every packet; it would exclude all traffic from the tunnel"
                }
                _ => "rule matches every packet; it would route all traffic through the tunnel",
            };
            out.approximations.push(Approximation {
                index: rule.index,
                detail: detail.to_owned(),
            });
        }

        match outbound {
            Outbound::Block => out.block_rules.push(mark_rule),
            Outbound::Direct => out.direct_rules.push(mark_rule),
            _ => out.rules.push(mark_rule),
        }
    }

    out
}

fn dedup_sorted(mut items: Vec<Cidr>) -> Vec<Cidr> {
    items.sort_by_key(|c| (c.addr, c.prefix));
    items.dedup();
    items
}

/// Renders a network in CIDR form, omitting a full-length prefix.
fn render_cidr(cidr: &Cidr) -> String {
    let full = if cidr.addr.is_ipv4() { 32 } else { 128 };
    if cidr.prefix == full {
        cidr.addr.to_string()
    } else {
        format!("{}/{}", cidr.addr, cidr.prefix)
    }
}

/// Renders a compiled ruleset as nftables input for `nft -f -`.
///
/// The output is deterministic: sets are sorted, so the same routing table
/// always produces byte-identical input.
///
/// A set is emitted only when at least one rule references it. A rule that
/// constrains a single dimension (only addresses, or only ports) references
/// the set directly, which keeps the ruleset compact. A rule that constrains
/// several dimensions at once is expanded into one statement per combination,
/// because referencing two sets in one statement would union them instead of
/// intersecting them.
#[must_use]
pub fn render_ruleset(ruleset: &CompiledRuleset) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "table inet {NFT_TABLE} {{");

    let any_address_set = ruleset.rules.iter().any(uses_address_set);
    let any_port_set = ruleset.rules.iter().any(uses_port_set);
    let inverted = ruleset.is_inverted();

    if any_address_set {
        let addresses: BTreeSet<String> = ruleset
            .rules
            .iter()
            .filter(|r| uses_address_set(r))
            .flat_map(|r| r.dest_v4.iter().map(render_cidr))
            .collect();
        let _ = writeln!(out, "\tset {SET_TUNNEL_V4} {{");
        let _ = writeln!(out, "\t\ttype ipv4_addr");
        let _ = writeln!(out, "\t\tflags interval");
        let _ = writeln!(out, "\t\telements = {{ {} }}", join(&addresses));
        let _ = writeln!(out, "\t}}");
    }

    if inverted {
        let exclusions: BTreeSet<String> = ruleset
            .direct_exclusions()
            .iter()
            .map(render_cidr)
            .collect();
        let _ = writeln!(out, "\tset {SET_DIRECT_V4} {{");
        let _ = writeln!(out, "\t\ttype ipv4_addr");
        let _ = writeln!(out, "\t\tflags interval");
        let _ = writeln!(out, "\t\telements = {{ {} }}", join(&exclusions));
        let _ = writeln!(out, "\t}}");
    }

    if any_port_set {
        let ports: BTreeSet<String> = ruleset
            .rules
            .iter()
            .filter(|r| uses_port_set(r))
            .flat_map(|r| r.dest_ports.iter().map(|(s, e)| render_port_range(*s, *e)))
            .collect();
        let _ = writeln!(out, "\tset {SET_TUNNEL_PORTS} {{");
        let _ = writeln!(out, "\t\ttype inet_service");
        let _ = writeln!(out, "\t\tflags interval");
        let _ = writeln!(out, "\t\telements = {{ {} }}", join(&ports));
        let _ = writeln!(out, "\t}}");
    }

    let _ = writeln!(out, "\tchain {CHAIN_MARK} {{");
    let _ = writeln!(
        out,
        "\t\ttype route hook output priority mangle; policy accept;"
    );

    // No port-based DNS exemption is emitted here. Exempting ports 53/853
    // would send a lookup to a foreign resolver directly, in the clear, which
    // is exactly what the inversion is meant to prevent. A resolver inside the
    // exclusion set (loopback, link-local, or a Russian address carried by
    // `geoip:ru`) is already direct, and the relay address is excluded
    // separately, so the general `ip daddr` rule below covers every case the
    // port exemption used to.
    if inverted {
        let _ = writeln!(
            out,
            "\t\tip daddr != @{SET_DIRECT_V4} meta mark set {WDTT_FWMARK:#x}"
        );
    } else {
        for rule in &ruleset.rules {
            for line in render_mark_rule(rule) {
                let _ = writeln!(out, "\t\t{line}");
            }
        }
    }

    let _ = writeln!(out, "\t}}");
    let _ = writeln!(out, "}}");
    out
}

/// Renders the block rules into their own table.
///
/// The table has a single `output` chain that drops every packet matching a
/// `block` rule and accepts everything else, so it never affects traffic the
/// user did not explicitly ask to block. Blocked destinations are held in a
/// dedicated address set, mirroring the mark table's layout.
#[must_use]
pub fn render_block_ruleset(ruleset: &CompiledRuleset) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "table inet {NFT_BLOCK_TABLE} {{");

    // The block set is declared unconditionally so `block_v4` always exists
    // when at least one rule references it, even if a rule is expanded inline.
    let addresses: BTreeSet<String> = ruleset
        .block_rules
        .iter()
        .flat_map(|r| r.dest_v4.iter().map(render_cidr))
        .collect();
    if !addresses.is_empty() {
        let _ = writeln!(out, "\tset {SET_BLOCK_V4} {{");
        let _ = writeln!(out, "\t\ttype ipv4_addr");
        let _ = writeln!(out, "\t\tflags interval");
        let _ = writeln!(out, "\t\telements = {{ {} }}", join(&addresses));
        let _ = writeln!(out, "\t}}");
    }

    let _ = writeln!(out, "\tchain {CHAIN_BLOCK} {{");
    let _ = writeln!(
        out,
        "\t\ttype filter hook output priority {BLOCK_PRIORITY}; policy accept;"
    );

    for rule in &ruleset.block_rules {
        for line in render_block_rule(rule) {
            let _ = writeln!(out, "\t\t{line}");
        }
    }

    let _ = writeln!(out, "\t}}");
    let _ = writeln!(out, "}}");
    out
}

/// Renders one block rule as one or more `drop` statements.
fn render_block_rule(rule: &MarkRule) -> Vec<String> {
    if uses_address_set(rule) {
        return vec![format!("ip daddr @{SET_BLOCK_V4} counter drop")];
    }
    render_rule_with(rule, "counter drop")
}

/// Returns true when a rule constrains addresses and nothing else, so it can
/// reference the address set directly.
fn uses_address_set(rule: &MarkRule) -> bool {
    !rule.dest_v4.is_empty() && rule.dest_ports.is_empty() && rule.uids.is_empty()
}

/// Returns true when a rule constrains ports and nothing else, so it can
/// reference the port set directly.
fn uses_port_set(rule: &MarkRule) -> bool {
    !rule.dest_ports.is_empty() && rule.dest_v4.is_empty() && rule.uids.is_empty()
}

fn join(items: &BTreeSet<String>) -> String {
    items.iter().cloned().collect::<Vec<_>>().join(", ")
}

fn render_port_range(start: u16, end: u16) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

/// Renders one mark rule as one or more nftables statements.
///
/// A rule that constrains a single dimension references the corresponding set.
/// A rule that constrains several dimensions is expanded into one statement
/// per combination, because nftables has no inline set syntax and referencing
/// two sets in one statement would union rather than intersect them.
fn render_mark_rule(rule: &MarkRule) -> Vec<String> {
    render_rule_with(rule, &format!("meta mark set {WDTT_FWMARK:#x}"))
}

/// Renders one rule, terminating each statement with `terminal`.
///
/// Shared by the mark rules (which set the routing mark) and the block rules
/// (which drop), so both expand multi-dimension rules identically.
fn render_rule_with(rule: &MarkRule, terminal: &str) -> Vec<String> {
    let mark = terminal;

    if uses_address_set(rule) {
        return vec![format!("ip daddr @{SET_TUNNEL_V4} {mark}")];
    }
    if uses_port_set(rule) {
        return render_port_statements(rule, &format!("th dport @{SET_TUNNEL_PORTS}"), mark);
    }

    let mut statements = Vec::new();

    let dests: Vec<Option<String>> = if rule.dest_v4.is_empty() {
        vec![None]
    } else {
        rule.dest_v4
            .iter()
            .map(|c| Some(format!("ip daddr {}", render_cidr(c))))
            .collect()
    };
    let ports: Vec<Option<String>> = if rule.dest_ports.is_empty() {
        vec![None]
    } else {
        rule.dest_ports
            .iter()
            .map(|(s, e)| Some(format!("th dport {}", render_port_range(*s, *e))))
            .collect()
    };
    let uids: Vec<Option<String>> = if rule.uids.is_empty() {
        vec![None]
    } else {
        rule.uids
            .iter()
            .map(|u| Some(format!("meta skuid {u}")))
            .collect()
    };

    for dest in &dests {
        for port in &ports {
            for uid in &uids {
                let mut parts: Vec<String> = Vec::new();
                if let Some(dest) = dest {
                    parts.push(dest.clone());
                }
                if let Some(uid) = uid {
                    parts.push(uid.clone());
                }
                if let Some(port) = port {
                    if rule.tcp && rule.udp {
                        parts.push(port.clone());
                    } else if rule.tcp {
                        parts.push("meta l4proto tcp".to_owned());
                        parts.push(port.clone());
                    } else if rule.udp {
                        parts.push("meta l4proto udp".to_owned());
                        parts.push(port.clone());
                    } else {
                        continue;
                    }
                }
                if parts.is_empty() {
                    continue;
                }
                statements.push(format!("{} {mark}", parts.join(" ")));
            }
        }
    }

    statements
}

/// Renders a port-only rule, expanding the protocol when it is restricted.
fn render_port_statements(rule: &MarkRule, port_clause: &str, mark: &str) -> Vec<String> {
    match (rule.tcp, rule.udp) {
        (true, true) => vec![format!("{port_clause} {mark}")],
        (true, false) => vec![format!("meta l4proto tcp {port_clause} {mark}")],
        (false, true) => vec![format!("meta l4proto udp {port_clause} {mark}")],
        (false, false) => Vec::new(),
    }
}

/// Applies a ruleset by piping it to `nft -f -`.
///
/// # Errors
///
/// Returns [`NftError::Spawn`] when `nft` cannot be executed and
/// [`NftError::Apply`] when it exits non-zero, with its stderr attached.
pub async fn apply_ruleset(ruleset: &CompiledRuleset) -> Result<(), NftError> {
    let script = render_ruleset(ruleset);
    run_nft(&script).await
}

/// Applies the block rules by piping them to `nft -f -`.
///
/// Any previous block table is removed first: a leftover table would make the
/// create fail, and a stale one is worse than none.
///
/// # Errors
///
/// Returns [`NftError::Spawn`] when `nft` cannot be executed and
/// [`NftError::Apply`] when it exits non-zero, with its stderr attached.
pub async fn apply_block_ruleset(ruleset: &CompiledRuleset) -> Result<(), NftError> {
    let _ = teardown_block().await;
    let script = render_block_ruleset(ruleset);
    run_nft(&script).await
}

/// Removes the block table, ignoring its absence.
///
/// # Errors
///
/// Returns [`NftError::Spawn`] when `nft` cannot be executed. A missing table
/// is not an error.
pub async fn teardown_block() -> Result<(), NftError> {
    let script =
        format!("table inet {NFT_BLOCK_TABLE} {{}}\ndelete table inet {NFT_BLOCK_TABLE}\n");
    match run_nft(&script).await {
        Ok(()) => Ok(()),
        Err(NftError::Apply(message)) if message.contains("No such file") => Ok(()),
        Err(other) => Err(other),
    }
}

/// Removes the table owned by this program, ignoring its absence.
///
/// # Errors
///
/// Returns [`NftError::Spawn`] when `nft` cannot be executed. A missing table
/// is not an error.
pub async fn teardown() -> Result<(), NftError> {
    let script = format!("table inet {NFT_TABLE} {{}}\ndelete table inet {NFT_TABLE}\n");
    match run_nft(&script).await {
        Ok(()) => Ok(()),
        Err(NftError::Apply(message)) if message.contains("No such file") => Ok(()),
        Err(other) => Err(other),
    }
}

async fn run_nft(script: &str) -> Result<(), NftError> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await?;
        drop(stdin);
    }

    let output = child.wait_with_output().await?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(NftError::Apply(stderr.trim().to_owned()))
}

/// Returns the criteria of a rule that nftables cannot express.
///
/// Used by callers to decide whether a rule needs domain resolution before it
/// can be projected.
#[must_use]
pub fn needs_resolution(rule: &CompiledRule) -> bool {
    !rule.matcher.domain.is_empty()
}

/// Returns true when the rule selects the tunnel.
#[must_use]
pub fn is_tunnelled(rule: &CompiledRule) -> bool {
    matches!(rule.outbound, Outbound::Proxy)
}

/// Formats a [`PortSpec`] for diagnostics.
#[must_use]
pub fn describe_ports(spec: &PortSpec) -> String {
    if spec.is_empty() {
        return "any".to_owned();
    }
    spec.0
        .iter()
        .map(|r| render_port_range(r.start, r.end))
        .collect::<Vec<_>>()
        .join(",")
}

/// Formats a [`NetworkSpec`] for diagnostics.
#[must_use]
pub fn describe_network(spec: &NetworkSpec) -> String {
    match (spec.matches_tcp(), spec.matches_udp()) {
        (true, true) => "tcp,udp".to_owned(),
        (true, false) => "tcp".to_owned(),
        (false, true) => "udp".to_owned(),
        (false, false) => "none".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingTable;
    use crate::routing::config::{PortRange, Routing};

    fn table_from_json(json: &str) -> RoutingTable {
        let routing: Routing = serde_json::from_str(json).expect("routing parses");
        let geo = crate::geo::GeoData::default();
        RoutingTable::compile(&routing, &geo).expect("routing compiles")
    }

    #[test]
    fn projects_ip_rule_to_address_set() {
        let table =
            table_from_json(r#"{"rules":[{"ip":["1.1.1.0/24","8.8.8.8"],"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].dest_v4.len(), 2);
        assert!(ruleset.rules[0].tcp);
        assert!(ruleset.rules[0].udp);
    }

    #[test]
    fn preserves_prefix_length() {
        let table = table_from_json(r#"{"rules":[{"ip":["1.1.1.0/24"],"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let cidr = ruleset.rules[0].dest_v4[0];
        assert_eq!(cidr.prefix, 24);
        assert_eq!(render_cidr(&cidr), "1.1.1.0/24");
    }

    #[test]
    fn host_route_omits_prefix() {
        let cidr = Cidr {
            addr: "8.8.8.8".parse().unwrap(),
            prefix: 32,
        };
        assert_eq!(render_cidr(&cidr), "8.8.8.8");
    }

    #[test]
    fn ipv6_cidrs_are_dropped_from_the_ipv4_set() {
        // A `geoip:` category carries IPv6 ranges alongside IPv4 ones. The
        // generated set is `type ipv4_addr`, so an IPv6 element makes nft
        // reject the whole set with "Address family for hostname not
        // supported". Only IPv4 may reach the set.
        let table = table_from_json(
            r#"{"rules":[{"ip":["1.1.1.0/24","2001:db8::/32","8.8.8.8"],"outboundTag":"proxy"}]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let rendered: Vec<String> = ruleset.rules[0].dest_v4.iter().map(render_cidr).collect();
        assert_eq!(rendered, vec!["1.1.1.0/24", "8.8.8.8"]);

        let script = render_ruleset(&ruleset);
        assert!(
            !script.contains("2001:db8"),
            "IPv6 leaked into the set:\n{script}"
        );
    }

    #[test]
    fn resolved_ipv6_addresses_are_dropped_too() {
        let table =
            table_from_json(r#"{"rules":[{"domain":["full:example.com"],"outboundTag":"proxy"}]}"#);
        let mut resolved = std::collections::HashMap::new();
        resolved.insert(
            0usize,
            vec![
                "93.184.216.34".parse().unwrap(),
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
            ],
        );
        let ruleset = compile_ruleset(&table, &resolved);
        let rendered: Vec<String> = ruleset.rules[0].dest_v4.iter().map(render_cidr).collect();
        assert_eq!(rendered, vec!["93.184.216.34"]);
    }

    #[test]
    fn block_rules_become_drop_rules() {
        let table = table_from_json(
            r#"{"rules":[
                {"ip":["1.1.1.1"],"outboundTag":"direct"},
                {"ip":["2.2.2.2"],"outboundTag":"block"},
                {"ip":["3.3.3.3"],"outboundTag":"proxy"}
            ]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        // Direct rules still vanish, but block is now projected separately.
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].dest_v4.len(), 1);
        assert!(ruleset.has_block_rules());
        assert_eq!(ruleset.block_rules.len(), 1);
        assert_eq!(ruleset.block_rules[0].dest_v4.len(), 1);
    }

    #[test]
    fn block_rules_render_into_a_separate_drop_table() {
        let table = table_from_json(r#"{"rules":[{"ip":["2.2.2.2"],"outboundTag":"block"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());

        let block = render_block_ruleset(&ruleset);
        assert!(block.contains("table inet wdtt_block {"));
        assert!(block.contains("set block_v4 {"));
        assert!(block.contains("chain block_out {"));
        assert!(block.contains("counter drop"));
        assert!(!block.contains("iptables"));

        // The mark ruleset must not carry the block table.
        let mark = render_ruleset(&ruleset);
        assert!(!mark.contains("wdtt_block"));
        assert!(!mark.contains("counter drop"));
    }

    #[test]
    fn direct_rules_build_exclusion_set() {
        let table = table_from_json(
            r#"{"rules":[
                {"ip":["1.1.1.1"],"outboundTag":"direct"},
                {"ip":["2.2.2.2"],"outboundTag":"proxy"}
            ]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        assert!(ruleset.is_inverted());
        assert_eq!(ruleset.direct_rules.len(), 1);
        let exclusions: Vec<String> = ruleset
            .direct_exclusions()
            .iter()
            .map(render_cidr)
            .collect();
        assert_eq!(exclusions, vec!["1.1.1.1"]);
    }

    #[test]
    fn inversion_marks_everything_else() {
        let table = table_from_json(r#"{"rules":[{"ip":["1.1.1.1"],"outboundTag":"direct"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let script = render_ruleset(&ruleset);
        // The exclusion set is emitted and referenced with a negation.
        assert!(script.contains("set direct_v4 {"));
        assert!(script.contains("ip daddr != @direct_v4 meta mark set 0x77647400"));
        // In inverted mode the positive address set is not referenced by a rule.
        assert!(!script.contains("ip daddr @tunnel_v4 meta mark"));
    }

    #[test]
    fn non_inverted_ruleset_still_marks_the_positive_set() {
        let table = table_from_json(r#"{"rules":[{"ip":["1.1.1.1"],"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        assert!(!ruleset.is_inverted());
        let script = render_ruleset(&ruleset);
        assert!(script.contains("ip daddr @tunnel_v4 meta mark set 0x77647400"));
        assert!(!script.contains("direct_v4"));
    }

    #[test]
    fn dns_ports_are_not_exempted_in_inverted_mode() {
        let table = table_from_json(r#"{"rules":[{"ip":["1.1.1.1"],"outboundTag":"direct"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let script = render_ruleset(&ruleset);
        // A blanket port exemption would leak a lookup to a foreign resolver
        // in the clear; a resolver that must stay direct is either loopback /
        // link-local (already in the infra set) or carried by the white list.
        assert!(!script.contains("th dport 53"));
        assert!(!script.contains("th dport 853"));
        assert!(script.contains("ip daddr != @direct_v4 meta mark set 0x77647400"));
    }

    #[test]
    fn overlapping_exclusions_are_coalesced() {
        // `geoip:ru`-style ranges overlap the infrastructure ranges and the
        // relay: `10.99.99.0/24` sits inside `10.0.0.0/8`, and both were seeded
        // alongside the white list. nft rejects such a set with "conflicting
        // intervals specified", so the merge has to remove the overlap.
        let table = table_from_json(
            r#"{"rules":[
                {"ip":["10.99.99.0/24","10.0.0.0/8","8.8.8.8"],"outboundTag":"direct"}
            ]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let exclusions = ruleset.direct_exclusions();
        let rendered: Vec<String> = exclusions.iter().map(render_cidr).collect();
        // The subnet collapses into the enclosing /8; only the /8 and the
        // unrelated host remain.
        assert_eq!(rendered, vec!["8.8.8.8", "10.0.0.0/8"]);

        // And the rendered set is non-overlapping, which is what nft requires.
        let mut prev_end: Option<u32> = None;
        for cidr in &exclusions {
            let IpAddr::V4(addr) = cidr.addr else {
                continue;
            };
            let start = u32::from(addr);
            let end = if cidr.prefix == 0 {
                u32::MAX
            } else {
                start
                    | (if cidr.prefix == 0 {
                        u32::MAX
                    } else {
                        !(u32::MAX << (32 - cidr.prefix))
                    })
            };
            if let Some(prev) = prev_end {
                assert!(start > prev, "ranges overlap: {rendered:?}");
            }
            prev_end = Some(end);
        }
    }

    #[test]
    fn adjacent_exclusions_are_merged() {
        // Two halves of a /24 must become the /24, not two /25 elements.
        let table = table_from_json(
            r#"{"rules":[
                {"ip":["192.168.1.0/25","192.168.1.128/25"],"outboundTag":"direct"}
            ]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let rendered: Vec<String> = ruleset
            .direct_exclusions()
            .iter()
            .map(render_cidr)
            .collect();
        assert_eq!(rendered, vec!["192.168.1.0/24"]);
    }

    #[test]
    fn non_power_of_two_exclusions_are_decomposed() {
        // Two adjacent CIDRs whose union spans 24576 addresses form a range
        // that no single CIDR denotes. Emitting the shortest covering CIDR
        // (5.8.0.0/17) would overlap the next element, and nft rejects an
        // interval set with "conflicting intervals specified". The range must
        // instead be split into exact blocks.
        let table = table_from_json(
            r#"{"rules":[
                {"ip":["5.8.0.0/18","5.8.64.0/19"],"outboundTag":"direct"}
            ]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let rendered: Vec<String> = ruleset
            .direct_exclusions()
            .iter()
            .map(render_cidr)
            .collect();
        assert_eq!(rendered, vec!["5.8.0.0/18", "5.8.64.0/19"]);
    }

    #[test]
    fn exclusions_never_overlap() {
        // The property nft enforces: in an interval set every element must
        // start strictly after the previous one's last address. The exclusion
        // set mixes a white-list category with infrastructure ranges, so
        // overlaps are the norm before coalescing.
        let table = table_from_json(
            r#"{"rules":[
                {"ip":["10.99.99.0/24","10.0.0.0/8","5.8.0.0/18","5.8.64.0/19","8.8.8.8"],
                 "outboundTag":"direct"}
            ]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let exclusions = ruleset.direct_exclusions();
        for pair in exclusions.windows(2) {
            let (left, right) = (&pair[0], &pair[1]);
            let IpAddr::V4(left_addr) = left.addr else {
                panic!("IPv6 element survived coalescing");
            };
            let IpAddr::V4(right_addr) = right.addr else {
                panic!("IPv6 element survived coalescing");
            };
            let left_end = u32::from(left_addr)
                | if left.prefix == 0 {
                    u32::MAX
                } else {
                    !(u32::MAX << (32 - left.prefix))
                };
            assert!(
                u32::from(right_addr) > left_end,
                "{right:?} overlaps {left:?}"
            );
        }
    }

    #[test]
    fn ipv6_exclusions_are_dropped() {
        // The rendered set is `type ipv4_addr`; an IPv6 element would make nft
        // reject the whole table.
        let table = table_from_json(
            r#"{"rules":[
                {"ip":["2001:db8::/32","8.8.8.8"],"outboundTag":"direct"}
            ]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let rendered: Vec<String> = ruleset
            .direct_exclusions()
            .iter()
            .map(render_cidr)
            .collect();
        assert_eq!(rendered, vec!["8.8.8.8"]);
    }

    #[test]
    fn block_rule_is_not_marked_as_tunnelled() {
        let table = table_from_json(r#"{"rules":[{"ip":["2.2.2.2"],"outboundTag":"block"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        // A blocked rule never enters the mark set, so it cannot be tunnelled.
        assert!(ruleset.is_empty());
        assert!(ruleset.rules.is_empty());
        assert_eq!(ruleset.block_rules[0].dest_v4.len(), 1);
    }

    #[test]
    fn unresolved_domain_rule_is_skipped_and_reported() {
        let table =
            table_from_json(r#"{"rules":[{"domain":["example.com"],"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        assert!(ruleset.is_empty());
        assert_eq!(ruleset.approximations.len(), 1);
        assert_eq!(ruleset.approximations[0].index, 0);
    }

    #[test]
    fn resolved_domain_rule_contributes_addresses() {
        let table =
            table_from_json(r#"{"rules":[{"domain":["example.com"],"outboundTag":"proxy"}]}"#);
        let mut resolved = std::collections::HashMap::new();
        resolved.insert(0usize, vec!["93.184.216.34".parse().unwrap()]);
        let ruleset = compile_ruleset(&table, &resolved);
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].dest_v4.len(), 1);
        assert!(ruleset.approximations.is_empty());
    }

    #[test]
    fn domain_and_ip_rule_is_flagged_as_approximation() {
        let table = table_from_json(
            r#"{"rules":[{"domain":["example.com"],"ip":["1.1.1.1"],"outboundTag":"proxy"}]}"#,
        );
        let mut resolved = std::collections::HashMap::new();
        resolved.insert(0usize, vec!["93.184.216.34".parse().unwrap()]);
        let ruleset = compile_ruleset(&table, &resolved);
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].dest_v4.len(), 2);
        assert_eq!(ruleset.approximations.len(), 1);
        assert!(ruleset.approximations[0].detail.contains("unioned"));
    }

    #[test]
    fn user_rule_projects_to_skuid() {
        let table = table_from_json(r#"{"rules":[{"user":["1000"],"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        assert_eq!(ruleset.rules[0].uids, vec![1000]);
    }

    #[test]
    fn port_and_network_project_to_protocol_and_dport() {
        let table = table_from_json(
            r#"{"rules":[{"port":"443,8000-8100","network":"tcp","outboundTag":"proxy"}]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let rule = &ruleset.rules[0];
        assert_eq!(rule.dest_ports, vec![(443, 443), (8000, 8100)]);
        assert!(rule.tcp);
        assert!(!rule.udp);
    }

    #[test]
    fn catch_all_rule_is_flagged() {
        let table = table_from_json(r#"{"rules":[{"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        assert!(ruleset.rules[0].is_catch_all());
        assert_eq!(ruleset.approximations.len(), 1);
    }

    #[test]
    fn renders_table_with_sets_and_chain() {
        let table = table_from_json(r#"{"rules":[{"ip":["1.1.1.0/24"],"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let script = render_ruleset(&ruleset);
        assert!(script.contains("table inet wdtt {"));
        assert!(script.contains("set tunnel_v4 {"));
        assert!(script.contains("type ipv4_addr"));
        assert!(script.contains("flags interval"));
        assert!(script.contains("1.1.1.0/24"));
        assert!(script.contains("chain mark_out {"));
        assert!(script.contains("type route hook output priority mangle; policy accept;"));
        assert!(script.contains("ip daddr @tunnel_v4 meta mark set 0x77647400"));
    }

    #[test]
    fn multi_dimension_rule_is_expanded_not_unioned() {
        let table = table_from_json(
            r#"{"rules":[{"ip":["1.1.1.0/24"],"port":"443","network":"tcp","outboundTag":"proxy"}]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let script = render_ruleset(&ruleset);
        assert!(script.contains("ip daddr 1.1.1.0/24 meta l4proto tcp th dport 443 meta mark set"));
        assert!(!script.contains("set tunnel_v4"));
        assert!(!script.contains("set tunnel_ports"));
    }

    #[test]
    fn port_only_rule_references_port_set() {
        let table = table_from_json(
            r#"{"rules":[{"port":"443,8000-8100","network":"tcp","outboundTag":"proxy"}]}"#,
        );
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let script = render_ruleset(&ruleset);
        assert!(script.contains("set tunnel_ports {"));
        assert!(script.contains("elements = { 443, 8000-8100 }"));
        assert!(script.contains("meta l4proto tcp th dport @tunnel_ports meta mark set"));
    }

    #[test]
    fn unused_sets_are_not_emitted() {
        let table = table_from_json(r#"{"rules":[{"user":["1000"],"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        let script = render_ruleset(&ruleset);
        assert!(!script.contains("set tunnel_v4"));
        assert!(!script.contains("set tunnel_ports"));
        assert!(script.contains("meta skuid 1000 meta mark set"));
    }

    #[test]
    fn render_is_deterministic() {
        let table =
            table_from_json(r#"{"rules":[{"ip":["8.8.8.8","1.1.1.1"],"outboundTag":"proxy"}]}"#);
        let ruleset = compile_ruleset(&table, &std::collections::HashMap::new());
        assert_eq!(render_ruleset(&ruleset), render_ruleset(&ruleset));
    }

    #[test]
    fn renders_port_range() {
        assert_eq!(render_port_range(443, 443), "443");
        assert_eq!(render_port_range(8000, 8100), "8000-8100");
    }

    #[test]
    fn describe_helpers_report_expected_text() {
        let spec = PortSpec(vec![PortRange { start: 80, end: 80 }]);
        assert_eq!(describe_ports(&spec), "80");
        assert_eq!(describe_ports(&PortSpec::default()), "any");
        assert_eq!(describe_network(&NetworkSpec::default()), "tcp,udp");
    }

    #[test]
    fn needs_resolution_only_for_domain_rules() {
        let table = table_from_json(
            r#"{"rules":[
                {"domain":["example.com"],"outboundTag":"proxy"},
                {"ip":["1.1.1.1"],"outboundTag":"proxy"}
            ]}"#,
        );
        assert!(needs_resolution(&table.rules()[0]));
        assert!(!needs_resolution(&table.rules()[1]));
    }

    #[test]
    fn is_tunnelled_matches_proxy_only() {
        let table = table_from_json(
            r#"{"rules":[
                {"ip":["1.1.1.1"],"outboundTag":"proxy"},
                {"ip":["2.2.2.2"],"outboundTag":"direct"}
            ]}"#,
        );
        assert!(is_tunnelled(&table.rules()[0]));
        assert!(!is_tunnelled(&table.rules()[1]));
    }
}
