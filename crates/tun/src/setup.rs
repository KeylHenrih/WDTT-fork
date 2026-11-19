//! Bring-up and teardown of the host-side tunnel configuration.
//!
//! Stage 3 built the pieces — interface addressing ([`crate::netcfg`]), policy
//! routing ([`crate::netlink`]), rule compilation ([`crate::nft`]), domain
//! resolution ([`crate::resolver`]), DNS ([`crate::dns`]) and the kill-switch
//! ([`crate::killswitch`]). This module is what actually sequences them, and —
//! more importantly — what guarantees they are undone.
//!
//! # Why teardown is the hard part
//!
//! Every step here mutates global host state: addresses, routing tables,
//! routing rules, nftables tables, the system resolver. A client that installs
//! them and then dies leaves the machine in a state its owner did not choose —
//! at worst with no working DNS and a routing rule pointing at an interface
//! that no longer exists. So the configuration is applied in a fixed order and
//! recorded as it goes; [`HostSetup::teardown`] then walks the record backwards.
//! A step that fails during bring-up triggers an immediate rollback of the
//! steps already applied, so a partial failure never leaves a partial config.
//!
//! # Ordering
//!
//! 1. **Interface address** — nothing else can work until the interface has one.
//! 2. **Relay bypass route** — a host route to the TURN relay through the
//!    *physical* gateway. Without it the tunnel's own transport would be routed
//!    into the tunnel, which is a loop that never resolves.
//! 3. **Tunnel route** — `default dev <tun>` inside [`WDTT_ROUTE_TABLE`].
//! 4. **Policy rule** — `fwmark <WDTT_FWMARK> lookup <WDTT_ROUTE_TABLE>`.
//! 5. **Mark rules** — the nftables table that sets the mark on selected
//!    traffic. Installed after the rule so no packet is ever marked before
//!    there is a table for it to be routed into.
//! 6. **DNS** — the forwarder and the system resolver switch.
//! 7. **Kill-switch** — last, so it never blocks a step above it.
//!
//! Teardown runs in exactly the reverse order.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use crate::dns::{DnsServerConfig, ResolverBackend, SystemResolver};
use crate::killswitch::{self, KillSwitchConfig};
use crate::netcfg::{self, RouteSpec, WDTT_FWMARK, WDTT_ROUTE_TABLE, WDTT_RULE_PRIORITY};
use crate::netlink::{self, NlRouteSpec, RuleSpec};
use crate::nft::{self, CompiledRuleset};
use crate::resolver::{DomainResolver, ResolverConfig};
use crate::routing::RoutingTable;
use crate::routing::matcher::Cidr;

/// Errors raised while configuring or restoring the host.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// Interface addressing or routing failed.
    #[error("host network configuration failed: {0}")]
    Network(#[from] crate::TunError),
    /// The nftables ruleset could not be applied.
    #[error("nftables configuration failed: {0}")]
    Nft(#[from] nft::NftError),
    /// The kill-switch could not be applied.
    #[error("kill-switch configuration failed: {0}")]
    KillSwitch(#[from] killswitch::KillSwitchError),
    /// The system resolver could not be switched.
    #[error("resolver configuration failed: {0}")]
    Resolver(#[from] crate::dns::ResolverError),
    /// A required value was missing from the configuration.
    #[error("missing configuration: {0}")]
    Missing(&'static str),
}

/// What the caller wants configured on the host.
#[derive(Debug, Clone)]
pub struct HostSetupConfig {
    /// Tunnel interface name, e.g. `wdtt0`.
    pub tunnel_interface: String,
    /// Address to assign to the tunnel interface.
    pub tunnel_address: Ipv4Addr,
    /// Prefix length for [`Self::tunnel_address`].
    pub tunnel_prefix: u8,
    /// The TURN relay's address, reached through the physical gateway.
    pub relay_address: Ipv4Addr,
    /// Physical interface carrying the relay traffic, e.g. `wlan0`.
    pub physical_interface: String,
    /// Physical gateway address, used for the relay bypass route.
    pub physical_gateway: Option<Ipv4Addr>,
    /// Compiled mark rules. When empty, no nftables table is installed.
    pub ruleset: CompiledRuleset,
    /// Whether to install the policy rule and tunnel route.
    pub policy_routing: bool,
    /// Whether to install the kill-switch.
    pub kill_switch: bool,
    /// Whether to switch the system resolver to the local forwarder.
    pub dns: bool,
    /// Address the DNS forwarder listens on.
    pub dns_listen: std::net::SocketAddr,
    /// Upstream the DNS forwarder queries.
    pub dns_upstream: std::net::SocketAddr,
}

impl HostSetupConfig {
    /// Builds a configuration with policy routing, DNS and the kill-switch all
    /// enabled, which is what a normal client run wants.
    pub fn new(
        tunnel_interface: impl Into<String>,
        tunnel_address: Ipv4Addr,
        relay_address: Ipv4Addr,
        physical_interface: impl Into<String>,
    ) -> Self {
        Self {
            tunnel_interface: tunnel_interface.into(),
            tunnel_address,
            tunnel_prefix: 24,
            relay_address,
            physical_interface: physical_interface.into(),
            physical_gateway: None,
            ruleset: CompiledRuleset::default(),
            policy_routing: true,
            kill_switch: true,
            dns: true,
            dns_listen: DnsServerConfig::default().listen_addr,
            dns_upstream: DnsServerConfig::default().upstream_addr,
        }
    }
}

/// A record of what has been applied, so it can be undone in reverse.
#[derive(Debug, Default)]
struct Applied {
    address: bool,
    relay_route: bool,
    tunnel_route: bool,
    policy_rule: bool,
    mark_table: bool,
    block_table: bool,
    kill_switch: bool,
    resolver: Option<SystemResolver>,
}

/// Owns the host-side configuration for the lifetime of a tunnel.
///
/// Dropping this value does **not** undo anything — teardown is asynchronous
/// and must be awaited. Call [`HostSetup::teardown`] explicitly, or use
/// [`HostSetup::run_until`] which does it for you.
#[derive(Debug)]
pub struct HostSetup {
    config: HostSetupConfig,
    applied: Applied,
}

impl HostSetup {
    /// Creates a setup handle. Nothing is applied until [`Self::apply`] runs.
    pub fn new(config: HostSetupConfig) -> Self {
        Self {
            config,
            applied: Applied::default(),
        }
    }

    /// The configuration this handle was built with.
    pub fn config(&self) -> &HostSetupConfig {
        &self.config
    }

    /// Applies the configuration in order, rolling back on the first failure.
    ///
    /// On error the steps already applied are undone before returning, so the
    /// host is left as it was found.
    pub async fn apply(&mut self) -> Result<(), SetupError> {
        if let Err(err) = self.apply_inner().await {
            self.teardown().await;
            return Err(err);
        }
        Ok(())
    }

    async fn apply_inner(&mut self) -> Result<(), SetupError> {
        let iface = self.config.tunnel_interface.clone();

        // 1. Address on the tunnel interface.
        netcfg::set_addr(&iface, self.config.tunnel_address)?;
        netcfg::set_netmask(&iface, prefix_to_mask(self.config.tunnel_prefix))?;
        netcfg::set_up(&iface)?;
        self.applied.address = true;

        // 2. Relay bypass: the tunnel's own transport must not enter the tunnel.
        let relay = RouteSpec::gateway(
            self.config.relay_address,
            32,
            self.config
                .physical_gateway
                .unwrap_or(self.config.relay_address),
            self.config.physical_interface.clone(),
        );
        netcfg::add_route(&relay)?;
        self.applied.relay_route = true;

        if self.config.policy_routing {
            // 3. Default route inside our own table.
            let tunnel_route = NlRouteSpec {
                dest: "0.0.0.0".parse().expect("valid literal"),
                prefix_len: 0,
                gateway: None,
                oif: netlink::ifindex(&iface)?,
                table: WDTT_ROUTE_TABLE,
            };
            netlink::add_route(&tunnel_route)?;
            self.applied.tunnel_route = true;

            // 4. Policy rule selecting that table for marked packets.
            let rule = RuleSpec::fwmark(WDTT_RULE_PRIORITY, WDTT_FWMARK, WDTT_ROUTE_TABLE);
            netlink::add_rule(&rule)?;
            self.applied.policy_rule = true;
        }

        // 5. Mark rules. Installed after the rule so a marked packet always has
        //    a table to be routed into. In inverted mode the infrastructure
        //    ranges are seeded first so the exclusion set can never tunnel the
        //    relay that carries it.
        let mut ruleset = self.config.ruleset.clone();
        if ruleset.is_inverted() {
            ruleset
                .direct_rules
                .extend(
                    infrastructure_exclusions(&self.config)
                        .into_iter()
                        .map(|cidr| nft::MarkRule {
                            dest_v4: vec![cidr],
                            dest_ports: Vec::new(),
                            tcp: true,
                            udp: true,
                            uids: Vec::new(),
                            source_index: usize::MAX,
                        }),
                );
        }
        if !ruleset.rules.is_empty() || ruleset.is_inverted() {
            nft::apply_ruleset(&ruleset).await?;
            self.applied.mark_table = true;
        }

        // 5b. Block rules. Kept in their own table so a drop decision is never
        //     confused with a routing decision.
        if self.config.ruleset.has_block_rules() {
            nft::apply_block_ruleset(&self.config.ruleset).await?;
            self.applied.block_table = true;
        }

        // 6. DNS.
        if self.config.dns {
            let mut resolver = SystemResolver::detect(&iface, self.config.dns_listen.ip()).await;
            resolver.apply().await?;
            self.applied.resolver = Some(resolver);
        }

        // 7. Kill-switch, last so it cannot block any step above.
        if self.config.kill_switch {
            let ks = KillSwitchConfig::new(&iface);
            killswitch::apply(&ks).await?;
            self.applied.kill_switch = true;
        }

        Ok(())
    }

    /// Undoes everything [`Self::apply`] installed, in reverse order.
    ///
    /// Every step is attempted even if an earlier one fails, so one stuck
    /// component cannot strand the rest. Errors are logged and the first is
    /// returned.
    pub async fn teardown(&mut self) {
        if self.applied.kill_switch {
            if let Err(err) = killswitch::teardown().await {
                tracing::warn!("kill-switch teardown failed: {err}");
            }
            self.applied.kill_switch = false;
        }

        if let Some(mut resolver) = self.applied.resolver.take()
            && let Err(err) = resolver.restore().await
        {
            tracing::warn!("resolver restore failed: {err}");
        }

        if self.applied.block_table {
            if let Err(err) = nft::teardown_block().await {
                tracing::warn!("nftables block teardown failed: {err}");
            }
            self.applied.block_table = false;
        }

        if self.applied.mark_table {
            if let Err(err) = nft::teardown().await {
                tracing::warn!("nftables teardown failed: {err}");
            }
            self.applied.mark_table = false;
        }

        if self.applied.policy_rule {
            let rule = RuleSpec::fwmark(WDTT_RULE_PRIORITY, WDTT_FWMARK, WDTT_ROUTE_TABLE);
            if let Err(err) = netlink::del_rule(&rule) {
                tracing::warn!("policy rule removal failed: {err}");
            }
            self.applied.policy_rule = false;
        }

        if self.applied.tunnel_route {
            let tunnel_route = NlRouteSpec {
                dest: "0.0.0.0".parse().expect("valid literal"),
                prefix_len: 0,
                gateway: None,
                oif: netlink::ifindex(&self.config.tunnel_interface).unwrap_or(0),
                table: WDTT_ROUTE_TABLE,
            };
            if let Err(err) = netlink::del_route(&tunnel_route) {
                tracing::warn!("tunnel route removal failed: {err}");
            }
            self.applied.tunnel_route = false;
        }

        if self.applied.relay_route {
            let relay = RouteSpec::gateway(
                self.config.relay_address,
                32,
                self.config
                    .physical_gateway
                    .unwrap_or(self.config.relay_address),
                self.config.physical_interface.clone(),
            );
            if let Err(err) = netcfg::del_route(&relay) {
                tracing::warn!("relay route removal failed: {err}");
            }
            self.applied.relay_route = false;
        }

        if self.applied.address {
            if let Err(err) =
                netcfg::del_addr(&self.config.tunnel_interface, self.config.tunnel_address)
            {
                tracing::warn!("address removal failed: {err}");
            }
            self.applied.address = false;
        }
    }

    /// Whether anything is currently applied.
    pub fn is_applied(&self) -> bool {
        self.applied.address
            || self.applied.relay_route
            || self.applied.tunnel_route
            || self.applied.policy_rule
            || self.applied.mark_table
            || self.applied.block_table
            || self.applied.kill_switch
            || self.applied.resolver.is_some()
    }
}

/// Converts a prefix length to a dotted-quad netmask.
fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits: u32 = if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits)
}

/// Resolves rule domains and compiles the mark ruleset in one step.
///
/// This is the bridge between the routing table parsed from configuration and
/// the nftables ruleset the host needs. It is separate from [`HostSetup`]
/// because it must run *before* the tunnel is up — the lookups go out over the
/// physical link, not through the tunnel.
pub async fn prepare_ruleset(
    table: &RoutingTable,
    resolver_config: ResolverConfig,
) -> (CompiledRuleset, HashMap<usize, Vec<IpAddr>>) {
    let mut resolver = DomainResolver::new(resolver_config);
    let report = resolver.resolve(table).await;
    let addresses = report.address_map();
    let ruleset = nft::compile_ruleset(table, &addresses);
    (ruleset, addresses)
}

/// Addresses that must never enter the tunnel, whatever the rules say.
///
/// In inverted mode the exclusion set decides what stays outside, so it has to
/// carry the local, link-local, multicast and infrastructure ranges as well as
/// the white list. Without them the tunnel would swallow the relay traffic that
/// carries it, or loop the tunnel's own subnet back into itself.
fn infrastructure_exclusions(config: &HostSetupConfig) -> Vec<Cidr> {
    let mut items: Vec<Cidr> = [
        ("0.0.0.0", 8),
        ("10.0.0.0", 8),
        ("127.0.0.0", 8),
        ("169.254.0.0", 16),
        ("172.16.0.0", 12),
        ("192.168.0.0", 16),
        ("224.0.0.0", 4),
        ("255.255.255.255", 32),
    ]
    .iter()
    .map(|(addr, prefix)| Cidr {
        addr: IpAddr::V4(addr.parse().expect("valid literal")),
        prefix: *prefix,
    })
    .collect();

    items.push(cidr_from_host(config.relay_address));

    let tunnel_prefix = config.tunnel_prefix.min(32);
    let tunnel_network =
        Ipv4Addr::from(u32::from(config.tunnel_address) & u32::from(prefix_to_mask(tunnel_prefix)));
    items.push(Cidr {
        addr: IpAddr::V4(tunnel_network),
        prefix: tunnel_prefix,
    });

    items.sort_by_key(|c| (c.addr, c.prefix));
    items.dedup();
    items
}

/// Builds a host-route CIDR from a single address.
fn cidr_from_host(addr: Ipv4Addr) -> Cidr {
    Cidr {
        addr: IpAddr::V4(addr),
        prefix: 32,
    }
}

/// The default location for the domain-resolution cache.
pub fn default_cache_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("wdtt")
}

/// Which resolver backend is in use, for logging.
pub fn describe_backend(backend: ResolverBackend) -> &'static str {
    match backend {
        ResolverBackend::Resolved => "systemd-resolved",
        ResolverBackend::ResolvConf => "/etc/resolv.conf",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_to_mask_covers_edges() {
        assert_eq!(prefix_to_mask(0), "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(
            prefix_to_mask(24),
            "255.255.255.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            prefix_to_mask(32),
            "255.255.255.255".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            prefix_to_mask(33),
            "255.255.255.255".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn new_config_enables_everything() {
        let cfg = HostSetupConfig::new(
            "wdtt0",
            "10.99.99.2".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            "wlan0",
        );
        assert!(cfg.policy_routing);
        assert!(cfg.kill_switch);
        assert!(cfg.dns);
        assert_eq!(cfg.tunnel_prefix, 24);
    }

    #[test]
    fn fresh_setup_is_not_applied() {
        let cfg = HostSetupConfig::new(
            "wdtt0",
            "10.99.99.2".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            "wlan0",
        );
        let setup = HostSetup::new(cfg);
        assert!(!setup.is_applied());
    }

    #[tokio::test]
    async fn teardown_without_apply_is_a_noop() {
        let cfg = HostSetupConfig::new(
            "wdtt0",
            "10.99.99.2".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            "wlan0",
        );
        let mut setup = HostSetup::new(cfg);
        setup.teardown().await;
        assert!(!setup.is_applied());
    }

    #[test]
    fn infrastructure_exclusions_cover_local_ranges_and_relay() {
        // A public relay address, deliberately outside the local ranges.
        let cfg = HostSetupConfig::new(
            "wdtt0",
            "10.99.99.2".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
            "wlan0",
        );
        let exclusions = infrastructure_exclusions(&cfg);
        let rendered: Vec<String> = exclusions
            .iter()
            .map(|c| format!("{}/{}", c.addr, c.prefix))
            .collect();

        // The relay must never be tunnelled, or the tunnel carries itself.
        assert!(rendered.iter().any(|c| c == "192.0.2.10/32"));
        // The tunnel subnet must not be routed back into the tunnel.
        assert!(rendered.iter().any(|c| c == "10.99.99.0/24"));
        // Private and link-local ranges stay outside.
        assert!(rendered.iter().any(|c| c == "192.168.0.0/16"));
        assert!(rendered.iter().any(|c| c == "10.0.0.0/8"));
        assert!(rendered.iter().any(|c| c == "127.0.0.0/8"));
        assert!(rendered.iter().any(|c| c == "169.254.0.0/16"));
        // Multicast and broadcast.
        assert!(rendered.iter().any(|c| c == "224.0.0.0/4"));
    }

    #[test]
    fn default_cache_dir_ends_with_wdtt() {
        let dir = default_cache_dir();
        assert_eq!(dir.file_name().and_then(|s| s.to_str()), Some("wdtt"));
    }

    #[test]
    fn backend_names_are_stable() {
        assert_eq!(
            describe_backend(ResolverBackend::Resolved),
            "systemd-resolved"
        );
        assert_eq!(
            describe_backend(ResolverBackend::ResolvConf),
            "/etc/resolv.conf"
        );
    }
}
