//! Kill-switch: stop marked traffic from escaping the tunnel.
//!
//! The routing rules in [`crate::nft`] mark the packets that should travel
//! through the tunnel, and the policy rule in [`crate::netlink`] sends marked
//! packets to the tunnel's routing table. That chain has one failure mode worth
//! guarding: a marked packet that does *not* end up on the tunnel interface.
//! It happens when the tunnel route is missing, when the interface is down, or
//! when a more specific route wins — and the packet then leaves in the clear
//! while the user believes it is tunnelled.
//!
//! This module closes exactly that gap, and nothing else. A packet carrying
//! [`WDTT_FWMARK`] that leaves by any interface other than the tunnel is
//! dropped. Unmarked traffic is left completely alone.
//!
//! # Why the switch is deliberately narrow
//!
//! The obvious stronger design — drop everything unmarked — cannot coexist with
//! another tunnel on the same host. A packet bound for a second tunnel's
//! endpoint is unmarked by our rules, so a blanket drop would kill that tunnel
//! along with the traffic it carries. Since the host is expected to keep running
//! whatever else it already runs, the narrow rule is the one that can be
//! installed without breaking anything that was working.
//!
//! The trade-off is explicit: this catches leaks of traffic that *was* selected
//! for the tunnel, and does not catch traffic that a routing rule failed to
//! select in the first place. That second case is a configuration error, and it
//! is reported by [`crate::nft::CompiledRuleset::approximations`] rather than
//! silently blocked here.
//!
//! # Relationship to the firewall already on the machine
//!
//! The rules live in their own `inet` table with their own name. Nothing here
//! reads, flushes or edits `ip filter`, `ip6 filter` or any other table: a
//! kill-switch that rewrote the host firewall would be indistinguishable from a
//! firewall misconfiguration, and the host's existing rules are not ours to
//! touch. The chain runs at a priority *after* the filter hook so the host's own
//! accepts are already applied, and it only ever drops — it never accepts on
//! behalf of another table.

use std::process::Stdio;

use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::netcfg::WDTT_FWMARK;

/// Name of the nftables table owned by the kill-switch.
///
/// Deliberately distinct from every table the host is expected to have, so that
/// teardown can delete exactly this table and nothing else.
pub const KILLSWITCH_TABLE: &str = "wdtt_killswitch";

/// Name of the chain that drops escaping traffic.
pub const CHAIN_KILL: &str = "kill_out";

/// Chain priority, relative to the `filter` hook.
///
/// `filter` is 0, which is where ufw and most host firewalls sit. Running later
/// means their accepts have already been evaluated, so this chain only sees
/// traffic the host was willing to send — it narrows, and never widens, what the
/// host permits.
pub const KILL_PRIORITY: i32 = 10;

/// Errors produced while installing or removing the kill-switch.
#[derive(Debug, thiserror::Error)]
pub enum KillSwitchError {
    /// The `nft` process could not be started.
    #[error("failed to run nft: {0}")]
    Spawn(#[from] std::io::Error),
    /// `nft` ran but rejected the ruleset.
    #[error("nft rejected the ruleset: {0}")]
    Apply(String),
    /// The requested configuration cannot be expressed.
    #[error("unsupported kill-switch configuration: {0}")]
    Unsupported(String),
}

/// What the kill-switch should treat as the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillSwitchConfig {
    /// Interface carrying the tunnel. Marked traffic leaving by it is expected;
    /// marked traffic leaving by anything else is a leak.
    pub tunnel_interface: String,
    /// Whether to also guard IPv6.
    ///
    /// On by default. The tunnel itself is IPv4-only, so a marked IPv6 packet
    /// can only be a leak; the rules cover both families so that a dual-stack
    /// host cannot slip past on the other one.
    pub guard_ipv6: bool,
}

impl KillSwitchConfig {
    /// Builds a configuration for `tunnel_interface`.
    pub fn new(tunnel_interface: impl Into<String>) -> Self {
        Self {
            tunnel_interface: tunnel_interface.into(),
            guard_ipv6: true,
        }
    }

    /// Sets whether IPv6 is guarded.
    pub fn with_ipv6_guard(mut self, guard: bool) -> Self {
        self.guard_ipv6 = guard;
        self
    }
}

/// Renders the nftables ruleset for `config`.
///
/// Split out from [`apply`] so the generated text can be inspected and tested
/// without touching a live firewall.
pub fn render(config: &KillSwitchConfig) -> Result<String, KillSwitchError> {
    if config.tunnel_interface.is_empty() {
        return Err(KillSwitchError::Unsupported(
            "tunnel interface name is empty".to_string(),
        ));
    }
    if config.tunnel_interface.contains(char::is_whitespace) {
        return Err(KillSwitchError::Unsupported(format!(
            "tunnel interface name {:?} contains whitespace",
            config.tunnel_interface
        )));
    }

    let mut out = String::new();
    out.push_str(&format!("table inet {KILLSWITCH_TABLE} {{\n"));
    out.push_str(&format!("\tchain {CHAIN_KILL} {{\n"));
    out.push_str(&format!(
        "\t\ttype filter hook output priority {}; policy accept;\n",
        KILL_PRIORITY
    ));

    // Only marked packets are our business. Everything else belongs to the host
    // and to whatever other tunnels it runs, and is returned to the host's own
    // policy untouched.
    out.push_str(&format!("\t\tmeta mark != {:#x} return\n", WDTT_FWMARK));

    // A marked packet on its way into the tunnel is exactly what we want.
    out.push_str(&format!(
        "\t\toifname \"{}\" accept\n",
        config.tunnel_interface
    ));

    // A marked packet leaving by anything else is a leak. Loopback is exempt
    // because a marked packet to a local service never reaches the network.
    out.push_str("\t\toifname \"lo\" accept\n");
    out.push_str("\t\tcounter drop\n");

    if config.guard_ipv6 {
        // The tunnel carries IPv4 only, so a marked IPv6 packet cannot be
        // legitimate. The rule above already covers it, since it keys on the
        // mark rather than on the family; this arm exists so the intent is
        // visible in the ruleset and so the family can be excluded wholesale if
        // a future tunnel carries IPv6.
        out.push_str("\t\t# IPv6 is covered by the mark test above.\n");
    }

    out.push_str("\t}\n");
    out.push_str("}\n");

    Ok(out)
}

/// Installs the kill-switch.
///
/// Replaces any previous instance: the table is deleted first so that a stale
/// ruleset from a crashed run cannot linger and block traffic the new one means
/// to allow.
pub async fn apply(config: &KillSwitchConfig) -> Result<(), KillSwitchError> {
    let ruleset = render(config)?;
    // A leftover table would make the create fail, and a stale one is worse than
    // none: it reflects a configuration that no longer applies.
    let _ = teardown().await;
    run_nft(&ruleset).await
}

/// Removes the kill-switch.
///
/// Succeeds when the table is already absent, so teardown is safe to call from
/// any path, including one that runs after a failed [`apply`].
pub async fn teardown() -> Result<(), KillSwitchError> {
    let script = format!("delete table inet {KILLSWITCH_TABLE}\n");
    match run_nft(&script).await {
        Ok(()) => Ok(()),
        Err(KillSwitchError::Apply(msg)) if msg.contains("No such file") => Ok(()),
        Err(other) => Err(other),
    }
}

/// Whether the kill-switch table is currently installed.
pub async fn is_active() -> Result<bool, KillSwitchError> {
    let output = Command::new("nft")
        .args(["list", "tables"])
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        return Err(KillSwitchError::Apply(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .any(|line| line.trim() == format!("table inet {KILLSWITCH_TABLE}")))
}

/// Reads the drop counter, for diagnostics.
///
/// Returns `None` when the table is not installed.
pub async fn drop_count() -> Result<Option<u64>, KillSwitchError> {
    let output = Command::new("nft")
        .args(["list", "chain", "inet", KILLSWITCH_TABLE, CHAIN_KILL])
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // The rendered rule ends in `counter drop`, and nft prints the running
    // totals inline: `counter packets 52 bytes 28832 drop`.
    for line in text.lines() {
        let line = line.trim();
        if !line.ends_with("drop") {
            continue;
        }
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "packets"
                && let Some(value) = parts.next()
                && let Ok(count) = value.parse::<u64>()
            {
                return Ok(Some(count));
            }
        }
    }
    Ok(Some(0))
}

async fn run_nft(script: &str) -> Result<(), KillSwitchError> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await?;
        // Dropping the handle closes the pipe so nft sees end of input.
    }

    let output = child.wait_with_output().await?;
    if output.status.success() {
        return Ok(());
    }
    Err(KillSwitchError::Apply(
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> KillSwitchConfig {
        KillSwitchConfig::new("wdtt0")
    }

    #[test]
    fn renders_a_table_with_its_own_name() {
        let text = render(&config()).unwrap();
        assert!(text.contains("table inet wdtt_killswitch {"));
        // The host's own tables must never appear.
        assert!(!text.contains("table ip filter"));
        assert!(!text.contains("table ip6 filter"));
        assert!(!text.contains("zapret"));
    }

    #[test]
    fn unmarked_traffic_is_returned_to_the_host() {
        let text = render(&config()).unwrap();
        assert!(text.contains("meta mark != 0x77647400 return"));
    }

    #[test]
    fn marked_traffic_on_the_tunnel_is_accepted() {
        let text = render(&config()).unwrap();
        assert!(text.contains("oifname \"wdtt0\" accept"));
    }

    #[test]
    fn marked_traffic_elsewhere_is_dropped() {
        let text = render(&config()).unwrap();
        assert!(text.contains("counter drop"));
    }

    #[test]
    fn loopback_is_exempt() {
        let text = render(&config()).unwrap();
        assert!(text.contains("oifname \"lo\" accept"));
    }

    #[test]
    fn never_drops_unmarked_traffic() {
        // The whole point of the narrow design: a second tunnel on the host
        // must keep working, so there is no blanket drop.
        let text = render(&config()).unwrap();
        assert!(!text.contains("meta mark 0 counter drop"));
        assert!(!text.contains("meta mark 0 drop"));
    }

    #[test]
    fn chain_priority_runs_after_the_filter_hook() {
        let text = render(&config()).unwrap();
        assert!(text.contains("type filter hook output priority 10; policy accept;"));
    }

    #[test]
    fn rejects_an_empty_interface_name() {
        let err = render(&KillSwitchConfig::new("")).unwrap_err();
        assert!(matches!(err, KillSwitchError::Unsupported(_)));
    }

    #[test]
    fn rejects_an_interface_name_with_whitespace() {
        let err = render(&KillSwitchConfig::new("wdtt 0")).unwrap_err();
        assert!(matches!(err, KillSwitchError::Unsupported(_)));
    }

    #[test]
    fn render_is_deterministic() {
        let cfg = config();
        assert_eq!(render(&cfg).unwrap(), render(&cfg).unwrap());
    }

    #[test]
    fn ipv6_guard_can_be_disabled() {
        let with = render(&config()).unwrap();
        let without = render(&config().with_ipv6_guard(false)).unwrap();
        assert!(with.contains("IPv6 is covered"));
        assert!(!without.contains("IPv6 is covered"));
    }
}
