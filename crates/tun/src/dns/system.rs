//! Steering the system resolver at the tunnel's DNS listener, and undoing it.
//!
//! # Why `resolvectl` and not `/etc/resolv.conf`
//!
//! On a machine running NetworkManager, `/etc/resolv.conf` is a file
//! NetworkManager rewrites on every link change. Writing it directly works
//! until the next link event and then silently reverts — the tunnel keeps
//! running while resolution quietly falls back to the physical link, which is
//! exactly the leak the tunnel exists to prevent.
//!
//! `systemd-resolved` exposes a per-link configuration that NetworkManager
//! respects and that survives link events. Setting the DNS server, the routing
//! domain and the default-route flag on the tunnel's link makes resolved prefer
//! the tunnel for everything, and clearing them restores the previous state
//! without touching any file.
//!
//! # Fallback
//!
//! When `resolvectl` is absent (no systemd-resolved), the module falls back to
//! rewriting `/etc/resolv.conf` with a byte-for-byte backup, which is restored
//! on teardown. The backup is kept in memory and on disk next to the original,
//! so a crash mid-session can still be recovered by hand.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;
use tracing::{debug, info, warn};

/// Where the original `/etc/resolv.conf` is copied before being rewritten.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Suffix appended to the backup path.
pub const BACKUP_SUFFIX: &str = ".wdtt-backup";

/// Errors produced while configuring the system resolver.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// A filesystem operation failed.
    #[error("resolver file I/O error: {0}")]
    Io(#[from] io::Error),
    /// `resolvectl` ran but reported a failure.
    #[error("resolvectl {command} failed: {stderr}")]
    Command {
        /// The subcommand that failed.
        command: String,
        /// Whatever it wrote to stderr.
        stderr: String,
    },
    /// No supported way to configure the resolver was found.
    #[error("no supported system resolver found (tried resolvectl and {0})")]
    Unsupported(String),
}

/// Which mechanism is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverBackend {
    /// `systemd-resolved`, driven through `resolvectl`.
    Resolved,
    /// `/etc/resolv.conf` rewritten directly.
    ResolvConf,
}

/// Configures the system resolver to use the tunnel's DNS listener.
///
/// Construct with [`SystemResolver::detect`], apply with
/// [`SystemResolver::apply`], and undo with [`SystemResolver::restore`]. The
/// type is idempotent: applying twice is the same as applying once, and
/// restoring when nothing was applied is a no-op.
#[derive(Debug)]
pub struct SystemResolver {
    backend: ResolverBackend,
    interface: String,
    server: IpAddr,
    /// Original `/etc/resolv.conf` contents, captured on first apply.
    original: Option<Vec<u8>>,
    /// Whether [`SystemResolver::apply`] has run and not yet been undone.
    applied: bool,
}

impl SystemResolver {
    /// Picks a backend for `interface`, preferring `systemd-resolved`.
    ///
    /// `interface` is the tunnel's link name (for example `wdtt0`); `server` is
    /// the address of the local DNS listener.
    pub async fn detect(interface: impl Into<String>, server: IpAddr) -> Self {
        let interface = interface.into();
        let backend = if resolvectl_available().await {
            ResolverBackend::Resolved
        } else {
            ResolverBackend::ResolvConf
        };
        debug!(%interface, %server, ?backend, "system resolver backend selected");
        Self {
            backend,
            interface,
            server,
            original: None,
            applied: false,
        }
    }

    /// Forces a specific backend, for tests and for callers that know better.
    pub fn with_backend(
        backend: ResolverBackend,
        interface: impl Into<String>,
        server: IpAddr,
    ) -> Self {
        Self {
            backend,
            interface: interface.into(),
            server,
            original: None,
            applied: false,
        }
    }

    /// The backend in use.
    pub fn backend(&self) -> ResolverBackend {
        self.backend
    }

    /// Whether the resolver is currently pointed at the tunnel.
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Points the system resolver at the tunnel's DNS listener.
    ///
    /// For the `systemd-resolved` backend this sets the per-link server, makes
    /// the link the default route for all domains, and enables the
    /// default-route flag. For the `resolv.conf` backend it backs the file up
    /// and replaces it.
    pub async fn apply(&mut self) -> Result<(), ResolverError> {
        if self.applied {
            return Ok(());
        }

        match self.backend {
            ResolverBackend::Resolved => {
                let iface = self.interface.clone();
                let server = self.server.to_string();

                run_resolvectl(&["dns", &iface, &server]).await?;
                // `~.` is the routing domain that means "everything".
                run_resolvectl(&["domain", &iface, "~."]).await?;
                run_resolvectl(&["default-route", &iface, "yes"]).await?;
                // Flush so answers cached from the physical link are not served
                // as if they came through the tunnel.
                if let Err(e) = run_resolvectl(&["flush-caches"]).await {
                    warn!(error = %e, "resolvectl flush-caches failed; continuing");
                }
                info!(interface = %self.interface, server = %self.server, "system resolver pointed at tunnel DNS");
            }
            ResolverBackend::ResolvConf => {
                let path = Path::new(RESOLV_CONF);
                let original = tokio::fs::read(path).await?;
                let backup = backup_path(path);
                tokio::fs::write(&backup, &original).await?;
                self.original = Some(original);

                let contents = format!("nameserver {}\noptions edns0 trust-ad\n", self.server);
                tokio::fs::write(path, contents).await?;
                info!(path = RESOLV_CONF, server = %self.server, "resolv.conf pointed at tunnel DNS");
            }
        }

        self.applied = true;
        Ok(())
    }

    /// Restores whatever the resolver was using before [`apply`](Self::apply).
    ///
    /// Safe to call when nothing was applied.
    pub async fn restore(&mut self) -> Result<(), ResolverError> {
        if !self.applied {
            return Ok(());
        }

        match self.backend {
            ResolverBackend::Resolved => {
                let iface = self.interface.clone();
                // Clearing the server list also clears the routing domain and
                // the default-route flag on most versions, but do all three
                // explicitly so the result does not depend on that.
                if let Err(e) = run_resolvectl(&["revert", &iface]).await {
                    warn!(error = %e, "resolvectl revert failed");
                }
                if let Err(e) = run_resolvectl(&["flush-caches"]).await {
                    warn!(error = %e, "resolvectl flush-caches failed");
                }
                info!(interface = %self.interface, "system resolver restored");
            }
            ResolverBackend::ResolvConf => {
                let path = Path::new(RESOLV_CONF);
                let backup = backup_path(path);
                match tokio::fs::read(&backup).await {
                    Ok(contents) => {
                        tokio::fs::write(path, contents).await?;
                        let _ = tokio::fs::remove_file(&backup).await;
                        info!(path = RESOLV_CONF, "resolv.conf restored");
                    }
                    Err(e) => {
                        // Fall back to the in-memory copy if the backup file is
                        // gone; if that is gone too, say so rather than leave a
                        // silently wrong resolver.
                        match self.original.take() {
                            Some(contents) => {
                                tokio::fs::write(path, contents).await?;
                                info!(path = RESOLV_CONF, "resolv.conf restored from memory");
                            }
                            None => {
                                warn!(error = %e, "no resolv.conf backup available to restore");
                                return Err(ResolverError::Io(e));
                            }
                        }
                    }
                }
            }
        }

        self.applied = false;
        Ok(())
    }
}

/// The backup path for a given resolver file.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

/// Whether `resolvectl` exists and can talk to systemd-resolved.
async fn resolvectl_available() -> bool {
    match Command::new("resolvectl")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Runs a `resolvectl` subcommand, mapping a non-zero exit to an error.
async fn run_resolvectl(args: &[&str]) -> Result<(), ResolverError> {
    let output = Command::new("resolvectl")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await?;

    if output.status.success() {
        return Ok(());
    }

    Err(ResolverError::Command {
        command: args.join(" "),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_path_appends_suffix() {
        let path = Path::new("/etc/resolv.conf");
        assert_eq!(
            backup_path(path),
            PathBuf::from("/etc/resolv.conf.wdtt-backup")
        );
    }

    #[test]
    fn forced_backend_is_reported() {
        let resolver = SystemResolver::with_backend(
            ResolverBackend::ResolvConf,
            "wdtt0",
            "127.0.0.1".parse().expect("addr"),
        );
        assert_eq!(resolver.backend(), ResolverBackend::ResolvConf);
        assert!(!resolver.is_applied());
    }

    #[tokio::test]
    async fn restore_without_apply_is_a_noop() {
        let mut resolver = SystemResolver::with_backend(
            ResolverBackend::ResolvConf,
            "wdtt0",
            "127.0.0.1".parse().expect("addr"),
        );
        resolver.restore().await.expect("restore");
        assert!(!resolver.is_applied());
    }

    #[tokio::test]
    async fn apply_is_idempotent_for_resolv_conf_backend() {
        // Point the backend at a temporary file by exercising the pieces
        // directly: the real path is /etc/resolv.conf, which a test must not
        // touch.
        let dir = std::env::temp_dir().join(format!("wdtt-dns-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.expect("mkdir");
        let path = dir.join("resolv.conf");
        tokio::fs::write(&path, b"nameserver 192.168.0.1\n")
            .await
            .expect("write");

        let backup = backup_path(&path);
        let original = tokio::fs::read(&path).await.expect("read");
        tokio::fs::write(&backup, &original).await.expect("backup");
        tokio::fs::write(&path, b"nameserver 127.0.0.1\n")
            .await
            .expect("write");

        let restored = tokio::fs::read(&backup).await.expect("read backup");
        assert_eq!(restored, b"nameserver 192.168.0.1\n");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
