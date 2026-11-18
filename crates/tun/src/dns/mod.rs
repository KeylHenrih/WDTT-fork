//! DNS handling for the tunnel: a local forwarding resolver plus system
//! resolver integration.
//!
//! The tunnel needs DNS for two distinct reasons, and they are handled by two
//! separate pieces:
//!
//! 1. **Rule resolution** (see [`crate::resolver`]) turns the domains named in
//!    routing rules into addresses *before* the tunnel comes up, using the
//!    system resolver. That is a one-shot, startup-time concern.
//! 2. **Runtime resolution** — this module — serves the applications on the
//!    machine while the tunnel is up. It listens on a loopback address, accepts
//!    standard DNS queries, and forwards them upstream *through the tunnel*, so
//!    that neither the queries nor the answers leak to the local network.
//!
//! # Why not just point `/etc/resolv.conf` at the listener?
//!
//! On a machine running NetworkManager and systemd-resolved, `/etc/resolv.conf`
//! is a file NetworkManager rewrites whenever a link changes. Writing it
//! directly works until the next link event, then silently reverts. The
//! supported way to steer resolution is to configure the resolver per link,
//! which is what [`system::SystemResolver`] does through `resolvectl`.
//!
//! # Layout
//!
//! - [`message`] — DNS wire format: parsing queries, building responses.
//! - [`server`] — the UDP listener and its upstream forwarding.
//! - [`system`] — pointing the system resolver at the listener, and undoing it.

pub mod message;
pub mod server;
pub mod system;

pub use message::{DnsError, Message, Question, RecordType};
pub use server::{DnsServer, DnsServerConfig};
pub use system::{ResolverBackend, ResolverError, SystemResolver};
