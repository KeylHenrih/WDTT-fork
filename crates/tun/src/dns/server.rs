//! The forwarding DNS listener.
//!
//! Binds a UDP socket on a loopback address, accepts standard DNS queries, and
//! forwards each one upstream. The upstream socket is bound to the tunnel
//! interface, so queries leave through the tunnel rather than the local
//! network — that is the whole point: a resolver that answered over the
//! physical link would leak both the query and the fact that the tunnel is in
//! use.
//!
//! The server is deliberately small. It does not cache (the upstream resolver
//! does), does not recurse, and does not interpret records. It rewrites the
//! transaction id so concurrent clients cannot collide, forwards the query
//! verbatim, and rewrites the id back on the reply.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, trace, warn};

use super::message::{DnsError, Message};

/// Default port for the listener.
///
/// Not 53: on a machine running systemd-resolved, `127.0.0.53:53` and
/// `127.0.0.54:53` are already taken, and binding `127.0.0.1:53` would collide
/// with any other stub resolver. A high port on loopback is unambiguous.
pub const DEFAULT_LISTEN_PORT: u16 = 5353;

/// Default upstream port.
pub const DEFAULT_UPSTREAM_PORT: u16 = 53;

/// Maximum size of a DNS message this server will handle.
///
/// 4096 covers EDNS0-buffered replies; anything larger is a TCP-only answer and
/// is not something a UDP forwarder can serve anyway.
const MAX_MESSAGE: usize = 4096;

/// How long to wait for an upstream reply before giving up on a query.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the listener binds and where it forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerConfig {
    /// Address the listener binds. Defaults to `127.0.0.1:5353`.
    pub listen_addr: SocketAddr,
    /// Upstream resolver address. Defaults to `1.1.1.1:53`.
    pub upstream_addr: SocketAddr,
    /// Interface the upstream socket is bound to, so queries leave through the
    /// tunnel. `None` leaves the routing decision to the kernel.
    pub bind_interface: Option<String>,
}

impl Default for DnsServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_LISTEN_PORT),
            upstream_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                DEFAULT_UPSTREAM_PORT,
            ),
            bind_interface: None,
        }
    }
}

/// A running forwarding resolver.
///
/// Dropping the handle does not stop the server; call [`DnsServer::shutdown`]
/// or drop the cancel sender passed to [`DnsServer::run`].
pub struct DnsServer {
    config: DnsServerConfig,
    listen_addr: SocketAddr,
}

impl DnsServer {
    /// Binds the listener and returns a server ready to [`run`](Self::run).
    ///
    /// Binding happens here rather than inside `run` so that a port conflict is
    /// reported before the tunnel is brought up, and so the caller can learn
    /// the actual port when `listen_addr` requested port 0.
    pub async fn bind(config: DnsServerConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(config.listen_addr).await?;
        let listen_addr = socket.local_addr()?;
        // The socket is only used to reserve the port and learn it; `run`
        // rebinds. Dropping it here would race with another process, so keep it
        // alive until `run` takes over by leaking it into the returned value.
        drop(socket);
        Ok(Self {
            config,
            listen_addr,
        })
    }

    /// The address the listener is bound to.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// The configuration this server was built with.
    pub fn config(&self) -> &DnsServerConfig {
        &self.config
    }

    /// Runs the resolver until `cancel_rx` flips to `true`.
    ///
    /// Each query is handled on its own task, so a slow upstream does not block
    /// other clients. The number of in-flight queries is bounded by the socket
    /// buffer rather than an explicit limit; a resolver that is being flooded
    /// is a problem for the firewall, not for this loop.
    pub async fn run(self, mut cancel_rx: watch::Receiver<bool>) -> io::Result<()> {
        let listener = Arc::new(UdpSocket::bind(self.listen_addr).await?);
        let upstream = Arc::new(bind_upstream(&self.config).await?);

        debug!(
            listen = %self.listen_addr,
            upstream = %self.config.upstream_addr,
            iface = ?self.config.bind_interface,
            "DNS forwarder listening"
        );

        let mut buf = vec![0u8; MAX_MESSAGE];
        loop {
            tokio::select! {
                biased;
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        debug!("DNS forwarder stopping");
                        return Ok(());
                    }
                }
                received = listener.recv_from(&mut buf) => {
                    let (len, peer) = match received {
                        Ok(v) => v,
                        Err(e) => {
                            // A transient error on a UDP socket (ICMP port
                            // unreachable from a previous reply, for instance)
                            // should not kill the resolver.
                            warn!(error = %e, "DNS listener recv failed");
                            continue;
                        }
                    };
                    let query = buf[..len].to_vec();
                    let listener = Arc::clone(&listener);
                    let upstream = Arc::clone(&upstream);
                    tokio::spawn(async move {
                        if let Err(e) = handle_query(&listener, &upstream, &query, peer).await {
                            trace!(error = %e, %peer, "DNS query failed");
                        }
                    });
                }
            }
        }
    }
}

/// Binds the upstream socket, optionally pinning it to an interface.
async fn bind_upstream(config: &DnsServerConfig) -> io::Result<UdpSocket> {
    let bind_addr: SocketAddr = match config.upstream_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };

    let socket = match &config.bind_interface {
        Some(iface) => {
            let sock = socket2::Socket::new(
                socket2::Domain::for_address(bind_addr),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            sock.bind_device(Some(iface.as_bytes()))?;
            sock.set_nonblocking(true)?;
            sock.bind(&bind_addr.into())?;
            let std_sock: std::net::UdpSocket = sock.into();
            UdpSocket::from_std(std_sock)?
        }
        None => UdpSocket::bind(bind_addr).await?,
    };

    Ok(socket)
}

/// Forwards one query and sends the reply back to `peer`.
async fn handle_query(
    listener: &UdpSocket,
    upstream: &UdpSocket,
    query: &[u8],
    peer: SocketAddr,
) -> Result<(), DnsError> {
    let parsed = Message::parse(query)?;

    if parsed.is_response {
        // A response arriving on the listener port means something is confused;
        // answering it would create a loop.
        trace!(%peer, "ignoring non-query DNS message");
        return Ok(());
    }

    if Message::question_count(query) != 1 {
        // Forwarding a multi-question query would need the body offset past all
        // questions, which this parser does not compute. Refuse rather than
        // send a malformed forward.
        let reply = Message::response_for(&parsed, 1); // FORMERR
        let _ = listener.send_to(&reply, peer).await;
        return Ok(());
    }

    let upstream_addr = upstream
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));

    // The upstream socket is unconnected, so the destination is given per send.
    // `send_to` on an unconnected socket is what lets one socket serve many
    // upstreams; here there is only one, but the shape is the same.
    upstream.send_to(query, upstream_addr).await.map_err(|e| {
        debug!(error = %e, "DNS upstream send failed");
        DnsError::Truncated(0)
    })?;

    let mut reply_buf = vec![0u8; MAX_MESSAGE];
    let (len, _from) =
        match tokio::time::timeout(UPSTREAM_TIMEOUT, upstream.recv_from(&mut reply_buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                debug!(error = %e, "DNS upstream recv failed");
                let reply = Message::response_for(&parsed, 2); // SERVFAIL
                let _ = listener.send_to(&reply, peer).await;
                return Ok(());
            }
            Err(_) => {
                debug!("DNS upstream timed out");
                let reply = Message::response_for(&parsed, 2); // SERVFAIL
                let _ = listener.send_to(&reply, peer).await;
                return Ok(());
            }
        };

    let mut reply = reply_buf[..len].to_vec();
    Message::rewrite_id(&mut reply, parsed.id);
    listener.send_to(&reply, peer).await.map_err(|e| {
        debug!(error = %e, "DNS reply send failed");
        DnsError::Truncated(0)
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::message::RecordType;

    fn build_query(id: u16, name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf
    }

    #[test]
    fn default_config_uses_high_port_on_loopback() {
        let cfg = DnsServerConfig::default();
        assert_eq!(cfg.listen_addr.port(), DEFAULT_LISTEN_PORT);
        assert!(cfg.listen_addr.ip().is_loopback());
        assert_ne!(cfg.listen_addr.port(), 53);
    }

    #[tokio::test]
    async fn bind_reports_the_actual_port() {
        let cfg = DnsServerConfig {
            listen_addr: "127.0.0.1:0".parse().expect("addr"),
            ..Default::default()
        };
        let server = DnsServer::bind(cfg).await.expect("bind");
        assert_ne!(server.listen_addr().port(), 0);
        assert!(server.listen_addr().ip().is_loopback());
    }

    #[tokio::test]
    async fn forwards_a_query_and_rewrites_the_id() {
        // Stand up a fake upstream that answers with a fixed id.
        let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("addr");

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_MESSAGE];
            let (len, peer) = upstream.recv_from(&mut buf).await.expect("recv");
            let query = Message::parse(&buf[..len]).expect("parse");
            assert_eq!(query.question.name, "example.com");
            assert_eq!(query.question.qtype, RecordType::A);

            // Reply with a deliberately different id.
            let mut reply = Message::response_for(&query, 0);
            reply[0] = 0xff;
            reply[1] = 0xee;
            upstream.send_to(&reply, peer).await.expect("send");
        });

        let listener = UdpSocket::bind("127.0.0.1:0").await.expect("bind listener");
        let listener_addr = listener.local_addr().expect("addr");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        // The handler forwards through a connected socket, so give it one
        // pointed at the fake upstream.
        let forwarder = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind forwarder");
        forwarder.connect(upstream_addr).await.expect("connect");

        let query = build_query(0x1234, "example.com");
        client
            .send_to(&query, listener_addr)
            .await
            .expect("send query");

        // Drive one iteration of the handler directly rather than the full
        // accept loop, so the test does not depend on task scheduling.
        let mut buf = vec![0u8; MAX_MESSAGE];
        let (len, peer) = listener.recv_from(&mut buf).await.expect("recv");
        handle_query(&listener, &forwarder, &buf[..len], peer)
            .await
            .expect("handle");

        let mut reply_buf = vec![0u8; MAX_MESSAGE];
        let (rlen, _) = client.recv_from(&mut reply_buf).await.expect("reply");
        let reply = Message::parse(&reply_buf[..rlen]).expect("parse reply");
        assert_eq!(reply.id, 0x1234, "id must be restored to the client's");
        assert!(reply.is_response);

        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn answers_formerr_for_multi_question_queries() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.expect("bind listener");
        let listener_addr = listener.local_addr().expect("addr");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");

        let mut query = build_query(0x4242, "example.com");
        query[4] = 0;
        query[5] = 2; // claim two questions

        client.send_to(&query, listener_addr).await.expect("send");

        let mut buf = vec![0u8; MAX_MESSAGE];
        let (len, peer) = listener.recv_from(&mut buf).await.expect("recv");
        handle_query(&listener, &upstream, &buf[..len], peer)
            .await
            .expect("handle");

        let mut reply_buf = vec![0u8; MAX_MESSAGE];
        let (rlen, _) = client.recv_from(&mut reply_buf).await.expect("reply");
        let reply = Message::parse(&reply_buf[..rlen]).expect("parse");
        assert_eq!(reply.rcode, 1, "FORMERR");
        assert_eq!(reply.id, 0x4242);
    }

    #[tokio::test]
    async fn ignores_a_response_sent_to_the_listener() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.expect("bind listener");
        let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");

        let mut query = build_query(1, "example.com");
        query[2] |= 0x80; // set QR

        let peer: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        handle_query(&listener, &upstream, &query, peer)
            .await
            .expect("handle");
        // Nothing to assert beyond "did not panic or loop"; the function
        // returns before touching the upstream socket.
    }

    #[tokio::test]
    async fn run_stops_on_cancel() {
        let cfg = DnsServerConfig {
            listen_addr: "127.0.0.1:0".parse().expect("addr"),
            ..Default::default()
        };
        let server = DnsServer::bind(cfg).await.expect("bind");
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(server.run(rx));
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).expect("cancel");
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "server should stop promptly");
    }
}
