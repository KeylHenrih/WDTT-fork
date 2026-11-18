//! Pool of TURN stream connections sharing one allocation budget.
//!
//! A single TCP/TLS stream to the TURN server is a single point of failure:
//! when the relay drops the allocation, the call ends, or the network moves,
//! every datagram in flight is lost until a new stream is established. The
//! pool keeps several [`StreamTurnClient`] instances alive at once and hands
//! them out one at a time, so a dead stream can be retired and replaced
//! without stalling the datapath.
//!
//! # Why the pool cannot trust the send path
//!
//! [`StreamTurnClient::send_channel_data`] enqueues into a bounded queue and
//! discards the result of the internal `try_send`, so a caller cannot learn
//! from the send path that the writer task has died. Liveness therefore has to
//! be observed on the receive path ([`StreamTurnClient::recv_frame`] returns
//! `Err` once the stream is closed) or probed explicitly with
//! [`StreamTurnClient::refresh_allocation`].
//!
//! # Ownership
//!
//! [`StreamTurnClient`] is not `Clone` and owns a `ReadHalf` plus a spawned
//! writer task, and `recv_frame` takes `&mut self`. The pool therefore owns
//! each client exclusively and hands out one at a time; retiring a stream is
//! done by dropping it, which aborts the writer task.

use crate::error::TurnError;
use crate::stream_client::{StreamClientConfig, StreamTurnClient};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Default number of streams the pool tries to keep established.
pub const DEFAULT_POOL_SIZE: usize = 2;

/// Default ceiling on concurrently established streams.
pub const DEFAULT_MAX_STREAMS: usize = 8;

/// How long a liveness probe may take before the stream is considered dead.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long establishing one stream may take before the attempt is abandoned.
///
/// A TURN server that accepts the TCP connection but never finishes the TLS
/// handshake (or never answers the allocation) would otherwise stall `fill`
/// for as long as the peer keeps the socket open; the observed failure mode was
/// a five-minute freeze with a healthy first stream sitting idle the whole
/// time.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A single pooled stream: the client plus the relay address it was granted.
pub(crate) struct PooledStream {
    client: StreamTurnClient,
    relayed_addr: SocketAddr,
}

/// Pool of TURN stream connections over TCP or TLS.
///
/// The pool owns every [`StreamTurnClient`] it creates. Callers borrow one
/// stream at a time through [`StreamPool::acquire`], report the outcome with
/// [`StreamPool::release`], and let the pool replace streams that fail.
pub struct StreamPool {
    config: StreamClientConfig,
    target_size: usize,
    max_size: usize,
    probe_timeout: Duration,
    connect_timeout: Duration,
    streams: Vec<PooledStream>,
    /// Relay address of the stream handed out by the last `acquire`, if any.
    in_use: Option<SocketAddr>,
    /// Number of streams retired because they failed.
    retired: u64,
}

impl StreamPool {
    /// Create an empty pool for the given stream configuration.
    ///
    /// `target_size` is clamped to `1..=max_size`; `max_size` is clamped to at
    /// least `1`.
    #[must_use]
    pub fn new(config: StreamClientConfig, target_size: usize, max_size: usize) -> Self {
        let max_size = max_size.max(1);
        let target_size = target_size.clamp(1, max_size);
        Self {
            config,
            target_size,
            max_size,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            streams: Vec::with_capacity(max_size),
            in_use: None,
            retired: 0,
        }
    }

    /// Override how long a liveness probe may take.
    #[must_use]
    pub fn with_probe_timeout(mut self, probe_timeout: Duration) -> Self {
        self.probe_timeout = probe_timeout;
        self
    }

    /// Override how long establishing one stream may take.
    #[must_use]
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    /// Number of streams currently established.
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether the pool currently holds no streams.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Number of streams retired because they failed.
    #[must_use]
    pub fn retired(&self) -> u64 {
        self.retired
    }

    /// The configured target size.
    #[must_use]
    pub fn target_size(&self) -> usize {
        self.target_size
    }

    /// The configured ceiling on established streams.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Establish one stream and add it to the pool.
    ///
    /// Returns the relay address the TURN server granted. Fails when the pool
    /// is already at `max_size` or when the allocation cannot be established.
    pub async fn add_stream(&mut self) -> Result<SocketAddr, TurnError> {
        if self.streams.len() >= self.max_size {
            return Err(TurnError::Transport(format!(
                "stream pool is full ({} of {})",
                self.streams.len(),
                self.max_size
            )));
        }

        // Bound the whole establish sequence: a peer that accepts the socket
        // but stalls the handshake must not hold up the pool.
        let established = timeout(self.connect_timeout, async {
            let mut client = StreamTurnClient::connect(self.config.clone()).await?;
            let relayed_addr = client.allocate_relay().await?;
            client.bind_peer(self.config.peer_addr).await?;
            Ok::<_, TurnError>((client, relayed_addr))
        })
        .await
        .map_err(|_| {
            TurnError::Transport(format!(
                "stream establish timed out after {:?}",
                self.connect_timeout
            ))
        })??;

        let (client, relayed_addr) = established;

        debug!(
            "Stream pool: established stream {} of {} (relay {relayed_addr})",
            self.streams.len() + 1,
            self.target_size
        );

        self.streams.push(PooledStream {
            client,
            relayed_addr,
        });
        Ok(relayed_addr)
    }

    /// Fill the pool up to its target size.
    ///
    /// Streams that fail to establish are logged and skipped; the pool keeps
    /// whatever it managed to build. Returns the number of streams added.
    pub async fn fill(&mut self) -> usize {
        let mut added = 0;
        while self.streams.len() < self.target_size {
            match self.add_stream().await {
                Ok(_) => added += 1,
                Err(e) => {
                    warn!("Stream pool: failed to establish stream: {e}");
                    break;
                }
            }
        }
        added
    }

    /// Take a stream out of the pool, establishing one if the pool is empty.
    ///
    /// The stream is removed from the pool for as long as the caller holds the
    /// returned guard, so the pool stays usable while a stream is checked out.
    /// Hand the guard back with [`StreamPool::release`] so the pool can retire
    /// it if it failed.
    pub async fn acquire(&mut self) -> Result<StreamGuard, TurnError> {
        if self.in_use.is_some() {
            return Err(TurnError::Transport(
                "stream pool already has a stream checked out".into(),
            ));
        }

        if self.streams.is_empty() {
            self.add_stream().await?;
        }

        // Prefer the last stream: it is the most recently established and so
        // the least likely to be near its allocation lifetime.
        let stream = self.streams.pop().expect("pool was just filled");
        self.in_use = Some(stream.relayed_addr);
        Ok(StreamGuard {
            stream: Some(stream),
            released: false,
        })
    }

    /// Return a stream to the pool.
    ///
    /// When `healthy` is `false` the stream is dropped (which aborts its
    /// writer task) and the pool is refilled to its target size.
    pub(crate) async fn release(&mut self, stream: PooledStream, healthy: bool) {
        if self.in_use == Some(stream.relayed_addr) {
            self.in_use = None;
        }

        if healthy {
            self.streams.push(stream);
            return;
        }

        self.retired += 1;
        warn!(
            "Stream pool: retired stream to relay {} ({} retired total)",
            stream.relayed_addr, self.retired
        );
        drop(stream);

        self.fill().await;
    }

    /// Probe every idle stream and retire the ones that fail to answer.
    ///
    /// A stream is considered dead when a `REFRESH` request does not complete
    /// within the probe timeout. The pool is refilled afterwards.
    pub async fn probe_and_prune(&mut self) {
        let mut dead = Vec::new();

        for (index, stream) in self.streams.iter_mut().enumerate() {
            if self.in_use == Some(stream.relayed_addr) {
                continue;
            }
            let lifetime = stream.client.negotiated_lifetime();
            let probe = timeout(
                self.probe_timeout,
                stream.client.refresh_allocation(lifetime),
            )
            .await;
            match probe {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!("Stream pool: probe failed for stream {index}: {e}");
                    dead.push(index);
                }
                Err(_) => {
                    debug!("Stream pool: probe timed out for stream {index}");
                    dead.push(index);
                }
            }
        }

        // Remove from the back so earlier indices stay valid.
        for index in dead.into_iter().rev() {
            let stream = self.streams.remove(index);
            self.retired += 1;
            warn!(
                "Stream pool: pruned dead stream to relay {} ({} retired total)",
                stream.relayed_addr, self.retired
            );
            drop(stream);
        }

        self.fill().await;
    }

    /// Drop every stream in the pool.
    pub fn clear(&mut self) {
        self.in_use = None;
        self.streams.clear();
    }

    /// The relay address of the stream at `index`, if it exists.
    #[must_use]
    pub fn relayed_addr(&self, index: usize) -> Option<SocketAddr> {
        self.streams.get(index).map(|s| s.relayed_addr)
    }

    /// The relay address of the stream currently checked out, if any.
    #[must_use]
    pub fn active_relayed_addr(&self) -> Option<SocketAddr> {
        self.in_use
    }

    /// Whether the stream with the given relay address is checked out.
    #[must_use]
    pub fn is_checked_out(&self, relayed_addr: SocketAddr) -> bool {
        self.in_use == Some(relayed_addr)
    }

    /// The relay address of the first established stream, if any.
    #[must_use]
    pub fn first_relayed_addr(&self) -> Option<SocketAddr> {
        self.streams.first().map(|s| s.relayed_addr)
    }
}

impl std::fmt::Debug for StreamPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamPool")
            .field("target_size", &self.target_size)
            .field("max_size", &self.max_size)
            .field("streams", &self.streams.len())
            .field("in_use", &self.in_use)
            .field("retired", &self.retired)
            .finish()
    }
}

/// Exclusive ownership of one pooled stream.
///
/// The guard dereferences to the underlying [`StreamTurnClient`]. Call
/// [`StreamGuard::release`] to hand the stream back and report whether it is
/// still usable; dropping the guard without releasing returns it as healthy.
pub struct StreamGuard {
    /// `None` once the stream has been handed back.
    stream: Option<PooledStream>,
    /// Set once the stream has been handed back, so `Drop` does not repeat it.
    released: bool,
}

impl StreamGuard {
    /// The relay address of the borrowed stream.
    #[must_use]
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.stream.as_ref().map(|s| s.relayed_addr)
    }

    /// Hand the stream back, reporting whether it is still usable.
    ///
    /// After this call the guard is inert: dropping it does nothing.
    pub async fn release(&mut self, pool: &mut StreamPool, healthy: bool) {
        if self.released {
            return;
        }
        self.released = true;
        if let Some(stream) = self.stream.take() {
            pool.release(stream, healthy).await;
        }
    }
}

impl std::ops::Deref for StreamGuard {
    type Target = StreamTurnClient;

    fn deref(&self) -> &Self::Target {
        &self
            .stream
            .as_ref()
            .expect("stream guard is only empty after release")
            .client
    }
}

impl std::ops::DerefMut for StreamGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self
            .stream
            .as_mut()
            .expect("stream guard is only empty after release")
            .client
    }
}

/// Establish a pool of `target_size` streams, capped at `max_size`.
///
/// Convenience wrapper around [`StreamPool::new`] plus [`StreamPool::fill`].
pub async fn establish_pool(
    config: StreamClientConfig,
    target_size: usize,
    max_size: usize,
) -> Result<StreamPool, TurnError> {
    let mut pool = StreamPool::new(config, target_size, max_size);
    if pool.fill().await == 0 {
        return Err(TurnError::Transport(
            "stream pool could not establish any stream".into(),
        ));
    }
    info!(
        "Stream pool ready: {} of {} streams established",
        pool.len(),
        pool.target_size()
    );
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_size_is_clamped_to_the_ceiling() {
        let pool = StreamPool::new(StreamClientConfig::default(), 99, 4);
        assert_eq!(pool.target_size(), 4);
        assert_eq!(pool.max_size(), 4);
    }

    #[test]
    fn target_size_is_at_least_one() {
        let pool = StreamPool::new(StreamClientConfig::default(), 0, 0);
        assert_eq!(pool.target_size(), 1);
        assert_eq!(pool.max_size(), 1);
    }

    #[test]
    fn a_fresh_pool_is_empty() {
        let pool = StreamPool::new(StreamClientConfig::default(), 2, 8);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.retired(), 0);
        assert!(pool.first_relayed_addr().is_none());
        assert!(pool.active_relayed_addr().is_none());
    }

    #[test]
    fn probe_timeout_is_configurable() {
        let pool = StreamPool::new(StreamClientConfig::default(), 2, 8)
            .with_probe_timeout(Duration::from_millis(250));
        assert_eq!(pool.probe_timeout, Duration::from_millis(250));
    }

    #[test]
    fn connect_timeout_is_configurable() {
        let pool = StreamPool::new(StreamClientConfig::default(), 2, 8)
            .with_connect_timeout(Duration::from_millis(120));
        assert_eq!(pool.connect_timeout, Duration::from_millis(120));
    }

    #[test]
    fn debug_reports_pool_shape() {
        let pool = StreamPool::new(StreamClientConfig::default(), 3, 8);
        let text = format!("{pool:?}");
        assert!(text.contains("target_size: 3"));
        assert!(text.contains("max_size: 8"));
        assert!(text.contains("streams: 0"));
    }
}
