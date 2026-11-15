//! Real-time telemetry and datapath metrics for tunnel sessions.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

/// Operational metrics collected across tunnel datapath.
#[derive(Debug, Default)]
pub struct TunnelMetrics {
    /// Total packets transmitted to the remote peer.
    pub packets_tx: AtomicU64,
    /// Total packets received from the remote peer.
    pub packets_rx: AtomicU64,
    /// Total payload bytes transmitted.
    pub bytes_tx: AtomicU64,
    /// Total payload bytes received.
    pub bytes_rx: AtomicU64,
    /// Packets dropped or reordered by the resequencer.
    pub reorder_drops: AtomicU64,
    /// Single-packet batches received via recvmmsg (count == 1).
    pub batches_single: AtomicU64,
    /// Multi-packet batches received via recvmmsg (count > 1).
    pub batches_multi: AtomicU64,
    /// Total number of keepalive/chaff Ping probes transmitted.
    pub pings_tx: AtomicU64,
    /// Total number of Ping probes received.
    pub pings_rx: AtomicU64,
    /// Latest measured round-trip time in milliseconds.
    pub rtt_latest_ms: AtomicU64,
    /// Highest confirmed keepalive interval in seconds (Pong acknowledged).
    pub confirmed_keepalive_sec: AtomicU64,
}

impl TunnelMetrics {
    /// Create a new empty metrics registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successfully transmitted packet.
    pub fn record_tx(&self, bytes: usize) {
        self.packets_tx.fetch_add(1, Ordering::Relaxed);
        self.bytes_tx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a successfully received packet.
    pub fn record_rx(&self, bytes: usize) {
        self.packets_rx.fetch_add(1, Ordering::Relaxed);
        self.bytes_rx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record received batch size.
    pub fn record_batch_rx(&self, count: usize) {
        if count == 1 {
            self.batches_single.fetch_add(1, Ordering::Relaxed);
        } else if count > 1 {
            self.batches_multi.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a transmitted ping probe.
    pub fn record_ping_tx(&self) {
        self.pings_tx.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a received ping probe.
    pub fn record_ping_rx(&self) {
        self.pings_rx.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an RTT sample in milliseconds.
    pub fn record_rtt_sample(&self, rtt_ms: u64) {
        self.rtt_latest_ms.store(rtt_ms, Ordering::Relaxed);
    }

    /// Record confirmed keepalive interval in seconds.
    pub fn record_confirmed_keepalive(&self, interval_sec: u64) {
        self.confirmed_keepalive_sec
            .store(interval_sec, Ordering::Relaxed);
    }

    /// Record a resequencer drop.
    pub fn record_reorder_drop(&self) {
        self.reorder_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot current metrics values.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_tx: self.packets_tx.load(Ordering::Relaxed),
            packets_rx: self.packets_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            reorder_drops: self.reorder_drops.load(Ordering::Relaxed),
            batches_single: self.batches_single.load(Ordering::Relaxed),
            batches_multi: self.batches_multi.load(Ordering::Relaxed),
            pings_tx: self.pings_tx.load(Ordering::Relaxed),
            pings_rx: self.pings_rx.load(Ordering::Relaxed),
            rtt_latest_ms: self.rtt_latest_ms.load(Ordering::Relaxed),
            confirmed_keepalive_sec: self.confirmed_keepalive_sec.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of tunnel metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Total packets transmitted.
    pub packets_tx: u64,
    /// Total packets received.
    pub packets_rx: u64,
    /// Total payload bytes transmitted.
    pub bytes_tx: u64,
    /// Total payload bytes received.
    pub bytes_rx: u64,
    /// Resequencer drops.
    pub reorder_drops: u64,
    /// Single-packet batches received via recvmmsg.
    pub batches_single: u64,
    /// Multi-packet batches received via recvmmsg.
    pub batches_multi: u64,
    /// Total Ping probes sent.
    pub pings_tx: u64,
    /// Total Ping probes received.
    pub pings_rx: u64,
    /// Latest measured RTT in ms.
    pub rtt_latest_ms: u64,
    /// Highest confirmed keepalive interval in seconds.
    pub confirmed_keepalive_sec: u64,
}
