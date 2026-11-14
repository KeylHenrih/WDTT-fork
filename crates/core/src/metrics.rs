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
}
