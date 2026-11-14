use bytes::Bytes;
use std::time::{Duration, Instant};

/// Default resequencer slot capacity (must be a power of 2).
/// At 1 Gbps with ~104,000 pps, 16,384 slots covers ~157 ms of multi-stream skew.
pub const DEFAULT_RESEQUENCER_CAPACITY: usize = 16_384;

/// Default baseline gap timeout before skipping a lost packet (5 milliseconds).
pub const DEFAULT_GAP_TIMEOUT: Duration = Duration::from_millis(5);

/// Minimum allowable adaptive gap timeout.
pub const MIN_GAP_TIMEOUT: Duration = Duration::from_millis(5);

/// Maximum allowable adaptive gap timeout (80 milliseconds).
pub const MAX_GAP_TIMEOUT: Duration = Duration::from_millis(80);

/// Maximum allowable forward jump in sequence counter before rejection (65,536 packets).
/// Protects against malicious or corrupted counter bursts that would otherwise force window advance.
pub const MAX_FORWARD_COUNTER_JUMP: u64 = 65_536;

/// Maximum concurrent receiver indices tracked simultaneously (WireGuard rekeying window).
pub const MAX_RECEIVER_STREAMS: usize = 4;

/// Packet stored in the resequencer buffer slot.
#[derive(Debug, Clone)]
struct SlotEntry {
    counter: u64,
    packet: Bytes,
}

/// Statistics tracked per WireGuard receiver stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResequencerStats {
    pub packets_in_order: u64,
    pub packets_reordered: u64,
    pub packets_duplicate_or_late: u64,
    pub packets_dropped_overflow: u64,
    pub packets_invalid_counter_jump: u64,
    pub gaps_skipped_timeout: u64,
    pub max_reorder_depth: u16,
}

/// Sequencing state for a single WireGuard `receiver_index`.
#[derive(Debug)]
pub struct ReceiverStreamState {
    pub receiver_index: u32,
    pub expected_counter: u64,
    pub capacity: usize,
    mask: usize,
    slots: Vec<Option<SlotEntry>>,
    pub gap_timeout: Duration,
    gap_started_at: Option<Instant>,
    pub stats: ResequencerStats,
    last_active: Instant,
}

impl ReceiverStreamState {
    pub fn new(receiver_index: u32, capacity: usize, gap_timeout: Duration, now: Instant) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be power of two");
        let mut slots = Vec::with_capacity(capacity);
        slots.resize_with(capacity, || None);

        Self {
            receiver_index,
            expected_counter: 0,
            capacity,
            mask: capacity - 1,
            slots,
            gap_timeout,
            gap_started_at: None,
            stats: ResequencerStats::default(),
            last_active: now,
        }
    }

    /// Update adaptive gap timeout based on measured path skew.
    ///
    /// The formula allocates 1.25x measured skew plus a 5ms margin, clamped to [MIN_GAP_TIMEOUT, MAX_GAP_TIMEOUT].
    /// For example, at a measured skew of 35ms:
    /// `35ms * 1.25 + 5ms = 48.75ms` (clamped to 48ms), ensuring packets from the slower path
    /// are not declared lost prematurely.
    pub fn update_measured_skew(&mut self, skew: Duration) {
        let adaptive_ms = ((skew.as_millis() as f64 * 1.25) as u64 + 5).clamp(
            MIN_GAP_TIMEOUT.as_millis() as u64,
            MAX_GAP_TIMEOUT.as_millis() as u64,
        );
        self.gap_timeout = Duration::from_millis(adaptive_ms);
    }

    /// Reset stream counter state (e.g. on `REORDER_RESET` flag).
    pub fn reset(&mut self, next_expected: u64) {
        self.expected_counter = next_expected;
        self.gap_started_at = None;
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
    }

    /// Ingest a packet with its WireGuard sequence counter.
    ///
    /// Returns ready packets in strictly monotonic counter order.
    pub fn push(&mut self, counter: u64, packet: Bytes, now: Instant, out: &mut Vec<Bytes>) {
        self.last_active = now;

        // 1. Packet is duplicate or older than our current expected window.
        if counter < self.expected_counter {
            self.stats.packets_duplicate_or_late += 1;
            return;
        }

        // 2. Packet arrives exactly in order.
        if counter == self.expected_counter {
            self.stats.packets_in_order += 1;
            out.push(packet);
            self.expected_counter += 1;
            self.drain_consecutive(out);
            return;
        }

        // 3. Packet is ahead of expected counter (reordering detected).
        let delta = counter - self.expected_counter;

        // Reject catastrophic forward counter jumps to protect session window.
        if delta > MAX_FORWARD_COUNTER_JUMP {
            self.stats.packets_invalid_counter_jump += 1;
            return;
        }

        let depth = delta.min(u16::MAX as u64) as u16;
        if depth > self.stats.max_reorder_depth {
            self.stats.max_reorder_depth = depth;
        }

        // Check if delta exceeds capacity (buffer overflow).
        if delta >= self.capacity as u64 {
            self.stats.packets_dropped_overflow += 1;
            // Advance expected counter to accommodate this packet without dropping steady stream.
            let new_expected = counter - (self.capacity as u64) + 1;
            self.advance_to(new_expected, out);
        }

        // Store packet into ring slot.
        let slot_idx = (counter as usize) & self.mask;
        if let Some(existing) = &self.slots[slot_idx]
            && existing.counter == counter
        {
            self.stats.packets_duplicate_or_late += 1;
            return;
        }

        self.slots[slot_idx] = Some(SlotEntry { counter, packet });
        self.stats.packets_reordered += 1;

        if self.gap_started_at.is_none() {
            self.gap_started_at = Some(now);
        }
    }

    /// Drain consecutive packets starting from `expected_counter`.
    fn drain_consecutive(&mut self, out: &mut Vec<Bytes>) {
        loop {
            let slot_idx = (self.expected_counter as usize) & self.mask;
            match self.slots[slot_idx].take() {
                Some(entry) => {
                    if entry.counter == self.expected_counter {
                        out.push(entry.packet);
                        self.expected_counter += 1;
                    } else {
                        // Stale entry in slot from previous ring cycle.
                        self.slots[slot_idx] = Some(entry);
                        break;
                    }
                }
                None => break,
            }
        }

        // If we caught up, reset gap timer.
        let next_slot = (self.expected_counter as usize) & self.mask;
        if self.slots[next_slot].is_none() {
            self.gap_started_at = None;
        }
    }

    /// Fast-forward expected counter past dropped/stale gaps up to `new_expected`.
    ///
    /// Rejects catastrophic forward jumps beyond `MAX_FORWARD_COUNTER_JUMP` to protect the window.
    fn advance_to(&mut self, new_expected: u64, out: &mut Vec<Bytes>) {
        let delta = new_expected.saturating_sub(self.expected_counter);
        if delta > MAX_FORWARD_COUNTER_JUMP {
            self.stats.packets_invalid_counter_jump += 1;
            return;
        }

        while self.expected_counter < new_expected {
            let slot_idx = (self.expected_counter as usize) & self.mask;
            if let Some(entry) = self.slots[slot_idx].take()
                && entry.counter >= new_expected
            {
                // Put back future entry
                self.slots[slot_idx] = Some(entry);
            }
            self.expected_counter += 1;
        }
        self.drain_consecutive(out);
    }

    /// Check if gap timeout has elapsed. If so, skips the missing counter and flushes queued packets.
    pub fn check_timeout(&mut self, now: Instant, out: &mut Vec<Bytes>) {
        if let Some(gap_start) = self.gap_started_at
            && now.saturating_duration_since(gap_start) >= self.gap_timeout
        {
            self.stats.gaps_skipped_timeout += 1;

            // Find the lowest buffered counter ahead of expected_counter.
            let mut next_available: Option<u64> = None;
            for i in 1..self.capacity {
                let c = self.expected_counter + (i as u64);
                let idx = (c as usize) & self.mask;
                if let Some(ref entry) = self.slots[idx]
                    && entry.counter == c
                {
                    next_available = Some(c);
                    break;
                }
            }

            if let Some(next_c) = next_available {
                self.advance_to(next_c, out);
            } else {
                self.gap_started_at = None;
            }
        }
    }
}

/// Multi-stream WireGuard Resequencer.
/// Manages separate resequencing pipelines per active `receiver_index`.
#[derive(Debug)]
pub struct WgResequencer {
    streams: Vec<ReceiverStreamState>,
    capacity: usize,
    gap_timeout: Duration,
}

impl WgResequencer {
    /// Create a new multi-stream resequencer.
    pub fn new(capacity: usize, gap_timeout: Duration) -> Self {
        Self {
            streams: Vec::with_capacity(MAX_RECEIVER_STREAMS),
            capacity,
            gap_timeout,
        }
    }

    /// Ingest a WireGuard data packet.
    ///
    /// - If packet is a Handshake packet (Types 1..3), it must NOT be fed here (bypasses resequencer directly).
    /// - Data packets (Type 4) are sequenced and emitted in strictly monotonic counter order into `out`.
    pub fn push(
        &mut self,
        receiver_index: u32,
        counter: u64,
        packet: Bytes,
        now: Instant,
        out: &mut Vec<Bytes>,
    ) {
        let stream = self.get_or_create_stream(receiver_index, now);
        stream.push(counter, packet, now, out);
    }

    /// Periodic tick to check for gap timeouts across all active receiver streams.
    pub fn tick(&mut self, now: Instant, out: &mut Vec<Bytes>) {
        for stream in &mut self.streams {
            stream.check_timeout(now, out);
        }
    }

    /// Update adaptive gap timeout for a specific receiver stream based on measured path skew.
    pub fn update_measured_skew(&mut self, receiver_index: u32, skew: Duration) {
        for stream in &mut self.streams {
            if stream.receiver_index == receiver_index {
                stream.update_measured_skew(skew);
                return;
            }
        }
    }

    /// Retrieve or allocate stream state for `receiver_index`.
    fn get_or_create_stream(
        &mut self,
        receiver_index: u32,
        now: Instant,
    ) -> &mut ReceiverStreamState {
        if let Some(idx) = self
            .streams
            .iter()
            .position(|s| s.receiver_index == receiver_index)
        {
            return &mut self.streams[idx];
        }

        // If pool is full, evict the least recently active stream.
        if self.streams.len() >= MAX_RECEIVER_STREAMS {
            let oldest_idx = self
                .streams
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.last_active)
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.streams.swap_remove(oldest_idx);
        }

        self.streams.push(ReceiverStreamState::new(
            receiver_index,
            self.capacity,
            self.gap_timeout,
            now,
        ));
        self.streams.last_mut().unwrap()
    }

    /// Get current telemetry statistics for a specific receiver stream.
    pub fn stats(&self, receiver_index: u32) -> Option<ResequencerStats> {
        self.streams
            .iter()
            .find(|s| s.receiver_index == receiver_index)
            .map(|s| s.stats)
    }

    /// Check if all managed streams have empty slot queues (no gaps waiting for timeout).
    pub fn is_empty(&self) -> bool {
        self.streams.iter().all(|s| s.gap_started_at.is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_adaptive_gap_timeout_with_35ms_skew() {
        let t0 = Instant::now();
        let mut reseq = WgResequencer::new(1024, DEFAULT_GAP_TIMEOUT);
        let mut out = Vec::new();

        // 1. Initial packet 0
        reseq.push(1, 0, Bytes::from_static(b"p0"), t0, &mut out);
        assert_eq!(out.len(), 1);

        // 2. Set measured path skew to 35ms (adaptive timeout -> 48ms)
        reseq.update_measured_skew(1, Duration::from_millis(35));

        // 3. Fast stream delivers packet 2 ahead of packet 1
        reseq.push(1, 2, Bytes::from_static(b"p2"), t0, &mut out);
        assert_eq!(out.len(), 1); // packet 2 is buffered waiting for 1

        // 4. Tick at 35ms (matching skew) -> packet 1 is NOT declared lost
        reseq.tick(t0 + Duration::from_millis(35), &mut out);
        assert_eq!(out.len(), 1);

        // 5. Delayed packet 1 arrives from slow stream at 36ms!
        reseq.push(
            1,
            1,
            Bytes::from_static(b"p1"),
            t0 + Duration::from_millis(36),
            &mut out,
        );
        assert_eq!(out.len(), 3); // 0, 1, 2 all emitted in order without loss!
        assert_eq!(out[0], Bytes::from_static(b"p0"));
        assert_eq!(out[1], Bytes::from_static(b"p1"));
        assert_eq!(out[2], Bytes::from_static(b"p2"));

        let stats = reseq.stats(1).unwrap();
        assert_eq!(stats.gaps_skipped_timeout, 0);
    }

    #[test]
    fn test_catastrophic_counter_jump_rejected() {
        let now = Instant::now();
        let mut reseq = WgResequencer::new(1024, DEFAULT_GAP_TIMEOUT);
        let mut out = Vec::new();

        reseq.push(1, 0, Bytes::from_static(b"p0"), now, &mut out);
        assert_eq!(out.len(), 1);

        // Feed catastrophic jump > MAX_FORWARD_COUNTER_JUMP (e.g. 100,000)
        reseq.push(1, 100_000, Bytes::from_static(b"malicious"), now, &mut out);
        assert_eq!(out.len(), 1);

        let stats = reseq.stats(1).unwrap();
        assert_eq!(stats.packets_invalid_counter_jump, 1);

        // Next legitimate packet 1 still accepted in order
        reseq.push(1, 1, Bytes::from_static(b"p1"), now, &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn test_advance_to_bound_check() {
        let now = Instant::now();
        let mut stream = ReceiverStreamState::new(1, 1024, DEFAULT_GAP_TIMEOUT, now);
        let mut out = Vec::new();
        assert_eq!(stream.expected_counter, 0);

        // Jump exceeding MAX_FORWARD_COUNTER_JUMP
        stream.advance_to(100_000, &mut out);
        assert_eq!(stream.expected_counter, 0);
        assert_eq!(stream.stats.packets_invalid_counter_jump, 1);

        // Valid jump
        stream.advance_to(10, &mut out);
        assert_eq!(stream.expected_counter, 10);
        assert_eq!(stream.stats.packets_invalid_counter_jump, 1);
    }

    #[test]
    fn test_in_order_delivery() {
        let now = Instant::now();
        let mut reseq = WgResequencer::new(1024, Duration::from_millis(5));
        let mut out = Vec::new();

        for c in 0..100 {
            let p = Bytes::from(format!("packet-{c}"));
            reseq.push(1, c, p, now, &mut out);
        }

        assert_eq!(out.len(), 100);
        for (i, p) in out.iter().enumerate() {
            assert_eq!(p.as_ref(), format!("packet-{i}").as_bytes());
        }
        let stats = reseq.stats(1).unwrap();
        assert_eq!(stats.packets_in_order, 100);
        assert_eq!(stats.packets_reordered, 0);
    }

    #[test]
    fn test_reordered_packets_restoration() {
        let now = Instant::now();
        let mut reseq = WgResequencer::new(1024, Duration::from_millis(5));
        let mut out = Vec::new();

        // Feed counters out of order: 1, 0, 3, 2
        reseq.push(1, 1, Bytes::from_static(b"p1"), now, &mut out);
        assert_eq!(out.len(), 0); // waiting for 0

        reseq.push(1, 0, Bytes::from_static(b"p0"), now, &mut out);
        assert_eq!(out.len(), 2); // 0 and 1 emitted!
        assert_eq!(out[0], Bytes::from_static(b"p0"));
        assert_eq!(out[1], Bytes::from_static(b"p1"));

        reseq.push(1, 3, Bytes::from_static(b"p3"), now, &mut out);
        assert_eq!(out.len(), 2); // waiting for 2

        reseq.push(1, 2, Bytes::from_static(b"p2"), now, &mut out);
        assert_eq!(out.len(), 4); // 2 and 3 emitted!
        assert_eq!(out[2], Bytes::from_static(b"p2"));
        assert_eq!(out[3], Bytes::from_static(b"p3"));

        let stats = reseq.stats(1).unwrap();
        assert_eq!(stats.packets_in_order, 2);
        assert_eq!(stats.packets_reordered, 2);
    }

    #[test]
    fn test_gap_timeout_skipping() {
        let start = Instant::now();
        let mut reseq = WgResequencer::new(1024, Duration::from_millis(5));
        let mut out = Vec::new();

        // Feed 0, then skip 1, feed 2
        reseq.push(1, 0, Bytes::from_static(b"p0"), start, &mut out);
        assert_eq!(out.len(), 1);

        reseq.push(1, 2, Bytes::from_static(b"p2"), start, &mut out);
        assert_eq!(out.len(), 1); // waiting for missing packet 1

        // Tick before timeout -> still waiting
        reseq.tick(start + Duration::from_millis(2), &mut out);
        assert_eq!(out.len(), 1);

        // Tick after timeout (6 ms) -> skips gap 1 and emits 2
        reseq.tick(start + Duration::from_millis(6), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1], Bytes::from_static(b"p2"));

        let stats = reseq.stats(1).unwrap();
        assert_eq!(stats.gaps_skipped_timeout, 1);
    }

    #[test]
    fn test_dual_receiver_index_isolation() {
        let now = Instant::now();
        let mut reseq = WgResequencer::new(1024, Duration::from_millis(5));
        let mut out = Vec::new();

        // Stream A (index 100) and Stream B (index 200) interleaved
        reseq.push(100, 0, Bytes::from_static(b"A0"), now, &mut out);
        reseq.push(200, 0, Bytes::from_static(b"B0"), now, &mut out);
        reseq.push(100, 1, Bytes::from_static(b"A1"), now, &mut out);
        reseq.push(200, 1, Bytes::from_static(b"B1"), now, &mut out);

        assert_eq!(out.len(), 4);
        assert_eq!(out[0], Bytes::from_static(b"A0"));
        assert_eq!(out[1], Bytes::from_static(b"B0"));
        assert_eq!(out[2], Bytes::from_static(b"A1"));
        assert_eq!(out[3], Bytes::from_static(b"B1"));
    }

    proptest! {
        #[test]
        fn prop_resequencer_arbitrary_permutation(
            count in 1usize..80
        ) {
            let mut shuffled: Vec<u64> = (0..count as u64).collect();
            // Deterministic pseudorandom shuffle
            for i in 0..shuffled.len() {
                let swap_idx = (i * 37 + 13) % shuffled.len();
                shuffled.swap(i, swap_idx);
            }

            let now = Instant::now();
            let mut reseq = WgResequencer::new(1024, Duration::from_millis(100));
            let mut out = Vec::new();

            for c in shuffled {
                let payload = Bytes::from(c.to_le_bytes().to_vec());
                reseq.push(42, c, payload, now, &mut out);
            }

            // All packets must be received
            prop_assert_eq!(out.len(), count);

            // Emitted counters must be strictly sorted 0..count
            for (expected, p) in out.iter().enumerate() {
                let c = u64::from_le_bytes(p.as_ref().try_into().unwrap());
                prop_assert_eq!(c, expected as u64);
            }
        }
    }
}
