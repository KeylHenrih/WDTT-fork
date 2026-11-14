use crate::error::CryptoError;

/// Number of 64-bit words in the sliding bitmap (32 * 64 = 2048 packets).
pub const REPLAY_WINDOW_WORDS: usize = 32;

/// Anti-replay window capacity in packets (RFC 6479).
pub const REPLAY_WINDOW_SIZE: u64 = (REPLAY_WINDOW_WORDS as u64) * 64;

/// Constant-time anti-replay sliding bitmask window (RFC 6479).
/// Zero heap allocations during operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiReplayWindow {
    bitmap: [u64; REPLAY_WINDOW_WORDS],
    last_seq: u64,
    initialized: bool,
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayWindow {
    /// Create a fresh anti-replay window starting at sequence 0.
    pub const fn new() -> Self {
        Self {
            bitmap: [0u64; REPLAY_WINDOW_WORDS],
            last_seq: 0,
            initialized: false,
        }
    }

    /// Reset anti-replay window state (e.g. after rekeying).
    pub fn reset(&mut self) {
        self.bitmap = [0u64; REPLAY_WINDOW_WORDS];
        self.last_seq = 0;
        self.initialized = false;
    }

    /// Check if a packet sequence counter is valid (not replayed and within window),
    /// and if valid, atomically mark it as seen.
    ///
    /// Returns `Ok(())` if accepted, or `Err(CryptoError::ReplayDetected)` if rejected.
    pub fn check_and_update(&mut self, seq: u64) -> Result<(), CryptoError> {
        if !self.initialized {
            self.initialized = true;
            self.last_seq = seq;
            self.bitmap[0] = 1;
            return Ok(());
        }

        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff < REPLAY_WINDOW_SIZE {
                self.shift_bitmap(diff as usize);
                self.bitmap[0] |= 1;
            } else {
                // Large forward jump exceeding entire window capacity: reset bitmap
                self.bitmap = [0u64; REPLAY_WINDOW_WORDS];
                self.bitmap[0] = 1;
            }
            self.last_seq = seq;
            Ok(())
        } else {
            let diff = self.last_seq - seq;
            if diff >= REPLAY_WINDOW_SIZE {
                return Err(CryptoError::ReplayDetected { counter: seq });
            }

            let word_idx = (diff / 64) as usize;
            let bit_idx = (diff % 64) as usize;
            let mask = 1u64 << bit_idx;

            if (self.bitmap[word_idx] & mask) != 0 {
                return Err(CryptoError::ReplayDetected { counter: seq });
            }

            self.bitmap[word_idx] |= mask;
            Ok(())
        }
    }

    /// Shift bitmap right by `shift` bits (representing advance of `last_seq`).
    #[inline]
    fn shift_bitmap(&mut self, shift: usize) {
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift >= REPLAY_WINDOW_WORDS {
            self.bitmap = [0u64; REPLAY_WINDOW_WORDS];
            return;
        }

        // Shift whole words backwards
        if word_shift > 0 {
            for i in (word_shift..REPLAY_WINDOW_WORDS).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
            for i in 0..word_shift {
                self.bitmap[i] = 0;
            }
        }

        // Shift remaining intra-word bits
        if bit_shift > 0 {
            let mut carry = 0u64;
            for word in &mut self.bitmap {
                let next_carry = *word >> (64 - bit_shift);
                *word = (*word << bit_shift) | carry;
                carry = next_carry;
            }
        }
    }

    /// Highest sequence counter accepted so far.
    #[inline]
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sequential_packets() {
        let mut window = AntiReplayWindow::new();
        for i in 0..5000 {
            assert!(window.check_and_update(i).is_ok());
        }
        assert_eq!(window.last_seq(), 4999);
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut window = AntiReplayWindow::new();
        assert!(window.check_and_update(100).is_ok());
        assert_eq!(
            window.check_and_update(100),
            Err(CryptoError::ReplayDetected { counter: 100 })
        );
    }

    #[test]
    fn test_out_of_order_within_window() {
        let mut window = AntiReplayWindow::new();
        assert!(window.check_and_update(50).is_ok());
        assert!(window.check_and_update(40).is_ok());
        assert!(window.check_and_update(45).is_ok());
        assert!(window.check_and_update(49).is_ok());
        assert!(window.check_and_update(51).is_ok());

        // Replaying 45 should fail
        assert_eq!(
            window.check_and_update(45),
            Err(CryptoError::ReplayDetected { counter: 45 })
        );
    }

    #[test]
    fn test_old_packet_beyond_window() {
        let mut window = AntiReplayWindow::new();
        assert!(window.check_and_update(3000).is_ok());

        // 3000 - 2048 = 952. Anything <= 952 is outside window
        assert_eq!(
            window.check_and_update(900),
            Err(CryptoError::ReplayDetected { counter: 900 })
        );

        // 953 is within window and hasn't been seen
        assert!(window.check_and_update(953).is_ok());
    }

    proptest! {
        #[test]
        fn prop_anti_replay_no_duplicates(
            seqs in prop::collection::vec(0u64..3000, 100)
        ) {
            let mut window = AntiReplayWindow::new();
            let mut accepted = std::collections::HashSet::new();

            for seq in seqs {
                let res = window.check_and_update(seq);
                if accepted.contains(&seq) {
                    prop_assert!(res.is_err(), "Duplicate {seq} was accepted!");
                } else if res.is_ok() {
                    accepted.insert(seq);
                }
            }
        }
    }
}
