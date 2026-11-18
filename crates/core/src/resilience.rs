//! Reconnection policy for the tunnel datapaths.
//!
//! A tunnel rides a TURN allocation that can disappear for reasons outside our
//! control: the relay drops the allocation, the call ends, the network moves,
//! or the credentials expire. The datapaths used to treat any such event as
//! fatal and return an error, which took the whole tunnel down and left the
//! user without connectivity until they restarted the daemon.
//!
//! This module holds the policy that decides how long to wait before trying
//! again, so the datapaths only have to ask "when?" and "should I keep going?".

use std::time::Duration;

/// How many consecutive failures are tolerated before giving up.
///
/// A tunnel that cannot be re-established after this many attempts is more
/// likely misconfigured than unlucky, so the daemon should surface the error
/// rather than retry forever.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 12;

/// The first delay between reconnection attempts.
pub const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// The ceiling for the exponential backoff.
pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// A bounded exponential backoff with jitter.
///
/// The delay doubles on every attempt up to a ceiling. A small amount of
/// jitter is subtracted so that many clients reconnecting after a shared
/// outage do not retry in lockstep and hammer the relay at the same instant.
#[derive(Debug, Clone)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    max_attempts: u32,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(
            DEFAULT_INITIAL_BACKOFF,
            DEFAULT_MAX_BACKOFF,
            DEFAULT_MAX_ATTEMPTS,
        )
    }
}

impl Backoff {
    /// Creates a backoff with the given bounds.
    ///
    /// `max_attempts` of zero is treated as one, so a backoff always permits
    /// at least a single retry.
    #[must_use]
    pub fn new(initial: Duration, max: Duration, max_attempts: u32) -> Self {
        Self {
            initial,
            max: max.max(initial),
            max_attempts: max_attempts.max(1),
            attempt: 0,
        }
    }

    /// Returns how many attempts have been made so far.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempt
    }

    /// Returns true when no further attempt is allowed.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.attempt >= self.max_attempts
    }

    /// Records a failed attempt and returns the delay to wait before the next.
    ///
    /// Returns `None` once the attempt budget is spent, which tells the caller
    /// to stop retrying and report the failure.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.is_exhausted() {
            return None;
        }
        self.attempt += 1;

        // Shift by at most 20 to keep the multiplication in range; the ceiling
        // clamps the result long before that matters.
        let factor = 1u32 << self.attempt.saturating_sub(1).min(20);
        let scaled = self.initial.saturating_mul(factor).min(self.max);

        // Subtract up to 12.5% so retries spread out. The jitter is derived
        // from the attempt number rather than a random source, which keeps the
        // sequence reproducible in tests while still differing between
        // clients that started at different times.
        let jitter = scaled / 8;
        let offset = jitter.mul_f64(f64::from(self.attempt % 8) / 8.0);
        Some(scaled.saturating_sub(offset))
    }

    /// Clears the attempt counter after a successful reconnection.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// What a datapath should do after a transport failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// Reconnect and carry on.
    Retry,
    /// Give up and surface the error.
    GiveUp,
}

/// Decides whether a failed reconnection is worth another attempt.
///
/// The distinction that matters is between a transient fault and a permanent
/// one. A relay that refuses the allocation, or credentials that are rejected,
/// will refuse again just as readily on the next attempt, so retrying only
/// delays the error the user needs to see. A dropped connection, by contrast,
/// usually succeeds on the next try.
#[must_use]
pub fn classify(error: &str) -> Recovery {
    let lowered = error.to_ascii_lowercase();
    const PERMANENT: [&str; 8] = [
        "401",
        "unauthorized",
        "forbidden",
        "invalid credential",
        "allocation mismatch",
        "no such allocation",
        "unsupported",
        "certificate",
    ];
    if PERMANENT.iter().any(|needle| lowered.contains(needle)) {
        Recovery::GiveUp
    } else {
        Recovery::Retry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        let mut backoff = Backoff::new(Duration::from_millis(100), Duration::from_millis(800), 10);
        let first = backoff.next_delay().unwrap();
        let second = backoff.next_delay().unwrap();
        let third = backoff.next_delay().unwrap();
        let fourth = backoff.next_delay().unwrap();

        assert!(first <= Duration::from_millis(100));
        assert!(second > first);
        assert!(third > second);
        // The ceiling clamps every later delay.
        assert!(fourth <= Duration::from_millis(800));
        assert!(backoff.next_delay().unwrap() <= Duration::from_millis(800));
    }

    #[test]
    fn backoff_stops_at_the_attempt_limit() {
        let mut backoff = Backoff::new(Duration::from_millis(1), Duration::from_millis(2), 3);
        assert!(backoff.next_delay().is_some());
        assert!(backoff.next_delay().is_some());
        assert!(backoff.next_delay().is_some());
        assert!(backoff.is_exhausted());
        assert!(backoff.next_delay().is_none());
        assert_eq!(backoff.attempts(), 3);
    }

    #[test]
    fn reset_restores_the_full_budget() {
        let mut backoff = Backoff::new(Duration::from_millis(1), Duration::from_millis(2), 2);
        assert!(backoff.next_delay().is_some());
        assert!(backoff.next_delay().is_some());
        assert!(backoff.is_exhausted());

        backoff.reset();
        assert!(!backoff.is_exhausted());
        assert_eq!(backoff.attempts(), 0);
        assert!(backoff.next_delay().is_some());
    }

    #[test]
    fn zero_attempts_still_permits_one_retry() {
        let mut backoff = Backoff::new(Duration::from_millis(1), Duration::from_millis(2), 0);
        assert!(backoff.next_delay().is_some());
        assert!(backoff.next_delay().is_none());
    }

    #[test]
    fn a_ceiling_below_the_initial_delay_is_raised() {
        let mut backoff = Backoff::new(Duration::from_millis(500), Duration::from_millis(10), 4);
        let delay = backoff.next_delay().unwrap();
        assert!(delay <= Duration::from_millis(500));
    }

    #[test]
    fn permanent_failures_are_not_retried() {
        assert_eq!(classify("401 Unauthorized"), Recovery::GiveUp);
        assert_eq!(classify("invalid credential supplied"), Recovery::GiveUp);
        assert_eq!(classify("no such allocation"), Recovery::GiveUp);
        assert_eq!(classify("certificate verify failed"), Recovery::GiveUp);
    }

    #[test]
    fn transient_failures_are_retried() {
        assert_eq!(classify("connection reset by peer"), Recovery::Retry);
        assert_eq!(classify("broken pipe"), Recovery::Retry);
        assert_eq!(classify("timed out waiting for response"), Recovery::Retry);
        assert_eq!(classify("unexpected eof"), Recovery::Retry);
    }
}
