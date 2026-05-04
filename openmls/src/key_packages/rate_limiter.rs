//! # In-memory `KeyPackageFetchRateLimiter` (server-side scaffold)
//!
//! KChat servers must rate-limit PQ KeyPackage fetches and Welcome fanout
//! to keep storage bounded and to slow down resource-exhaustion attacks.
//! See [`PHASES.md`](../../../PHASES.md) "Server Components — Abuse / rate
//! limit".
//!
//! This module provides a sliding-window rate limiter keyed by
//! `(user_id, device_id)`. Each `check_and_record` call:
//!
//! 1. drops timestamps that fell out of the configured window,
//! 2. checks whether adding *this* fetch would exceed
//!    `max_fetches_per_window`,
//! 3. records the new timestamp on success, or returns
//!    [`RateLimitError::Exceeded`] on failure.
//!
//! The limiter is in-memory only — production servers should keep this
//! shape but back it with a TTL'd cache (e.g. Redis) so per-pod state
//! does not hide bursts.

use std::collections::HashMap;

/// Errors returned by [`KeyPackageFetchRateLimiter::check_and_record`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RateLimitError {
    /// Fetcher exceeded the configured per-`(user_id, device_id)` cap
    /// over the configured sliding window.
    #[error("device {user_id:?}/{device_id:?} exceeded {limit} fetches per {window_secs}s window")]
    Exceeded {
        /// User identifier as opaque bytes.
        user_id: Vec<u8>,
        /// Device identifier as opaque bytes.
        device_id: Vec<u8>,
        /// Configured fetch cap.
        limit: usize,
        /// Configured sliding-window length, in seconds.
        window_secs: u64,
    },
}

/// Composite key identifying a device.
type DeviceKey = (Vec<u8>, Vec<u8>);

/// Sliding-window rate limiter for KeyPackage fetches.
///
/// Construct one limiter per server with an explicit cap and window
/// length. A typical configuration is `max_fetches_per_window = 60`,
/// `window_duration_secs = 60` (1 fetch/sec average burst headroom).
#[derive(Debug)]
pub struct KeyPackageFetchRateLimiter {
    /// Maximum number of fetches a device can issue inside any
    /// `window_duration_secs`-length window.
    pub max_fetches_per_window: usize,
    /// Sliding window duration, in seconds.
    pub window_duration_secs: u64,
    fetches: HashMap<DeviceKey, Vec<u64>>,
}

impl KeyPackageFetchRateLimiter {
    /// Construct a new limiter with the configured cap and window.
    pub fn new(max_fetches_per_window: usize, window_duration_secs: u64) -> Self {
        Self {
            max_fetches_per_window,
            window_duration_secs,
            fetches: HashMap::new(),
        }
    }

    /// Check whether `(user_id, device_id)` can issue another fetch at
    /// `now_secs`, and record the fetch on success. Drops any timestamps
    /// that have aged out of the window before the check.
    pub fn check_and_record(
        &mut self,
        user_id: &[u8],
        device_id: &[u8],
        now_secs: u64,
    ) -> Result<(), RateLimitError> {
        let window = self.window_duration_secs;
        let cap = self.max_fetches_per_window;
        let key: DeviceKey = (user_id.to_vec(), device_id.to_vec());
        let entry = self.fetches.entry(key.clone()).or_default();
        // Drop expired timestamps. `saturating_sub` so we don't
        // underflow when `now_secs < window`.
        let cutoff = now_secs.saturating_sub(window);
        entry.retain(|t| *t >= cutoff);

        if entry.len() >= cap {
            return Err(RateLimitError::Exceeded {
                user_id: key.0,
                device_id: key.1,
                limit: cap,
                window_secs: window,
            });
        }

        entry.push(now_secs);
        Ok(())
    }

    /// Reset the recorded fetches for a single device. Intended for
    /// tests; production servers typically don't reset state explicitly.
    pub fn reset(&mut self, user_id: &[u8], device_id: &[u8]) {
        self.fetches.remove(&(user_id.to_vec(), device_id.to_vec()));
    }

    /// Number of devices currently tracked (each with at least one
    /// recorded fetch).
    pub fn tracked_devices(&self) -> usize {
        self.fetches.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_limit_is_accepted() {
        let mut rl = KeyPackageFetchRateLimiter::new(3, 60);
        for t in [0_u64, 5, 30] {
            rl.check_and_record(b"alice", b"phone", t)
                .expect("under limit");
        }
        assert_eq!(rl.tracked_devices(), 1);
    }

    #[test]
    fn at_limit_rejects_next_fetch() {
        let mut rl = KeyPackageFetchRateLimiter::new(2, 60);
        rl.check_and_record(b"alice", b"phone", 0).unwrap();
        rl.check_and_record(b"alice", b"phone", 5).unwrap();

        let err = rl
            .check_and_record(b"alice", b"phone", 30)
            .expect_err("third fetch must be rejected");
        match err {
            RateLimitError::Exceeded {
                limit,
                window_secs,
                user_id,
                device_id,
            } => {
                assert_eq!(limit, 2);
                assert_eq!(window_secs, 60);
                assert_eq!(user_id, b"alice".to_vec());
                assert_eq!(device_id, b"phone".to_vec());
            }
        }
    }

    #[test]
    fn window_expiry_allows_new_fetches() {
        let mut rl = KeyPackageFetchRateLimiter::new(2, 60);
        rl.check_and_record(b"alice", b"phone", 0).unwrap();
        rl.check_and_record(b"alice", b"phone", 5).unwrap();

        // Both initial fetches age out by t = 100. The next call
        // should succeed.
        rl.check_and_record(b"alice", b"phone", 100)
            .expect("post-window fetch ok");

        // And we should be back at one recorded timestamp.
        let entry = rl
            .fetches
            .get(&(b"alice".to_vec(), b"phone".to_vec()))
            .unwrap();
        assert_eq!(entry.len(), 1);
        assert_eq!(entry[0], 100);
    }

    #[test]
    fn limits_are_per_device() {
        let mut rl = KeyPackageFetchRateLimiter::new(1, 60);
        rl.check_and_record(b"alice", b"phone", 0).unwrap();
        // Same user, different device — still under limit.
        rl.check_and_record(b"alice", b"laptop", 0).unwrap();
        // Different user, same device id — also under limit.
        rl.check_and_record(b"bob", b"phone", 0).unwrap();

        // But a second fetch for (alice, phone) inside the window
        // fails.
        assert!(rl.check_and_record(b"alice", b"phone", 1).is_err());
    }

    #[test]
    fn reset_clears_a_specific_device_only() {
        let mut rl = KeyPackageFetchRateLimiter::new(1, 60);
        rl.check_and_record(b"alice", b"phone", 0).unwrap();
        rl.check_and_record(b"bob", b"phone", 0).unwrap();

        rl.reset(b"alice", b"phone");

        // Alice can fetch again; Bob is still at-limit.
        rl.check_and_record(b"alice", b"phone", 1)
            .expect("alice reset works");
        assert!(rl.check_and_record(b"bob", b"phone", 1).is_err());
    }

    #[test]
    fn small_window_with_zero_cap_rejects_immediately() {
        let mut rl = KeyPackageFetchRateLimiter::new(0, 60);
        let err = rl
            .check_and_record(b"alice", b"phone", 0)
            .expect_err("zero cap means every fetch is rejected");
        assert!(matches!(err, RateLimitError::Exceeded { limit: 0, .. }));
    }

    #[test]
    fn timestamps_at_window_boundary_count_as_in_window() {
        // window = 10, cap = 1. Fetch at t=0, then fetch at t=10:
        //   cutoff = 10 - 10 = 0, entry has [0], 0 >= 0, retained
        //   → over cap.
        // Fetch at t=11: cutoff = 1, [0] dropped, ok.
        let mut rl = KeyPackageFetchRateLimiter::new(1, 10);
        rl.check_and_record(b"alice", b"phone", 0).unwrap();
        let err = rl
            .check_and_record(b"alice", b"phone", 10)
            .expect_err("boundary inclusive");
        assert!(matches!(err, RateLimitError::Exceeded { .. }));
        rl.check_and_record(b"alice", b"phone", 11)
            .expect("just past window");
    }
}
