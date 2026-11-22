//! Backend health: a pure state machine plus the active TCP prober.
//!
//! States: `Unknown` (never probed, not eligible), `Up`, `Down`. Rules, all counting
//! *consecutive* results so one blip never flips anything:
//!
//! * `Unknown` + success -> `Up` immediately (a fresh LB or a new backend should not sit out
//!   `rise` intervals); `Unknown` + `fall` failures -> `Down`.
//! * `Up` + `fall` failures -> `Down`.
//! * `Down` + `rise` successes -> `Up`.
//!
//! Real traffic feeds the same counters when passive checking is on: a failed connect to a backend
//! is a failure, a successful one a success. Only *connect-level* outcomes count; what a backend
//! does after the connection is established is the application's business (an L4 LB that
//! second-guessed payloads would be parsing them).
//!
//! Probing is a bounded TCP connect (and, if PROXY v2 is on, a PROXY `LOCAL` header, which is what
//! the protocol defines for proxy-originated health checks, so the backend does not log a
//! malformed connection every interval). Under DSR the LB never sees backend replies, which is
//! why probing is active at all (RFC 0031 open question 5): a half-open backend that accepts the
//! SYN but never serves is caught by the application-level probe the edge exposes behind the same
//! port, and by passive failures; a pure L4 connect cannot see it, and this is documented.

use crate::backend::HealthSpec;

/// Backend health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Not yet probed.
    Unknown,
    /// Taking new flows.
    Up,
    /// Not taking new flows.
    Down,
}

impl Health {
    /// Metric / log label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Health::Unknown => "unknown",
            Health::Up => "up",
            Health::Down => "down",
        }
    }
}

/// Consecutive-result tracker for one backend.
#[derive(Debug, Clone)]
pub struct HealthTracker {
    state: Health,
    ok_streak: u32,
    fail_streak: u32,
}

impl Default for HealthTracker {
    fn default() -> Self {
        HealthTracker {
            state: Health::Unknown,
            ok_streak: 0,
            fail_streak: 0,
        }
    }
}

impl HealthTracker {
    /// Current state.
    #[must_use]
    pub fn state(&self) -> Health {
        self.state
    }

    /// Feed one result. Returns `(from, to)` when the state changed.
    pub fn record(&mut self, ok: bool, spec: &HealthSpec) -> Option<(Health, Health)> {
        let from = self.state;
        if ok {
            self.fail_streak = 0;
            self.ok_streak = self.ok_streak.saturating_add(1);
            match self.state {
                Health::Unknown => self.state = Health::Up,
                Health::Down if self.ok_streak >= spec.rise => self.state = Health::Up,
                _ => {}
            }
        } else {
            self.ok_streak = 0;
            self.fail_streak = self.fail_streak.saturating_add(1);
            if self.state != Health::Down && self.fail_streak >= spec.fall {
                self.state = Health::Down;
            }
        }
        (from != self.state).then_some((from, self.state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(rise: u32, fall: u32) -> HealthSpec {
        HealthSpec {
            rise,
            fall,
            ..HealthSpec::default()
        }
    }

    #[test]
    fn unknown_goes_up_on_the_first_success() {
        let mut t = HealthTracker::default();
        assert_eq!(
            t.record(true, &spec(3, 3)),
            Some((Health::Unknown, Health::Up))
        );
    }

    #[test]
    fn unknown_goes_down_after_fall_failures_not_before() {
        let mut t = HealthTracker::default();
        assert_eq!(t.record(false, &spec(2, 3)), None);
        assert_eq!(t.record(false, &spec(2, 3)), None);
        assert_eq!(
            t.record(false, &spec(2, 3)),
            Some((Health::Unknown, Health::Down))
        );
    }

    #[test]
    fn up_needs_fall_consecutive_failures() {
        let mut t = HealthTracker::default();
        t.record(true, &spec(2, 3));
        assert_eq!(t.record(false, &spec(2, 3)), None);
        assert_eq!(t.record(false, &spec(2, 3)), None);
        // A success in the middle resets the streak.
        assert_eq!(t.record(true, &spec(2, 3)), None);
        assert_eq!(t.record(false, &spec(2, 3)), None);
        assert_eq!(t.record(false, &spec(2, 3)), None);
        assert_eq!(
            t.record(false, &spec(2, 3)),
            Some((Health::Up, Health::Down))
        );
    }

    #[test]
    fn down_needs_rise_consecutive_successes() {
        let mut t = HealthTracker::default();
        for _ in 0..3 {
            t.record(false, &spec(2, 3));
        }
        assert_eq!(t.state(), Health::Down);
        assert_eq!(t.record(true, &spec(2, 3)), None);
        // A failure resets the success streak.
        assert_eq!(t.record(false, &spec(2, 3)), None);
        assert_eq!(t.record(true, &spec(2, 3)), None);
        assert_eq!(
            t.record(true, &spec(2, 3)),
            Some((Health::Down, Health::Up))
        );
    }

    #[test]
    fn rise_and_fall_of_one_flip_immediately() {
        let mut t = HealthTracker::default();
        t.record(true, &spec(1, 1));
        assert_eq!(
            t.record(false, &spec(1, 1)),
            Some((Health::Up, Health::Down))
        );
        assert_eq!(
            t.record(true, &spec(1, 1)),
            Some((Health::Down, Health::Up))
        );
    }

    #[test]
    fn streak_counters_saturate_instead_of_overflowing() {
        let mut t = HealthTracker {
            state: Health::Up,
            ok_streak: u32::MAX,
            fail_streak: 0,
        };
        assert_eq!(t.record(true, &spec(2, 3)), None);
        let mut t = HealthTracker {
            state: Health::Down,
            ok_streak: 0,
            fail_streak: u32::MAX,
        };
        assert_eq!(t.record(false, &spec(2, 3)), None);
    }
}
