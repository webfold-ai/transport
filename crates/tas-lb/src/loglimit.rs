//! A tiny rate limiter for log lines that an attacker can trigger.
//!
//! Refusals are counted in metrics (unbounded, cheap); the log line that names the offending
//! source is rate limited so a flood of spoofed headers or over-limit connects cannot also be a
//! flood of log volume.

use std::sync::Mutex;

use crate::flows::lock;

/// Allows at most `per_sec` events per wall-clock second.
#[derive(Debug)]
pub struct LogLimiter {
    per_sec: u32,
    window: Mutex<(u64, u32)>,
}

impl LogLimiter {
    /// A limiter allowing `per_sec` events per second.
    #[must_use]
    pub fn new(per_sec: u32) -> Self {
        LogLimiter {
            per_sec,
            window: Mutex::new((0, 0)),
        }
    }

    /// Whether an event at `now_sec` may be logged.
    pub fn allow(&self, now_sec: u64) -> bool {
        let mut w = lock(&self.window);
        if w.0 != now_sec {
            *w = (now_sec, 0);
        }
        if w.1 >= self.per_sec {
            return false;
        }
        w.1 += 1;
        true
    }
}

/// Wall-clock seconds since the epoch (0 if the clock is before it).
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_per_second_and_resets() {
        let l = LogLimiter::new(2);
        assert!(l.allow(1) && l.allow(1));
        assert!(!l.allow(1));
        assert!(l.allow(2));
    }
}
