//! The node-owned origin for monotonic process uptime.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Monotonic process start, recorded once at node startup.
///
/// Core initializes its uptime clock at process start (`GetUptime`,
/// `src/common/system.cpp`), so every later query reports true elapsed
/// runtime. A lazily initialized clock would restart on first read, which is
/// the first-call-reports-approximately-zero bug the utility parity audit
/// records for `uptime`; the earliest-wins record here makes the node, not
/// the first RPC caller, own the origin.
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

/// Records the authoritative process start instant for uptime accounting.
///
/// Idempotent and earliest-wins: the first caller fixes the uptime origin,
/// mirroring Core's static initialization. `run` records this before wiring
/// subsystems so the clock covers the whole node lifecycle.
pub fn record_process_start(start: Instant) {
    let _ = PROCESS_START.set(start);
}

/// Returns the recorded process start instant, or `None` before
/// [`record_process_start`] has run.
#[must_use]
pub fn process_start() -> Option<Instant> {
    PROCESS_START.get().copied()
}

/// Returns monotonic uptime since the recorded process start, or `None`
/// before [`record_process_start`] has run.
///
/// `None` keeps the not-yet-started state observable instead of silently
/// restarting the clock on read.
#[must_use]
pub fn process_uptime() -> Option<Duration> {
    PROCESS_START.get().map(Instant::elapsed)
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn process_start_is_recorded_once_and_uptime_advances() {
        record_process_start(Instant::now());
        let first = process_start();
        let before = process_uptime();

        thread::sleep(Duration::from_millis(25));
        // A second record must not move the clock — earliest-wins is what
        // makes the node, rather than the latest caller, own the origin.
        record_process_start(Instant::now());

        assert_eq!(
            process_start(),
            first,
            "a second record_process_start must not move the start instant"
        );
        let Some(before) = before else {
            panic!("uptime must be observable after record_process_start");
        };
        let after = process_uptime().unwrap_or_else(|| panic!("uptime must stay observable"));
        assert!(
            after >= before + Duration::from_millis(20),
            "uptime must advance with elapsed time: {before:?} -> {after:?}"
        );
    }
}
