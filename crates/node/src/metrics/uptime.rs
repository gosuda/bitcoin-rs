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
