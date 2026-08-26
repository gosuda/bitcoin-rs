use std::time::Duration;

use anyhow::Result;
use parking_lot::{Condvar, Mutex, const_mutex};

static DRAINED: Mutex<bool> = const_mutex(true);
static DRAINED_CVAR: Condvar = Condvar::new();

/// Broadcast state for a shutdown request.
///
/// Split from the process-wide static as a type so the request/wake contract
/// is testable on isolated instances; the free functions delegate to the one
/// process-wide instance.
struct ShutdownBroadcast {
    requested: Mutex<bool>,
    wake: Condvar,
}

impl ShutdownBroadcast {
    const fn new() -> Self {
        Self {
            requested: const_mutex(false),
            wake: Condvar::new(),
        }
    }

    /// Marks the request and wakes every parked waiter.
    fn request(&self) {
        let mut requested = self.requested.lock();
        *requested = true;
        self.wake.notify_all();
    }

    fn requested(&self) -> bool {
        *self.requested.lock()
    }

    /// Parks until the request arrives or `deadline` elapses.
    ///
    /// Returns whether shutdown is requested; a request that raced ahead of
    /// the park is observed through the flag, so no wake can be lost.
    fn wait_for(&self, deadline: Duration) -> bool {
        let mut requested = self.requested.lock();
        if *requested {
            return true;
        }
        let _timed_out = self.wake.wait_for(&mut requested, deadline);
        *requested
    }
}

static SHUTDOWN: ShutdownBroadcast = ShutdownBroadcast::new();

/// Marks subsystem draining as active.
pub(crate) fn mark_draining() {
    *DRAINED.lock() = false;
}

/// Notifies waiters that all v1 tick subsystems have drained.
pub(crate) fn notify_drained() {
    *DRAINED.lock() = true;
    DRAINED_CVAR.notify_all();
}

/// Waits for subsystem drain notification or the shutdown deadline.
pub fn drain_and_shutdown(deadline: Duration) -> Result<()> {
    let mut drained = DRAINED.lock();
    if !*drained {
        let _timeout = DRAINED_CVAR.wait_for(&mut drained, deadline);
    }
    Ok(())
}

/// Marks shutdown as requested and wakes every [`wait_for_shutdown`] waiter.
///
/// Idempotent. Long-poll style waiters block in [`wait_for_shutdown`] and must
/// observe a shutdown decision the moment it is made — not at their next
/// timeout slice — which is the wake Core's shutdown sequence gives its own
/// long-lived waiters. Every code path that decides to shut the node down
/// (signal thread, event loop exit, fatal subsystem failure) calls this.
pub fn request_shutdown() {
    SHUTDOWN.request();
}

/// Returns whether shutdown has been requested.
#[must_use]
pub fn shutdown_requested() -> bool {
    SHUTDOWN.requested()
}

/// Blocks until shutdown is requested or `deadline` elapses.
///
/// Returns `true` when shutdown is (or became) requested; `false` only when
/// the deadline elapsed without a request.
pub fn wait_for_shutdown(deadline: Duration) -> bool {
    SHUTDOWN.wait_for(deadline)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use super::ShutdownBroadcast;

    #[test]
    fn request_wakes_a_blocked_waiter() {
        let broadcast = Arc::new(ShutdownBroadcast::new());
        let waiter = {
            let broadcast = Arc::clone(&broadcast);
            thread::spawn(move || broadcast.wait_for(Duration::from_secs(30)))
        };

        thread::sleep(Duration::from_millis(25));
        broadcast.request();

        // The waiter parks for 30s; only the wake can return it promptly, so
        // joining at all proves the wake fired.
        assert!(
            waiter.join().unwrap_or(false),
            "waiter must wake on request rather than time out"
        );
    }

    #[test]
    fn wait_for_times_out_when_never_requested() {
        let broadcast = ShutdownBroadcast::new();

        assert!(!broadcast.wait_for(Duration::from_millis(25)));
    }

    #[test]
    fn request_is_idempotent_and_pre_requested_wait_returns_immediately() {
        let broadcast = ShutdownBroadcast::new();

        broadcast.request();
        broadcast.request();

        assert!(broadcast.requested());
        assert!(broadcast.wait_for(Duration::ZERO));
    }

    #[test]
    fn process_wide_functions_share_one_registry() {
        super::request_shutdown();

        assert!(super::shutdown_requested());
        assert!(super::wait_for_shutdown(Duration::ZERO));
    }
}
