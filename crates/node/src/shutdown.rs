use std::time::Duration;

use anyhow::Result;
use parking_lot::{Condvar, Mutex, const_mutex};

static DRAINED: Mutex<bool> = const_mutex(true);
static DRAINED_CVAR: Condvar = Condvar::new();

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
