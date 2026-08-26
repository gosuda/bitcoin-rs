use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread::{self, JoinHandle};

use anyhow::Result;
use crossbeam_channel::Sender;
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

/// Installs SIGINT/SIGTERM handling on a dedicated forwarding thread.
///
/// The forwarding thread trips the unified shutdown trigger so the node-owned
/// flag is stored before the process-wide broadcast, then forwards into the
/// event-loop channel. Waiters parked in [`crate::shutdown::wait_for_shutdown`]
/// therefore wake at signal receipt even when that bounded channel is full.
pub fn install_shutdown_handler(
    shutdown: Arc<AtomicBool>,
    shutdown_tx: Sender<()>,
) -> Result<JoinHandle<()>> {
    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    let handle = thread::spawn(move || {
        for _signal in signals.forever() {
            crate::shutdown::trigger_shutdown(&shutdown);
            if shutdown_tx.try_send(()).is_err() {
                break;
            }
        }
    });
    Ok(handle)
}
