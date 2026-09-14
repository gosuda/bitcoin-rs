use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use anyhow::Result;
use crossbeam_channel::Sender;
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

/// Owns the signal iterator and its forwarding thread.
///
/// Closing the iterator is required before joining: setting the node shutdown
/// flag alone does not wake `Signals::forever`, so dropping only its join
/// handle would leak a process-level signal worker. The lifecycle service
/// graph owns this handler from install until the shared teardown closes and
/// joins it, so no lifecycle leaks — or double-joins — the forwarding thread.
pub(crate) struct ShutdownHandler {
    handle: signal_hook::iterator::Handle,
    thread: Option<JoinHandle<()>>,
}

impl ShutdownHandler {
    /// Installs SIGINT/SIGTERM handling on a dedicated forwarding thread.
    pub(crate) fn install(shutdown: Arc<AtomicBool>, shutdown_tx: Sender<()>) -> Result<Self> {
        let mut signals = Signals::new([SIGTERM, SIGINT])?;
        let handle = signals.handle();
        let thread = thread::spawn(move || {
            for _signal in signals.forever() {
                // First signal flips the flag; later ones only re-wake.
                let _ =
                    shutdown.compare_exchange(false, true, Ordering::Release, Ordering::Acquire);
                if shutdown_tx.try_send(()).is_err() {
                    break;
                }
            }
        });
        #[cfg(test)]
        testing::note_installed();
        Ok(Self {
            handle,
            thread: Some(thread),
        })
    }

    /// Closes the signal iterator and joins the forwarding thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the forwarding thread panicked; the iterator is
    /// closed either way, so SIGINT/SIGTERM handling is released.
    pub(crate) fn close_and_join(&mut self) -> Result<()> {
        self.handle.close();
        match self.thread.take() {
            Some(thread) => {
                #[cfg(test)]
                testing::note_closed();
                thread
                    .join()
                    .map_err(|_| anyhow::anyhow!("signal forwarding thread panicked"))
            }
            None => Ok(()),
        }
    }
}

impl Drop for ShutdownHandler {
    fn drop(&mut self) {
        let _ = self.close_and_join();
    }
}

/// Per-thread install/close counters for the lifecycle regressions.
///
/// Installs and closes both happen on the lifecycle owner's thread, so the
/// counters measure exactly the handler a test installed — even while other
/// tests run their own lifecycles concurrently.
#[cfg(test)]
pub(crate) mod testing {
    use core::cell::Cell;

    thread_local! {
        static INSTALLED: Cell<usize> = const { Cell::new(0) };
        static CLOSED: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn note_installed() {
        INSTALLED.with(|count| count.set(count.get() + 1));
    }

    pub(crate) fn note_closed() {
        CLOSED.with(|count| count.set(count.get() + 1));
    }

    pub(crate) fn installed_total() -> usize {
        INSTALLED.with(Cell::get)
    }

    pub(crate) fn closed_total() -> usize {
        CLOSED.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Closing must release the forwarding thread promptly: `close_and_join`
    /// blocks forever if the iterator is not closed before the join, which
    /// is exactly the leak the handler exists to prevent.
    #[test]
    fn close_and_join_releases_the_forwarding_thread() -> Result<()> {
        let (shutdown_tx, _shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let mut handler = ShutdownHandler::install(Arc::new(AtomicBool::new(false)), shutdown_tx)?;
        assert!(handler.thread.is_some(), "the forwarding thread is running");

        handler.close_and_join()?;

        assert!(
            handler.thread.is_none(),
            "close_and_join must join and release the forwarding thread"
        );
        Ok(())
    }

    /// Repeated lifecycles must each acquire and release the process-level
    /// signal handling: a second install after a close must work and close
    /// again, which is what lets a host run several node lifetimes without
    /// inheriting a stale handler from the previous one.
    #[test]
    fn signal_handler_supports_repeated_lifecycles() -> Result<()> {
        let installed_before = testing::installed_total();
        let closed_before = testing::closed_total();

        for _ in 0..2 {
            let (shutdown_tx, _shutdown_rx) = crossbeam_channel::bounded::<()>(1);
            let mut handler =
                ShutdownHandler::install(Arc::new(AtomicBool::new(false)), shutdown_tx)?;
            handler.close_and_join()?;
        }

        assert_eq!(
            testing::installed_total(),
            installed_before + 2,
            "each lifecycle installs exactly one handler"
        );
        assert_eq!(
            testing::closed_total(),
            closed_before + 2,
            "each lifecycle must close and join its handler"
        );
        Ok(())
    }
}
