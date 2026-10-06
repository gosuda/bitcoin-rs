use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use anyhow::Result;
use crossbeam_channel::Sender;

#[cfg(not(windows))]
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
#[cfg(not(windows))]
pub(crate) struct ShutdownHandler {
    handle: signal_hook::iterator::Handle,
    thread: Option<JoinHandle<()>>,
}

#[cfg(windows)]
pub(crate) struct ShutdownHandler {
    id: usize,
    thread: Option<JoinHandle<()>>,
}

#[cfg(not(windows))]
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

#[cfg(windows)]
static NEXT_HANDLER_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

#[cfg(windows)]
static ACTIVE_HANDLERS: parking_lot::Mutex<Vec<(usize, Sender<u32>)>> =
    parking_lot::Mutex::new(Vec::new());

#[cfg(windows)]
unsafe extern "system" fn win_console_ctrl_handler(ctrl_type: u32) -> i32 {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT
        | CTRL_SHUTDOWN_EVENT => {
            let handlers = ACTIVE_HANDLERS.lock();
            for (_id, tx) in handlers.iter() {
                let _ = tx.try_send(ctrl_type);
            }
            1
        }
        _ => 0,
    }
}

#[cfg(windows)]
impl ShutdownHandler {
    pub(crate) fn install(shutdown: Arc<AtomicBool>, shutdown_tx: Sender<()>) -> Result<Self> {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

        let id = NEXT_HANDLER_ID.fetch_add(1, Ordering::Relaxed);
        let (ctrl_tx, ctrl_rx) = crossbeam_channel::bounded::<u32>(1);

        {
            let mut handlers = ACTIVE_HANDLERS.lock();
            if handlers.is_empty() {
                // SAFETY: win_console_ctrl_handler is an extern "system" function pointer with the PHANDLER_ROUTINE signature.
                let success = unsafe { SetConsoleCtrlHandler(Some(win_console_ctrl_handler), 1) };
                if success == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            handlers.push((id, ctrl_tx));
        }

        let thread = thread::spawn(move || {
            for _ctrl in ctrl_rx {
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
            id,
            thread: Some(thread),
        })
    }

    pub(crate) fn close_and_join(&mut self) -> Result<()> {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

        {
            let mut handlers = ACTIVE_HANDLERS.lock();
            handlers.retain(|(id, _)| *id != self.id);
            if handlers.is_empty() {
                // SAFETY: unregistering the previously registered win_console_ctrl_handler function pointer.
                let _ = unsafe { SetConsoleCtrlHandler(Some(win_console_ctrl_handler), 0) };
            }
        }

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

    #[cfg(windows)]
    #[test]
    fn windows_console_ctrl_triggers_shutdown() -> Result<()> {
        use windows_sys::Win32::System::Console::CTRL_C_EVENT;

        let shutdown = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let mut handler = ShutdownHandler::install(Arc::clone(&shutdown), shutdown_tx)?;

        // SAFETY: simulating a console event callback into the registered handler.
        let handled = unsafe { win_console_ctrl_handler(CTRL_C_EVENT) };
        assert_eq!(
            handled, 1,
            "console control handler must handle CTRL_C_EVENT"
        );

        assert!(
            shutdown_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .is_ok(),
            "CTRL_C_EVENT must wake shutdown channel"
        );
        assert!(
            shutdown.load(Ordering::Acquire),
            "CTRL_C_EVENT must set shutdown atomic"
        );

        handler.close_and_join()?;
        Ok(())
    }
}
