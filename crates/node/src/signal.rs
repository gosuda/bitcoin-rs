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

/// Installed console-ctrl targets plus every close-type dispatch still
/// owed teardown completions. One lock covers both fields so a dispatch is
/// registered before — never after — the event reaches the handlers, and a
/// teardown report resolves every dispatch that was waiting on it.
#[cfg(windows)]
static CONSOLE_REGISTRY: parking_lot::Mutex<ConsoleRegistry> =
    parking_lot::Mutex::new(ConsoleRegistry {
        handlers: Vec::new(),
        dispatches: Vec::new(),
    });

#[cfg(windows)]
struct ConsoleRegistry {
    handlers: Vec<(usize, Sender<u32>)>,
    dispatches: Vec<CloseDispatch>,
}

/// One close-type console event broadcast to every handler installed at
/// dispatch time. The console callback may return only after each of those
/// lifecycles reports its teardown: `pending` names the handler ids still
/// owed a completion.
#[cfg(windows)]
struct CloseDispatch {
    pending: std::collections::BTreeSet<usize>,
    done: Sender<()>,
}

#[cfg(windows)]
impl ConsoleRegistry {
    /// Marks `id`'s teardown as finished. Dispatches that were waiting on
    /// it stop blocking on it; any dispatch whose pending set empties is
    /// released and removed. A dispatch only ever waits on the handler set
    /// it broadcast to, so one lifecycle finishing cannot release a wait
    /// owed by another.
    fn teardown_completed(&mut self, id: usize) {
        self.dispatches.retain(|dispatch| {
            dispatch.pending.remove(&id);
            if dispatch.pending.is_empty() {
                let _ = dispatch.done.try_send(());
                return false;
            }
            true
        });
    }
}

#[cfg(windows)]
unsafe extern "system" fn win_console_ctrl_handler(ctrl_type: u32) -> i32 {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            let registry = CONSOLE_REGISTRY.lock();
            if registry.handlers.is_empty() {
                return 0;
            }
            for (_id, tx) in registry.handlers.iter() {
                let _ = tx.try_send(ctrl_type);
            }
            1
        }
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            let (done_tx, done_rx) = {
                let mut registry = CONSOLE_REGISTRY.lock();
                if registry.handlers.is_empty() {
                    return 0;
                }
                let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
                registry.dispatches.push(CloseDispatch {
                    pending: registry.handlers.iter().map(|(id, _)| *id).collect(),
                    done: done_tx.clone(),
                });
                for (_id, tx) in registry.handlers.iter() {
                    let _ = tx.try_send(ctrl_type);
                }
                (done_tx, done_rx)
            };
            // Windows terminates the process once the close/logoff/shutdown
            // callback returns. Wait until every dispatched lifecycle has
            // reported its teardown — checkpoint publication must finish —
            // bounded inside Windows' ~5 second close deadline.
            let _ = done_rx.recv_timeout(std::time::Duration::from_millis(4500));
            // On timeout the wait is abandoned: drop the stale dispatch so
            // later teardowns never release a receiver that is gone.
            let mut registry = CONSOLE_REGISTRY.lock();
            registry
                .dispatches
                .retain(|dispatch| !dispatch.done.same_channel(&done_tx));
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
            let mut registry = CONSOLE_REGISTRY.lock();
            if registry.handlers.is_empty() {
                // SAFETY: win_console_ctrl_handler is an extern "system" function pointer with the PHANDLER_ROUTINE signature.
                let success = unsafe { SetConsoleCtrlHandler(Some(win_console_ctrl_handler), 1) };
                if success == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            registry.handlers.push((id, ctrl_tx));
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

        let mut unregister_error = None;
        {
            let mut registry = CONSOLE_REGISTRY.lock();
            // Unregistering stops future events reaching this handler but
            // cannot release waits on it: the lifecycle's teardown (clean
            // checkpoint publication included) is still owed to any
            // dispatch that counted this handler.
            registry.handlers.retain(|(id, _)| *id != self.id);
            if registry.handlers.is_empty() {
                // SAFETY: unregistering the previously registered win_console_ctrl_handler function pointer.
                let success = unsafe { SetConsoleCtrlHandler(Some(win_console_ctrl_handler), 0) };
                if success == 0 {
                    unregister_error = Some(std::io::Error::last_os_error());
                }
            }
        }

        let join_result = match self.thread.take() {
            Some(thread) => {
                #[cfg(test)]
                testing::note_closed();
                thread
                    .join()
                    .map_err(|_| anyhow::anyhow!("signal forwarding thread panicked"))
            }
            None => Ok(()),
        };

        if let Some(error) = unregister_error {
            return Err(error.into());
        }
        join_result
    }
}

/// Reports `handler`'s lifecycle teardown as finished.
///
/// Windows may terminate the process as soon as a close-type console
/// callback returns, so the callback holds until every lifecycle it was
/// dispatched to has reported here through its own handler id.
#[cfg(windows)]
pub(crate) fn teardown_completed(handler: &ShutdownHandler) {
    CONSOLE_REGISTRY.lock().teardown_completed(handler.id);
}

/// No-op outside Windows: the signal worker exits independently of
/// teardown order.
#[cfg(not(windows))]
pub(crate) fn teardown_completed(_handler: &ShutdownHandler) {}

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

    /// Serializes the Windows console-ctrl tests: they share the
    /// process-global registry and console-handler slot, so the parallel
    /// test runner would let one test's teardown resolve another's wait.
    #[cfg(windows)]
    static SERIAL: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[cfg(windows)]
    #[test]
    fn windows_console_ctrl_triggers_shutdown() -> Result<()> {
        use windows_sys::Win32::System::Console::CTRL_C_EVENT;

        let _serial = SERIAL.lock();
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

    /// A close-type event must hold the console callback until EVERY
    /// lifecycle it was broadcast to has reported teardown: the first
    /// finisher cannot release a wait still owed by another handler.
    #[cfg(windows)]
    #[test]
    fn windows_console_ctrl_close_waits_for_every_dispatched_teardown() -> Result<()> {
        use windows_sys::Win32::System::Console::CTRL_CLOSE_EVENT;

        let _serial = SERIAL.lock();
        let shutdown_a = Arc::new(AtomicBool::new(false));
        let shutdown_b = Arc::new(AtomicBool::new(false));
        let (shutdown_tx_a, shutdown_rx_a) = crossbeam_channel::bounded::<()>(1);
        let (shutdown_tx_b, shutdown_rx_b) = crossbeam_channel::bounded::<()>(1);
        let mut handler_a = ShutdownHandler::install(Arc::clone(&shutdown_a), shutdown_tx_a)?;
        let mut handler_b = ShutdownHandler::install(Arc::clone(&shutdown_b), shutdown_tx_b)?;

        let (handler_done_tx, handler_done_rx) = crossbeam_channel::bounded::<i32>(1);
        std::thread::spawn(move || {
            // SAFETY: simulating a console close event callback.
            let handled = unsafe { win_console_ctrl_handler(CTRL_CLOSE_EVENT) };
            let _ = handler_done_tx.send(handled);
        });

        for (rx, flag) in [(&shutdown_rx_a, &shutdown_a), (&shutdown_rx_b, &shutdown_b)] {
            assert!(
                rx.recv_timeout(std::time::Duration::from_secs(1)).is_ok(),
                "CTRL_CLOSE_EVENT must wake every dispatched shutdown channel"
            );
            assert!(
                flag.load(Ordering::Acquire),
                "CTRL_CLOSE_EVENT must set every dispatched shutdown atomic"
            );
        }
        assert!(
            handler_done_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "callback must wait for teardown completions"
        );

        teardown_completed(&handler_a);
        assert!(
            handler_done_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "the first teardown must not release a wait still owed by another lifecycle"
        );

        teardown_completed(&handler_b);
        let Ok(handled) = handler_done_rx.recv_timeout(std::time::Duration::from_secs(1)) else {
            panic!("callback must return once every dispatched lifecycle tore down");
        };
        assert_eq!(handled, 1, "handler must return 1 for CTRL_CLOSE_EVENT");

        handler_a.close_and_join()?;
        handler_b.close_and_join()?;

        // SAFETY: simulating console event callback with no active handlers.
        let handled_empty = unsafe { win_console_ctrl_handler(CTRL_CLOSE_EVENT) };
        assert_eq!(
            handled_empty, 0,
            "console control handler must return 0 when no handlers are active"
        );

        Ok(())
    }
}
