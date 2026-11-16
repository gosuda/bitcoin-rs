use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

type Hook = Box<dyn FnOnce() + Send + 'static>;

struct Shared {
    triggered: AtomicBool,
    wake_tx: Mutex<Option<Sender<()>>>,
    wake_rx: Receiver<()>,
    hooks: Mutex<Option<Vec<(u64, Hook)>>>,
    next_id: AtomicU64,
    parent_guard: Mutex<Option<HookGuard>>,
}

impl Shared {
    fn new() -> Self {
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(0);
        Self {
            triggered: AtomicBool::new(false),
            wake_tx: Mutex::new(Some(wake_tx)),
            wake_rx,
            hooks: Mutex::new(Some(Vec::new())),
            next_id: AtomicU64::new(0),
            parent_guard: Mutex::new(None),
        }
    }

    fn trigger(&self) {
        self.trigger_deferred()();
    }

    fn trigger_deferred(&self) -> impl FnOnce() + use<> {
        let pending = if self.triggered.load(Ordering::Acquire) {
            None
        } else {
            let mut hooks_guard = self.hooks.lock();
            if self.triggered.swap(true, Ordering::Release) {
                None
            } else {
                drop(self.wake_tx.lock().take());
                let guard = self.parent_guard.lock().take();
                Some((hooks_guard.take().unwrap_or_default(), guard))
            }
        };
        move || {
            if let Some((hooks_to_run, parent_guard)) = pending {
                drop(parent_guard);
                for (_id, hook) in hooks_to_run {
                    hook();
                }
            }
        }
    }

    fn remove_hook(&self, id: u64) {
        let mut guard = self.hooks.lock();
        if let Some(hooks) = guard.as_mut() {
            if let Some(pos) = hooks.iter().position(|(hook_id, _)| *hook_id == id) {
                drop(hooks.swap_remove(pos));
            }
        }
    }

    #[cfg(test)]
    fn hook_count(&self) -> usize {
        self.hooks.lock().as_ref().map_or(0, Vec::len)
    }
}

fn register_hook(shared: &Arc<Shared>, hook: Hook) -> HookGuard {
    if shared.triggered.load(Ordering::Acquire) {
        hook();
        return HookGuard::inert();
    }
    let mut guard = shared.hooks.lock();
    if shared.triggered.load(Ordering::Acquire) {
        drop(guard);
        hook();
        return HookGuard::inert();
    }
    if let Some(hooks) = guard.as_mut() {
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        hooks.push((id, hook));
        HookGuard {
            shared: Arc::downgrade(shared),
            id: Some(id),
        }
    } else {
        drop(guard);
        hook();
        HookGuard::inert()
    }
}

/// Cancellation token writer representing the trigger side of a one-way latch.
///
/// Invariants:
/// - One-way latch: Once triggered, the latch never resets and remains triggered.
/// - Hook-once: Any registered cancellation hook is executed exactly once
///   outside the internal lock. Dropping a writer does not trigger the latch.
pub struct LatchWriter {
    shared: Arc<Shared>,
}

impl fmt::Debug for LatchWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LatchWriter")
            .field("triggered", &self.shared.triggered.load(Ordering::Acquire))
            .finish()
    }
}

impl Default for LatchWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl LatchWriter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared::new()),
        }
    }

    #[must_use]
    pub fn reader(&self) -> LatchReader {
        LatchReader {
            shared: Arc::clone(&self.shared),
        }
    }

    pub fn trigger(&self) {
        self.shared.trigger();
    }

    /// The latch is triggered and waiters are woken before return. The caller must
    /// release external locks before it calls the returned function to run the hooks.
    #[must_use = "call after releasing external locks to run cancellation hooks"]
    pub fn trigger_deferred(&self) -> impl FnOnce() + use<> {
        self.shared.trigger_deferred()
    }

    #[cfg(test)]
    #[must_use]
    pub fn hook_count(&self) -> usize {
        self.shared.hook_count()
    }
}

/// Cancellation token reader representing the observation side of a one-way latch.
///
/// Invariants:
/// - One-way latch: Once triggered, the latch never resets and all subsequent
///   reads observe the triggered state.
/// - Hook-once: Registered hooks execute at most once upon triggering, or
///   immediately if already triggered. Dropping a guard before trigger ensures
///   the hook never runs.
#[derive(Clone)]
pub struct LatchReader {
    shared: Arc<Shared>,
}

impl fmt::Debug for LatchReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LatchReader")
            .field("triggered", &self.is_triggered())
            .finish()
    }
}

impl LatchReader {
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.shared.triggered.load(Ordering::Acquire)
    }

    /// Returns a receiver that disconnects when the latch triggers.
    #[must_use]
    pub fn closed(&self) -> &Receiver<()> {
        &self.shared.wake_rx
    }

    pub fn on_cancel(&self, hook: impl FnOnce() + Send + 'static) -> HookGuard {
        register_hook(&self.shared, Box::new(hook))
    }

    #[must_use]
    pub fn child(&self) -> LatchWriter {
        let child_writer = LatchWriter::new();
        let weak_child = Arc::downgrade(&child_writer.shared);
        let guard = register_hook(
            &self.shared,
            Box::new(move || {
                if let Some(child) = weak_child.upgrade() {
                    child.trigger();
                }
            }),
        );
        *child_writer.shared.parent_guard.lock() = Some(guard);
        child_writer
    }

    #[must_use]
    pub fn fixture_never() -> Self {
        LatchWriter::new().reader()
    }

    #[cfg(test)]
    #[must_use]
    pub fn hook_count(&self) -> usize {
        self.shared.hook_count()
    }
}

#[derive(Debug)]
pub struct HookGuard {
    shared: Weak<Shared>,
    id: Option<u64>,
}

impl HookGuard {
    #[must_use]
    pub const fn inert() -> Self {
        Self {
            shared: Weak::new(),
            id: None,
        }
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            if let Some(shared) = self.shared.upgrade() {
                shared.remove_hook(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use crossbeam_channel::Receiver;

    use super::{HookGuard, LatchReader, LatchWriter};

    fn spawn_with_timeout<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(
        f: F,
    ) -> (JoinHandle<()>, Receiver<T>) {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let handle = std::thread::spawn(move || {
            let res = f();
            let _ = tx.send(res);
        });
        (handle, rx)
    }

    fn join_timeout<T>(handle: JoinHandle<()>, rx: &Receiver<T>) -> T {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(val) => {
                assert!(handle.join().is_ok(), "thread panicked");
                val
            }
            Err(_) => {
                if handle.is_finished() {
                    assert!(handle.join().is_ok(), "thread panicked");
                }
                panic!("join deadline exceeded: thread did not complete within 5 seconds");
            }
        }
    }

    #[test]
    fn select_wakes_on_trigger() {
        let writer = LatchWriter::new();
        let reader = writer.reader();
        let (handle, rx) = spawn_with_timeout(move || {
            let never = crossbeam_channel::never::<()>();
            crossbeam_channel::select! {
                recv(reader.closed()) -> _ => true,
                recv(never) -> _ => false,
            }
        });
        writer.trigger();
        let result = join_timeout(handle, &rx);
        assert!(result);
    }

    #[test]
    fn trigger_is_idempotent_and_clones_observe_true() {
        let writer = LatchWriter::new();
        let reader1 = writer.reader();
        let reader2 = reader1.clone();
        assert!(!reader1.is_triggered());
        assert!(!reader2.is_triggered());
        writer.trigger();
        writer.trigger();
        let reader3 = reader1.clone();
        assert!(reader1.is_triggered());
        assert!(reader2.is_triggered());
        assert!(reader3.is_triggered());
    }

    #[test]
    fn concurrent_triggers_run_hook_once() {
        let writer = Arc::new(LatchWriter::new());
        let reader = writer.reader();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        let _guard = reader.on_cancel(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        let mut joins = Vec::new();
        for _ in 0..8 {
            let w = Arc::clone(&writer);
            joins.push(spawn_with_timeout(move || {
                w.trigger();
            }));
        }
        for (handle, rx) in joins {
            join_timeout(handle, &rx);
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn hook_after_trigger_runs_immediately() {
        let writer = LatchWriter::new();
        let reader = writer.reader();
        writer.trigger();
        let ran = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&ran);
        let _guard = reader.on_cancel(move || {
            r.store(true, Ordering::SeqCst);
        });
        assert!(ran.load(Ordering::SeqCst));
    }

    #[test]
    fn dropped_guard_prevents_hook_execution() {
        let writer = LatchWriter::new();
        let reader = writer.reader();
        let ran = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&ran);
        let guard = reader.on_cancel(move || {
            r.store(true, Ordering::SeqCst);
        });
        drop(guard);
        writer.trigger();
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[test]
    fn child_propagation_and_isolation() {
        let parent = LatchWriter::new();
        let p_reader = parent.reader();
        let child = p_reader.child();
        let c_reader = child.reader();
        let grandchild = c_reader.child();
        let gc_reader = grandchild.reader();
        assert!(!p_reader.is_triggered());
        assert!(!c_reader.is_triggered());
        assert!(!gc_reader.is_triggered());

        let isolated_parent = LatchWriter::new();
        let isolated_p_reader = isolated_parent.reader();
        let isolated_child = isolated_p_reader.child();
        let isolated_c_reader = isolated_child.reader();
        isolated_child.trigger();
        assert!(isolated_c_reader.is_triggered());
        assert!(!isolated_p_reader.is_triggered());

        parent.trigger();
        assert!(p_reader.is_triggered());
        assert!(c_reader.is_triggered());
        assert!(gc_reader.is_triggered());
    }

    #[test]
    fn abandoned_child_deregisters_and_does_not_block_parent() {
        let parent = LatchWriter::new();
        let p_reader = parent.reader();
        assert_eq!(p_reader.hook_count(), 0);
        {
            let child = p_reader.child();
            assert_eq!(p_reader.hook_count(), 1);
            drop(child);
        }
        assert_eq!(p_reader.hook_count(), 0);
        parent.trigger();
        assert!(p_reader.is_triggered());
    }

    #[test]
    fn fixture_never_remains_untriggered() {
        let never = LatchReader::fixture_never();
        assert!(!never.is_triggered());
    }

    #[test]
    fn types_implement_send_and_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LatchWriter>();
        assert_send_sync::<LatchReader>();
        assert_send_sync::<HookGuard>();
    }
}
