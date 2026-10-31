use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

#[cfg(test)]
mod tests;

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
        if self.triggered.load(Ordering::Acquire) {
            return;
        }
        let (hooks_to_run, parent_guard) = {
            let mut hooks_guard = self.hooks.lock();
            if self.triggered.swap(true, Ordering::Release) {
                return;
            }
            drop(self.wake_tx.lock().take());
            let guard = self.parent_guard.lock().take();
            (hooks_guard.take().unwrap_or_default(), guard)
        };
        drop(parent_guard);
        for (_id, hook) in hooks_to_run {
            hook();
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
