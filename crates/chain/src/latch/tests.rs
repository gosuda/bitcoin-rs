use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::Receiver;

use crate::latch::{HookGuard, LatchReader, LatchWriter};

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
    let res = rx.recv_timeout(Duration::from_secs(5));
    assert!(
        res.is_ok(),
        "join deadline exceeded: thread did not complete within 5 seconds"
    );
    let join_res = handle.join();
    assert!(join_res.is_ok(), "thread panicked");
    match res {
        Ok(val) => val,
        Err(_) => unreachable!(),
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
    assert!(!reader1.load());
    writer.trigger();
    writer.trigger();
    let reader3 = reader1.clone();
    assert!(reader1.is_triggered());
    assert!(reader2.is_triggered());
    assert!(reader3.is_triggered());
    assert!(reader1.load());
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
fn flag_reader_compatibility_and_fixture_never() {
    let flag = Arc::new(AtomicBool::new(false));
    let reader = LatchReader::new(Arc::clone(&flag));
    assert!(!reader.is_triggered());
    flag.store(true, Ordering::Release);
    assert!(reader.is_triggered());
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

#[test]
fn token_store_preserves_one_way_latch() {
    let writer = LatchWriter::new();
    let reader = writer.reader();
    assert!(!reader.is_triggered());
    reader.store(false);
    assert!(!reader.is_triggered());
    reader.store(true);
    assert!(reader.is_triggered());
    reader.store(false);
    assert!(reader.is_triggered());
}
