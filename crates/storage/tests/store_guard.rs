use bitcoin_rs_storage::StoreGuard;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Probe {
    live: Arc<AtomicBool>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.live.store(false, Ordering::SeqCst);
    }
}

fn probe() -> (StoreGuard, Arc<AtomicBool>) {
    let live = Arc::new(AtomicBool::new(true));
    let guard: StoreGuard = Arc::new(Probe {
        live: Arc::clone(&live),
    });
    (guard, live)
}

#[test]
fn flat_file_guard_install_is_single() -> TestResult {
    use bitcoin_rs_storage::FlatFileBlockStore;

    let dir = tempfile::TempDir::new()?;
    let (first, first_live) = probe();
    let store = FlatFileBlockStore::open(dir.path())?.guarded_by(first);
    assert!(
        first_live.load(Ordering::SeqCst),
        "the installed guard must stay alive with the store"
    );
    let (second, second_live) = probe();
    let refused = std::panic::catch_unwind(AssertUnwindSafe(|| store.guarded_by(second)));
    assert!(
        refused.is_err(),
        "a second guard must not silently replace the first"
    );
    assert!(
        !second_live.load(Ordering::SeqCst),
        "the refused guard must drop with the rejected call"
    );
    Ok(())
}

#[test]
fn dropped_flat_file_store_releases_its_guard() -> TestResult {
    use bitcoin_rs_storage::FlatFileBlockStore;

    let dir = tempfile::TempDir::new()?;
    let (guard, live) = probe();
    let store = FlatFileBlockStore::open(dir.path())?.guarded_by(guard);
    assert!(live.load(Ordering::SeqCst));
    drop(store);
    assert!(
        !live.load(Ordering::SeqCst),
        "the guard must die with the store handle"
    );
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_guard_install_is_single() -> TestResult {
    use bitcoin_rs_storage::FjallStore;

    let dir = tempfile::TempDir::new()?;
    let (first, first_live) = probe();
    let store = FjallStore::open(dir.path())?.guarded_by(first);
    assert!(first_live.load(Ordering::SeqCst));
    let (second, second_live) = probe();
    let refused = std::panic::catch_unwind(AssertUnwindSafe(|| store.guarded_by(second)));
    assert!(
        refused.is_err(),
        "a second guard must not silently replace the first"
    );
    assert!(!second_live.load(Ordering::SeqCst));
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_guard_install_is_single() -> TestResult {
    use bitcoin_rs_storage::RedbStore;

    let dir = tempfile::TempDir::new()?;
    let (first, first_live) = probe();
    let store = RedbStore::open(dir.path())?.guarded_by(first);
    assert!(first_live.load(Ordering::SeqCst));
    let (second, second_live) = probe();
    let refused = std::panic::catch_unwind(AssertUnwindSafe(|| store.guarded_by(second)));
    assert!(
        refused.is_err(),
        "a second guard must not silently replace the first"
    );
    assert!(!second_live.load(Ordering::SeqCst));
    Ok(())
}

#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_guard_install_is_single() -> TestResult {
    use bitcoin_rs_storage::RocksDbStore;

    let dir = tempfile::TempDir::new()?;
    let (first, first_live) = probe();
    let store = RocksDbStore::open(dir.path())?.guarded_by(first);
    assert!(first_live.load(Ordering::SeqCst));
    let (second, second_live) = probe();
    let refused = std::panic::catch_unwind(AssertUnwindSafe(|| store.guarded_by(second)));
    assert!(
        refused.is_err(),
        "a second guard must not silently replace the first"
    );
    assert!(!second_live.load(Ordering::SeqCst));
    Ok(())
}
