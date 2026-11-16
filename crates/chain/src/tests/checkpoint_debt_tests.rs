use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Network};
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT;
use bitcoin_rs_storage::utxo::UtxoSet;

use crate::CheckpointError;
use crate::test_fixtures::TestResult;
use crate::test_support::MemoryBodies;

fn checkpoint_dirs(root: &std::path::Path) -> TestResult<BTreeSet<String>> {
    let mut dirs = BTreeSet::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(dirs)
}

#[test]
fn checkpoint_refuses_inflight_disconnect_and_preserves_state() -> TestResult {
    let dir = tempfile::tempdir()?;
    let network = Network::Regtest;
    let mut handles = crate::test_fixtures::handles(network, Arc::new(UtxoSet::new()));
    handles.block_body_store = Some(Arc::new(MemoryBodies::default()));
    handles.apply_block(&BlockImage::from_local(network.genesis_block()))?;
    handles.configure_checkpointing(dir.path(), Arc::new(AtomicU32::new(0)))?;
    assert!(handles.publish_checkpoint()?.is_some());

    let checkpoint_root = dir.path().join(CHECKPOINT_ROOT);
    let armed_hash = Hash256::from_le_bytes(&[0xab; 32]);
    let armed_height = 10;
    handles
        .undo_store
        .arm_disconnect(armed_height, armed_hash)?;
    let marker_before = handles.undo_store.load_disconnect_marker()?;
    let current_before = std::fs::read(checkpoint_root.join("CURRENT"))?;
    let dirs_before = checkpoint_dirs(&checkpoint_root)?;

    let result = handles.publish_checkpoint();
    let Err(CheckpointError::DisconnectInFlight { hash, height }) = result else {
        panic!("expected DisconnectInFlight refusal, got {result:?}");
    };
    assert_eq!(hash, armed_hash);
    assert_eq!(height, armed_height);

    assert_eq!(handles.undo_store.load_disconnect_marker()?, marker_before);
    assert_eq!(
        std::fs::read(checkpoint_root.join("CURRENT"))?,
        current_before
    );
    assert_eq!(checkpoint_dirs(&checkpoint_root)?, dirs_before);
    Ok(())
}

// RCV-14, SYNC-04
#[test]
fn checkpoint_refuses_a_closed_for_recovery_chainstate() -> TestResult {
    let dir = tempfile::tempdir()?;
    let network = Network::Regtest;
    let mut handles = crate::test_fixtures::handles(network, Arc::new(UtxoSet::new()));
    handles.block_body_store = Some(Arc::new(MemoryBodies::default()));
    handles.apply_block(&BlockImage::from_local(network.genesis_block()))?;
    handles.configure_checkpointing(dir.path(), Arc::new(AtomicU32::new(0)))?;
    assert!(handles.publish_checkpoint()?.is_some());

    let checkpoint_root = dir.path().join(CHECKPOINT_ROOT);
    let current_before = std::fs::read(checkpoint_root.join("CURRENT"))?;
    let dirs_before = checkpoint_dirs(&checkpoint_root)?;

    handles.fail_closed_for_recovery();
    let result = handles.publish_checkpoint();
    let Err(CheckpointError::ClosedForRecovery) = result else {
        panic!("expected ClosedForRecovery refusal, got {result:?}");
    };

    assert_eq!(
        std::fs::read(checkpoint_root.join("CURRENT"))?,
        current_before
    );
    assert_eq!(checkpoint_dirs(&checkpoint_root)?, dirs_before);
    Ok(())
}

struct PausedBodySync {
    inner: MemoryBodies,
    pause: AtomicBool,
    entered: mpsc::SyncSender<()>,
    release: parking_lot::Mutex<mpsc::Receiver<()>>,
}

impl BlockBodyStore for PausedBodySync {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.inner.persist_block_body(height, hash, body)
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_block_body(height, hash)
    }

    fn sync(&self) -> Result<(), StorageError> {
        if self.pause.swap(false, Ordering::AcqRel) {
            self.entered.send(()).map_err(StorageError::backend)?;
            self.release.lock().recv().map_err(StorageError::backend)?;
        }
        Ok(())
    }
}

// RCV-14, SYNC-04
#[test]
fn recovery_closure_waits_for_admitted_checkpoint_and_refuses_later_publication() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::channel();
    let bodies = Arc::new(PausedBodySync {
        inner: MemoryBodies::default(),
        pause: AtomicBool::new(false),
        entered: entered_tx,
        release: parking_lot::Mutex::new(release_rx),
    });
    let mut chain = crate::test_fixtures::handles(Network::Regtest, Arc::new(UtxoSet::new()));
    chain.block_body_store = Some(bodies.clone());
    chain.apply_block(&BlockImage::from_local(Network::Regtest.genesis_block()))?;
    chain.configure_checkpointing(dir.path(), Arc::new(AtomicU32::new(0)))?;
    assert!(chain.publish_checkpoint()?.is_some());
    let root = dir.path().join(CHECKPOINT_ROOT);
    let previous = std::fs::read(root.join("CURRENT"))?;

    bodies.pause.store(true, Ordering::Release);
    let publishing = chain.clone();
    let publisher = std::thread::spawn(move || publishing.publish_checkpoint());
    entered_rx.recv_timeout(Duration::from_secs(2))?;
    let closing = chain.clone();
    let (closed_tx, closed_rx) = mpsc::channel();
    let closer = std::thread::spawn(move || {
        closing.fail_closed_for_recovery();
        let _ = closed_tx.send(());
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !chain.admission.close_attempted.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            let _ = release_tx.send(());
            panic!("recovery closure never attempted the publication mutex");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let blocked = closed_rx.recv_timeout(Duration::from_millis(50));
    let closed_during_publication = chain.is_closed_for_recovery();
    release_tx.send(()).map_err(StorageError::backend)?;
    let published = publisher
        .join()
        .map_err(|_| "checkpoint thread panicked")??;
    closer
        .join()
        .map_err(|_| "recovery closure thread panicked")?;
    assert!(matches!(blocked, Err(mpsc::RecvTimeoutError::Timeout)));
    assert!(!closed_during_publication);
    assert!(published.is_some());
    assert!(chain.is_closed_for_recovery());
    assert!(chain.shutdown_reader().is_triggered());
    let current = std::fs::read(root.join("CURRENT"))?;
    assert_ne!(
        current, previous,
        "the admitted checkpoint precedes closure"
    );
    let directories = checkpoint_dirs(&root)?;
    assert!(matches!(
        chain.publish_checkpoint(),
        Err(CheckpointError::ClosedForRecovery)
    ));
    assert_eq!(std::fs::read(root.join("CURRENT"))?, current);
    assert_eq!(checkpoint_dirs(&root)?, directories);
    Ok(())
}
