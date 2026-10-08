//! An in-flight disconnect refuses checkpoint publication without touching
//! the published state.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use bitcoin_rs_primitives::{Hash256, Network};
use bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT;
use bitcoin_rs_utxo::UtxoSet;

use crate::CheckpointError;
use crate::test_fixtures::MemoryBodies;

fn checkpoint_dirs(root: &std::path::Path) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let mut dirs = BTreeSet::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(dirs)
}

/// An `InFlight` disconnect marker refuses publication and leaves the marker,
/// `CURRENT`, and the generation directories exactly as they were.
#[test]
fn checkpoint_refuses_inflight_disconnect_and_preserves_state()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let network = Network::Regtest;
    let mut handles = crate::test_fixtures::handles(network, Arc::new(UtxoSet::new()));
    handles.block_body_store = Some(Arc::new(MemoryBodies::default()));
    handles.apply_block(&network.genesis_block(), None)?;
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
