//! Integration tests for crash recovery across all enabled storage backends.
//!
//! Exercises the recovery-meta sidecar protocol (`crates/node/src/crash_recovery.rs`)
//! over every backend compiled into this test binary.  Each test loops over
//! `available_backends()` so a single `cargo test --features rocksdb,fjall,redb`
//! invocation exercises `RocksDB`, fjall, and redb in one run.
//!
//! Proof surface:
//! - **Simulated interrupted apply**: advance `height` past
//!   `last_committed_height`, restart, and assert the gap is replayed and the
//!   meta converges to `last_committed == height`.
//! - **Atomic write protocol**: after a clean commit the sidecar is readable
//!   and no `.tmp` residue remains.
//! - **Torn meta refusal**: a corrupt `.json` (simulating a crash that tore
//!   the sidecar) is refused on restart — `read_meta` returns `Err`, not a
//!   silent default.
//! - **Stale `.tmp` tolerance**: a orphaned `.tmp` left by a crashed write
//!   does not interfere with recovery; the valid `.json` is read and the
//!   next `write_meta` cleans up the stale temp.

#![cfg(any(feature = "rocksdb", feature = "fjall", feature = "redb"))]

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{Network, NodeConfig, crash_recovery, state::NodeState};

/// Returns the list of storage backends compiled into this test binary.
fn available_backends() -> Vec<&'static str> {
    [
        cfg!(feature = "rocksdb").then_some("rocksdb"),
        cfg!(feature = "fjall").then_some("fjall"),
        cfg!(feature = "redb").then_some("redb"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn make_config(temp: &tempfile::TempDir, backend: &str) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join(format!("node-{backend}"));
    backend.clone_into(&mut config.storage_backend);
    config.p2p_listen.clear();
    config
}

/// Simulated interrupted apply: advance `height` to 10, rewind
/// `last_committed_height` to 7, restart, and assert the gap [8, 9, 10] is
/// replayed and the meta converges.
#[test]
fn recovery_replays_from_last_committed_height_to_tip() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        {
            let state = NodeState::open(config.clone(), None)?;
            for height in 1..=10 {
                state.record_synthetic_block_for_recovery(height)?;
            }
            crash_recovery::set_last_committed_height(&state, 7)?;
        }

        let restarted = NodeState::open(config, None)?;
        crash_recovery::recover_if_needed(&restarted)?;

        let meta = crash_recovery::read_meta(&restarted)?.context("missing recovery metadata")?;
        assert_eq!(
            meta.height, 10,
            "{backend}: height should be 10 after recovery"
        );
        assert_eq!(
            meta.last_committed_height, 10,
            "{backend}: last_committed_height should converge to 10"
        );
        assert_eq!(
            restarted.replayed_heights(),
            vec![8, 9, 10],
            "{backend}: replay should cover the gap [8, 9, 10]"
        );
    }
    Ok(())
}

/// Atomic write protocol: after a clean commit the sidecar is readable and
/// no `.tmp` residue remains.
#[test]
fn recovery_meta_write_leaves_readable_sidecar_without_tmp() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        let meta_path = config.data_dir.join("recovery_meta.json");
        let tmp_path = config.data_dir.join("recovery_meta.json.tmp");
        {
            let state = NodeState::open(config, None)?;
            state.record_synthetic_block_for_recovery(3)?;
        }

        assert!(meta_path.exists(), "{backend}: meta file should exist");
        let bytes = std::fs::read(&meta_path)
            .with_context(|| format!("read recovery metadata {}", meta_path.display()))?;
        let meta: crash_recovery::Meta = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse recovery metadata {}", meta_path.display()))?;
        assert_eq!(meta.height, 3, "{backend}: height should be 3");
        assert_eq!(
            meta.last_committed_height, 3,
            "{backend}: last_committed_height should be 3"
        );
        assert!(
            !tmp_path.exists(),
            "{backend}: no .tmp residue after atomic rename"
        );
    }
    Ok(())
}

/// Torn meta refusal: corrupt the `.json` sidecar (simulating a crash that
/// tore the file), reopen, and assert `read_meta` returns `Err` — the node
/// refuses torn state rather than silently defaulting.
#[test]
fn torn_meta_after_crash_is_refused() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        // Establish a clean state at height 5.
        {
            let state = NodeState::open(config.clone(), None)?;
            for height in 1..=5 {
                state.record_synthetic_block_for_recovery(height)?;
            }
        }

        // Simulate a crash that tore the meta file — write garbage bytes
        // directly into recovery_meta.json.  This is the failure mode the
        // atomic-rename protocol prevents in production; the test proves the
        // read path detects and refuses it rather than silently recovering
        // from a default or stale value.
        let meta_path = config.data_dir.join("recovery_meta.json");
        std::fs::write(&meta_path, b"{ this is not valid json }")?;

        let restarted = NodeState::open(config, None)?;
        let result = crash_recovery::read_meta(&restarted);
        assert!(
            result.is_err(),
            "{backend}: torn meta must be refused (returned Err), not silently accepted"
        );

        // recover_if_needed propagates the error — the node does not proceed.
        let recovery_result = crash_recovery::recover_if_needed(&restarted);
        assert!(
            recovery_result.is_err(),
            "{backend}: recover_if_needed must fail when meta is torn"
        );
    }
    Ok(())
}

/// Stale `.tmp` tolerance: a `.tmp` orphaned by a crashed write does not
/// interfere with recovery.  The valid `.json` is read, recovery succeeds,
/// and a subsequent `write_meta` overwrites the stale temp cleanly.
#[test]
fn stale_tmp_after_crash_does_not_corrupt_recovery() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        // Establish a clean state at height 8, then simulate an interrupted
        // apply by rewinding last_committed_height to 5.
        {
            let state = NodeState::open(config.clone(), None)?;
            for height in 1..=8 {
                state.record_synthetic_block_for_recovery(height)?;
            }
            crash_recovery::set_last_committed_height(&state, 5)?;
        }

        // Plant a stale .tmp from a crashed write — garbage that must never
        // be read as the recovery meta.
        let tmp_path = config.data_dir.join("recovery_meta.json.tmp");
        std::fs::write(&tmp_path, b"garbage from a crashed write")?;

        // Restart: recovery reads the valid .json and ignores the stale .tmp.
        let restarted = NodeState::open(config, None)?;
        crash_recovery::recover_if_needed(&restarted)?;

        let meta = crash_recovery::read_meta(&restarted)?.context("missing recovery metadata")?;
        assert_eq!(meta.height, 8, "{backend}: height should be 8");
        assert_eq!(
            meta.last_committed_height, 8,
            "{backend}: last_committed_height should converge to 8"
        );
        assert_eq!(
            restarted.replayed_heights(),
            vec![6, 7, 8],
            "{backend}: replay should cover the gap [6, 7, 8]"
        );

        // A subsequent write_meta overwrites the stale .tmp cleanly.
        crash_recovery::write_meta(&restarted, &meta)?;
        assert!(
            !tmp_path.exists(),
            "{backend}: stale .tmp cleaned up by subsequent write"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Production crash-recovery tests: apply real blocks through the production
// apply path (which persists the recovery meta with a tip hash), simulate a
// crash by dropping the state without a clean checkpoint, reopen, and verify
// that `recover_if_needed` replays the gap from stored block bodies.
// ---------------------------------------------------------------------------

// Helpers for mining regtest blocks with valid PoW.

/// Decodes a 256-bit compact target into little-endian bytes.
fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mantissa = u64::from(bits & 0x007f_ffff);
    let mut target = [0_u8; 32];
    if mantissa == 0 || bits & 0x0080_0000 != 0 || exponent > 34 {
        return target;
    }
    let mantissa_bytes = mantissa.to_le_bytes();
    if exponent >= 3 {
        let offset = exponent - 3;
        for (index, byte) in mantissa_bytes.iter().enumerate().take(3) {
            if let Some(slot) = target.get_mut(offset + index) {
                *slot = *byte;
            }
        }
    } else {
        let shifted = mantissa >> (8 * (3 - exponent));
        target[..8].copy_from_slice(&shifted.to_le_bytes());
    }
    target
}

/// Returns true when `hash` is at or below the compact target.
fn pow_met(bits: u32, hash: &bitcoin_rs_primitives::BlockHash) -> bool {
    let target = compact_to_target(bits);
    let hash_le = hash.as_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// Mines a regtest block on top of `prev_hash` with a coinbase transaction.
///
/// `time` must exceed the parent's median-time-past; callers should derive it
/// from the genesis timestamp (e.g. `genesis.header.time + height`) so every
/// block in the chain advances past the growing MTP window.
fn mine_regtest_block(
    prev_hash: bitcoin_rs_primitives::BlockHash,
    height: u32,
    time: u32,
) -> Result<bitcoin_rs_primitives::Block> {
    let coinbase = bitcoin_rs_primitives::Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![bitcoin_rs_primitives::TxIn {
            previous_output: bitcoin_rs_primitives::OutPoint::new(
                bitcoin_rs_primitives::Txid::default(),
                u32::MAX,
            ),
            script_sig: vec![0x51, u8::try_from(height).unwrap_or(0)],
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![bitcoin_rs_primitives::TxOut {
            value: 50 * 100_000_000,
            script_pubkey: vec![0x51],
        }],
    };
    let mut block = bitcoin_rs_primitives::Block {
        header: bitcoin_rs_primitives::Header {
            version: 0x2000_0000,
            prev_blockhash: prev_hash,
            merkle_root: coinbase.txid().into(),
            time,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    while !pow_met(block.header.bits, &block.block_hash()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .context("nonce exhausted")?;
    }
    Ok(block)
}

/// Production crash recovery: apply genesis, publish a checkpoint, apply
/// three blocks, crash (drop state without clean checkpoint), reopen, and
/// assert that `recover_if_needed` replays blocks 1–3 from stored bodies.
#[test]
fn crash_recovery_replays_from_stored_bodies_after_crash() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();

        // Phase 1: open, apply genesis, publish checkpoint at height 0.
        {
            let state = NodeState::open(config.clone(), None)?;
            let tip = state.apply_block(&genesis)?;
            assert_eq!(tip.height, 0, "{backend}: genesis should be height 0");
            state.publish_checkpoint()?;
        }

        // Phase 2: reopen, apply blocks 1–3, crash (drop without checkpoint).
        {
            let state = NodeState::open(config.clone(), None)?;
            let mut prev = genesis_hash;
            for height in 1..=3_u32 {
                let block = mine_regtest_block(prev, height, genesis.header.time + height)?;
                let tip = state.apply_block(&block)?;
                assert_eq!(
                    tip.height, height,
                    "{backend}: block {height} should apply at height {height}"
                );
                prev = block.block_hash();
            }
            // Drop state without publishing a checkpoint — simulates a crash.
        }

        // Phase 3: reopen — checkpoint restores to height 0, recovery meta
        // says height 3 with a tip hash.
        let restarted = NodeState::open(config, None)?;
        let restored_tip = restarted
            .applied_tip()
            .load()
            .as_ref()
            .map_or(0, |t| t.height);
        assert_eq!(
            restored_tip, 0,
            "{backend}: checkpoint should restore to height 0"
        );

        crash_recovery::recover_if_needed(&restarted)?;

        let meta = crash_recovery::read_meta(&restarted)?
            .with_context(|| format!("{backend}: missing recovery metadata after recovery"))?;
        assert_eq!(
            meta.height, 3,
            "{backend}: meta height should be 3 after recovery"
        );
        assert_eq!(
            meta.last_committed_height, 3,
            "{backend}: last_committed_height should converge to 3"
        );
        assert!(
            meta.tip_hash_hex.is_some(),
            "{backend}: tip_hash_hex should be present after production recovery"
        );
        assert_eq!(
            restarted.replayed_heights(),
            vec![1, 2, 3],
            "{backend}: replay should cover the gap [1, 2, 3]"
        );

        // The replay path must actually apply the blocks, not just record
        // the gap.  The fallback (in-memory record only) leaves the applied
        // tip at the checkpoint height; a real replay advances it to 3.
        let recovered_tip = restarted
            .applied_tip()
            .load()
            .as_ref()
            .map_or(0, |t| t.height);
        assert_eq!(
            recovered_tip, 3,
            "{backend}: replayed blocks should advance the applied tip to height 3"
        );
    }
    Ok(())
}

/// Production crash recovery with no checkpoint: recovery must replay the
/// stored chain from genesis through the last applied block.
#[test]
fn crash_recovery_replays_from_genesis_without_checkpoint() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();
        let mut tip_hash = genesis_hash;

        // Phase 1: open, apply genesis and blocks 1–3, then crash without a
        // checkpoint.
        {
            let state = NodeState::open(config.clone(), None)?;
            state.apply_block(&genesis)?;
            let mut prev = genesis_hash;
            for height in 1..=3_u32 {
                let block = mine_regtest_block(prev, height, genesis.header.time + height)?;
                state.apply_block(&block)?;
                prev = block.block_hash();
                tip_hash = prev;
            }
        }

        // Phase 2: no checkpoint exists, so recovery starts with no applied
        // tip and must replay genesis as well as blocks 1–3.
        let restarted = NodeState::open(config, None)?;
        assert!(
            restarted.applied_tip().load().is_none(),
            "{backend}: no checkpoint should leave the applied tip empty"
        );

        crash_recovery::recover_if_needed(&restarted)?;

        let recovered_tip_snapshot = restarted.applied_tip().load();
        let recovered_tip = recovered_tip_snapshot
            .as_ref()
            .context("recovery should restore an applied tip")?;
        assert_eq!(recovered_tip.height, 3, "{backend}: recovered tip height");
        assert_eq!(
            recovered_tip.hash,
            tip_hash.into(),
            "{backend}: recovered tip hash"
        );
        assert_eq!(
            restarted.replayed_heights(),
            vec![0, 1, 2, 3],
            "{backend}: replay should cover genesis and blocks [1, 2, 3]"
        );

        let meta = crash_recovery::read_meta(&restarted)?
            .with_context(|| format!("{backend}: missing recovery metadata after recovery"))?;
        assert_eq!(meta.height, 3, "{backend}: meta height should be 3");
        assert_eq!(
            meta.last_committed_height, 3,
            "{backend}: last_committed_height should converge to 3"
        );
    }
    Ok(())
}

#[test]
fn crash_recovery_replays_genesis_only_without_checkpoint() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();

        // Phase 1: apply only genesis without publishing a checkpoint.
        {
            let state = NodeState::open(config.clone(), None)?;
            state.apply_block(&genesis)?;
        }

        // Phase 2: a cold reopen has no applied tip and must replay genesis.
        let restarted = NodeState::open(config, None)?;
        assert!(
            restarted.applied_tip().load().is_none(),
            "{backend}: no checkpoint should leave the applied tip empty"
        );

        crash_recovery::recover_if_needed(&restarted)?;

        let recovered_tip_snapshot = restarted.applied_tip().load();
        let recovered_tip = recovered_tip_snapshot
            .as_ref()
            .context("recovery should restore the genesis tip")?;
        assert_eq!(recovered_tip.height, 0, "{backend}: recovered tip height");
        assert_eq!(
            recovered_tip.hash,
            genesis_hash.into(),
            "{backend}: recovered genesis hash"
        );
        assert_eq!(
            restarted.replayed_heights(),
            vec![0],
            "{backend}: replay should cover genesis only"
        );
    }
    Ok(())
}

/// Production meta persistence: after applying a block through the
/// production apply path, the recovery meta should contain a tip hash.
/// This test verifies the wiring — if the apply path stops writing
/// `tip_hash_hex`, the crash-recovery replay path cannot function.
#[test]
fn production_apply_writes_meta_with_tip_hash() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        let genesis = Network::Regtest.genesis_block();

        {
            let state = NodeState::open(config.clone(), None)?;
            state.apply_block(&genesis)?;
        }

        // Reopen and check that the meta was written by the production path.
        let state = NodeState::open(config, None)?;
        let meta = crash_recovery::read_meta(&state)?
            .with_context(|| format!("{backend}: recovery meta should exist after apply"))?;
        assert_eq!(
            meta.height, 0,
            "{backend}: meta height should be 0 after genesis apply"
        );
        assert_eq!(
            meta.last_committed_height, 0,
            "{backend}: last_committed_height should be 0 after genesis apply"
        );
        assert!(
            meta.tip_hash_hex.is_some(),
            "{backend}: production apply should write tip_hash_hex"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Periodic checkpoint publication tests (issue #219).
//
// These tests prove the periodic checkpoint worker publishes a checkpoint
// during sync without any clean shutdown, and that a killed-and-reopened
// node resumes from the periodic checkpoint rather than the older
// clean-shutdown one.
// ---------------------------------------------------------------------------

/// Periodic checkpoint: apply genesis (clean checkpoint at height 0), start
/// the checkpoint worker with a 3-block cadence, apply 4 blocks, wait for
/// the worker to publish, drop the state without a clean checkpoint, reopen,
/// and assert the resumed tip is at height 4 (the periodic checkpoint), not
/// height 0 (the clean-shutdown checkpoint).
#[test]
fn periodic_checkpoint_anchors_progress_without_clean_shutdown() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();

        // Phase 1: open, apply genesis, publish a clean checkpoint at height 0.
        // This is the "old" checkpoint that must be superseded by the periodic one.
        {
            let state = NodeState::open(config.clone(), None)?;
            state.apply_block(&genesis)?;
            state.publish_checkpoint()?;
        }

        // Phase 2: reopen, start the periodic checkpoint worker with a 3-block
        // cadence, apply 4 blocks (past the cadence), and wait for the worker
        // to publish. Then stop the worker and drop the state WITHOUT a clean
        // checkpoint — this simulates a crash/kill mid-sync.
        {
            let state = NodeState::open(config.clone(), None)?;

            // Start the periodic checkpoint worker with a 3-block cadence
            // and a 1-hour time fallback (so only the block count fires).
            let worker = state.start_periodic_checkpoint(3, std::time::Duration::from_hours(1))?;

            let mut prev = genesis_hash;
            for height in 1..=4_u32 {
                let block = mine_regtest_block(prev, height, genesis.header.time + height)?;
                let tip = state.apply_block(&block)?;
                assert_eq!(
                    tip.height, height,
                    "{backend}: block {height} should apply at height {height}"
                );
                prev = block.block_hash();
            }

            // Wait for the worker to publish. The worker polls every 5s, but
            // the checkpoint write itself is synchronous and quick for a tiny
            // regtest chainstate. Poll the checkpoint CURRENT file until it
            // names a generation whose restored height exceeds 0.
            let checkpoint_root = config.data_dir.join("chainstate-checkpoints");
            let mut published = false;
            for _ in 0..60 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let Ok(current_bytes) = std::fs::read(checkpoint_root.join("CURRENT")) {
                    if let Ok(current) = serde_json::from_slice::<serde_json::Value>(&current_bytes)
                    {
                        if let Some(generation) = current
                            .get("generation")
                            .and_then(serde_json::Value::as_u64)
                        {
                            // A generation > 1 means a second checkpoint was published
                            // (generation 1 was the clean-shutdown one at height 0).
                            if generation > 1 {
                                published = true;
                                break;
                            }
                        }
                    }
                }
            }
            assert!(
                published,
                "{backend}: periodic checkpoint should have been published after 4 blocks with cadence 3"
            );

            // Stop the worker before dropping the state so it releases
            // database locks. Then drop state without a clean checkpoint —
            // simulates a crash.
            state
                .shutdown()
                .store(true, std::sync::atomic::Ordering::Release);
            match worker.join() {
                Ok(()) => {}
                Err(payload) => panic!("checkpoint worker thread panicked: {payload:?}"),
            }
            drop(state);
        }

        // Phase 3: reopen — the checkpoint should restore to height 4 (the
        // periodic checkpoint), not height 0 (the clean-shutdown one).
        let restarted = NodeState::open(config, None)?;
        let restored_tip = restarted
            .applied_tip()
            .load()
            .as_ref()
            .map_or(0, |t| t.height);
        assert_eq!(
            restored_tip, 4,
            "{backend}: periodic checkpoint should restore to height 4, not the clean-shutdown height 0"
        );

        // The recovery sidecar should also agree: after the periodic checkpoint
        // rewrote it, the sidecar height should be 4.
        let meta = crash_recovery::read_meta(&restarted)?.with_context(|| {
            format!("{backend}: recovery meta should exist after periodic checkpoint")
        })?;
        assert_eq!(
            meta.height, 4,
            "{backend}: sidecar height should be 4 after periodic checkpoint publication"
        );
    }
    Ok(())
}

/// Periodic checkpoint exists without shutdown: apply genesis, start the
/// worker with a 2-block cadence, apply 3 blocks, wait for publication, and
/// assert a checkpoint generation exists — all without ever calling
/// `publish_checkpoint` or shutting down cleanly.
#[test]
fn periodic_checkpoint_published_during_sync_without_shutdown() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();

        // Open, apply genesis (no clean checkpoint this time — the periodic
        // worker should be the only publisher).
        let state = NodeState::open(config.clone(), None)?;
        state.apply_block(&genesis)?;

        // Start the periodic checkpoint worker with a 2-block cadence.
        let worker = state.start_periodic_checkpoint(2, std::time::Duration::from_hours(1))?;

        let mut prev = genesis_hash;
        for height in 1..=3_u32 {
            let block = mine_regtest_block(prev, height, genesis.header.time + height)?;
            let tip = state.apply_block(&block)?;
            assert_eq!(
                tip.height, height,
                "{backend}: block {height} should apply at height {height}"
            );
            prev = block.block_hash();
        }

        // Wait for the worker to publish a checkpoint.
        let checkpoint_root = config.data_dir.join("chainstate-checkpoints");
        let mut published = false;
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if let Ok(current_bytes) = std::fs::read(checkpoint_root.join("CURRENT")) {
                if let Ok(current) = serde_json::from_slice::<serde_json::Value>(&current_bytes) {
                    if let Some(generation) = current
                        .get("generation")
                        .and_then(serde_json::Value::as_u64)
                    {
                        if generation >= 1 {
                            published = true;
                            break;
                        }
                    }
                }
            }
        }
        assert!(
            published,
            "{backend}: periodic checkpoint should have been published after 3 blocks with cadence 2"
        );

        // Shut down the worker by setting the shutdown flag and joining,
        // then drop the state (no clean checkpoint publication).
        state
            .shutdown()
            .store(true, std::sync::atomic::Ordering::Release);
        match worker.join() {
            Ok(()) => {}
            Err(payload) => panic!("checkpoint worker thread panicked: {payload:?}"),
        }
        drop(state);

        // Reopen and verify the checkpoint restored to height 3.
        let restarted = NodeState::open(config, None)?;
        let restored_tip = restarted
            .applied_tip()
            .load()
            .as_ref()
            .map_or(0, |t| t.height);
        assert_eq!(
            restored_tip, 3,
            "{backend}: periodic checkpoint should restore to height 3 without any clean shutdown"
        );
    }
    Ok(())
}
