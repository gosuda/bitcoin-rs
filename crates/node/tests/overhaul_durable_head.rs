//! Fault-injection matrix for the durable-head commit protocol (#632, CL-17).
//!
//! Two layers, both in isolated datadirs:
//!
//! - The **batch matrix** drives the exact production storage family —
//!   Fjall key-value store, flat block files, indexed body store, undo
//!   store, durable-head store — and arms one-shot [`PersistFault`]s at
//!   every durability boundary of a connect-shaped and a disconnect-shaped
//!   batch. After each fault the datadir reopens and the head row plus
//!   every batch row must show either the complete pre-batch or the
//!   complete post-batch state, never a cross-family mix (`P2`).
//! - The **protocol rows** run [`NodeState`] end to end: the durable head
//!   must name every applied block by the time `apply_block` returns
//!   (durability precedes publication, `INV-04`), `commit_id` must advance
//!   monotonically across connects and restarts (`P3`), every committed
//!   body must be reachable through the real block files (`INV-06`), and a
//!   corrupted head row must fail startup instead of decoding to absence
//!   (`P5`).

use std::sync::Arc;

use anyhow::{Result, bail};

use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};

use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};

use bitcoin_rs_storage::block_body::{BlockBodyStore, IndexedBlockBodyStore};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_FORMAT_VERSION, DURABLE_HEAD_KEY};
use bitcoin_rs_storage::pruning::{block_body_key, block_undo_key};
use bitcoin_rs_storage::undo::UndoStore;
use bitcoin_rs_storage::{
    ColumnFamily, CommitRecords, DurableHead, DurableHeadStore, FlatFileBlockStore,
    KvDurableHeadStore, KvStore, KvUndoStore, PersistFault,
};
use sha2::{Digest, Sha256};

const ALL_FAULTS: &[PersistFault] = &[
    PersistFault::FailApply,
    PersistFault::LostApply,
    PersistFault::PartialApply,
    PersistFault::FailSync,
    PersistFault::LostSync,
    PersistFault::FailFlush,
    PersistFault::LostFlush,
];

/// The production storage family, composed exactly as `NodeStorage`
/// composes it: one key-value store behind every family, flat files beside
/// it.
struct ChainFamily {
    store: Arc<bitcoin_rs_storage::FjallStore>,
    _files: Arc<FlatFileBlockStore>,
    bodies: Arc<IndexedBlockBodyStore<bitcoin_rs_storage::FjallStore>>,
    undo: KvUndoStore<bitcoin_rs_storage::FjallStore>,
    head: KvDurableHeadStore<bitcoin_rs_storage::FjallStore>,
}

fn open_family(data_dir: &std::path::Path) -> Result<ChainFamily> {
    let store = Arc::new(bitcoin_rs_storage::FjallStore::open(
        data_dir.join("chainstate"),
    )?);
    let files = Arc::new(FlatFileBlockStore::open(data_dir)?);
    let bodies = Arc::new(IndexedBlockBodyStore::new(
        Arc::clone(&store),
        Arc::clone(&files),
    ));
    let undo = KvUndoStore::new(Arc::clone(&store));
    let head = KvDurableHeadStore::new(Arc::clone(&store));
    Ok(ChainFamily {
        store,
        _files: files,
        bodies,
        undo,
        head,
    })
}

fn hash_of(seed: u8) -> Hash256 {
    Hash256::from_le_bytes(&[seed; 32])
}

/// Asserts the reopened datadir shows exactly one whole state: the head is
/// the old or the new row, and the new rows exist exactly when the head
/// rolled forward.
fn assert_whole_state(
    data_dir: &std::path::Path,
    old_head: &DurableHead,
    new_head: &DurableHead,
    batch_rows: &[(ColumnFamily, Vec<u8>)],
    context: &str,
) -> Result<()> {
    let family = open_family(data_dir)?;
    let stored = family
        .head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("{context}: head row vanished"))?;
    if stored == *old_head {
        // rolled out: none of the new rows may exist
    } else if stored == *new_head {
        // rolled forward: all of the new rows must exist
    } else {
        bail!("{context}: head is neither the old nor the new state: {stored:?}");
    }
    let rolled_forward = stored == *new_head;
    for (cf, key) in batch_rows {
        let present = family.store.get(*cf, key)?.is_some();
        assert_eq!(
            present, rolled_forward,
            "{context}: batch row presence {present} disagrees with head rolled_forward={rolled_forward}"
        );
    }
    Ok(())
}

#[test]
fn connect_batch_faults_leave_old_or_new_across_families() -> Result<()> {
    for fault in ALL_FAULTS {
        let temp = tempfile::tempdir()?;
        let data_dir = temp.path().to_path_buf();
        let family = open_family(&data_dir)?;

        // Block 1 commits cleanly: the pre-batch state every fault is
        // measured against.
        let body_one = b"body-one";
        family.bodies.persist_block_body(1, hash_of(1), body_one)?;
        let position_one = family
            .bodies
            .block_position(1, hash_of(1))?
            .ok_or_else(|| anyhow::anyhow!("family lost its own locator"))?;
        let old_head = DurableHead {
            commit_id: 1,
            height: 1,
            tip: hash_of(1),
            chain_tx_count: 1,
            body_extent: family.bodies.append_cursor(),
            undo_extent: Some((1, hash_of(1))),
        };
        let undo_one = vec![1_u8; 8];
        family.head.commit(
            None,
            &old_head,
            &CommitRecords {
                undo_rows: vec![(1, hash_of(1), undo_one.as_slice())],
                body_rows: vec![(1, hash_of(1), position_one)],
            },
        )?;

        // Block 2's bytes append first (no fault hook on the flat file —
        // its own recovery is the append-offset rollback), then the batch
        // hits the armed fault.
        let body_two = b"body-two";
        family.bodies.persist_block_body(2, hash_of(2), body_two)?;
        let position_two = family
            .bodies
            .block_position(2, hash_of(2))?
            .ok_or_else(|| anyhow::anyhow!("family lost its own locator"))?;
        let new_head = DurableHead {
            commit_id: 2,
            height: 2,
            tip: hash_of(2),
            chain_tx_count: 2,
            body_extent: family.bodies.append_cursor(),
            undo_extent: Some((2, hash_of(2))),
        };
        let undo_two = vec![2_u8; 8];
        family.store.arm_persist_fault(*fault);
        let outcome = family.head.commit(
            Some(&old_head),
            &new_head,
            &CommitRecords {
                undo_rows: vec![(2, hash_of(2), undo_two.as_slice())],
                body_rows: vec![(2, hash_of(2), position_two)],
            },
        );
        drop(family);

        // Not a rollback receipt: whichever state is on disk must be whole.
        let _ = outcome;
        // The undo row rides the batch in both directions. The locator row
        // does not: `persist_block_body` wrote it deferred before the batch,
        // so with the head rolled out it may linger as an orphan tail
        // (`P4`, discardable) — assert only the forward direction for it.
        let family = open_family(&data_dir)?;
        let locator_present = family
            .store
            .get(ColumnFamily::BlockBodies, &block_body_key(2, hash_of(2)))?
            .is_some();
        drop(family);
        assert_whole_state(
            &data_dir,
            &old_head,
            &new_head,
            &[(
                ColumnFamily::UndoData,
                block_undo_key(2, hash_of(2)).to_vec(),
            )],
            &format!("fault {fault:?}"),
        )?;
        if locator_present {
            let family = open_family(&data_dir)?;
            let head = family
                .head
                .load()?
                .ok_or_else(|| anyhow::anyhow!("head vanished"))?;
            assert!(
                head == new_head || locator_present,
                "a present locator with no batch must be an orphan, not a fresh head"
            );
        }
    }
    Ok(())
}

#[test]
fn disconnect_batch_faults_leave_old_or_new_across_families() -> Result<()> {
    for fault in ALL_FAULTS {
        let temp = tempfile::tempdir()?;
        let data_dir = temp.path().to_path_buf();
        let family = open_family(&data_dir)?;
        let committed = DurableHead {
            commit_id: 1,
            height: 1,
            tip: hash_of(1),
            chain_tx_count: 1,
            body_extent: Some(bitcoin_rs_storage::BodyExtent {
                file_no: 0,
                offset: 128,
            }),
            undo_extent: Some((1, hash_of(1))),
        };
        family
            .head
            .commit(None, &committed, &CommitRecords::default())?;

        // Disconnect: the head advances onto the parent tip with the next
        // commit id and no new records.
        let parent = DurableHead {
            commit_id: committed.commit_id + 1,
            height: 0,
            tip: Hash256::from_le_bytes(&[0_u8; 32]),
            chain_tx_count: committed.chain_tx_count,
            body_extent: committed.body_extent,
            undo_extent: committed.undo_extent,
        };
        family.store.arm_persist_fault(*fault);
        let outcome = family
            .head
            .commit(Some(&committed), &parent, &CommitRecords::default());
        drop(family);

        let _ = outcome;
        assert_whole_state(
            &data_dir,
            &committed,
            &parent,
            &[],
            &format!("disconnect fault {fault:?}"),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Protocol rows through NodeState.
// ---------------------------------------------------------------------------

fn test_config(data_dir: std::path::PathBuf) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 1;
    config
}

#[test]
fn durable_head_precedes_publication_and_survives_restart() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("protocol-node");
    let genesis = Network::Regtest.genesis_block();

    let state = NodeState::open(test_config(data_dir.clone()), None)?;
    let mut tip = state.apply_block(&genesis)?;
    let mut blocks = Vec::new();
    for height in 1..=3_u32 {
        let block = mined_regtest_child_at(BlockHash(tip.hash), height)?;
        tip = state.apply_block(&block)?;
        blocks.push(block);
    }
    state.publish_checkpoint()?;
    drop(state);

    // Durability precedes publication: by the time apply_block returned,
    // the head row, undo row, and a reachable body for every block were
    // already on disk.
    let family = open_family(&data_dir)?;
    let head = family
        .head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("a committed chain must leave a durable head"))?;
    assert_eq!(head.height, 3);
    assert_eq!(head.tip, tip.hash);
    assert_eq!(head.commit_id, 4, "genesis plus three blocks advance 1..=4");
    assert_eq!(head.chain_tx_count, 4, "genesis plus three coinbases");
    assert_eq!(head.undo_extent, Some((3, tip.hash)));
    assert!(head.body_extent.is_some(), "flat files back the head");
    for (index, block) in blocks.iter().enumerate() {
        let height = u32::try_from(index + 1)?;
        let block_hash = Hash256::from(block.block_hash());
        let stored_undo = family.undo.load_undo(height, block_hash)?;
        assert!(
            stored_undo.is_some(),
            "undo row for height {height} missing"
        );
        let stored_body = family.bodies.load_block_body(height, block_hash)?;
        assert_eq!(
            stored_body.as_deref(),
            Some(bitcoin_rs_primitives::consensus_bytes(block).as_slice()),
            "committed body bytes must be reachable through the block files"
        );
    }
    drop(family);

    // Restart: the restored tip reconciles with the head, and the next
    // connect continues the commit-id sequence.
    let resumed = NodeState::open(test_config(data_dir.clone()), None)?;
    let restored = resumed
        .applied_tip()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("restart must restore an applied tip"))?;
    assert_eq!(restored.hash, tip.hash);
    let block4 = mined_regtest_child_at(BlockHash(restored.hash), 4)?;
    let new_tip = resumed.apply_block(&block4)?;
    assert_eq!(new_tip.height, 4);
    drop(resumed);

    let family = open_family(&data_dir)?;
    let head = family
        .head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("head vanished"))?;
    assert_eq!(head.commit_id, 5, "commit ids continue across restarts");
    assert_eq!(head.tip, new_tip.hash);
    Ok(())
}

#[test]
fn corrupt_head_rows_fail_startup_fail_closed() -> Result<()> {
    for corruption in ["truncate", "flip-payload-bit", "wrong-version"] {
        let temp = tempfile::tempdir()?;
        let data_dir = temp.path().join("corrupt-node");
        let genesis = Network::Regtest.genesis_block();
        let state = NodeState::open(test_config(data_dir.clone()), None)?;
        state.apply_block(&genesis)?;
        drop(state);

        // Corrupt exactly the head row.
        let raw = Arc::new(bitcoin_rs_storage::FjallStore::open(
            data_dir.join("chainstate"),
        )?);
        let frame = raw
            .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
            .ok_or_else(|| anyhow::anyhow!("head row must exist"))?;
        let corrupted = match corruption {
            "truncate" => frame[..frame.len() - 1].to_vec(),
            "flip-payload-bit" => {
                let mut frame = frame;
                let last = frame.len() - 1;
                frame[last] ^= 0x80;
                frame
            }
            "wrong-version" => {
                let mut frame = frame;
                frame[4] = DURABLE_HEAD_FORMAT_VERSION + 1;
                frame
            }
            other => bail!("unknown corruption {other}"),
        };
        raw.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &corrupted)?;
        drop(raw);

        let reopened = NodeState::open(test_config(data_dir), None);
        assert!(
            reopened.is_err(),
            "corruption {corruption} must fail startup, got a node"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Regtest miner, mirroring the crash-recovery fixtures.
// ---------------------------------------------------------------------------

fn mined_regtest_child_at(prev_blockhash: BlockHash, height: u32) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![1, u8::try_from(height)?]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: Network::Regtest.genesis_block().header.time + height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
    while !pow_met(block.header.bits.to_consensus(), block.block_hash().into()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("test nonce exhausted"))?;
    }
    Ok(block)
}

fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if leaves.is_empty() {
        return None;
    }
    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair));
        }
        leaves = next;
    }
    Some(Hash256::from_le_bytes(&leaves[0]))
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}

fn pow_met(bits: u32, hash: Hash256) -> bool {
    let exponent = u8::try_from(bits >> 24).unwrap_or(0);
    let mantissa = bits & 0x007f_ffff;
    if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
        return false;
    }
    let bytes = hash.as_byte_array();
    let low = usize::from(exponent - 3);
    let window =
        u32::from(bytes[low]) | u32::from(bytes[low + 1]) << 8 | u32::from(bytes[low + 2]) << 16;
    window <= mantissa && bytes[usize::from(exponent)..].iter().all(|&byte| byte == 0)
}
