use core::num::NonZeroU32;
use std::sync::Arc;

use bitcoin_rs_chain::regtest_fixture::{
    merkle_root, mine_header_to_declared_target, mined_regtest_child_at,
};
use bitcoin_rs_chain::{LatchReader, TipSnapshot, validate_pow};
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_primitives::{
    Block, BlockPayload, Hash256, Network, Script, Witness, consensus_bytes, deserialize,
};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget};
use bitcoin_rs_storage::{
    BoundedReadError, InMemoryUndoStore, MandatoryRetention, RetentionRegistry, StorageError,
    UndoStore,
};
use bitcoin_rs_utxo::UtxoSet;
use hashbrown::{HashMap, HashSet};
use parking_lot::Mutex;

use super::{
    BodyDecodeError, CheckLevel, VerifyError, VerifyOutcome, VerifyRequest, verify_recent_blocks,
};
use crate::test_fixtures::handles;
use crate::{Chainstate, ChainstateRole};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const LEVELS: [CheckLevel; 4] = [
    CheckLevel::ReadBodies,
    CheckLevel::CheckBodies,
    CheckLevel::CheckUndo,
    CheckLevel::CheckUndoAndCommitments,
];

/// A body store the tests can damage, empty, corrupt, or interleave with a read.
#[derive(Default)]
struct Bodies {
    rows: Mutex<HashMap<(u32, Hash256), Vec<u8>>>,
    corrupt: Mutex<HashSet<(u32, Hash256)>>,
    before_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Bodies {
    fn bytes(&self, height: u32, hash: Hash256) -> Result<Vec<u8>> {
        Ok(self
            .rows
            .lock()
            .get(&(height, hash))
            .cloned()
            .ok_or("fixture body is missing")?)
    }

    fn replace(&self, height: u32, hash: Hash256, bytes: Vec<u8>) {
        self.rows.lock().insert((height, hash), bytes);
    }

    fn remove(&self, height: u32, hash: Hash256) {
        self.rows.lock().remove(&(height, hash));
    }
}

impl BlockBodyStore for Bodies {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> std::result::Result<(), StorageError> {
        self.replace(height, hash, body.to_vec());
        Ok(())
    }

    fn load_block_body(
        &self,
        height: u32,
        hash: Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
        Ok(self.rows.lock().get(&(height, hash)).cloned())
    }

    fn load_block_body_bounded(
        &self,
        height: u32,
        hash: Hash256,
        _max_bytes: usize,
    ) -> std::result::Result<Option<Vec<u8>>, BoundedReadError> {
        Ok(self.rows.lock().get(&(height, hash)).cloned())
    }

    fn load_block_body_for_verification_bounded(
        &self,
        height: u32,
        hash: Hash256,
        _max_bytes: usize,
    ) -> std::result::Result<Option<Vec<u8>>, BoundedReadError> {
        let hook = self.before_read.lock().take();
        if let Some(hook) = hook {
            hook();
        }
        if self.corrupt.lock().contains(&(height, hash)) {
            return Err(BoundedReadError::Storage(StorageError::CorruptBlockFrame(
                "fixture corrupt frame",
            )));
        }
        Ok(self.rows.lock().get(&(height, hash)).cloned())
    }

    fn sync(&self) -> std::result::Result<(), StorageError> {
        Ok(())
    }
}

struct Fixture {
    chain: Chainstate,
    bodies: Arc<Bodies>,
    undo: Arc<InMemoryUndoStore>,
    retention: Arc<RetentionRegistry>,
    /// Genesis, then one child per height.
    blocks: Vec<Block>,
}

fn fixture(children: u32) -> Result<Fixture> {
    let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let bodies = Arc::new(Bodies::default());
    let undo = Arc::new(InMemoryUndoStore::default());
    let retention = Arc::new(RetentionRegistry::new());
    chain.block_body_store = Some(bodies.clone());
    chain.undo_store = undo.clone();
    chain.retention = MandatoryRetention::new(Arc::clone(&retention));
    chain.history = HistoryAccess::new(Arc::clone(&retention), RetentionBudget::from_blocks(288));
    let genesis = Network::Regtest.genesis_block();
    chain.apply_block(&BlockPayload::from_local(genesis.clone()))?;
    let mut blocks = vec![genesis];
    for height in 1..=children {
        let previous = blocks.last().ok_or("no parent")?.block_hash();
        let block = mined_regtest_child_at(previous, height)?;
        chain.apply_block(&BlockPayload::from_local(block.clone()))?;
        blocks.push(block);
    }
    Ok(Fixture {
        chain,
        bodies,
        undo,
        retention,
        blocks,
    })
}

impl Fixture {
    fn hash(&self, height: usize) -> Hash256 {
        self.blocks[height].block_hash().into()
    }

    fn damage_body(&self, height: u32, damage: impl FnOnce(&mut Vec<u8>)) -> Result {
        let index = usize::try_from(height)?;
        let mut bytes = self.bodies.bytes(height, self.hash(index))?;
        damage(&mut bytes);
        self.bodies.replace(height, self.hash(index), bytes);
        Ok(())
    }

    fn drop_body(&self, height: u32) -> Result {
        self.bodies
            .remove(height, self.hash(usize::try_from(height)?));
        Ok(())
    }

    fn corrupt_body(&self, height: u32) -> Result {
        let index = usize::try_from(height)?;
        self.bodies
            .corrupt
            .lock()
            .insert((height, self.hash(index)));
        Ok(())
    }

    fn outcome(&self, level: CheckLevel, depth: Option<u32>) -> Result<VerifyOutcome> {
        Ok(verify_recent_blocks(&self.chain, request(level, depth))?)
    }

    fn damage(&self, level: CheckLevel, depth: Option<u32>) -> Result<VerifyError> {
        Ok(verify_recent_blocks(&self.chain, request(level, depth))
            .err()
            .ok_or("verification passed over damage")?)
    }
}

fn request(level: CheckLevel, depth: Option<u32>) -> VerifyRequest {
    VerifyRequest {
        level,
        depth: depth.and_then(NonZeroU32::new),
        cancellation: None,
    }
}

fn cancellable_request(
    level: CheckLevel,
    depth: Option<u32>,
    cancellation: &LatchReader,
) -> VerifyRequest {
    VerifyRequest {
        level,
        depth: depth.and_then(NonZeroU32::new),
        cancellation: Some(cancellation.clone()),
    }
}

#[test]
fn an_intact_window_passes_at_every_level() -> Result {
    let f = fixture(4)?;
    for level in LEVELS {
        assert_eq!(
            f.outcome(level, None)?,
            VerifyOutcome::Passed { blocks: 4 },
            "{level:?}"
        );
        assert_eq!(
            f.outcome(level, Some(2))?,
            VerifyOutcome::Passed { blocks: 2 },
            "{level:?}"
        );
        assert_eq!(
            f.outcome(level, Some(100))?,
            VerifyOutcome::Passed { blocks: 4 },
            "{level:?}"
        );
    }
    assert_eq!(
        f.retention.active_leases(),
        0,
        "the walk must release its history pin"
    );
    Ok(())
}

#[test]
fn a_chain_with_no_block_above_genesis_has_nothing_to_check() -> Result {
    let empty = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis_only = fixture(0)?;
    for level in LEVELS {
        assert_eq!(
            verify_recent_blocks(&empty, request(level, None))?,
            VerifyOutcome::Passed { blocks: 0 }
        );
        assert_eq!(
            verify_recent_blocks(&genesis_only.chain, request(level, None))?,
            VerifyOutcome::Passed { blocks: 0 }
        );
    }
    Ok(())
}

/// A corrupt referenced frame is damage at every level: never a missing
/// body, and never a skip, even without a history floor.
#[test]
fn a_corrupt_referenced_frame_is_damage_not_missing_or_skipped() -> Result {
    let f = fixture(4)?;
    f.corrupt_body(3)?;
    for level in LEVELS {
        let error = f.damage(level, None)?;
        assert!(
            matches!(error, VerifyError::BodyCorrupt { height: 3, .. }),
            "{level:?}: {error}"
        );
    }
    assert_eq!(
        f.retention.active_leases(),
        0,
        "the walk must release its history pin"
    );
    Ok(())
}

#[test]
fn a_store_without_block_bodies_skips_the_window() -> Result {
    let mut f = fixture(3)?;
    f.chain.block_body_store = None;
    assert_eq!(
        f.outcome(CheckLevel::CheckUndo, None)?,
        VerifyOutcome::SkippedNoBlockData { height: 3 }
    );
    Ok(())
}

#[test]
fn a_missing_body_above_the_floor_is_damage_inside_the_window_only() -> Result {
    let f = fixture(4)?;
    f.drop_body(2)?;
    for level in LEVELS {
        let error = f.damage(level, None)?;
        assert!(
            matches!(error, VerifyError::BodyMissing { height: 2, hash } if hash == f.hash(2)),
            "{level:?}: {error}"
        );
    }
    assert_eq!(
        f.outcome(CheckLevel::CheckUndo, Some(2))?,
        VerifyOutcome::Passed { blocks: 2 },
        "a window above the damage must not see it"
    );
    Ok(())
}

#[test]
fn bodies_that_are_not_the_named_block_fail_to_decode() -> Result {
    // Truncated: not one complete block.
    let f = fixture(4)?;
    f.damage_body(3, |bytes| bytes.truncate(bytes.len() - 1))?;
    for level in LEVELS {
        let error = f.damage(level, None)?;
        assert!(
            matches!(
                error,
                VerifyError::BodyDecode {
                    height: 3,
                    source: BodyDecodeError::Malformed(_),
                    ..
                }
            ),
            "{level:?}: {error}"
        );
    }

    // Trailing bytes are not a canonical block either.
    let f = fixture(4)?;
    f.damage_body(3, |bytes| bytes.push(0))?;
    let error = f.damage(CheckLevel::ReadBodies, None)?;
    assert!(
        matches!(
            error,
            VerifyError::BodyDecode {
                height: 3,
                source: BodyDecodeError::Malformed(_),
                ..
            }
        ),
        "{error}"
    );

    // A header that hashes to something else is another block's body.
    let f = fixture(4)?;
    f.damage_body(2, |bytes| bytes[79] ^= 0xff)?;
    let error = f.damage(CheckLevel::ReadBodies, None)?;
    assert!(
        matches!(
            error,
            VerifyError::BodyDecode {
                height: 2,
                source: BodyDecodeError::HashMismatch { found },
                ..
            } if found != f.hash(2)
        ),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_body_that_decodes_but_breaks_its_header_binding_needs_the_body_level() -> Result {
    let f = fixture(4)?;
    // The final byte is the coinbase lock time: the body still decodes and
    // keeps its header, but its transaction id and Merkle root change.
    f.damage_body(3, |bytes| {
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xff;
        }
    })?;
    assert_eq!(
        f.outcome(CheckLevel::ReadBodies, None)?,
        VerifyOutcome::Passed { blocks: 4 },
        "reading and decoding cannot see a commitment mismatch"
    );
    for level in [CheckLevel::CheckBodies, CheckLevel::CheckUndo] {
        let error = f.damage(level, None)?;
        assert!(
            matches!(
                error,
                VerifyError::Binding {
                    height: 3,
                    source: ConsensusError::MerkleRoot,
                    ..
                }
            ),
            "{level:?}: {error}"
        );
    }
    Ok(())
}

#[test]
fn a_body_with_valid_commitments_but_broken_transaction_rules_needs_the_body_level() -> Result {
    let f = fixture(4)?;
    let tip = f.chain.applied_tip_snapshot().ok_or("no applied tip")?;
    // Shorten the tip coinbase scriptSig below the 2-byte consensus floor,
    // then re-root and re-mine the header so the Merkle root, the header
    // hash and the work all check out and only the transaction rules fail.
    let mut ruled = f.blocks[4].clone();
    ruled.txs[0].inputs[0].script_sig = Script::from_bytes(vec![0]);
    ruled.header.merkle_root = merkle_root(&ruled.txs).ok_or("the tip keeps its transaction")?;
    mine_header_to_declared_target(&mut ruled.header)?;
    let ruled_hash = Hash256::from(ruled.block_hash());
    f.bodies.replace(4, ruled_hash, consensus_bytes(&ruled));
    {
        let mut tree = f.chain.block_tree().write();
        let node = tree.node_mut(tip.tip_id)?;
        node.hash = ruled_hash;
        node.header = ruled.header;
    }
    f.chain.applied_tip().store(Some(Arc::new(TipSnapshot {
        hash: ruled_hash,
        ..(*tip).clone()
    })));

    assert_eq!(
        f.outcome(CheckLevel::ReadBodies, None)?,
        VerifyOutcome::Passed { blocks: 4 },
        "reading and decoding cannot see broken transaction rules"
    );
    for level in [
        CheckLevel::CheckBodies,
        CheckLevel::CheckUndo,
        CheckLevel::CheckUndoAndCommitments,
    ] {
        let error = f.damage(level, None)?;
        assert!(
            matches!(
                error,
                VerifyError::Binding {
                    height: 4,
                    source: ConsensusError::CoinbaseScriptSigSize { len: 1 },
                    ..
                }
            ),
            "{level:?}: {error}"
        );
    }
    Ok(())
}

#[test]
fn a_witness_only_mutation_passes_core_levels_but_fails_the_startup_level() -> Result {
    let f = fixture(4)?;
    // A witness stack on the tip coinbase changes the stored bytes without
    // touching the txid, the header, or the work, so no re-root, re-mine, or
    // tree surgery is needed.
    let mut bytes = f.bodies.bytes(4, f.hash(4))?;
    let mut block: Block = deserialize(&bytes)?;
    block.txs[0].inputs[0].witness = Witness::from_stack(vec![[0u8; 32].to_vec()]);
    bytes = consensus_bytes(&block);
    f.bodies.replace(4, f.hash(4), bytes);
    for level in [
        CheckLevel::ReadBodies,
        CheckLevel::CheckBodies,
        CheckLevel::CheckUndo,
    ] {
        assert_eq!(
            f.outcome(level, None)?,
            VerifyOutcome::Passed { blocks: 4 },
            "{level:?}: witness data is outside Core's context-free scope"
        );
    }
    let error = f.damage(CheckLevel::CheckUndoAndCommitments, None)?;
    assert!(
        matches!(
            error,
            VerifyError::Binding {
                height: 4,
                source: ConsensusError::UnexpectedWitness,
                ..
            }
        ),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_header_that_misses_its_target_fails_the_body_level() -> Result {
    let f = fixture(4)?;
    let tip = f.chain.applied_tip_snapshot().ok_or("no applied tip")?;
    // Same parent, height, and transactions; a nonce whose hash misses the
    // regtest target. The tree is then made to name this block, so the body
    // is exactly the block the chain claims and only its work is wrong.
    let mut unmined = f.blocks[4].clone();
    loop {
        let hash = Hash256::from(unmined.header.compute_hash());
        if validate_pow(&unmined.header, hash, Network::Regtest).is_err() {
            break;
        }
        unmined.header.nonce += 1;
    }
    let unmined_hash = Hash256::from(unmined.block_hash());
    f.bodies.replace(4, unmined_hash, consensus_bytes(&unmined));
    {
        let mut tree = f.chain.block_tree().write();
        let node = tree.node_mut(tip.tip_id)?;
        node.hash = unmined_hash;
        node.header = unmined.header;
    }
    f.chain.applied_tip().store(Some(Arc::new(TipSnapshot {
        hash: unmined_hash,
        ..(*tip).clone()
    })));

    assert_eq!(
        f.outcome(CheckLevel::ReadBodies, None)?,
        VerifyOutcome::Passed { blocks: 4 }
    );
    for level in [
        CheckLevel::CheckBodies,
        CheckLevel::CheckUndo,
        CheckLevel::CheckUndoAndCommitments,
    ] {
        let error = f.damage(level, None)?;
        assert!(
            matches!(error, VerifyError::ProofOfWork { height: 4, .. }),
            "{level:?}: {error}"
        );
    }
    Ok(())
}

#[test]
fn undo_records_are_read_and_decoded_only_at_the_undo_level() -> Result {
    let f = fixture(4)?;
    f.undo.remove_archived(3, f.hash(3));
    f.undo.persist_undo(2, f.hash(2), &[0xff, 0x00])?;
    for level in [CheckLevel::ReadBodies, CheckLevel::CheckBodies] {
        assert_eq!(
            f.outcome(level, None)?,
            VerifyOutcome::Passed { blocks: 4 },
            "{level:?}"
        );
    }
    let error = f.damage(CheckLevel::CheckUndo, None)?;
    assert!(
        matches!(error, VerifyError::UndoMissing { height: 3, hash } if hash == f.hash(3)),
        "{error}"
    );
    // Heights below the missing record still hold the undecodable one.
    f.undo.persist_undo(3, f.hash(3), &[0xff, 0x00])?;
    let error = f.damage(CheckLevel::CheckUndo, None)?;
    assert!(
        matches!(error, VerifyError::UndoDecode { height: 3, .. }),
        "{error}"
    );
    Ok(())
}

#[test]
fn an_executed_prune_line_ends_the_window_without_hiding_damage_above_it() -> Result {
    let f = fixture(5)?;
    f.retention.reserve(3).commit(3);
    // Height 1 is below the line and its body is gone, as pruning leaves it.
    f.drop_body(1)?;
    f.undo.remove_archived(1, f.hash(1));
    for level in LEVELS {
        assert_eq!(
            f.outcome(level, None)?,
            VerifyOutcome::SkippedNoBlockData { height: 2 },
            "{level:?}"
        );
    }
    // The line itself is retained history: height 3 is checked.
    f.drop_body(3)?;
    let error = f.damage(CheckLevel::CheckUndo, None)?;
    assert!(
        matches!(error, VerifyError::BodyMissing { height: 3, .. }),
        "{error}"
    );
    // A window entirely above the line is an ordinary window.
    assert_eq!(
        f.outcome(CheckLevel::CheckUndo, Some(2))?,
        VerifyOutcome::Passed { blocks: 2 }
    );
    Ok(())
}

#[test]
fn a_window_reaching_a_prune_in_flight_is_skipped_until_the_claim_ends() -> Result {
    let f = fixture(5)?;
    let claim = f.retention.reserve(4);
    assert_eq!(
        f.outcome(CheckLevel::CheckUndo, None)?,
        VerifyOutcome::SkippedNoBlockData { height: 3 }
    );
    drop(claim);
    assert_eq!(
        f.outcome(CheckLevel::CheckUndo, None)?,
        VerifyOutcome::Passed { blocks: 5 },
        "an aborted pass deletes nothing"
    );
    Ok(())
}

#[test]
fn an_assumed_valid_base_is_never_checked() -> Result {
    let f = fixture(5)?;
    f.drop_body(1)?;
    f.drop_body(2)?;
    f.chain.set_role(ChainstateRole::AssumedActive {
        base_height: 2,
        base_hash: f.hash(2),
    });
    assert_eq!(
        f.outcome(CheckLevel::CheckUndo, None)?,
        VerifyOutcome::SkippedNoBlockData { height: 2 },
        "the base and everything under it was never connected here"
    );
    f.drop_body(3)?;
    let error = f.damage(CheckLevel::ReadBodies, None)?;
    assert!(
        matches!(error, VerifyError::BodyMissing { height: 3, .. }),
        "{error}"
    );
    f.chain.set_role(ChainstateRole::AssumedActive {
        base_height: 5,
        base_hash: f.hash(5),
    });
    assert_eq!(
        f.outcome(CheckLevel::CheckUndo, None)?,
        VerifyOutcome::SkippedNoBlockData { height: 5 },
        "a chain with no block above its snapshot base has nothing to check"
    );
    Ok(())
}

#[test]
fn a_historical_role_keeps_its_whole_window() -> Result {
    let f = fixture(4)?;
    f.chain.set_role(ChainstateRole::Historical {
        base_height: 3,
        base_hash: f.hash(3),
    });
    f.drop_body(1)?;
    let error = f.damage(CheckLevel::ReadBodies, None)?;
    assert!(
        matches!(error, VerifyError::BodyMissing { height: 1, .. }),
        "{error}"
    );
    Ok(())
}

#[test]
fn shutdown_during_the_walk_skips_instead_of_failing() -> Result {
    let f = fixture(4)?;
    f.chain
        .shutdown
        .store(true, core::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        f.outcome(CheckLevel::CheckUndo, None)?,
        VerifyOutcome::SkippedNoBlockData { height: 4 }
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}

#[test]
fn a_request_cancelled_before_admission_never_reads_or_pins() -> Result {
    let f = fixture(4)?;
    let flag = Arc::new(core::sync::atomic::AtomicBool::new(true));
    let cancellation = LatchReader::new(Arc::clone(&flag));
    let error = verify_recent_blocks(
        &f.chain,
        cancellable_request(CheckLevel::CheckUndo, None, &cancellation),
    )
    .err()
    .ok_or("a cancelled request must not pass")?;
    assert!(
        matches!(error, VerifyError::Interrupted),
        "cancellation is an operator stop, not damage: {error}"
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}

#[test]
fn a_request_cancelled_during_the_walk_interrupts_without_success() -> Result {
    let f = fixture(4)?;
    let flag = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let cancellation = LatchReader::new(Arc::clone(&flag));
    let trigger = Arc::clone(&flag);
    *f.bodies.before_read.lock() = Some(Box::new(move || {
        trigger.store(true, core::sync::atomic::Ordering::SeqCst);
    }));
    let error = verify_recent_blocks(
        &f.chain,
        cancellable_request(CheckLevel::CheckUndo, None, &cancellation),
    )
    .err()
    .ok_or("a cancelled walk must not pass")?;
    assert!(
        matches!(error, VerifyError::Interrupted),
        "the mid-walk latch must interrupt, not fail as damage: {error}"
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}

#[test]
fn a_recovery_closed_chainstate_is_unavailable_even_over_an_empty_window() -> Result {
    let f = fixture(4)?;
    f.chain.fail_closed_for_recovery();
    let error = verify_recent_blocks(&f.chain, request(CheckLevel::CheckUndo, None))
        .err()
        .ok_or("a closed chainstate must not verify")?;
    assert!(
        matches!(error, VerifyError::ClosedForRecovery),
        "closure is fail-closed admission state, not damage: {error}"
    );
    assert_eq!(
        f.retention.active_leases(),
        0,
        "the refusal must not pin history"
    );
    let empty = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    empty.fail_closed_for_recovery();
    let error = verify_recent_blocks(&empty, request(CheckLevel::ReadBodies, None))
        .err()
        .ok_or("a closed chainstate must not pass an empty window")?;
    assert!(matches!(error, VerifyError::ClosedForRecovery), "{error}");
    Ok(())
}

#[test]
fn closing_for_recovery_during_the_walk_refuses_success() -> Result {
    let f = fixture(4)?;
    let chain = f.chain.clone();
    *f.bodies.before_read.lock() = Some(Box::new(move || {
        chain.fail_closed_for_recovery();
    }));
    let error = verify_recent_blocks(&f.chain, request(CheckLevel::CheckUndo, None))
        .err()
        .ok_or("a walk closed mid-read must not pass")?;
    assert!(
        matches!(error, VerifyError::ClosedForRecovery),
        "the closure must fail closed, not skip or pass: {error}"
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}

#[test]
fn a_pin_withdrawn_mid_walk_skips_even_when_the_rows_are_still_readable() -> Result {
    let mut f = fixture(5)?;
    f.chain.history = HistoryAccess::new(Arc::clone(&f.retention), RetentionBudget::Depth(1));
    let retention = Arc::clone(&f.retention);
    *f.bodies.before_read.lock() = Some(Box::new(move || {
        drop(retention.reserve(5));
        assert_eq!(retention.retention_floor(), None, "the pin was withdrawn");
    }));
    assert_eq!(
        f.outcome(CheckLevel::ReadBodies, None)?,
        VerifyOutcome::SkippedNoBlockData { height: 4 },
        "readable rows under a withdrawn pin are skipped, never passed"
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}

#[test]
fn rows_a_prune_pass_took_while_the_pin_was_withdrawn_are_not_damage() -> Result {
    let mut f = fixture(5)?;
    // A budget of one block lets the pass below expire the walk's pin.
    f.chain.history = HistoryAccess::new(Arc::clone(&f.retention), RetentionBudget::Depth(1));
    let (bodies, retention, doomed) = (Arc::clone(&f.bodies), Arc::clone(&f.retention), f.hash(5));
    *f.bodies.before_read.lock() = Some(Box::new(move || {
        assert_eq!(
            retention.retention_floor(),
            Some(1),
            "the window must be pinned before its first read"
        );
        // The pass reserves a deletion line far above the pin, which expires
        // it, and then deletes the row under the current read.
        drop(retention.reserve(5));
        assert_eq!(retention.retention_floor(), None, "the pin was withdrawn");
        bodies.remove(5, doomed);
    }));
    assert_eq!(
        f.outcome(CheckLevel::ReadBodies, None)?,
        VerifyOutcome::SkippedNoBlockData { height: 5 }
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}
/// A latch fired on the window's only (hence final) read interrupts before
/// success: the per-height poll already passed over the quiet latch, so only
/// the pre-success poll observes it. Removing that poll reports Passed.
#[test]
fn a_request_cancelled_on_the_final_read_interrupts_before_success() -> Result {
    let f = fixture(4)?;
    let flag = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let cancellation = LatchReader::new(Arc::clone(&flag));
    let trigger = Arc::clone(&flag);
    *f.bodies.before_read.lock() = Some(Box::new(move || {
        trigger.store(true, core::sync::atomic::Ordering::SeqCst);
    }));
    let error = verify_recent_blocks(
        &f.chain,
        cancellable_request(CheckLevel::CheckUndo, Some(1), &cancellation),
    )
    .err()
    .ok_or("a walk cancelled on its final read must not pass")?;
    assert!(
        matches!(error, VerifyError::Interrupted),
        "the final-read latch must interrupt, not pass as success: {error}"
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}

/// A recovery closure landing on the window's only (hence final) read refuses
/// success: the per-height poll already passed over the open chainstate, so
/// only the pre-success poll observes it. Removing that poll reports Passed.
#[test]
fn closing_for_recovery_on_the_final_read_refuses_success() -> Result {
    let f = fixture(4)?;
    let chain = f.chain.clone();
    *f.bodies.before_read.lock() = Some(Box::new(move || {
        chain.fail_closed_for_recovery();
    }));
    let error = verify_recent_blocks(&f.chain, request(CheckLevel::CheckUndo, Some(1)))
        .err()
        .ok_or("a walk closed on its final read must not pass")?;
    assert!(
        matches!(error, VerifyError::ClosedForRecovery),
        "the final-read closure must fail closed, not pass: {error}"
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}

/// A pin withdrawn on the window's only (hence final) read skips instead of
/// passing: the per-height poll already passed over the live pin, so only the
/// pre-success poll observes the withdrawal. Removing that poll reports
/// Passed over rows the owner no longer protects.
#[test]
fn a_pin_withdrawn_on_the_final_read_skips_instead_of_passing() -> Result {
    let mut f = fixture(5)?;
    f.chain.history = HistoryAccess::new(Arc::clone(&f.retention), RetentionBudget::Depth(1));
    let retention = Arc::clone(&f.retention);
    *f.bodies.before_read.lock() = Some(Box::new(move || {
        // The lease floors at the tip (5) under a depth-1 budget, so the
        // pass must claim past 6 to expire it; the mechanics are otherwise
        // the mid-walk pin test's.
        drop(retention.reserve(7));
        assert_eq!(retention.retention_floor(), None, "the pin was withdrawn");
    }));
    assert_eq!(
        f.outcome(CheckLevel::ReadBodies, Some(1))?,
        VerifyOutcome::SkippedNoBlockData { height: 5 },
        "a row readable under a withdrawn pin is skipped, never passed"
    );
    assert_eq!(f.retention.active_leases(), 0);
    Ok(())
}
