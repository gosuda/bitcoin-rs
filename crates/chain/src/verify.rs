use core::num::NonZeroU32;
use std::sync::Arc;

use crate::chain::{BlockTreeReader, ChainError, NodeId, softfork_state, validate_pow};
use bitcoin_rs_consensus::latch::LatchReader;
use bitcoin_rs_consensus::primitives::{Block, DecodeError, Hash256, deserialize};
use bitcoin_rs_consensus::{
    BlockRuleContext, ConsensusError, check_block_body_binding,
    verify_block::verify_block_non_contextual,
};
use bitcoin_rs_storage::utxo::contract::{
    UndoCodecError, decode_undo_record_for_block, undo_record_size_limit,
};
use bitcoin_rs_storage::{
    BoundedReadError,
    block_body::BlockBodyStore,
    pruning::{HistoryLease, HistoryUnavailable},
};

use crate::block_spends::MAX_BLOCK_QUERY_BYTES;
use crate::{Chainstate, ChainstateRole};

pub const STARTUP_VERIFY_DEPTH: NonZeroU32 = match NonZeroU32::new(6) {
    Some(depth) => depth,
    None => panic!("the startup verification depth is nonzero"),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckLevel {
    ReadBodies,
    CheckBodies,
    CheckUndo,
    CheckUndoAndCommitments,
}

#[derive(Clone, Debug)]
pub struct VerifyRequest {
    pub level: CheckLevel,
    pub depth: Option<NonZeroU32>,
    pub cancellation: Option<LatchReader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Passed { blocks: u32 },
    SkippedNoBlockData { height: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum BodyDecodeError {
    #[error(transparent)]
    Malformed(DecodeError),
    #[error("header hashes to {found}")]
    HashMismatch { found: Hash256 },
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("block {hash} at height {height} has no stored body")]
    BodyMissing { height: u32, hash: Hash256 },
    #[error("reading the body of block {hash} at height {height} failed: {source}")]
    BodyRead {
        height: u32,
        hash: Hash256,
        #[source]
        source: BoundedReadError,
    },
    /// The stored body frame is malformed or truncated.
    ///
    /// Corruption the verifier observes is damage, never a missing body and never a
    /// skip: a prune pass deletes rows atomically and never leaves corrupt frames
    /// behind.
    #[error("body frame of block {hash} at height {height} is corrupt: {evidence}")]
    BodyCorrupt {
        height: u32,
        hash: Hash256,
        evidence: &'static str,
    },
    #[error("body of block {hash} at height {height} does not decode: {source}")]
    BodyDecode {
        height: u32,
        hash: Hash256,
        #[source]
        source: BodyDecodeError,
    },
    #[error("block {hash} at height {height} fails its proof-of-work check: {source}")]
    ProofOfWork {
        height: u32,
        hash: Hash256,
        #[source]
        source: Box<ChainError>,
    },
    #[error("body of block {hash} at height {height} does not match its header: {source}")]
    Binding {
        height: u32,
        hash: Hash256,
        #[source]
        source: ConsensusError,
    },
    #[error("block {hash} at height {height} has no stored undo record")]
    UndoMissing { height: u32, hash: Hash256 },
    #[error("reading the undo record of block {hash} at height {height} failed: {source}")]
    UndoRead {
        height: u32,
        hash: Hash256,
        #[source]
        source: BoundedReadError,
    },
    #[error("chainstate is closed for recovery")]
    ClosedForRecovery,
    #[error("block verification was interrupted")]
    Interrupted,
    #[error("undo record of block {hash} at height {height} does not decode: {source}")]
    UndoDecode {
        height: u32,
        hash: Hash256,
        #[source]
        source: Box<UndoCodecError>,
    },
}

/// INVARIANT: no history is read unpinned, and a read that finds nothing
/// after the owner withdrew the pin is `SkippedNoBlockData`, never damage.
///
/// The pin is also checked at every progress boundary and before reporting
/// success, so a withdrawal the walk already passed still refuses `Passed`.
pub fn verify_recent_blocks(
    chainstate: &Chainstate,
    request: VerifyRequest,
) -> Result<VerifyOutcome, VerifyError> {
    if request
        .cancellation
        .as_ref()
        .is_some_and(LatchReader::is_triggered)
    {
        return Err(VerifyError::Interrupted);
    }
    if chainstate.is_closed_for_recovery() {
        return Err(VerifyError::ClosedForRecovery);
    }
    let Some(tip) = chainstate
        .applied_tip_snapshot()
        .filter(|tip| tip.height > 0)
    else {
        return Ok(VerifyOutcome::Passed { blocks: 0 });
    };
    let Some(store) = chainstate.block_body_store_handle() else {
        return Ok(VerifyOutcome::SkippedNoBlockData { height: tip.height });
    };
    let requested = request
        .depth
        .map_or(1, |depth| tip.height.saturating_sub(depth.get() - 1))
        .max(1);
    let (lease, start) = match pin_window(chainstate, requested, tip.height) {
        Ok(pinned) => pinned,
        Err(height) => return Ok(VerifyOutcome::SkippedNoBlockData { height }),
    };
    let walk = Walk {
        chainstate,
        store,
        lease,
        level: request.level,
        cancellation: request.cancellation,
    };
    match walk.run(tip.tip_id, tip.hash, tip.height, start) {
        Ok(_) if start > requested => Ok(VerifyOutcome::SkippedNoBlockData {
            height: start.saturating_sub(1),
        }),
        Ok(blocks) => Ok(VerifyOutcome::Passed { blocks }),
        Err(Stop::Skipped { height }) => Ok(VerifyOutcome::SkippedNoBlockData { height }),
        Err(Stop::Interrupted) => Err(VerifyError::Interrupted),
        Err(Stop::Failed(error)) => Err(error),
    }
}

fn pin_window(
    chainstate: &Chainstate,
    requested: u32,
    tip_height: u32,
) -> Result<(HistoryLease, u32), u32> {
    let role_floor = match chainstate.role() {
        ChainstateRole::AssumedActive { base_height, .. } => base_height.saturating_add(1),
        ChainstateRole::Ordinary | ChainstateRole::Historical { .. } => 0,
    };
    let mut start = requested.max(role_floor);
    for _ in 0..PIN_ATTEMPTS {
        if start > tip_height {
            break;
        }
        match chainstate.history.request_history(start) {
            Ok(lease) => return Ok((lease, start)),
            Err(HistoryUnavailable::Pruned { below } | HistoryUnavailable::Reserved { below })
                if below > start =>
            {
                start = below;
            }
            Err(_) => break,
        }
    }
    Err(tip_height)
}

const PIN_ATTEMPTS: usize = 3;

enum Stop {
    Skipped { height: u32 },
    Interrupted,
    Failed(VerifyError),
}

impl From<VerifyError> for Stop {
    fn from(error: VerifyError) -> Self {
        Self::Failed(error)
    }
}

struct Ancestor {
    hash: Hash256,
    parent: NodeId,
    prev_hash: Hash256,
    segwit_active: bool,
}

struct Walk<'a> {
    chainstate: &'a Chainstate,
    store: Arc<dyn BlockBodyStore>,
    lease: HistoryLease,
    level: CheckLevel,
    cancellation: Option<LatchReader>,
}

impl Walk<'_> {
    fn run(
        &self,
        tip_id: NodeId,
        tip_hash: Hash256,
        tip_height: u32,
        start: u32,
    ) -> Result<u32, Stop> {
        let tree = self.chainstate.block_tree_reader();
        let mut next = (tip_id, tip_hash);
        let mut checked = 0_u32;
        for height in (start..=tip_height).rev() {
            self.poll_boundaries(height)?;
            let ancestor = self.locate(&tree, next.0, height, next.1)?;
            next = (ancestor.parent, ancestor.prev_hash);
            self.check(height, &ancestor)?;
            checked = checked.saturating_add(1);
        }
        self.poll_boundaries(tip_height)?;
        Ok(checked)
    }

    fn poll_boundaries(&self, height: u32) -> Result<(), Stop> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(LatchReader::is_triggered)
        {
            return Err(Stop::Interrupted);
        }
        if self.chainstate.is_closed_for_recovery() {
            return Err(Stop::Failed(VerifyError::ClosedForRecovery));
        }
        if self.chainstate.shutdown.reader().is_triggered() {
            return Err(Stop::Skipped { height });
        }
        if self.lease.floor().is_none() {
            return Err(Stop::Skipped { height });
        }
        Ok(())
    }

    fn locate(
        &self,
        tree: &BlockTreeReader,
        id: NodeId,
        height: u32,
        hash: Hash256,
    ) -> Result<Ancestor, VerifyError> {
        let guard = tree.read();
        let Some(node) = guard
            .node(id)
            .ok()
            .filter(|node| node.height == height && node.hash == hash)
        else {
            return Err(VerifyError::BodyMissing { height, hash });
        };
        let prev_hash = node.header.prev_blockhash.0;
        let Some(parent) = node.parent else {
            return Err(VerifyError::BodyMissing {
                height: height.saturating_sub(1),
                hash: prev_hash,
            });
        };
        let segwit_active = self.level >= CheckLevel::CheckUndoAndCommitments
            && softfork_state(&guard, self.chainstate.network, Some(parent), height).segwit_active;
        Ok(Ancestor {
            hash,
            parent,
            prev_hash,
            segwit_active,
        })
    }

    fn check(&self, height: u32, ancestor: &Ancestor) -> Result<(), Stop> {
        let block = self.read_block(height, ancestor.hash)?;
        if self.level >= CheckLevel::CheckBodies {
            check_body(self.chainstate, &block, height, ancestor.hash)?;
        }
        if self.level >= CheckLevel::CheckUndo {
            self.check_undo(&block, height, ancestor.hash)?;
        }
        if self.level >= CheckLevel::CheckUndoAndCommitments {
            check_binding(&block, height, ancestor)?;
        }
        Ok(())
    }

    fn read_block(&self, height: u32, hash: Hash256) -> Result<Block, Stop> {
        let bytes = match self.store.load_block_body_for_verification_bounded(
            height,
            hash,
            MAX_BLOCK_QUERY_BYTES,
        ) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Err(self.absent(height, VerifyError::BodyMissing { height, hash })),
            Err(BoundedReadError::CorruptFrame(evidence)) => {
                return Err(Stop::Failed(VerifyError::BodyCorrupt {
                    height,
                    hash,
                    evidence,
                }));
            }
            Err(source) => {
                return Err(Stop::Failed(VerifyError::BodyRead {
                    height,
                    hash,
                    source,
                }));
            }
        };
        Ok(decode_body(&bytes, height, hash)?)
    }

    fn check_undo(&self, block: &Block, height: u32, hash: Hash256) -> Result<(), Stop> {
        let record = self.load_undo(block, height, hash)?;
        decode_undo_record_for_block(&record, block)
            .map(drop)
            .map_err(|source| {
                Stop::Failed(VerifyError::UndoDecode {
                    height,
                    hash,
                    source: Box::new(source),
                })
            })
    }

    fn load_undo(&self, block: &Block, height: u32, hash: Hash256) -> Result<Vec<u8>, Stop> {
        match self.chainstate.undo_store.load_undo_bounded(
            height,
            hash,
            undo_record_size_limit(block, bitcoin_rs_consensus::script::MAX_SCRIPT_SIZE),
        ) {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(self.absent(height, VerifyError::UndoMissing { height, hash })),
            Err(source) => Err(Stop::Failed(VerifyError::UndoRead {
                height,
                hash,
                source,
            })),
        }
    }

    fn absent(&self, height: u32, damage: VerifyError) -> Stop {
        if self.lease.floor().is_some() {
            Stop::Failed(damage)
        } else {
            Stop::Skipped { height }
        }
    }
}

fn decode_body(bytes: &[u8], height: u32, hash: Hash256) -> Result<Block, VerifyError> {
    let refused = |source| VerifyError::BodyDecode {
        height,
        hash,
        source,
    };
    let block: Block =
        deserialize(bytes).map_err(|source| refused(BodyDecodeError::Malformed(source)))?;
    let found = block.block_hash().0;
    if found != hash {
        return Err(refused(BodyDecodeError::HashMismatch { found }));
    }
    Ok(block)
}

fn check_body(
    chainstate: &Chainstate,
    block: &Block,
    height: u32,
    hash: Hash256,
) -> Result<(), VerifyError> {
    validate_pow(&block.header, hash, chainstate.network).map_err(|source| {
        VerifyError::ProofOfWork {
            height,
            hash,
            source: Box::new(source),
        }
    })?;
    verify_block_non_contextual(block).map_err(|source| VerifyError::Binding {
        height,
        hash,
        source,
    })
}

fn check_binding(block: &Block, height: u32, ancestor: &Ancestor) -> Result<(), VerifyError> {
    let hash = ancestor.hash;
    check_block_body_binding(
        block,
        BlockRuleContext {
            segwit_active: ancestor.segwit_active,
        },
    )
    .map_err(|source| VerifyError::Binding {
        height,
        hash,
        source,
    })
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;
    use std::sync::Arc;

    use crate::chain::regtest_fixture::{
        merkle_root, mine_header_to_declared_target, mined_regtest_child_at,
    };
    use crate::chain::{TipSnapshot, validate_pow};
    use bitcoin_rs_consensus::ConsensusError;
    use bitcoin_rs_consensus::latch::{LatchReader, LatchWriter};
    use bitcoin_rs_consensus::primitives::{
        Block, BlockImage, Hash256, Network, Script, Witness, consensus_bytes, deserialize,
    };
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget};
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::{
        BoundedReadError, KvUndoStore, MandatoryRetention, RetentionRegistry, StorageError,
        UndoStore,
    };
    use hashbrown::{HashMap, HashSet};
    use parking_lot::Mutex;

    use super::{
        BodyDecodeError, CheckLevel, VerifyError, VerifyOutcome, VerifyRequest,
        verify_recent_blocks,
    };
    use crate::test_fixtures::{TestError, TestResult, handles};
    use crate::{Chainstate, ChainstateRole};

    type Result<T = ()> = TestResult<T>;

    const LEVELS: [CheckLevel; 4] = [
        CheckLevel::ReadBodies,
        CheckLevel::CheckBodies,
        CheckLevel::CheckUndo,
        CheckLevel::CheckUndoAndCommitments,
    ];

    #[derive(Default)]
    struct Bodies {
        rows: Mutex<HashMap<(u32, Hash256), Vec<u8>>>,
        corrupt: Mutex<HashSet<(u32, Hash256)>>,
        before_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        fail_verification: Mutex<Option<BoundedReadError>>,
    }

    impl Bodies {
        fn bytes(&self, height: u32, hash: Hash256) -> Result<Vec<u8>> {
            self.rows
                .lock()
                .get(&(height, hash))
                .cloned()
                .ok_or(TestError::Missing("fixture body is missing"))
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
            let injected = self.fail_verification.lock().take();
            if let Some(error) = injected {
                return Err(error);
            }
            if self.corrupt.lock().contains(&(height, hash)) {
                return Err(BoundedReadError::from(StorageError::CorruptBlockFrame(
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
        undo: Arc<KvUndoStore<dyn bitcoin_rs_storage::KvStore>>,
        retention: Arc<RetentionRegistry>,
        blocks: Vec<Block>,
    }

    fn fixture(children: u32) -> Result<Fixture> {
        let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let bodies = Arc::new(Bodies::default());
        let undo = Arc::new(KvUndoStore::new(Arc::clone(chain.commit_authority.store())));
        let retention = Arc::new(RetentionRegistry::new());
        chain.block_body_store = Some(bodies.clone());
        chain.undo_store = undo.clone();
        chain.retention = MandatoryRetention::new(Arc::clone(&retention));
        chain.history =
            HistoryAccess::new(Arc::clone(&retention), RetentionBudget::from_blocks(288));
        let genesis = Network::Regtest.genesis_block();
        chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
        let mut blocks = vec![genesis];
        for height in 1..=children {
            let previous = blocks
                .last()
                .ok_or(TestError::Missing("no parent"))?
                .block_hash();
            let block = mined_regtest_child_at(previous, height)?;
            chain.apply_block(&BlockImage::from_local(block.clone()))?;
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

        fn fail_next_verification_read(&self, error: BoundedReadError) {
            *self.bodies.fail_verification.lock() = Some(error);
        }

        fn outcome(&self, level: CheckLevel, depth: Option<u32>) -> Result<VerifyOutcome> {
            Ok(verify_recent_blocks(&self.chain, request(level, depth))?)
        }

        fn damage(&self, level: CheckLevel, depth: Option<u32>) -> Result<VerifyError> {
            verify_recent_blocks(&self.chain, request(level, depth))
                .err()
                .ok_or(TestError::UnexpectedSuccess(
                    "verification passed over damage",
                ))
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
        let tip = f
            .chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("no applied tip"))?;
        let mut ruled = f.blocks[4].clone();
        ruled.txs[0].inputs[0].script_sig = Script::from_bytes(vec![0]);
        ruled.header.merkle_root =
            merkle_root(&ruled.txs).ok_or(TestError::Missing("the tip keeps its transaction"))?;
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
        let tip = f
            .chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("no applied tip"))?;
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
        f.undo.remove_archived(3, f.hash(3))?;
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
        f.drop_body(1)?;
        f.undo.remove_archived(1, f.hash(1))?;
        for level in LEVELS {
            assert_eq!(
                f.outcome(level, None)?,
                VerifyOutcome::SkippedNoBlockData { height: 2 },
                "{level:?}"
            );
        }
        f.drop_body(3)?;
        let error = f.damage(CheckLevel::CheckUndo, None)?;
        assert!(
            matches!(error, VerifyError::BodyMissing { height: 3, .. }),
            "{error}"
        );
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
        f.chain.request_shutdown();
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
        let cancellation = {
            let trigger = LatchWriter::new();
            trigger.trigger();
            trigger.reader()
        };
        let error = verify_recent_blocks(
            &f.chain,
            cancellable_request(CheckLevel::CheckUndo, None, &cancellation),
        )
        .err()
        .ok_or(TestError::UnexpectedSuccess(
            "a cancelled request must not pass",
        ))?;
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
        let trigger = LatchWriter::new();
        let cancellation = trigger.reader();
        *f.bodies.before_read.lock() = Some(Box::new(move || {
            trigger.trigger();
        }));
        let error = verify_recent_blocks(
            &f.chain,
            cancellable_request(CheckLevel::CheckUndo, None, &cancellation),
        )
        .err()
        .ok_or(TestError::UnexpectedSuccess(
            "a cancelled walk must not pass",
        ))?;
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
            .ok_or(TestError::UnexpectedSuccess(
                "a closed chainstate must not verify",
            ))?;
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
            .ok_or(TestError::UnexpectedSuccess(
                "a closed chainstate must not pass an empty window",
            ))?;
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
            .ok_or(TestError::UnexpectedSuccess(
                "a walk closed mid-read must not pass",
            ))?;
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
        f.chain.history = HistoryAccess::new(Arc::clone(&f.retention), RetentionBudget::Depth(1));
        let (bodies, retention, doomed) =
            (Arc::clone(&f.bodies), Arc::clone(&f.retention), f.hash(5));
        *f.bodies.before_read.lock() = Some(Box::new(move || {
            assert_eq!(
                retention.retention_floor(),
                Some(1),
                "the window must be pinned before its first read"
            );
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
    #[test]
    fn a_request_cancelled_on_the_final_read_interrupts_before_success() -> Result {
        let f = fixture(4)?;
        let trigger = LatchWriter::new();
        let cancellation = trigger.reader();
        *f.bodies.before_read.lock() = Some(Box::new(move || {
            trigger.trigger();
        }));
        let error = verify_recent_blocks(
            &f.chain,
            cancellable_request(CheckLevel::CheckUndo, Some(1), &cancellation),
        )
        .err()
        .ok_or(TestError::UnexpectedSuccess(
            "a walk cancelled on its final read must not pass",
        ))?;
        assert!(
            matches!(error, VerifyError::Interrupted),
            "the final-read latch must interrupt, not pass as success: {error}"
        );
        assert_eq!(f.retention.active_leases(), 0);
        Ok(())
    }

    #[test]
    fn closing_for_recovery_on_the_final_read_refuses_success() -> Result {
        let f = fixture(4)?;
        let chain = f.chain.clone();
        *f.bodies.before_read.lock() = Some(Box::new(move || {
            chain.fail_closed_for_recovery();
        }));
        let error = verify_recent_blocks(&f.chain, request(CheckLevel::CheckUndo, Some(1)))
            .err()
            .ok_or(TestError::UnexpectedSuccess(
                "a walk closed on its final read must not pass",
            ))?;
        assert!(
            matches!(error, VerifyError::ClosedForRecovery),
            "the final-read closure must fail closed, not pass: {error}"
        );
        assert_eq!(f.retention.active_leases(), 0);
        Ok(())
    }

    #[test]
    fn a_pin_withdrawn_on_the_final_read_skips_instead_of_passing() -> Result {
        let mut f = fixture(5)?;
        f.chain.history = HistoryAccess::new(Arc::clone(&f.retention), RetentionBudget::Depth(1));
        let retention = Arc::clone(&f.retention);
        *f.bodies.before_read.lock() = Some(Box::new(move || {
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

    // SYNC-04
    #[test]
    fn a_backend_failure_that_names_corruption_is_a_read_failure_not_damage() -> Result {
        let f = fixture(1)?;
        f.fail_next_verification_read(BoundedReadError::Storage(
            "backend-specific: database is corrupted".to_owned(),
        ));
        let error = f.damage(CheckLevel::ReadBodies, None)?;
        assert!(
            matches!(error, VerifyError::BodyRead { .. }),
            "an index backend failure keeps its read-failure class: {error}"
        );
        let f = fixture(1)?;
        f.fail_next_verification_read(BoundedReadError::CorruptFrame("frame checksum mismatch"));
        let error = f.damage(CheckLevel::ReadBodies, None)?;
        assert!(
            matches!(
                error,
                VerifyError::BodyCorrupt {
                    height: 1,
                    evidence: "frame checksum mismatch",
                    ..
                }
            ),
            "a typed corrupt frame stays damage: {error}"
        );
        Ok(())
    }
}
