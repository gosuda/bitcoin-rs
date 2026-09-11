//! Authoritative chainstate mutation: connect, disconnect, and window apply.
//!
//! Ownership, admission, and the `Chainstate` / `ChainTransition` boundary
//! are specified by `ARCH-07` in `docs/contracts/architecture.md`. Apply
//! publishes the tip and returns a concrete connect or disconnect outcome.
//! [`crate::chain_effects`] consumes that outcome after the commit.

#[cfg(test)]
use rayon::prelude::*;
mod connect;
mod contextual;
mod disconnect;
mod entrypoints;
pub(crate) mod prepare;
mod publication;
pub(crate) mod window;

use crate::apply::error::ApplyError;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::TipSnapshot;
#[cfg(test)]
use bitcoin_rs_consensus::MAX_SCRIPT_SIZE;
use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_mempool::ChainChangeGuard;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolGateway;
#[cfg(test)]
use bitcoin_rs_primitives::Amount;
use bitcoin_rs_primitives::Block;
#[cfg(test)]
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Hash256;
#[cfg(test)]
use bitcoin_rs_primitives::LockTime;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::OutPoint;
#[cfg(test)]
use bitcoin_rs_primitives::Script;
#[cfg(test)]
use bitcoin_rs_primitives::Sequence;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::TxOut;
use bitcoin_rs_primitives::Txid;
#[cfg(test)]
use bitcoin_rs_primitives::Witness;
#[cfg(test)]
use bitcoin_rs_primitives::consensus_bytes;
#[cfg(test)]
use bitcoin_rs_storage::DisconnectMarker;
use bitcoin_rs_storage::InMemoryUndoStore;
#[cfg(test)]
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_utxo::LiveOutput;
use bitcoin_rs_utxo::LiveOutputMeta;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::connect::SpentOutputLookup;
#[cfg(test)]
use bitcoin_rs_utxo::connect::build_block_changes;
use bitcoin_rs_utxo::is_coinbase_tx;
#[cfg(test)]
use connect::applied_header_tip;
#[cfg(test)]
use connect::applied_predecessor;
use connect::apply_block_with_serialized_admitted;
use connect::apply_committed_block_admitted;
#[cfg(test)]
use contextual::check_bip30_and_bip34;
#[cfg(test)]
use contextual::check_bip68_sequence_locks;
#[cfg(test)]
use contextual::check_coinbase_maturity_with_tx_plan;
#[cfg(test)]
use contextual::check_pow_limit_and_continuity;
#[cfg(test)]
use contextual::compact_is_met_by;
#[cfg(test)]
use contextual::compact_to_target;
#[cfg(test)]
use contextual::compute_verify_flags;
use disconnect::disconnect_block_admitted;
use hashbrown::HashMap;
#[cfg(test)]
use hashbrown::HashSet;
use parking_lot::Mutex;
use parking_lot::MutexGuard;
use parking_lot::RwLock;
use parking_lot::RwLockReadGuard;
use parking_lot::RwLockWriteGuard;
#[cfg(test)]
use prepare::bytes_are_block;
#[cfg(test)]
use prepare::parse_block_for_apply;
#[cfg(test)]
use prepare::plan_block_transactions;
#[cfg(test)]
use prepare::verify_block_transactions;
#[cfg(test)]
use publication::advance_chain_tx_count;
#[cfg(test)]
use publication::rewind_chain_tx_count;
#[cfg(test)]
use scratch::ApplyScratch;
use scratch::ApplyScratchCapacities;
use scratch::SameBlockSpentSet;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use window::apply_window_admitted;
#[cfg(test)]
use window::is_permanent_apply_error;
#[cfg(test)]
use window::prove_window;

/// Typed chainstate mutation failures.
pub mod error;
mod scratch;

pub(crate) use bitcoin_rs_storage::{DisconnectPhase, KvUndoStore, UndoStore};

/// Number of blocks after a coinbase that its outputs become spendable.
/// Consensus rule since Bitcoin v0.3.1; universal across networks.
const COINBASE_MATURITY: u32 = 100;
/// BIP68 sequence-bit masks.
const BIP68_DISABLE_FLAG: u32 = 0x8000_0000;
const BIP68_TYPE_FLAG: u32 = 0x0040_0000;
const BIP68_MASK: u32 = 0x0000_ffff;
const BIP68_TIME_GRANULARITY_SECONDS: u32 = 512;
const BIP34_IMPLIES_BIP30_LIMIT: u32 = 1_983_702;
const LOCAL_OVERLAY_TXID_SET_THRESHOLD: usize = 8;

/// Double SHA256, kept next to the witness merkle reduction its only remaining
/// caller (a test fixture helper) uses.
#[cfg(test)]
fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    use sha2::Sha256;
    let inner = Sha256::digest(data);
    let outer = Sha256::digest(inner);
    outer.into()
}

/// Merkle reduction over 32-byte leaves, duplicating the last leaf on odd
/// widths; test-fixture helper after the witness-commitment precheck moved to
/// the consensus crate.
#[cfg(test)]
fn merkle_root_bytes(leaves: &mut Vec<[u8; 32]>) -> Option<[u8; 32]> {
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
            next.push(sha256d(&pair));
        }
        *leaves = next;
    }
    Some(leaves[0])
}

/// Admission barrier shared by every cloned apply handle.
pub(crate) struct ApplyAdmission {
    closed: AtomicBool,
    barrier: RwLock<()>,
}

impl ApplyAdmission {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            barrier: RwLock::new(()),
        }
    }

    fn ensure_open(&self) -> Result<(), ApplyError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ApplyError::Shutdown);
        }
        Ok(())
    }

    fn enter(&self) -> Result<RwLockReadGuard<'_, ()>, ApplyError> {
        self.ensure_open()?;
        let permit = self.barrier.read();
        if let Err(error) = self.ensure_open() {
            drop(permit);
            return Err(error);
        }
        Ok(permit)
    }

    pub(crate) fn close(&self) -> RwLockWriteGuard<'_, ()> {
        self.closed.store(true, Ordering::Release);
        self.barrier.write()
    }

    /// Temporarily pauses new chain transitions while the returned guard lives.
    pub(crate) fn pause(&self) -> RwLockWriteGuard<'_, ()> {
        self.barrier.write()
    }

    /// Closes admission without taking the barrier.
    ///
    /// [`Self::close`] hands back the write guard because shutdown holds it
    /// while it drains. A torn chainstate has nothing to drain and no owner to
    /// hold a guard: it needs the flag set and every later `enter` refused,
    /// including the one that would otherwise apply the next block.
    pub(crate) fn close_permanently(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// Proof that admission and the chain-transition lock are both held.
///
/// [`begin_chain_transition`] is the only constructor. Field order releases
/// the transition lock before the permit. This is the lock token only; the
/// caller-facing mutation capability is [`ChainTransition`].
pub(crate) struct TransitionLock<'a> {
    _transition: MutexGuard<'a, ()>,
    _admission: RwLockReadGuard<'a, ()>,
}

fn begin_chain_transition<'a>(
    admission: &'a ApplyAdmission,
    chain_transition: &'a Mutex<()>,
) -> core::result::Result<TransitionLock<'a>, ApplyError> {
    let admission_guard = admission.enter()?;
    let transition = chain_transition.lock();
    admission.ensure_open()?;
    Ok(TransitionLock {
        _transition: transition,
        _admission: admission_guard,
    })
}

/// Unforgeable proof that a chain change is active: holds both the
/// admission/transition lock ([`TransitionLock`]) and the gateway's
/// [`ChainChangeGuard`] (odd generation).
///
/// Fields and constructor are private to this module. The admitted helpers
/// accept `&ChainChangeProof`, not independent `&TransitionLock` and
/// `&ChainChangeGuard` arguments, so a call without an active odd generation
/// fails to compile. Build one proof per single operation, whole window, or
/// whole reorg. Finish it once the operation reaches a consistent chainstate:
/// a successful return, or a clean refusal whose failing block was refused
/// before the UTXO commit-of-record (`utxo.commit_borrowed_block`). Every
/// failure before that point touches only idempotent derived state (undo,
/// block body, header tree) that a retry overwrites; a `UtxoCommit` refusal
/// may tear the UTXO set, so the transition must be dropped and left odd
/// until recovery establishes a consistent chainstate. Callers that own the
/// retry loop (e.g. [`BlockSync`]) may finish on a clean refusal; convenience
/// entry points finish on success and drop on refusal so the gateway stays
/// fail-closed.
pub(crate) struct ChainChangeProof<'a> {
    #[expect(
        dead_code,
        reason = "carried for unforgeability: holding the proof proves both tokens were acquired"
    )]
    transition: TransitionLock<'a>,
    guard: ChainChangeGuard,
}

impl<'a> ChainChangeProof<'a> {
    /// Constructs the combined proof from its two halves.
    ///
    /// Private to this module: only the entry-point functions that begin a
    /// chain change call this.
    pub(crate) fn new(transition: TransitionLock<'a>, guard: ChainChangeGuard) -> Self {
        Self { transition, guard }
    }

    /// Returns the exact odd generation this proof reserved.
    #[cfg(test)]
    pub(crate) fn odd_generation(&self) -> u64 {
        self.guard.odd_generation()
    }

    /// Returns the reserved even value.
    #[cfg(test)]
    pub(crate) fn reserved_even(&self) -> u64 {
        self.guard.reserved_even()
    }

    /// Finishes the chain change, storing the reserved even value.
    ///
    /// Consumes the proof so it cannot be used after finish.
    pub(crate) fn finish(self) -> core::result::Result<(), ApplyError> {
        self.guard.finish().map_err(|_| ApplyError::Shutdown)
    }
}

/// Chain-mutation authority required by destructive block-body pruning.
#[derive(Clone)]
pub(crate) struct PruneAuthority {
    admission: Arc<ApplyAdmission>,
    chain_transition: Arc<Mutex<()>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
}

impl PruneAuthority {
    pub(crate) fn begin(&self) -> core::result::Result<PruneGuard<'_>, ApplyError> {
        Ok(PruneGuard {
            _transition: begin_chain_transition(&self.admission, &self.chain_transition)?,
            applied_tip: &self.applied_tip,
        })
    }
}

/// Proof that pruning owns chain mutation and may read the authoritative tip.
pub(crate) struct PruneGuard<'a> {
    _transition: TransitionLock<'a>,
    applied_tip: &'a ArcSwapOption<TipSnapshot>,
}

impl PruneGuard<'_> {
    #[must_use]
    pub(crate) fn applied_tip_height(&self) -> Option<u32> {
        self.applied_tip.load().as_ref().map(|tip| tip.height)
    }
}

/// Hash-pinned assume-valid trust gate (Bitcoin Core `-assumevalid` semantics).
///
/// Historical script verification may be skipped only while the active header
/// chain is verified to contain the pinned anchor block. The gate starts
/// trusted when no anchor applies (no pin configured) and starts untrusted
/// when an anchor is pinned; [`AssumeValidGate::evaluate`] re-evaluates trust
/// against the block tree whenever a new inbound headers batch is accepted.
#[derive(Debug)]
pub struct AssumeValidGate {
    /// Pinned `(height, hash)` anchor, or `None` when no pin applies.
    anchor: Option<(u32, Hash256)>,
    /// Whether the active chain is currently verified to contain the anchor.
    trusted: AtomicBool,
    /// Whether the diverged-chain warning has already been emitted.
    warned: AtomicBool,
}

impl AssumeValidGate {
    /// Builds the gate for `network` gated on `configured_height`.
    ///
    /// The network's pinned anchor applies only when `configured_height` equals
    /// the anchor height (the production default). Any other value — `0` (full
    /// verification opt-in) or a custom height-only shortcut — leaves the gate
    /// unpinned and therefore always trusted.
    #[must_use]
    pub fn new(network: Network, configured_height: u32) -> Self {
        let anchor = network
            .assume_valid_anchor()
            .filter(|(height, _)| *height == configured_height);
        Self {
            trusted: AtomicBool::new(anchor.is_none()),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    /// Builds a gate directly from an optional pinned anchor.
    #[must_use]
    pub fn with_anchor(anchor: Option<(u32, Hash256)>) -> Self {
        Self {
            trusted: AtomicBool::new(anchor.is_none()),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    /// Returns whether historical script verification may currently be skipped.
    #[must_use]
    pub fn trusted(&self) -> bool {
        self.trusted.load(Ordering::Relaxed)
    }

    /// Re-evaluates trust against `tree`'s active chain.
    ///
    /// Trusted only when the active tip is at or above the pinned height and
    /// the node at the pinned height on the active chain carries the pinned
    /// hash. Emits a one-time warning when a chain at/past the anchor height
    /// lacks the anchor block; such a chain is never trusted.
    pub fn evaluate(&self, tree: &BlockTree) {
        let Some((pinned_height, pinned_hash)) = self.anchor else {
            return;
        };
        let Some(tip) = tree.tip() else {
            self.trusted.store(false, Ordering::Relaxed);
            return;
        };
        if tip.height < pinned_height {
            self.trusted.store(false, Ordering::Relaxed);
            return;
        }
        let trusted = tree
            .node_at_height_from(tip.tip_id, pinned_height)
            .is_some_and(|id| tree.lookup(pinned_hash) == Some(id));
        if !trusted && !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                pinned_height,
                pinned_hash = %pinned_hash,
                "active chain lacks the assume-valid anchor block; verifying every script",
            );
        }
        self.trusted.store(trusted, Ordering::Relaxed);
    }
}

/// Where a block being applied came from. Decides whether its scripts execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockProvenance {
    /// Untrusted input (peer delivery, submitblock, file import): scripts run
    /// unless the assume-valid gate covers the height.
    Network,
    /// A body this node validated and persisted under its recovery marker
    /// before the crash; its scripts already ran here.
    LocalReplay,
}

/// Committed connect. Derived consumers read this after the tip is published.
#[derive(Clone, Debug)]
pub struct ConnectOutcome {
    /// New applied tip.
    pub tip: TipSnapshot,
    /// Height of the connected block.
    pub height: u32,
    /// Hash of the connected block.
    pub hash: Hash256,
    /// Transaction ids in block order.
    pub txids: Vec<Txid>,
    /// Canonical block bytes when a derived consumer asked for them, else empty.
    pub block_bytes: bytes::Bytes,
    /// Per-transaction wire bytes when a derived consumer asked for `rawtx`.
    pub raw_txs: Option<Vec<Vec<u8>>>,
}

/// Committed disconnect. Derived consumers read this after the tip is published.
#[derive(Clone, Debug)]
pub struct DisconnectOutcome {
    /// Applied tip after the rollback (the parent).
    pub parent_tip: TipSnapshot,
    /// Hash of the disconnected block.
    pub hash: Hash256,
    /// Creating txids of coins the undo restored, for orphan re-evaluation.
    pub restored_parents: Vec<Txid>,
}

/// Connect intent. See `ARCH-07` in `docs/contracts/architecture.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplyIntent {
    Commit,
    /// See `ARCH-07` in `docs/contracts/architecture.md`.
    Propose,
}

/// Outcome of [`apply_block_admitted`] once intent is known.
enum ApplyFinish {
    /// Commit path: the new applied tip, already published.
    Committed(ConnectOutcome),
    /// See `ARCH-07` in `docs/contracts/architecture.md`.
    Proposed,
}

/// Coherent read of header tip, applied tip, and chain-tx count.
///
/// Produced by [`Chainstate::snapshot`]. Applied tip and `chain_tx_count` are
/// one publication. Header tip is a separate cell and may legitimately be
/// ahead of the applied chain. The snapshot cannot mutate chainstate.
#[derive(Clone, Debug)]
pub struct ChainstateSnapshot {
    /// Best-work header tip, if the tree has one.
    pub header: Option<TipSnapshot>,
    /// Authoritative applied tip, if any block has committed.
    pub applied: Option<TipSnapshot>,
    /// Cumulative transaction count of the applied chain, or `0` when unknown.
    ///
    /// Published with `applied`, never independently of it.
    pub chain_tx_count: u64,
}

/// In-process facade for authoritative applied-chain mutation.
///
/// See `ARCH-07` in `docs/contracts/architecture.md`. Construction and
/// lifecycle stay in `node`. Mutation goes through [`Self::begin_transition`].
#[derive(Clone)]
pub struct Chainstate {
    pub(crate) network: Network,
    pub(crate) chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(crate) applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Cumulative transaction count of the applied chain, or `0` when unknown.
    ///
    /// Bitcoin Core's `CBlockIndex::m_chain_tx_count`, including its convention
    /// that zero means *unset* rather than *empty* (`HaveNumChainTxs()`). Only a
    /// chain applied from genesis by a node that maintains this counter can know
    /// it; a cold start before genesis or an arithmetic inconsistency leaves it
    /// unknown until the chain is applied again.
    ///
    /// Kept beside `applied_tip`. Connect and disconnect publish the pair
    /// under `applied_seq` so [`Chainstate::snapshot`] copies one view.
    pub(crate) chain_tx_count: Arc<AtomicU64>,
    /// Seqlock for the applied-tip / chain-tx-count pair.
    ///
    /// Odd means a writer is between the two stores; even is a stable pair.
    /// Snapshot readers retry instead of taking the transition lock.
    pub(crate) applied_seq: Arc<AtomicU64>,
    pub(crate) block_tree: Arc<RwLock<BlockTree>>,
    pub(crate) utxo: Arc<UtxoSet>,
    pub(crate) coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    /// Read-only pool handle shared with `NodeState`. Apply mutates through
    /// `mempool_gateway`. Tests inspect this cell; production apply does not.
    #[allow(
        dead_code,
        reason = "shared with NodeState and tests; apply uses mempool_gateway"
    )]
    pub(crate) mempool: Arc<RwLock<Mempool>>,
    /// Strong gateway handle for production mempool mutation. Apply and reorg
    /// call this directly; they never call `MempoolGateway::shared` or recover
    /// from the weak registry. The raw `mempool` field stays for read-only
    /// node code that still needs the pool.
    pub(crate) mempool_gateway: Arc<MempoolGateway>,
    pub(crate) chain_events: Arc<crate::state::ChainEventPublisher>,
    pub(crate) block_body_store: Option<Arc<dyn BlockBodyStore>>,
    pub(crate) undo_store: Arc<dyn UndoStore>,
    pub(crate) admission: Arc<ApplyAdmission>,
    pub(crate) shutdown: Arc<AtomicBool>,
    /// Serializes whole chain transitions against each other.
    ///
    /// Distinct from `admission`, which is a shutdown barrier: `enter` takes a
    /// READ guard, so any number of applies hold it at once and it excludes
    /// nothing but a checkpoint close. A transition reads the applied tip,
    /// decides what follows it, mutates chain-owned state, and publishes the
    /// result. Two such operations interleaved can both validate against the
    /// same tip and then invalidate each other's retention or publication
    /// decisions. This lock spans connects, windows, disconnects, and pruning.
    pub(crate) chain_transition: Arc<parking_lot::Mutex<()>>,
    pub(crate) assume_valid_height: u32,
    pub(crate) assume_valid_gate: Arc<AssumeValidGate>,
    /// Chainstate-journal writer, when the journal is enabled (issue #230).
    ///
    /// `None` = journal off: the apply path emits nothing and behaves exactly
    /// as a checkpoint-only node. The writer is single-owner (the apply path);
    /// the `Mutex` only makes the shared handle exclusive.
    pub(crate) journal: Option<crate::chainstate_journal::SharedJournalWriter>,
    /// Publishes checkpoints to settle rolled-back disconnect debt after a
    /// non-fatal reorg. `None` in unit-test handle sets that never reorg.
    pub(crate) checkpoint_publisher: Option<Arc<crate::checkpoint_worker::CheckpointPublisher>>,
    /// Capture per-transaction wire bytes for a derived `rawtx` consumer.
    pub(crate) capture_rawtx: bool,
    /// Serialize the full block for a derived consumer (body store, index, rawblock).
    pub(crate) capture_block_bytes: bool,
}

/// One admitted chain mutation.
///
/// Owns admission, the exclusive transition lock, and mempool generation.
/// Connect, window-connect, and disconnect run only through this type.
/// Dropping without [`Self::finish`] leaves generation odd by design.
///
/// # Persistence
///
/// Connect and replay write the block body and commit the UTXO set before
/// publishing `applied_tip`. A successful return means the new tip is visible
/// in memory. Store durability follows the journal batch cadence and the next
/// clean checkpoint (`docs/chainstate-recovery.md`). A crash before that
/// checkpoint recovers from the last authenticated checkpoint plus any
/// committed journal suffix. Permanent consensus failures must not be retried
/// with the same block; operational failures (storage, UTXO commit, shutdown)
/// stay with the caller to retry.
///
/// Disconnect arms a durable `DisconnectMarker` before the UTXO undo. The
/// commit point is the `applied_tip` rollback after a successful undo
/// (`EVT-05` in `docs/contracts/chain-events.md`). `DisconnectError::Refused`
/// means nothing was mutated. `DisconnectError::Fatal` means a partial undo:
/// do not retry, poison admission, and shut down. A crash during rollback is
/// recovered from the marker, not by retrying the disconnect. The
/// `RolledBack` marker stays until the checkpoint that publishes the
/// rolled-back state.
///
/// Window apply commits one block at a time. A failure leaves the committed
/// prefix in place. Permanent failures invalidate the failed subtree;
/// operational failures leave that block retryable.
///
/// [`Self::finish`] stores the reserved even mempool generation. It does not
/// persist chainstate. Call it once the window attempt concludes on a
/// consistent chainstate: a successful return, or a failure whose committed
/// prefix is already in place and whose failing block was refused before the
/// UTXO commit-of-record (`utxo.commit_borrowed_block`). Every failure before
/// that point touches only idempotent derived state (undo, block body, header
/// tree) that a retry overwrites. A `UtxoCommit` refusal is different: the
/// per-shard commit is not all-or-nothing across runs, so the UTXO set may be
/// torn; drop the transition and leave generation odd until recovery
/// establishes a consistent chainstate. A drop on crash, panic, or any torn
/// state does the same.
pub struct ChainTransition<'a> {
    chainstate: &'a Chainstate,
    proof: ChainChangeProof<'a>,
}

impl<'a> ChainTransition<'a> {
    /// Connects `block` as the next applied tip.
    ///
    /// Consensus refusal happens before the first write. See the type-level
    /// persistence notes for the commit point and retry rules.
    pub fn connect(&self, block: &Block) -> core::result::Result<ConnectOutcome, ApplyError> {
        apply_committed_block_admitted(
            self.chainstate,
            block,
            None,
            None,
            BlockProvenance::Network,
            &self.proof,
        )
    }

    /// Connects `block` reusing preserved wire-format bytes.
    ///
    /// Same commit point and retry rules as [`Self::connect`].
    pub fn connect_serialized(
        &self,
        block: &Block,
        serialized: bytes::Bytes,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        apply_block_with_serialized_admitted(self.chainstate, block, serialized, &self.proof)
    }

    /// Re-applies a body this node already validated and persisted before a crash.
    ///
    /// Scripts do not run again (`BlockProvenance::LocalReplay`). Persistence
    /// otherwise matches [`Self::connect`].
    pub fn replay_local(
        &self,
        block: &Block,
        serialized: bytes::Bytes,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        apply_committed_block_admitted(
            self.chainstate,
            block,
            Some(serialized),
            None,
            BlockProvenance::LocalReplay,
            &self.proof,
        )
    }

    /// Disconnects `block`, which must be the current applied tip.
    ///
    /// See the type-level persistence notes for marker arming, the commit
    /// point, and `Refused` versus `Fatal`.
    pub fn disconnect(
        &self,
        block: &Block,
    ) -> core::result::Result<DisconnectOutcome, crate::DisconnectError> {
        disconnect_block_admitted(self.chainstate, block, &self.proof)
    }

    /// Applies consecutive blocks under this one transition.
    ///
    /// Commits one at a time and in order. A failure leaves the committed
    /// prefix in place, matching per-block apply. See the type-level
    /// persistence notes for permanent versus operational retry.
    #[allow(clippy::result_large_err)]
    pub fn connect_window(
        &self,
        blocks: &[&Block],
        serialized: &[bytes::Bytes],
    ) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
        apply_window_admitted(self.chainstate, blocks, serialized, &self.proof)
    }

    pub(crate) fn proof(&self) -> &ChainChangeProof<'a> {
        &self.proof
    }

    pub(crate) fn chainstate(&self) -> &'a Chainstate {
        self.chainstate
    }

    /// Finishes the chain change, storing the reserved even generation.
    ///
    /// Consumes the capability so it cannot be used after finish. Does not
    /// persist chainstate. Call it once the attempt has reached a consistent
    /// chainstate — a successful return, or a clean refusal whose committed
    /// prefix is already in place and whose failing block was refused before
    /// the UTXO commit-of-record (`utxo.commit_borrowed_block`). Drop on a
    /// `UtxoCommit` refusal, panic, or torn state leaves generation odd until
    /// recovery establishes a consistent chainstate.
    pub fn finish(self) -> core::result::Result<(), ApplyError> {
        self.proof.finish()
    }
}

impl Chainstate {
    pub(crate) fn scripts_verified_upstream(
        &self,
        provenance: BlockProvenance,
        height: u32,
    ) -> bool {
        match provenance {
            BlockProvenance::LocalReplay => true,
            BlockProvenance::Network => {
                self.assume_valid_height > 0
                    && height <= self.assume_valid_height
                    && self.assume_valid_gate.trusted()
            }
        }
    }

    pub(crate) fn prune_authority(&self) -> PruneAuthority {
        PruneAuthority {
            admission: Arc::clone(&self.admission),
            chain_transition: Arc::clone(&self.chain_transition),
            applied_tip: Arc::clone(&self.applied_tip),
        }
    }

    /// Admission plus the exclusive transition lock, without mempool generation.
    ///
    /// Used for read-consistent planning that may abort without mutating
    /// (reorg replans, `validate_block`, pruning). Mutation requires
    /// [`Self::begin_transition`] or [`Self::begin_transition_locked`].
    pub(crate) fn lock_transition(&self) -> core::result::Result<TransitionLock<'_>, ApplyError> {
        begin_chain_transition(&self.admission, &self.chain_transition)
    }

    /// Completes a held lock into a mutation capability by reserving mempool generation.
    pub(crate) fn begin_transition_locked<'a>(
        &'a self,
        lock: TransitionLock<'a>,
    ) -> core::result::Result<ChainTransition<'a>, ApplyError> {
        let guard = self
            .mempool_gateway
            .begin_chain_change()
            .map_err(|_| ApplyError::Shutdown)?;
        Ok(ChainTransition {
            chainstate: self,
            proof: ChainChangeProof::new(lock, guard),
        })
    }

    /// Begins an admitted chain mutation: admission, the transition lock, and
    /// the mempool generation reservation.
    ///
    /// The returned capability is the only way to connect or disconnect. Finish
    /// it once the attempt reaches a consistent chainstate: a successful
    /// return, or a clean refusal whose committed prefix is already in place
    /// and whose failing block was refused before the UTXO commit-of-record
    /// (`utxo.commit_borrowed_block`). Drop on a `UtxoCommit` refusal, panic,
    /// or torn state leaves generation odd until recovery establishes a
    /// consistent chainstate. Failure before this method returns a capability
    /// acquires no transition and therefore makes no generation postcondition.
    pub fn begin_transition(&self) -> core::result::Result<ChainTransition<'_>, ApplyError> {
        let lock = self.lock_transition()?;
        self.begin_transition_locked(lock)
    }

    /// Builds a chainstate facade for tests and composition that do not go
    /// through `NodeState::open`.
    ///
    /// Derived consumers are not attached. Capture flags default off; set them
    /// with [`Self::capturing`] when a caller will dispatch `rawtx` or block
    /// bytes after the commit.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        network: Network,
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        utxo: Arc<UtxoSet>,
        coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
        mempool: Arc<RwLock<Mempool>>,
        mempool_gateway: Arc<MempoolGateway>,
        chain_events: Arc<crate::state::ChainEventPublisher>,
    ) -> Self {
        Self {
            network,
            chain_tip,
            applied_tip,
            chain_tx_count: Arc::new(AtomicU64::new(0)),
            applied_seq: Arc::new(AtomicU64::new(0)),
            block_tree,
            utxo,
            coin_stats,
            mempool,
            mempool_gateway,
            chain_events,
            block_body_store: None,
            undo_store: Arc::new(InMemoryUndoStore::default()),
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            chain_transition: Arc::new(parking_lot::Mutex::new(())),
            assume_valid_height: 0,
            assume_valid_gate: Arc::new(AssumeValidGate::with_anchor(None)),
            journal: None,
            checkpoint_publisher: None,
            capture_rawtx: false,
            capture_block_bytes: false,
        }
    }

    /// Captures derived payloads on later connects: per-tx wire bytes and/or
    /// the canonical block serialization.
    #[must_use]
    pub fn capturing(mut self, rawtx: bool, block_bytes: bool) -> Self {
        self.capture_rawtx = rawtx;
        self.capture_block_bytes = block_bytes;
        self
    }
}

/// Everything a disconnect can refuse, decided before anything is mutated.
///
/// Split out because the ordering matters more than the code: if a check can
/// live here it must, since a refusal from this function costs nothing while a
/// refusal after the first write leaves a partly disconnected chain. Anything
/// added to `disconnect_block` that can fail belongs here unless it physically
/// cannot run this early.
struct DisconnectPlan {
    parent_tip: TipSnapshot,
    parent_prev_hash: Hash256,
    parent_chain_tx_count: u64,
    undo: bitcoin_rs_utxo::UndoBatch,
    height: u32,
    tx_count_delta: u64,
}

/// Seqlock guard for the applied-tip / chain-tx-count pair.
///
/// [`Chainstate::snapshot`] retries while the sequence is odd. Dropping the
/// guard stores the matching even value, including on panic, so readers do
/// not spin forever. A panic between the two stores can still expose a mixed
/// pair; the transition lock already treats that as fatal process state.
struct AppliedPublication<'a> {
    seq: &'a AtomicU64,
}

impl Drop for AppliedPublication<'_> {
    fn drop(&mut self) {
        self.seq.fetch_add(1, Ordering::Release);
    }
}

/// How many consecutive blocks share one script-verification dispatch.
///
/// The window amortises dispatch, it does not add parallelism. A mainnet block
/// early in the chain carries about 19 input checks, so fanning those across 32
/// workers costs more in wakeups than the work itself: measured over blocks
/// `0..150_000`, per-block dispatch left 29s of checks running serially in blocks
/// below the parallel threshold and wasted a further 11s above it. Sixty-four
/// blocks turns roughly 21,000 dispatches into 330.
///
/// Bounded by memory: the window holds every block's parsed kernel block and
/// resolved prevouts at once, which costs far more than the block bytes.
/// Measured over `0..150_000`, pinned to 32 cores, medians of interleaved runs:
///
///   window     wall     CPU     peak RSS
///       64    66.2s   596.3s      397 MB
///      128    75.8s   525.6s      409 MB
///      256    69.8s   471.5s      436 MB
///     1024    51.8s   388.7s      572 MB
///     4096    47.2s   377.1s     1205 MB
///
/// CPU falls by a third from 64 to 1024 because the cost being removed is rayon
/// dispatch and spin, not verification. RSS is what stops it: 4096 doubles the
/// resident set for a few more seconds.
///
/// This is a COUNT cap, and count alone is the wrong bound. Early-chain blocks
/// average about 4.6 KB, so 1024 of them is 5 MB of block data; at the tip they
/// are 2 MB, so the same 1024 would hold 2 GB. [`SCRIPT_BATCH_MAX_BYTES`] is the
/// other half, and the window is whichever bound hits first.
///
/// Peer sync does not reach 1024 today. `RECEIVED_BLOCK_BUDGET` caps staging at
/// 256 blocks, so the windows it forms are at most that, worth 471s CPU against
/// 596s at 64 — a real gain, and not the 389s the replay driver reaches.
/// Raising the staging cap further is not a constant change: the staller-arming
/// invariant ties the staged byte budget to the staged count at
/// `MAX_SERIALIZED_BLOCK_SIZE`, so a 1024-block stage would demand a 2 GB bound.
pub const SCRIPT_BATCH_WINDOW: usize = 1024;

/// How many bytes of block data one window may hold.
///
/// The count cap above is sized for small early-chain blocks. This is what
/// keeps the same constant safe at the tip, where a block is roughly 2 MB and
/// the count would otherwise let a window hold gigabytes. Whichever cap binds
/// first ends the window, so the batch is large exactly where blocks are small
/// and dispatch dominates, and small where blocks are large and it does not.
pub const SCRIPT_BATCH_MAX_BYTES: usize = 64 << 20;

/// Returns how many of `sizes` fit in one window.
///
/// At least one block always fits, even one larger than the byte cap on its
/// own: refusing it would stall the chain on an oversized block rather than
/// verify it.
pub fn window_len(sizes: impl IntoIterator<Item = usize>) -> usize {
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for size in sizes {
        if count == SCRIPT_BATCH_WINDOW {
            break;
        }
        let next = bytes.saturating_add(size);
        if count > 0 && next > SCRIPT_BATCH_MAX_BYTES {
            break;
        }
        bytes = next;
        count = count.saturating_add(1);
    }
    count
}

/// A window that failed partway, and how many of its blocks committed first.
///
/// The count is what a caller needs to recover: it must record the hashes that
/// landed, retry only the one that failed, and put the rest back. A bare
/// `ApplyError` cannot say where the window stopped.
#[derive(Debug)]
pub struct WindowApplyError {
    /// Blocks that committed before the failure.
    pub applied: usize,
    /// Outcomes for the committed prefix, in apply order.
    pub committed: Vec<ConnectOutcome>,
    /// What stopped the block at index `applied`.
    pub source: ApplyError,
    /// How the caller must treat this failure: `Permanent` failures poisoned
    /// the failed block's header subtree while the chain transition was still
    /// held; `Operational` failures poisoned nothing; `Fatal` means the
    /// transition itself could not be settled (the reserved even generation
    /// could not be published), so admission stays closed until recovery.
    pub disposition: WindowApplyDisposition,
    /// Hashes marked invalid under the held transition when `disposition` is
    /// [`WindowApplyDisposition::Permanent`]: the failed block and every
    /// descendant, in deterministic slab order. Empty otherwise.
    pub invalidated: Box<[Hash256]>,
}

impl core::fmt::Display for WindowApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "window failed after applying {} block(s): {}",
            self.applied, self.source
        )
    }
}

impl std::error::Error for WindowApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl WindowApplyError {
    /// Failure kind the caller should act on.
    #[must_use]
    pub const fn disposition(&self) -> WindowApplyDisposition {
        self.disposition
    }

    /// Hashes invalidated for a `Permanent` failure, empty otherwise.
    #[must_use]
    pub fn invalidated(&self) -> &[Hash256] {
        &self.invalidated
    }
}

/// Whether a window failure is permanent or operational.
///
/// The caller must not re-classify the source error: the node classifier and
/// the reorg classifier are the same predicate, and the disposition here is
/// what that predicate decided at the failure point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowApplyDisposition {
    /// The failed block and its descendants can never be valid. Their header
    /// subtrees were invalidated under the window's chain transition; purge
    /// every returned hash from staged/download state without retrying.
    Permanent,
    /// Transient failure (storage, UTXO commit, shutdown). Nothing was
    /// invalidated; the failed block and its tail stay retryable.
    Operational,
    /// The transition could not be concluded: the reserved even generation
    /// could not be published (`ChainChangeGuard::finish` failed /
    /// `GenerationMoved`). Mempool admission stays closed; a retry cannot
    /// begin until recovery or restart re-establishes a consistent gateway.
    /// Nothing about the blocks is invalid — committed blocks stay applied
    /// and nothing is purged.
    Fatal,
}

/// Chain context that determines the ordered transaction checks for one block.
///
/// A window captures this before it applies any block. The commit path derives
/// it again from the live chain and accepts a proof only when every field still
/// agrees.
#[derive(Debug, Eq, PartialEq)]
struct BlockValidationContext {
    hash: Hash256,
    parent: Hash256,
    height: u32,
    flags: bitcoin_rs_script::VerifyFlags,
    locktime_cutoff: u32,
}

/// Chain facts BIP68 evaluates against: the validation context fixing the
/// block's height, the parent median-time-past, the softfork state at
/// connect, and the applied tip the prevout ancestry hangs from.
#[derive(Clone, Copy)]
struct Bip68Context<'a> {
    validation: &'a BlockValidationContext,
    median_time_past: u32,
    softfork_state: bitcoin_rs_chain::SoftforkState,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
}

/// Evidence that every ordered transaction pre-check, input script, and
/// transaction post-check passed for this exact prepared block state.
///
/// The proof is private, single-use, and owns the prepared state it certifies.
/// It is constructed only after the whole window verifier succeeds, so callers
/// cannot pair a block's verdict with foreign resolved prevouts.
struct BlockValidationProof<'b> {
    prepared: PreparedApply<'b>,
    context: BlockValidationContext,
}

/// Prepared state returned by a successful window attempt.
///
/// Assume-valid is not proof. A skipped block must re-enter the ordinary
/// transaction path at commit so it reads the trust gate in its current state.
enum ProvenApply<'b> {
    Proven(BlockValidationProof<'b>),
    AssumeValidSkipped(PreparedApply<'b>),
}

/// Everything a block's application needs that depends only on the block and
/// the outputs it spends, not on the chain state the commit will mutate.
///
/// Split out because a window of consecutive blocks can produce all of these
/// at once, against one ordered overlay, and share a single script dispatch.
/// The measured duplication that made an earlier batching attempt a wash was
/// exactly the kernel parse and the prevout resolution below being done twice.
struct PreparedApply<'b> {
    kernel_block: bitcoin_rs_consensus::kernel::KernelBlock,
    /// Parse-once transaction state: identities computed once in
    /// [`parse_block_for_apply`], witness IDs on demand, and the prevout
    /// matrix installed once right before script verification.
    view: bitcoin_rs_consensus::BlockView<'b>,
    tx_plan: BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
}

/// Parses a block and resolves the outputs it spends.
///
/// `source` is where prevouts come from. Today that is always the committed
/// UTXO set; a window passes an overlay so a block can see outputs an earlier
/// block in the same window created.
///
/// Runs no consensus rule and mutates nothing, which is what lets a window
/// prepare several blocks before committing any of them.
/// A sink that compares what is written to it against `expected`.
///
/// Used to check preserved bytes against a block without serialising the block
/// into a second buffer: nothing is allocated and the first differing byte ends
/// the walk.
struct ByteEquality<'a> {
    expected: &'a [u8],
    offset: usize,
    equal: bool,
}

impl bitcoin_rs_primitives::Sink for ByteEquality<'_> {
    fn write_all(&mut self, buf: &[u8]) {
        if self.equal {
            match self
                .expected
                .get(self.offset..self.offset.saturating_add(buf.len()))
            {
                Some(window) if window == buf => {}
                _ => self.equal = false,
            }
        }
        self.offset = self.offset.saturating_add(buf.len());
    }
}

/// Transaction IDs of an already-decoded block, hashed exactly once.
///
/// Blocks beyond the threshold the window verifier uses fan the hashing out;
/// below it, serial iteration wins because dispatch costs more than the
/// per-transaction double SHA256.
#[cfg(test)]
fn block_txids(block: &Block) -> Vec<Txid> {
    if block.txs.len() > 32 {
        block.txs.par_iter().map(Tx::txid).collect()
    } else {
        block.txs.iter().map(Tx::txid).collect()
    }
}

struct BlockTxPlan {
    only_coinbase: bool,
    needs_local_utxo_overlay: bool,
    overlay_capacity: usize,
    witness_presence: WitnessPresence,
    has_bip68_sequence_locks: bool,
    created_output_count: usize,
    spent_input_count: usize,
    same_block_spent: Option<SameBlockSpentSet>,
    same_block_spent_input_count: usize,
}

impl BlockTxPlan {
    /// Outpoints this block both creates and spends, empty when it has none.
    ///
    /// The overlay nets these out exactly as `build_block_changes` does: such an
    /// output never reaches the committed set, so a view carrying it would
    /// resolve a later spend the real set would refuse.
    fn same_block_spent_set(&self) -> &SameBlockSpentSet {
        static NONE: std::sync::LazyLock<SameBlockSpentSet> =
            std::sync::LazyLock::new(SameBlockSpentSet::new);
        self.same_block_spent.as_ref().unwrap_or(&NONE)
    }

    fn into_scratch_parts(
        self,
        txids: Vec<Txid>,
    ) -> (
        Vec<Txid>,
        ApplyScratchCapacities,
        Option<SameBlockSpentSet>,
        usize,
    ) {
        (
            txids,
            ApplyScratchCapacities {
                created_outputs: self.created_output_count,
                spent_inputs: self.spent_input_count,
            },
            self.same_block_spent,
            self.same_block_spent_input_count,
        )
    }
}

#[derive(Clone, Copy)]
enum WitnessPresence {
    Absent,
    Present,
}

impl WitnessPresence {
    const fn from_bool(has_witness: bool) -> Self {
        if has_witness {
            Self::Present
        } else {
            Self::Absent
        }
    }

    const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

/// All external (already-committed) prevouts for one block, resolved in a single
/// parallel pass so `script_verify`, `coinbase_maturity`, and `bip68` reuse one
/// lookup table instead of hitting the `UtxoSet` repeatedly.
struct ResolvedUtxoView {
    external: HashMap<OutPoint, LiveOutput>,
}

impl ResolvedUtxoView {
    /// Resolves a block's external prevouts from any source of live outputs.
    ///
    /// Generic so a window can substitute an overlay carrying the outputs its
    /// earlier blocks created. Every caller outside a window passes the
    /// committed set.
    fn resolve<S: crate::window_overlay::OutputSource + ?Sized>(
        utxo: &S,
        block: &Block,
        tx_plan: &BlockTxPlan,
    ) -> Self {
        let same_block = tx_plan.same_block_spent.as_ref();
        let candidates = block
            .txs
            .iter()
            .filter(|tx| !is_coinbase_tx(tx))
            .flat_map(|tx| &tx.inputs)
            .filter(|input| same_block.is_none_or(|set| !set.contains(&input.previous_output)))
            .map(|input| input.previous_output);
        // Serial on purpose. A UTXO lookup is a sharded hashmap hit of order
        // 500 ns, so a rayon fan-out costs more than the work it distributes.
        // Measured on mainnet 0..150_000, 3x medians pinned to `taskset -c
        // 0-31`, parallel and serial interleaved: `into_par_iter` 143.8s vs
        // serial 134.7s, and serial won every round. Apply alone goes 116.2s
        // to 103.6s. Parallelize a stage only when per-item work exceeds the
        // dispatch, as the script checks do at ~100 us per input.
        Self {
            external: candidates
                .filter_map(|outpoint| utxo.get_entry(&outpoint).map(|entry| (outpoint, entry)))
                .collect(),
        }
    }
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            external: HashMap::new(),
        }
    }

    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.external.get(outpoint).map(|entry| entry.txout.clone())
    }

    /// Full resolved entry for a spent outpoint, including creation metadata.
    fn entry(&self, outpoint: &OutPoint) -> Option<&LiveOutput> {
        self.external.get(outpoint)
    }

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<LiveOutputMeta> {
        self.external.get(outpoint).map(|entry| LiveOutputMeta {
            coinbase: entry.coinbase,
            height: entry.height,
        })
    }
}

impl UtxoView for ResolvedUtxoView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.lookup(outpoint)
    }
}

impl SpentOutputLookup for ResolvedUtxoView {
    fn entry(&self, outpoint: &OutPoint) -> Option<&LiveOutput> {
        self.entry(outpoint)
    }
}

struct BlockLocalUtxoView<'b> {
    base: Arc<ResolvedUtxoView>,
    txdata: &'b [Tx],
    height: u32,
    overlay: HashMap<OutPoint, Option<u32>>,
}

impl<'b> BlockLocalUtxoView<'b> {
    fn new(
        base: Arc<ResolvedUtxoView>,
        txdata: &'b [Tx],
        height: u32,
        overlay_capacity: usize,
    ) -> Self {
        Self {
            base,
            txdata,
            height,
            overlay: HashMap::with_capacity(overlay_capacity),
        }
    }

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<LiveOutputMeta> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let tx_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            self.txdata.get(tx_index)?.outputs.get(vout)?;
            return Some(LiveOutputMeta {
                coinbase: tx_index == 0,
                height: self.height,
            });
        }
        self.base.lookup_meta(outpoint)
    }

    fn spend_inputs(&mut self, tx: &Tx) {
        for input in &tx.inputs {
            self.overlay.insert(input.previous_output, None);
        }
    }

    fn add_outputs(
        &mut self,
        tx_index: u32,
        txid: Txid,
        output_count: usize,
    ) -> core::result::Result<(), ApplyError> {
        for vout in 0..output_count {
            let vout = u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(self.height))?;
            self.overlay
                .insert(OutPoint::new(txid, vout), Some(tx_index));
        }
        Ok(())
    }
}

impl UtxoView for BlockLocalUtxoView<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let tx_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            return self.txdata.get(tx_index)?.outputs.get(vout).cloned();
        }
        self.base.lookup(outpoint)
    }
}

#[cfg(test)]
pub(crate) fn check_coinbase_maturity(
    handles: &Chainstate,
    block: &Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let tx_plan = plan_block_transactions(block, &block_txids(block));
    let resolved = Arc::new(ResolvedUtxoView::resolve(
        handles.utxo.as_ref(),
        block,
        &tx_plan,
    ));
    let txids = block_txids(block);
    check_coinbase_maturity_with_tx_plan(handles, block, &tx_plan, &txids, resolved, height)
}

#[cfg(test)]
mod consensus_rule_tests;

#[cfg(test)]
fn check_pow_limit_and_continuity_for_seeded_tip(
    handles: &Chainstate,
    block: &Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let prior = handles.chain_tip.load_full();
    check_pow_limit_and_continuity(handles, prior.as_deref(), block, height)
}

#[cfg(test)]
mod contextual_softfork_tests;
#[cfg(test)]
mod zmq_emit_tests;

#[cfg(test)]
mod with_zmq_publisher_tests;

#[cfg(test)]
mod admission_tests;

#[cfg(test)]
mod chain_tx_count_tests;

#[cfg(test)]
mod chain_generation_tests;
