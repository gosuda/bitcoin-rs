//! Storage-sync barrier for the staged-template durability proof.
//!
//! [`BarrierBodies`] wraps the node's real body store, delegates every
//! [`BlockBodyStore`] method to it, and holds only an armed next
//! [`BlockBodyStore::sync`] on [`SyncGate`]. The durable commit tail
//! (`sync_appended_blocks`, then the head batch) still runs against the real
//! disk backend; the gate only delays it so the test can observe the staged
//! preparation before the commit publishes. Every other sync passes through.
//!
//! Release is unwind-safe: hold [`SyncGate::release_guard`] inside the
//! `thread::scope` body that runs the apply, so a failed assertion drops the
//! guard and unblocks the apply thread before the scope joins it. All waits
//! are bounded and report a missing boundary instead of hanging.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::Result;
use bitcoin_rs_chain::regtest_fixture::{self, REGTEST_BITS};
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{
    Amount, Block, BlockBodyMetadata, BlockHash, CompactTarget, Hash256, Header, LockTime,
    OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, unix_time_secs,
};
use bitcoin_rs_script::push_int;
use bitcoin_rs_storage::block_body::{BlockBodyReader, BlockBodyStore};
use bitcoin_rs_storage::{BlockFilePosition, BodyExtent, BoundedReadError, StorageError};

use super::support::current_tip;

/// Deadlock bound for every barrier wait: a missed boundary fails the test,
/// never hangs it. No timing behaviour is asserted.
const BARRIER_BOUND: Duration = Duration::from_secs(10);

struct GateState {
    armed: bool,
    entered: bool,
    released: bool,
}

/// One-shot hold gate for the next body-store sync.
///
/// Linearizability is not needed across threads here: the gate only orders
/// one apply thread past one armed sync behind one test thread. The mutex
/// plus condvar gives that causal order; every wait loops on its predicate
/// (`entered` / `released`) so a spurious wakeup can never release the apply
/// or satisfy the test early.
pub(crate) struct SyncGate {
    state: Mutex<GateState>,
    cvar: Condvar,
}

impl SyncGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState {
                armed: false,
                entered: false,
                released: false,
            }),
            cvar: Condvar::new(),
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Arms the next [`BlockBodyStore::sync`] to hold. Call before spawning
    /// the apply; an apply that reaches sync before the arm would pass
    /// through and the test would fail on `wait_entered` instead of hanging.
    pub(crate) fn arm(&self) {
        let mut state = self.lock_state();
        state.armed = true;
        state.entered = false;
        state.released = false;
    }

    /// Holds the calling sync until [`Self::release`], exactly once per arm.
    /// Called on the apply thread; unarmed syncs pass straight through to the
    /// real store.
    fn hold(&self) {
        let mut state = self.lock_state();
        if !state.armed {
            return;
        }
        state.armed = false;
        state.entered = true;
        self.cvar.notify_all();
        while !state.released {
            state = self
                .cvar
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Waits (bounded) until the armed sync is held. `false` means the
    /// boundary was never reached: staging never fired, the apply failed
    /// early, or the arm raced the spawn.
    pub(crate) fn wait_entered(&self, timeout: Duration) -> bool {
        let (state, _) = self
            .cvar
            .wait_timeout_while(self.lock_state(), timeout, |state| !state.entered)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entered
    }

    /// Releases a held sync. Idempotent: safe to call after the apply
    /// finished and safe to repeat from the unwind guard.
    pub(crate) fn release(&self) {
        let mut state = self.lock_state();
        state.released = true;
        self.cvar.notify_all();
    }

    /// Unwind-safe release: drop (or an explicit early drop after `release`)
    /// unblocks the apply thread. Hold inside the `thread::scope` body so a
    /// panicking assertion releases before the scope joins the apply thread.
    pub(crate) fn release_guard(&self) -> ReleaseGuard<'_> {
        ReleaseGuard { gate: self }
    }
}

pub(crate) struct ReleaseGuard<'a> {
    gate: &'a SyncGate,
}

impl Drop for ReleaseGuard<'_> {
    fn drop(&mut self) {
        self.gate.release();
    }
}

/// The real body store with one interceptable durability boundary.
///
/// Every method delegates to the inner store; only [`BlockBodyStore::sync`]
/// consults the gate, and only while armed. Reads, appends, cursors, and the
/// index flush are never gated, so the preparation worker and every other
/// reader observe real store state throughout the hold.
pub(crate) struct BarrierBodies {
    inner: Arc<dyn BlockBodyStore>,
    gate: Arc<SyncGate>,
}

impl BlockBodyStore for BarrierBodies {
    fn load_staged_body(
        &self,
        height: u32,
        hash: Hash256,
        position: Option<BlockFilePosition>,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_staged_body(height, hash, position)
    }

    fn stage_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<Option<BlockFilePosition>, StorageError> {
        self.inner.stage_block_body(height, hash, body)
    }

    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.inner.persist_block_body(height, hash, body)
    }

    fn persist_block_body_value(
        &self,
        height: u32,
        hash: Hash256,
        body: bytes::Bytes,
    ) -> Result<(), StorageError> {
        self.inner.persist_block_body_value(height, hash, body)
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_block_body(height, hash)
    }

    fn load_block_body_for_verification(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_block_body_for_verification(height, hash)
    }

    fn load_block_body_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, BoundedReadError> {
        self.inner.load_block_body_bounded(height, hash, max_bytes)
    }

    // Like the verification read above, the bounded verification read has
    // real backend behavior and must delegate explicitly.
    fn load_block_body_for_verification_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, BoundedReadError> {
        self.inner
            .load_block_body_for_verification_bounded(height, hash, max_bytes)
    }

    fn reader(&self) -> Result<Box<dyn BlockBodyReader + '_>, StorageError> {
        self.inner.reader()
    }

    fn undo_record(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.undo_record(height, hash)
    }

    fn load_block_body_range(
        &self,
        height: u32,
        hash: Hash256,
        offset: u32,
        len: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_block_body_range(height, hash, offset, len)
    }

    fn block_body_metadata(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<BlockBodyMetadata>, StorageError> {
        self.inner.block_body_metadata(height, hash)
    }

    fn append_cursor(&self) -> Option<BodyExtent> {
        self.inner.append_cursor()
    }

    fn block_position(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<BlockFilePosition>, StorageError> {
        self.inner.block_position(height, hash)
    }

    fn disk_usage(&self) -> Option<u64> {
        self.inner.disk_usage()
    }

    fn sync(&self) -> Result<(), StorageError> {
        self.gate.hold();
        self.inner.sync()
    }

    fn flush_index(&self) -> Result<(), StorageError> {
        self.inner.flush_index()
    }
}

/// A node opened on a real disk backend whose next armed body sync holds.
///
/// The temp dir lives as long as the node; dropping both closes the store.
pub(crate) struct BarrierNode {
    pub(crate) state: NodeState,
    pub(crate) gate: Arc<SyncGate>,
    _dir: tempfile::TempDir,
}

/// Opens a regtest node through the test-seam body-store entry with the sync
/// barrier wrapped around the real store. The gate starts disarmed so genesis
/// and seeding syncs pass through; each proof arms it for one commit.
pub(crate) fn open_barrier_node() -> Result<BarrierNode> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let gate = SyncGate::new();
    let hold = Arc::clone(&gate);
    let state = NodeState::open_with_body_store(config, None, move |store| {
        let wrapped: Arc<dyn BlockBodyStore> = Arc::new(BarrierBodies {
            inner: store,
            gate: hold,
        });
        wrapped
    })?;
    Ok(BarrierNode {
        state,
        gate,
        _dir: dir,
    })
}

/// Builds a one-coinbase child plus `txs` with the height-encoding coinbase
/// `seed_chain` uses, so `seed_coinbase_spend_at` spends resolve against it.
/// Time is caller-chosen: fresh-chain seeding and tip children pass the wall
/// clock, keeping the published tip within the IBD recency window so the
/// staged-tip hook fires.
pub(crate) fn fresh_child(prev: Hash256, height: u32, time: u32, txs: Vec<Tx>) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(super::support::REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(coinbase).chain(txs).collect(),
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("fresh child must have a merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .map_err(|error| anyhow::anyhow!("fresh child mining failed: {error}"))?;
    Ok(block)
}

/// Returns the wall clock as a consensus timestamp, or fails when it no
/// longer fits `u32`.
pub(crate) fn wall_time() -> Result<u32> {
    u32::try_from(unix_time_secs())
        .map_err(|_| anyhow::anyhow!("wall clock {} out of u32 range", unix_time_secs()))
}

/// Builds a fresh-time child of the node's applied tip carrying `txs`.
pub(crate) fn fresh_tip_child(state: &NodeState, txs: Vec<Tx>) -> Result<Block> {
    let tip = current_tip(state)?;
    fresh_child(tip.hash, tip.height + 1, wall_time()?, txs)
}

/// Applies genesis (when needed) then `count` fresh-time children with
/// increasing timestamps landing on the wall clock. The tip ends within the
/// IBD recency window, so the next commit's staged-tip hook fires; the
/// height-encoding coinbases mature exactly like `seed_chain`'s for
/// `seed_coinbase_spend_at` spends.
pub(crate) fn seed_fresh_chain(state: &NodeState, count: u32) -> Result<Hash256> {
    if state.chainstate().applied_tip_snapshot().is_none() {
        let genesis = Network::Regtest.genesis_block();
        state
            .apply_block(&genesis)
            .map_err(|error| anyhow::anyhow!("genesis apply failed: {error}"))?;
    }
    let now = u64::from(wall_time()?);
    let mut tip = current_tip(state)?;
    for index in 1..=count {
        let height = tip.height + 1;
        // Increasing by one interval per block, tip at the wall clock.
        let time = u32::try_from(now.saturating_sub(u64::from(count - index) * 600))
            .map_err(|_| anyhow::anyhow!("fresh seed time out of u32 range"))?;
        let block = fresh_child(tip.hash, height, time, Vec::new())?;
        state
            .apply_block(&block)
            .map_err(|error| anyhow::anyhow!("fresh seed block {height} failed: {error}"))?;
        tip = current_tip(state)?;
        if tip.height != height {
            return Err(anyhow::anyhow!(
                "fresh seed block did not become the tip at height {height}"
            ));
        }
    }
    Ok(tip.hash)
}

/// Deadlock bound shared by the coordination proofs. A missed boundary fails
/// the test; no timing behaviour is asserted.
pub(crate) fn barrier_bound() -> Duration {
    BARRIER_BOUND
}

struct DivergentBodies {
    plain: Vec<u8>,
    verified: Vec<u8>,
}

impl BlockBodyStore for DivergentBodies {
    fn persist_block_body(&self, _: u32, _: Hash256, _: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }

    fn load_block_body(&self, _: u32, _: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(Some(self.plain.clone()))
    }

    fn load_block_body_for_verification(
        &self,
        _: u32,
        _: Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(Some(self.verified.clone()))
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[test]
fn barrier_bodies_verification_read_uses_the_inner_verification_path() -> Result<()> {
    // The trait default routes verification reads to `load_block_body`,
    // which would return `plain` here; the override must surface `verified`.
    let bodies = BarrierBodies {
        inner: Arc::new(DivergentBodies {
            plain: vec![1],
            verified: vec![2],
        }),
        gate: SyncGate::new(),
    };
    let hash = Hash256::from_le_bytes(&[0x11; 32]);
    assert_eq!(bodies.load_block_body(7, hash)?, Some(vec![1]));
    assert_eq!(
        bodies.load_block_body_for_verification(7, hash)?,
        Some(vec![2])
    );
    Ok(())
}

/// The barrier forwards verification reads through the inner store's
/// verification path, so framed corruption surfaces instead of degrading
/// to an ordinary miss.
#[test]
fn barrier_preserves_inner_verification_corruption() {
    struct CorruptInner;
    impl BlockBodyStore for CorruptInner {
        fn persist_block_body(&self, _: u32, _: Hash256, _: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }
        fn load_block_body(&self, _: u32, _: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }
        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
        fn load_block_body_for_verification(
            &self,
            _: u32,
            _: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Err(StorageError::CorruptBlockFrame("frame"))
        }
    }
    let wrapped = BarrierBodies {
        inner: Arc::new(CorruptInner),
        gate: SyncGate::new(),
    };
    let hash = Hash256::from_le_bytes(&[0xB4; 32]);
    assert!(
        matches!(
            wrapped.load_block_body_for_verification(1, hash),
            Err(StorageError::CorruptBlockFrame(_))
        ),
        "the barrier must preserve verification corruption like the inner store"
    );
}
