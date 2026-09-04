//! Mutation records for the mempool's mutation API.
//!
//! Every mutating [`Mempool`](crate::Mempool) method returns a
//! [`MutationResult`] describing exactly what it committed, in commit order.
//! The pool advances its [`Mempool::sequence_number`] counter exactly once
//! per emitted change while the write lock is held, so each change in a
//! batch carries a distinct, contiguous sequence value that observers can
//! publish verbatim.

use alloc::vec::Vec;

use bitcoin_rs_primitives::{Hash256, Txid};

/// Why an entry left the pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemovalReason {
    /// The entry confirmed in a connected block.
    BlockInclusion,
    /// A connected block's transaction took the entry's inputs.
    Conflict,
    /// A BIP125 replacement evicted the entry.
    Replaced,
    /// The entry descended from an evicted or replaced entry.
    Descendant,
    /// Size or fee-rate policy evicted the entry.
    PolicyEviction,
    /// The entry outlived its expiry.
    Expiry,
    /// A wholesale clear emptied the pool.
    Clear,
    /// A reorg disconnected the entry's containing state.
    Reorg,
}

/// What happened to one transaction in a committed mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOutcome {
    /// The transaction was admitted to the pool.
    Accepted,
    /// The transaction left the pool for the recorded reason.
    Removed(RemovalReason),
}

/// One transaction's committed outcome, in commit order within a
/// [`MutationResult`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationChange {
    /// Transaction id in native consensus byte order.
    pub txid: Hash256,
    /// What happened to the transaction.
    pub outcome: MutationOutcome,
}

/// Builds a change for `txid`, converting the pool's internal `Txid` once at
/// this seam.
pub(crate) fn change(txid: &Txid, outcome: MutationOutcome) -> MutationChange {
    MutationChange {
        txid: Hash256::from(*txid),
        outcome,
    }
}

/// The ordered record of one committed mempool mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationResult {
    /// Committed changes in commit order.
    pub changes: Vec<MutationChange>,
    /// Mempool sequence assigned to `changes[0]`; each later change took the
    /// next value. `0` when `changes` is empty.
    ///
    /// The pool advances its sequence exactly once per emitted change under
    /// the write lock, so a batch's sequences are contiguous.
    pub sequence_base: u64,
}

impl MutationResult {
    /// An empty result: nothing was committed and no sequence moved.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            changes: Vec::new(),
            sequence_base: 0,
        }
    }

    /// Number of committed changes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Returns `true` when nothing was committed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The sequence assigned to `changes[index]`, when in bounds.
    #[must_use]
    pub fn sequence_of(&self, index: usize) -> Option<u64> {
        if self.changes.is_empty() {
            return None;
        }
        let offset = u64::try_from(index).ok()?;
        self.sequence_base.checked_add(offset)
    }

    /// The txid of every change that left the pool, in commit order.
    ///
    /// Converts each record's native txid back to the pool's `Txid` at
    /// this seam — the inverse of the `change` helper — so callers
    /// comparing against entry or wire txids need no conversion of their
    /// own.
    #[must_use]
    pub fn removed_txids(&self) -> Vec<Txid> {
        self.changes
            .iter()
            .filter(|change| matches!(change.outcome, MutationOutcome::Removed(_)))
            .map(|change| Txid::from(change.txid))
            .collect()
    }
}

/// The committed outcome of one admission insert.
///
/// [`Mempool::insert_entry`](crate::Mempool::insert_entry) and
/// [`Mempool::replace_transaction`](crate::Mempool::replace_transaction)
/// commit before they can learn that the post-insert size-limit trim shed
/// the very entry they just placed: the conflict removals, the insert
/// itself, and any trim evictions are already durable, and the mempool
/// sequence has advanced. `Err` therefore means *nothing* was committed; a
/// shed entry travels as [`InsertionOutcome::ShedAfterCommit`] carrying the
/// full [`MutationResult`], so observers still learn every committed change
/// while callers still treat the entry as rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InsertionOutcome {
    /// The entry committed and stayed in the pool.
    Accepted(MutationResult),
    /// The entry committed, then the trim evicted it. The carried mutation
    /// includes the entry's own `Accepted` change followed by its
    /// `Removed(PolicyEviction)` removal -- and, for a replacement, the
    /// conflict removals that committed first.
    ShedAfterCommit(MutationResult),
}

impl InsertionOutcome {
    /// The committed mutation record, whatever the entry's fate.
    #[must_use]
    pub const fn mutation(&self) -> &MutationResult {
        match self {
            Self::Accepted(result) | Self::ShedAfterCommit(result) => result,
        }
    }

    /// Consumes the outcome into its committed mutation record.
    #[must_use]
    pub fn into_mutation(self) -> MutationResult {
        match self {
            Self::Accepted(result) | Self::ShedAfterCommit(result) => result,
        }
    }

    /// Returns `true` when the pool shed the inserted entry after commit.
    #[must_use]
    pub const fn is_shed(&self) -> bool {
        matches!(self, Self::ShedAfterCommit(_))
    }
}

/// Identifies the network peer a transaction arrived from.
///
/// Plain data by contract: the mempool crate never depends on the p2p
/// stack, so the node passes a token it minted at connection time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PeerToken {
    /// The peer's wire address.
    pub addr: core::net::SocketAddr,
    /// The node-local id of the connection the peer arrived on.
    pub connection_id: u64,
}

/// How the transaction behind a committed mutation entered the node.
///
/// [`AdmissionOrigin::Peer`] is emitted by P2P ingress
/// (`crates/node/src/tx_ingress.rs`). [`AdmissionOrigin::Block`] is emitted
/// by the apply-path sweep (`crates/node/src/apply.rs`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionOrigin {
    /// Submitted through RPC (`sendrawtransaction`).
    Rpc,
    /// Relayed in from a network peer.
    Peer(PeerToken),
    /// Re-admitted by a reorg's disconnect walk.
    Reorg,
    /// Confirmed in by block application.
    Block,
}

/// What the gateway hands its observers: the committed result plus how the
/// mutating transaction entered the node.
///
/// [`MempoolGateway`] clones one [`MutationResult`] into the envelope for
/// each committed non-empty batch that has an observer attached, enqueues
/// that envelope, then returns the original result to the caller. Observers
/// receive `&MutationEnvelope` after the publish mutex is released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationEnvelope {
    /// How the transaction entered the node.
    pub origin: AdmissionOrigin,
    /// The committed mutation, in commit order.
    pub result: MutationResult,
}
