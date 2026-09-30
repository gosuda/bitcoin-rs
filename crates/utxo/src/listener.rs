//! Commit-event delivery from the shard machinery to the coinstats listener.
//!
//! The notification interface is batch-only and order-independent, and it is
//! machinery internal to this crate: the only listener the node attaches is
//! [`CoinStatsListener`](crate::stats::CoinStatsListener), through
//! [`UtxoSet::track_coin_stats`](crate::UtxoSet::track_coin_stats).

use bitcoin_rs_primitives::{OutPoint, TxOut};
use smallvec::SmallVec;

use crate::stats::muhash3072;

/// Receives UTXO mutations committed to durable shard state.
///
/// The notification interface is batch-only and order-independent. A commit
/// that touches exactly one shard delivers its same-transaction runs directly
/// through [`Self::on_insert_coins`] and [`Self::on_remove_coins`]; a commit
/// that touches two or more shards collects every shard's events and delivers
/// them once, after all shard mutations have landed, through
/// [`Self::on_committed_event_batches`].
///
/// Multi-shard batch order and chunking are not semantic. Batches arrive in
/// shard order and each groups one shard's same-transaction runs, but they may
/// be chunked, merged, or split without changing the mutations they
/// represent. A listener must derive the same final state from direct
/// single-shard batches and collected multi-shard batches. The one ordering
/// guarantee that always holds within a commit: the removal of an outpoint is
/// delivered before the insertion that replaces it — overwrite removals
/// arrive as one-element `RemoveBatch` events ahead of their replacement
/// `InsertBatch`.
pub(crate) trait UtxoChangeListener {
    /// Called after a run of same-transaction outputs has been inserted into
    /// its shard.
    fn on_insert_coins(&self, insertions: &[UtxoInserted<'_>]);

    /// Called after a run of same-transaction outputs has been removed from
    /// its shard. Overwrite removals arrive as one-element batches ordered
    /// ahead of their replacement insertions.
    fn on_remove_coins(&self, removals: &[UtxoRemoved]);

    /// Called once with every collected shard event batch for a multi-shard
    /// commit, synchronously, after the shard mutations have landed and
    /// before any shard error is returned.
    ///
    /// Every event for a mutation that landed is delivered here even when a
    /// later shard failed: a partial commit stays fatal and never rolls back,
    /// so the listener must observe exactly what the shards now hold.
    fn on_committed_event_batches(&self, batches: &[UtxoChangeEvents<'_>]);

    /// Returns the current `MuHash3072` snapshot trailer, when this listener tracks one.
    fn muhash3072(&self) -> Option<[u8; muhash3072::BYTE_LEN]> {
        None
    }
}

/// One inserted UTXO event delivered to a change listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UtxoInserted<'a> {
    /// Outpoint that was inserted.
    pub op: &'a OutPoint,
    /// Inserted transaction output.
    pub txout: &'a TxOut,
    /// Height at which the inserted output was created.
    pub height: u32,
    /// Whether the inserted output came from a coinbase transaction.
    pub coinbase: bool,
}

impl<'a> UtxoInserted<'a> {
    /// Constructs one inserted UTXO event.
    #[must_use]
    pub(crate) const fn new(
        op: &'a OutPoint,
        txout: &'a TxOut,
        height: u32,
        coinbase: bool,
    ) -> Self {
        Self {
            op,
            txout,
            height,
            coinbase,
        }
    }
}

/// One removed UTXO event delivered to a change listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UtxoRemoved {
    /// Outpoint that was removed.
    pub op: OutPoint,
    /// Removed transaction output.
    pub txout: TxOut,
    /// Height at which the removed output was created.
    pub height: u32,
    /// Whether the removed output came from a coinbase transaction.
    pub coinbase: bool,
}

impl UtxoRemoved {
    /// Constructs one removed UTXO event.
    #[must_use]
    pub(crate) const fn new(op: OutPoint, txout: TxOut, height: u32, coinbase: bool) -> Self {
        Self {
            op,
            txout,
            height,
            coinbase,
        }
    }
}

enum UtxoChangeEvent<'a> {
    InsertBatch(SmallVec<[UtxoInserted<'a>; 8]>),
    RemoveBatch(SmallVec<[UtxoRemoved; 2]>),
}

/// Events collected from the shards one multi-shard commit touched.
///
/// Handed to [`UtxoChangeListener::on_committed_event_batches`] after every
/// shard mutation has landed. Batch order and chunking are not semantic:
/// batches arrive in shard order and each groups one shard's
/// same-transaction runs, but a listener must derive the same final state
/// however the events are chunked or merged. Within one commit the removal
/// of an outpoint always precedes the insertion that replaces it; overwrite
/// removals appear as one-element `RemoveBatch` events ahead of their
/// replacement `InsertBatch`.
pub(crate) struct UtxoChangeEvents<'a> {
    events: Vec<UtxoChangeEvent<'a>>,
    operation_count: usize,
}

/// Read-only view over one committed UTXO event.
///
/// One inserted batch or one removed batch. Removed batches include the
/// one-element batches emitted at overwrite boundaries, ordered ahead of
/// their replacement insertions.
#[derive(Clone, Copy)]
pub(crate) enum UtxoCommittedEvent<'batch, 'coin> {
    /// Batch of inserted UTXOs.
    InsertBatch(&'batch [UtxoInserted<'coin>]),
    /// Batch of removed UTXOs, including one-element overwrite removals.
    RemoveBatch(&'batch [UtxoRemoved]),
}

impl<'a> UtxoChangeEvents<'a> {
    pub(crate) fn with_capacity_hint(insertions: usize, removals: usize) -> Self {
        Self {
            events: Vec::with_capacity(usize::from(insertions > 0) + usize::from(removals > 0)),
            operation_count: 0,
        }
    }

    /// Appends a run of insertions, merging into the previous insert batch
    /// when the stream still ends on one.
    pub(crate) fn push_insert_batch(&mut self, insertions: SmallVec<[UtxoInserted<'a>; 8]>) {
        if insertions.is_empty() {
            return;
        }
        self.operation_count = self.operation_count.saturating_add(insertions.len());
        if let Some(UtxoChangeEvent::InsertBatch(existing)) = self.events.last_mut() {
            existing.extend(insertions);
        } else {
            self.events.push(UtxoChangeEvent::InsertBatch(insertions));
        }
    }

    /// Appends one insertion, merging into the previous insert batch.
    pub(crate) fn push_insert_coin(&mut self, insertion: UtxoInserted<'a>) {
        self.operation_count = self.operation_count.saturating_add(1);
        if let Some(UtxoChangeEvent::InsertBatch(existing)) = self.events.last_mut() {
            existing.push(insertion);
        } else {
            let mut insertions = SmallVec::<[UtxoInserted<'a>; 8]>::new();
            insertions.push(insertion);
            self.events.push(UtxoChangeEvent::InsertBatch(insertions));
        }
    }

    /// Appends a run of removals, merging into the previous remove batch when
    /// the stream still ends on one.
    pub(crate) fn push_remove_batch(&mut self, removals: SmallVec<[UtxoRemoved; 2]>) {
        if removals.is_empty() {
            return;
        }
        self.operation_count = self.operation_count.saturating_add(removals.len());
        if let Some(UtxoChangeEvent::RemoveBatch(existing)) = self.events.last_mut() {
            existing.extend(removals);
        } else {
            self.events.push(UtxoChangeEvent::RemoveBatch(removals));
        }
    }

    /// Appends one removal as its own remove batch.
    ///
    /// Used for overwrite removals, which must not merge with a previous remove
    /// batch so the replacement insert is ordered after this exact removal.
    pub(crate) fn push_remove_coin(&mut self, removal: UtxoRemoved) {
        self.operation_count = self.operation_count.saturating_add(1);
        let mut removals = SmallVec::<[UtxoRemoved; 2]>::new();
        removals.push(removal);
        self.events.push(UtxoChangeEvent::RemoveBatch(removals));
    }

    /// Visits committed events in collection order.
    pub(crate) fn for_each(&self, mut visit: impl FnMut(UtxoCommittedEvent<'_, 'a>)) {
        for event in &self.events {
            match event {
                UtxoChangeEvent::InsertBatch(insertions) => {
                    visit(UtxoCommittedEvent::InsertBatch(insertions));
                }
                UtxoChangeEvent::RemoveBatch(removals) => {
                    visit(UtxoCommittedEvent::RemoveBatch(removals));
                }
            }
        }
    }

    /// Returns the number of output-level mutations represented by these events.
    #[must_use]
    pub(crate) fn operation_count(&self) -> usize {
        self.operation_count
    }

    /// Visits committed events split into bounded chunks.
    ///
    /// Chunking is not semantic: any chunk size yields the same mutations.
    pub(crate) fn for_each_chunk<'batch>(
        &'batch self,
        chunk_size: usize,
        mut visit: impl FnMut(UtxoCommittedEvent<'batch, 'a>),
    ) {
        let chunk_size = chunk_size.max(1);
        for event in &self.events {
            match event {
                UtxoChangeEvent::InsertBatch(insertions) => {
                    for chunk in insertions.chunks(chunk_size) {
                        visit(UtxoCommittedEvent::InsertBatch(chunk));
                    }
                }
                UtxoChangeEvent::RemoveBatch(removals) => {
                    for chunk in removals.chunks(chunk_size) {
                        visit(UtxoCommittedEvent::RemoveBatch(chunk));
                    }
                }
            }
        }
    }
}
