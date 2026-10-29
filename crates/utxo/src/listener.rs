//! guarantee that always holds within a commit: the removal of an outpoint is
//! delivered before the insertion that replaces it — overwrite removals
//! arrive as one-element `RemoveBatch` events ahead of their replacement
//! `InsertBatch`.

use bitcoin_rs_primitives::{OutPoint, TxOut};
use smallvec::SmallVec;

#[derive(Debug)]
pub(crate) struct UtxoInserted<'a> {
    pub op: &'a OutPoint,
    pub txout: &'a TxOut,
    pub height: u32,
    pub coinbase: bool,
}

impl<'a> UtxoInserted<'a> {
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

#[derive(Debug)]
pub(crate) struct UtxoRemoved {
    pub op: OutPoint,
    pub txout: TxOut,
    pub height: u32,
    pub coinbase: bool,
}

impl UtxoRemoved {
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

pub(crate) struct UtxoChangeEvents<'a> {
    events: Vec<UtxoChangeEvent<'a>>,
    operation_count: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum UtxoCommittedEvent<'batch, 'coin> {
    InsertBatch(&'batch [UtxoInserted<'coin>]),
    RemoveBatch(&'batch [UtxoRemoved]),
}

impl<'a> UtxoChangeEvents<'a> {
    pub(crate) fn new() -> Self {
        Self {
            events: Vec::new(),
            operation_count: 0,
        }
    }

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

    pub(crate) fn push_remove_coin(&mut self, removal: UtxoRemoved) {
        self.operation_count = self.operation_count.saturating_add(1);
        let mut removals = SmallVec::<[UtxoRemoved; 2]>::new();
        removals.push(removal);
        self.events.push(UtxoChangeEvent::RemoveBatch(removals));
    }

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

    #[must_use]
    pub(crate) fn operation_count(&self) -> usize {
        self.operation_count
    }

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
