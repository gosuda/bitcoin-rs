use bitcoin_rs_storage::CommittedFacts;
use crossbeam_channel::{Receiver, Sender};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

pub const DEFAULT_FACTS_QUEUE_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_FACTS_QUEUE_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gap;

// PRJ-04, PRJ-02, IDX-08
#[derive(Clone)]
pub struct FactsQueue {
    tx: Sender<Arc<CommittedFacts>>,
    rx: Receiver<Arc<CommittedFacts>>,
    bytes: Arc<AtomicU64>,
    gap: Arc<AtomicBool>,
    budget: u64,
}

impl FactsQueue {
    #[must_use]
    pub fn new(capacity: usize, budget_bytes: u64) -> Self {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        Self {
            tx,
            rx,
            bytes: Arc::new(AtomicU64::new(0)),
            gap: Arc::new(AtomicBool::new(false)),
            budget: budget_bytes,
        }
    }

    #[must_use]
    pub fn with_default_budget() -> Self {
        Self::new(
            DEFAULT_FACTS_QUEUE_CAPACITY,
            DEFAULT_FACTS_QUEUE_BUDGET_BYTES,
        )
    }

    pub fn try_push(&self, facts: Arc<CommittedFacts>) -> bool {
        if self.gap.load(Ordering::SeqCst) {
            return false;
        }
        let size = facts.size_bytes();
        let mut current = self.bytes.load(Ordering::SeqCst);
        loop {
            if current.saturating_add(size) > self.budget {
                self.gap.store(true, Ordering::SeqCst);
                return false;
            }
            match self.bytes.compare_exchange_weak(
                current,
                current.saturating_add(size),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        match self.tx.try_send(facts) {
            Ok(()) => true,
            Err(_) => {
                self.bytes.fetch_sub(size, Ordering::SeqCst);
                self.gap.store(true, Ordering::SeqCst);
                false
            }
        }
    }

    pub fn drain(&self) -> Result<Vec<Arc<CommittedFacts>>, Gap> {
        if self.gap.load(Ordering::SeqCst) {
            while let Ok(facts) = self.rx.try_recv() {
                self.bytes.fetch_sub(facts.size_bytes(), Ordering::SeqCst);
            }
            return Err(Gap);
        }
        let mut items = Vec::new();
        while let Ok(facts) = self.rx.try_recv() {
            self.bytes.fetch_sub(facts.size_bytes(), Ordering::SeqCst);
            items.push(facts);
        }
        Ok(items)
    }

    #[must_use]
    pub fn has_gap(&self) -> bool {
        self.gap.load(Ordering::SeqCst)
    }

    pub fn set_gap(&self) {
        self.gap.store(true, Ordering::SeqCst);
    }

    pub fn clear_gap(&self) {
        self.gap.store(false, Ordering::SeqCst);
    }

    #[must_use]
    pub fn receiver(&self) -> Receiver<Arc<CommittedFacts>> {
        self.rx.clone()
    }

    #[must_use]
    pub fn bytes_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.bytes)
    }

    #[must_use]
    pub fn gap_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.gap)
    }
}
