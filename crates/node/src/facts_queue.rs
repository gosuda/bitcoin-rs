use bitcoin_rs_storage::CommittedFacts;
use bitcoin_rs_storage::budget::{BudgetReclaimer, ChargeHandle};
use crossbeam_channel::{Receiver, Sender};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub const DEFAULT_FACTS_QUEUE_CAPACITY: usize = 256;

// PRJ-04, PRJ-02, IDX-08, BUD-06, BUD-07
#[derive(Clone)]
pub struct FactsQueue {
    tx: Sender<Arc<CommittedFacts>>,
    rx: Receiver<Arc<CommittedFacts>>,
    charge: ChargeHandle,
    gap: Arc<AtomicBool>,
}

impl FactsQueue {
    #[must_use]
    pub fn new(capacity: usize, charge: ChargeHandle) -> Self {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        Self {
            tx,
            rx,
            charge,
            gap: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn try_push(&self, facts: Arc<CommittedFacts>) -> bool {
        if self.gap.load(Ordering::SeqCst) {
            return false;
        }
        let size = facts.size_bytes();
        if self.charge.charge(size).is_err() {
            self.gap.store(true, Ordering::SeqCst);
            return false;
        }
        match self.tx.try_send(facts) {
            Ok(()) => true,
            Err(_) => {
                self.charge.release(size);
                self.gap.store(true, Ordering::SeqCst);
                false
            }
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn has_gap(&self) -> bool {
        self.gap.load(Ordering::SeqCst)
    }

    pub fn set_gap(&self) {
        self.gap.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn receiver(&self) -> Receiver<Arc<CommittedFacts>> {
        self.rx.clone()
    }

    #[must_use]
    pub fn charge_handle(&self) -> ChargeHandle {
        self.charge.clone()
    }

    #[must_use]
    pub fn gap_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.gap)
    }
}

impl BudgetReclaimer for FactsQueue {
    fn reclaim(&self, bytes: u64) -> u64 {
        let mut freed = 0;
        while freed < bytes {
            let Ok(facts) = self.rx.try_recv() else {
                break;
            };
            let size = facts.size_bytes();
            self.charge.release(size);
            freed = freed.saturating_add(size);
        }
        if freed > 0 {
            self.gap.store(true, Ordering::SeqCst);
        }
        freed
    }
}

struct FactsReclaimer {
    queue: std::sync::Weak<FactsQueue>,
}

impl BudgetReclaimer for FactsReclaimer {
    fn reclaim(&self, bytes: u64) -> u64 {
        self.queue.upgrade().map_or(0, |queue| queue.reclaim(bytes))
    }
}

impl FactsQueue {
    pub(crate) fn reclaimer(self: &Arc<Self>) -> Arc<dyn BudgetReclaimer> {
        Arc::new(FactsReclaimer {
            queue: Arc::downgrade(self),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{BudgetCaps, NodeBudget};
    use bitcoin_rs_storage::budget::{BudgetCharge, BudgetOwner};
    use bitcoin_rs_storage::committed_facts::{CommittedBlock, CommittedFacts};

    fn budget() -> Arc<NodeBudget> {
        Arc::new(NodeBudget::new(
            BudgetCaps {
                staged_images: 8_192,
                engine_cache: 0,
                coin_cache: 0,
                facts_queue: 4_096,
                index_builder: 0,
                query_views: 0,
                peer_outbound: 0,
                foreground_reserve: 0,
            },
            4,
        ))
    }

    fn facts(commit_id: u64) -> Arc<CommittedFacts> {
        Arc::new(CommittedFacts {
            commit_id,
            blocks: vec![CommittedBlock {
                height: 0,
                hash: [1u8; 32],
                parent_hash: [0u8; 32],
                header: [0u8; 80],
                txs: Vec::new(),
            }],
        })
    }

    fn queue(budget: &Arc<NodeBudget>) -> FactsQueue {
        let ledger: Arc<dyn BudgetCharge> = budget.clone();
        let charge = ChargeHandle::new(ledger, BudgetOwner::FactsQueue);
        FactsQueue::new(8, charge)
    }

    // BUD-06
    #[expect(clippy::expect_used)]
    #[test]
    fn facts_queue_charge_is_owned_by_the_node_budget() {
        let budget = budget();
        let queue = queue(&budget);
        let facts = facts(1);
        let size = facts.size_bytes();
        assert!(queue.try_push(Arc::clone(&facts)));
        assert_eq!(
            budget.available_of_charges(BudgetOwner::FactsQueue),
            size,
            "the queued facts must be charged to the node budget"
        );
        assert_eq!(budget.available_of_reservations(BudgetOwner::FactsQueue), 0);
        let received = queue.receiver().try_recv().expect("one queued fact");
        queue.charge_handle().release(received.size_bytes());
        assert_eq!(budget.available_of_charges(BudgetOwner::FactsQueue), 0);
    }

    // BUD-07
    #[expect(clippy::expect_used)]
    #[test]
    fn ensure_available_reclaims_queued_facts() {
        let budget = budget();
        let queue = Arc::new(queue(&budget));
        budget.add_reclaimer(queue.reclaimer());
        let facts = facts(1);
        let size = facts.size_bytes();
        assert!(queue.try_push(facts));

        let staged = 8_192;
        budget
            .reserve(BudgetOwner::StagedImages, staged)
            .expect("staged reservation fits");
        budget
            .allocate(BudgetOwner::StagedImages, staged)
            .expect("staged allocation fits");
        assert_eq!(budget.total_committed(), 8_192 + size);

        budget
            .ensure_available(BudgetOwner::FactsQueue, 4_096)
            .expect("reclaiming queued facts frees the reservation");
        assert_eq!(
            budget.available_of_charges(BudgetOwner::FactsQueue),
            0,
            "the reclaimer released the queued facts"
        );
        assert_eq!(
            budget.available_of_reservations(BudgetOwner::FactsQueue),
            4_096
        );
        assert!(queue.has_gap(), "dropping queued facts sets the gap");
    }
}
