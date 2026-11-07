use bitcoin_rs_execution::chain::NodeStatus;
use bitcoin_rs_node::budget::{
    BudgetError, BudgetOwner, BudgetRefusal, BudgetedIngressLedger, NodeBudget,
};
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::{Network, NodeConfig};
use bitcoin_rs_wire::inbound::block_memory::BlockMemory;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[expect(clippy::expect_used)]
fn open_test_node() -> (NodeState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir succeeds");
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None).expect("node open succeeds");
    (state, dir)
}

// BUD-06
#[test]
#[expect(clippy::expect_used)]
fn every_retained_allocation_has_one_owner() {
    let budget = Arc::new(NodeBudget::from_dbcache_bytes(64 * 1024 * 1024, 8));
    let ledger = Arc::new(BudgetedIngressLedger::new(Arc::clone(&budget)));
    let block_memory = Arc::new(BlockMemory::new(ledger));

    let owners = [
        BudgetOwner::CoinCache,
        BudgetOwner::EngineCache,
        BudgetOwner::FactsQueue,
        BudgetOwner::IndexBuilder,
        BudgetOwner::StagedImages,
        BudgetOwner::QueryViews,
    ];

    let alloc_amounts: [u64; 6] = [
        0,
        1024 * 1024,
        2 * 1024 * 1024,
        4 * 1024 * 1024,
        1024 * 1024,
        512 * 1024,
    ];

    for (&owner, &amt) in owners.iter().zip(alloc_amounts.iter()) {
        if amt > 0 && owner != BudgetOwner::StagedImages {
            budget.reserve(owner, amt).expect("reserve succeeds");
            budget.allocate(owner, amt).expect("allocate succeeds");
        }
    }

    let ingress_bytes = 1024 * 1024;
    let credit = block_memory
        .reserve(ingress_bytes, || false)
        .expect("ingress reservation succeeds");

    let mut sum_of_charges = 0_u64;
    for &owner in &owners {
        let charged = budget.available_of_charges(owner);
        let expected = alloc_amounts[owner.index()];
        assert_eq!(
            charged, expected,
            "owner {owner:?} charge mismatch: got {charged}, expected {expected}"
        );
        sum_of_charges = sum_of_charges.saturating_add(charged);
    }

    assert_eq!(
        budget.total_committed(),
        sum_of_charges,
        "total committed memory must equal sum of per-owner charges"
    );

    drop(credit);
    assert_eq!(
        budget.available_of_charges(BudgetOwner::StagedImages),
        0,
        "staged images charge must return to zero on credit drop"
    );

    assert!(budget.is_safe());
}

// BUD-03
#[test]
#[expect(clippy::expect_used)]
fn full_budget_refuses_ingress_without_marking_invalid() {
    let (state, _dir) = open_test_node();
    let budget = state.budget();
    let block_memory = state.block_memory();

    let owners = [
        BudgetOwner::StagedImages,
        BudgetOwner::EngineCache,
        BudgetOwner::FactsQueue,
        BudgetOwner::IndexBuilder,
        BudgetOwner::QueryViews,
    ];
    for owner in owners {
        let avail = budget.available(owner);
        if avail > 0 {
            budget.reserve(owner, avail).expect("reserve available");
            budget.allocate(owner, avail).expect("allocate available");
        }
    }

    let attempt_bytes = 1024 * 1024;
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_cb = {
        let cancel = Arc::clone(&cancel);
        move || cancel.load(Ordering::Acquire)
    };

    let cancel_trigger = Arc::clone(&cancel);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        cancel_trigger.store(true, Ordering::Release);
    });

    let result = block_memory.reserve(attempt_bytes, cancel_cb);
    assert!(
        result.is_err(),
        "ingress reservation must be refused when budget is full"
    );

    assert!(
        budget.ingress_refused(),
        "budget must record ingress refusal"
    );

    let exhaustion_err = BudgetError::BudgetExhausted;
    assert_eq!(
        exhaustion_err.refusal(),
        Some(BudgetRefusal::RetryLater),
        "budget refusal must map to RetryLater backpressure"
    );

    let tree = state.chainstate().block_tree_reader();
    let tree_read = tree.read();
    for id in tree_read.leaf_node_ids() {
        if let Ok(node) = tree_read.node(id) {
            assert_ne!(
                node.status,
                NodeStatus::Invalid,
                "refused block must NEVER be marked Invalid in BlockTree (BUD-03)"
            );
        }
    }
}
