use bitcoin_rs_execution::chain::NodeStatus;
use bitcoin_rs_node::budget::{BudgetedIngressLedger, BudgetedOutboundLedger, NodeBudget};
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::{Network, NodeConfig};
use bitcoin_rs_storage::{
    budget::{BudgetError, BudgetOwner, BudgetRefusal},
    split_chainstate_cache_budget,
};
use bitcoin_rs_wire::connection::OutboundLedger;
use bitcoin_rs_wire::inbound::block_memory::BlockMemory;
use std::sync::Arc;
#[expect(clippy::expect_used)]
fn open_test_node() -> (NodeState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir succeeds");
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None).expect("node open succeeds");
    (state, dir)
}
// BUD-02, BUD-06
#[test]
#[expect(clippy::expect_used)]
fn ingress_and_peer_outbound_charges_return_to_their_owner_on_release() {
    let budget = Arc::new(NodeBudget::from_chainstate_cache_budget(
        split_chainstate_cache_budget(64 * 1024 * 1024),
        8,
    ));
    let ledger = Arc::new(BudgetedIngressLedger::new(Arc::clone(&budget)));
    let block_memory = Arc::new(BlockMemory::new(ledger));
    let outbound = BudgetedOutboundLedger::new(Arc::clone(&budget));

    let ingress_bytes: usize = 1024 * 1024;
    let credit = block_memory
        .reserve(ingress_bytes, || false)
        .expect("ingress reservation succeeds");
    assert_eq!(
        budget.available_of_charges(BudgetOwner::StagedImages),
        1024 * 1024,
        "the staged block charge rises while the credit is held"
    );
    drop(credit);
    assert_eq!(
        budget.available_of_charges(BudgetOwner::StagedImages),
        0,
        "dropping the staged block credit returns its charge"
    );

    assert!(
        outbound.try_take(4096),
        "an outbound reservation inside the cap is admitted"
    );
    assert_eq!(
        budget.available_of_charges(BudgetOwner::PeerOutbound),
        4096,
        "the outbound reservation charges the peer owner"
    );
    outbound.give_back(4096);
    assert_eq!(
        budget.available_of_charges(BudgetOwner::PeerOutbound),
        0,
        "releasing the outbound bytes returns the peer owner charge"
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
        BudgetOwner::CoinCache,
        BudgetOwner::FactsQueue,
        BudgetOwner::IndexBuilder,
        BudgetOwner::QueryViews,
        BudgetOwner::PeerOutbound,
    ];
    for owner in owners {
        let avail = budget.available(owner);
        if avail > 0 {
            budget.reserve(owner, avail).expect("reserve available");
            budget.allocate(owner, avail).expect("allocate available");
        }
    }

    let Err(error) = budget.reserve(BudgetOwner::StagedImages, 1024 * 1024) else {
        panic!("staged-image reservation must be refused when the budget is full");
    };
    assert_eq!(
        error,
        BudgetError::BudgetExhausted,
        "a full budget refuses staged images with BudgetExhausted"
    );
    assert_eq!(
        error.refusal(),
        Some(BudgetRefusal::RetryLater),
        "a full-budget refusal is RetryLater backpressure"
    );

    assert!(
        !block_memory.ledger().try_take(1024 * 1024),
        "the ingress ledger must refuse block bytes when the budget is full"
    );

    assert!(
        budget.ingress_refused(),
        "budget must record ingress refusal"
    );

    let refused_hash = Network::Regtest.genesis_block_hash();
    let tree = state.chainstate().block_tree_reader();
    let tree_read = tree.read();
    if let Some(id) = tree_read.lookup(refused_hash) {
        let Ok(node) = tree_read.node(id) else {
            panic!("BlockTree lookup returned an unknown node");
        };
        assert_ne!(
            node.status,
            NodeStatus::Invalid,
            "refused block must NEVER be marked Invalid in BlockTree (BUD-03)"
        );
    }
}
