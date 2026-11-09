use super::*;
use crate::test_support::TestError;
// BUD-02
#[test]
fn open_wires_peer_outbound_ledger_to_node_budget() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let budget = state.budget();
    let shared = state.p2p().shared_outbound_budget();
    assert_eq!(
        budget.available_of_charges(bitcoin_rs_storage::budget::BudgetOwner::PeerOutbound),
        0
    );
    assert!(shared.test_try_charge(4096));
    assert_eq!(
        budget.available_of_charges(bitcoin_rs_storage::budget::BudgetOwner::PeerOutbound),
        4096
    );
    shared.test_release(4096);
    assert_eq!(
        budget.available_of_charges(bitcoin_rs_storage::budget::BudgetOwner::PeerOutbound),
        0
    );
    Ok(())
}
