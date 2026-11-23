use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::p2p::sync::chain::{
    HeaderAdmission, HeaderAdmissionError, HeaderAdmissionOutcome, HeaderCandidate,
    HistoricalAdvance, ReorgError, SyncChain, SyncChainError, WindowApplyDisposition,
    WindowCommitError,
};
use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Header, Network};
use bitcoin_rs_p2p::{InboundHeaders, PeerTable};
use crossbeam_channel::Receiver;

pub use crate::p2p::sync::{BlockSync, default_sync_budget};

struct NodeSyncChain {
    assumeutxo: Option<Arc<bitcoin_rs_chain::AssumeUtxoManager>>,
    handles: Arc<bitcoin_rs_chain::Chainstate>,
    block_tree: bitcoin_rs_chain::chain::BlockTreeReader,
    followers: crate::chain_effects::ChainFollowers,
    budget: Arc<crate::budget::NodeBudget>,
}

#[must_use]
pub struct BlockSyncInputs {
    pub handles: Arc<bitcoin_rs_chain::Chainstate>,
    pub followers: crate::chain_effects::ChainFollowers,
    pub peer_table: Arc<PeerTable>,
    pub inbound_headers_rx: Receiver<InboundHeaders>,
    pub inbound_blocks_rx: Receiver<bitcoin_rs_p2p::InboundBlock>,
    pub ibd: Arc<bitcoin_rs_chain::chain::InitialBlockDownload>,
    pub assumeutxo: Option<Arc<bitcoin_rs_chain::AssumeUtxoManager>>,
    pub budget: Arc<crate::budget::NodeBudget>,
}

fn with_historical_background_permit<T>(
    budget: &crate::budget::NodeBudget,
    validate: impl FnOnce() -> T,
) -> T {
    let _permit = budget.cpu().try_acquire_background();
    validate()
}

#[must_use]
pub fn block_sync(inputs: BlockSyncInputs) -> BlockSync {
    let block_tree = inputs.handles.block_tree_reader();
    BlockSync::new(
        Arc::new(NodeSyncChain {
            assumeutxo: inputs.assumeutxo,
            handles: Arc::clone(&inputs.handles),
            block_tree,
            followers: inputs.followers,
            budget: inputs.budget,
        }),
        inputs.peer_table,
        inputs.inbound_headers_rx,
        inputs.inbound_blocks_rx,
        inputs.ibd,
    )
}

fn settle_window_failure(
    transition: bitcoin_rs_chain::ChainTransition<'_>,
    mempool_change: Option<bitcoin_rs_mempool::ChainChangeGuard>,
    mut error: bitcoin_rs_chain::WindowApplyError,
) -> bitcoin_rs_chain::WindowApplyError {
    let handles = transition.chainstate();
    if error.disposition == bitcoin_rs_chain::WindowApplyDisposition::Fatal
        || bitcoin_rs_chain::classify_apply_error(&error.source)
            == bitcoin_rs_chain::WindowApplyDisposition::Fatal
    {
        handles.fail_closed_for_recovery();
        error.disposition = bitcoin_rs_chain::WindowApplyDisposition::Fatal;
    } else if let Err(finish_source) =
        crate::chain_effects::ChainFollowers::finish_transition(handles, transition, mempool_change)
    {
        tracing::error!(
            original = %error.source,
            finish = %finish_source,
            "chain transition could not be settled after a window failure; \
             mempool admission stays closed until recovery or restart"
        );
        error.disposition = bitcoin_rs_chain::WindowApplyDisposition::Fatal;
    }
    error
}

fn settle_window_refused(
    transition: bitcoin_rs_chain::ChainTransition<'_>,
    mempool_change: Option<bitcoin_rs_mempool::ChainChangeGuard>,
    refusal: WindowCommitError,
) -> WindowCommitError {
    let handles = transition.chainstate();
    handles.fail_closed_for_recovery();
    drop(mempool_change);
    drop(transition);
    tracing::error!(
        refusal = %refusal.source,
        "chain transition halted after a committed window: a follower refused settlement; \
         mempool admission stays closed until recovery or restart"
    );
    refusal
}

fn settle_window_success(
    transition: bitcoin_rs_chain::ChainTransition<'_>,
    mempool_change: Option<bitcoin_rs_mempool::ChainChangeGuard>,
    applied: usize,
    committed: Vec<bitcoin_rs_chain::ConnectOutcome>,
) -> core::result::Result<usize, bitcoin_rs_chain::WindowApplyError> {
    let handles = transition.chainstate();
    match crate::chain_effects::ChainFollowers::finish_transition(
        handles,
        transition,
        mempool_change,
    ) {
        Ok(()) => Ok(applied),
        Err(finish_source) => {
            tracing::error!(
                finish = %finish_source,
                "chain transition could not be settled after a committed window; \
                 mempool admission stays closed until recovery or restart"
            );
            Err(bitcoin_rs_chain::WindowApplyError {
                applied,
                committed,
                source: Box::new(finish_source),
                disposition: bitcoin_rs_chain::WindowApplyDisposition::Fatal,
                invalidated: Box::default(),
            })
        }
    }
}

#[cfg(test)]
pub(crate) fn fixture_insert_header_node(
    handles: &bitcoin_rs_chain::Chainstate,
    parent: bitcoin_rs_chain::chain::NodeId,
    header: bitcoin_rs_consensus::primitives::Header,
    status: bitcoin_rs_chain::chain::NodeStatus,
) -> Result<bitcoin_rs_chain::chain::NodeId, bitcoin_rs_chain::chain::ChainError> {
    let mut tree = handles.block_tree().write();
    tree.insert_node(Some(parent), header, status)
}

impl SyncChain for NodeSyncChain {
    fn historical_base(&self) -> Option<Hash256> {
        match self.handles.role() {
            bitcoin_rs_chain::assumeutxo::ChainstateRole::AssumedActive { base_hash, .. } => {
                Some(base_hash)
            }
            _ => None,
        }
    }

    fn closed_for_recovery(&self) -> bool {
        self.handles.is_closed_for_recovery()
    }

    fn advance_historical(&self) -> Result<HistoricalAdvance, SyncChainError> {
        let Some(manager) = &self.assumeutxo else {
            return Ok(HistoricalAdvance::Complete);
        };
        manager.advance_historical().map_err(|error| {
            self.handles.fail_closed_for_recovery();
            SyncChainError::from(error)
        })
    }

    fn connect_historical(&self, payload: &BlockImage) -> Result<(), SyncChainError> {
        let manager = self
            .assumeutxo
            .as_ref()
            .ok_or("historical validation is not configured")?;
        with_historical_background_permit(&self.budget, || manager.step_historical(payload))
            .map(|_| ())
            .map_err(SyncChainError::from)
    }

    fn network(&self) -> Network {
        self.handles.network()
    }

    fn block_tree(&self) -> parking_lot::RwLockReadGuard<'_, bitcoin_rs_chain::chain::BlockTree> {
        self.block_tree.read()
    }

    fn chain_tip(&self) -> Option<Arc<bitcoin_rs_chain::chain::TipSnapshot>> {
        self.handles.header_tip()
    }

    fn applied_tip(&self) -> Option<Arc<bitcoin_rs_chain::chain::TipSnapshot>> {
        self.handles.applied_tip_snapshot()
    }

    fn bootstrap_genesis(&self) {
        if let Err(error) = crate::chain_effects::bootstrap_genesis(&self.handles, &self.followers)
        {
            tracing::warn!(%error, "failed to bootstrap genesis");
        }
    }

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
        match self.handles.admit_headers(headers) {
            Ok(outcome) => HeaderAdmission::Accepted {
                accepted: outcome.accepted,
                announced_tip: outcome.announced_tip,
                active_height: outcome.active_height,
                demoted_tip: outcome.demoted_tip,
            },
            Err(bitcoin_rs_chain::HeaderAdmissionError::Rejected(error)) => {
                HeaderAdmission::Rejected(error)
            }
            Err(bitcoin_rs_chain::HeaderAdmissionError::Refused(error)) => {
                HeaderAdmission::Refused(bitcoin_rs_chain::chain::HeaderRefusal::from_cause(&error))
            }
            Err(bitcoin_rs_chain::HeaderAdmissionError::Resource(error)) => {
                HeaderAdmission::Refused(bitcoin_rs_chain::chain::HeaderRefusal::from_resource(
                    &error,
                ))
            }
            Err(bitcoin_rs_chain::HeaderAdmissionError::Candidate(error)) => {
                HeaderAdmission::Refused(bitcoin_rs_chain::chain::HeaderRefusal::from_cause(&error))
            }
        }
    }

    fn begin_header_candidate(
        &self,
        anchor: Hash256,
        minimum_work: bitcoin_rs_consensus::header_rules::ChainWork,
    ) -> Result<HeaderCandidate, HeaderAdmissionError> {
        self.handles.begin_header_candidate(anchor, minimum_work)
    }

    fn admit_verified_headers(
        &self,
        candidate: &mut HeaderCandidate,
        maximum: usize,
    ) -> Result<HeaderAdmissionOutcome, HeaderAdmissionError> {
        self.handles.admit_verified_headers(candidate, maximum)
    }

    fn maintain_header_retention(&self) -> Result<usize, HeaderAdmissionError> {
        self.handles.maintain_header_retention()
    }

    fn check_body_binding(&self, block: &BlockImage) -> Result<(), SyncChainError> {
        let hash = Hash256::from(block.block_hash());
        let segwit_active = {
            let tree = self.block_tree.read();
            tree.lookup(hash)
                .and_then(|node_id| tree.node(node_id).ok())
                .is_none_or(|node| {
                    bitcoin_rs_chain::chain::softfork_state(
                        &tree,
                        self.handles.network(),
                        node.parent,
                        node.height,
                    )
                    .segwit_active
                })
        };
        bitcoin_rs_consensus::check_image_body_binding(
            block,
            bitcoin_rs_consensus::BlockRuleContext { segwit_active },
        )
        .map_err(SyncChainError::from)
    }

    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
        bitcoin_rs_chain::window_len_within(serialized_sizes, self.budget.script_batch_limits())
    }

    fn commit_window(&self, payloads: &[&BlockImage]) -> Result<usize, WindowCommitError> {
        let transition = self
            .handles
            .begin_transition()
            .map_err(|source| WindowCommitError {
                applied: 0,
                disposition: WindowApplyDisposition::Operational,
                invalidated: Box::default(),
                source: source.into(),
            })?;
        let mempool_change =
            self.followers
                .begin_mempool_change()
                .map_err(|source| WindowCommitError {
                    applied: 0,
                    disposition: WindowApplyDisposition::Operational,
                    invalidated: Box::default(),
                    source: source.into(),
                })?;
        let _foreground = self.budget.cpu().acquire_foreground();
        match transition.connect_window(payloads) {
            Ok(outcomes) => {
                match settle_committed_followers(&self.followers, payloads, &outcomes) {
                    Ok(()) => {
                        settle_window_success(transition, mempool_change, outcomes.len(), outcomes)
                            .map_err(window_commit_error)
                    }
                    Err(refusal) => Err(settle_window_refused(
                        transition,
                        mempool_change,
                        WindowCommitError {
                            applied: outcomes.len(),
                            ..refused_window(refusal)
                        },
                    )),
                }
            }
            Err(error) => {
                let settled =
                    settle_committed_followers(&self.followers, payloads, &error.committed);
                match settled {
                    Ok(()) => Err(window_commit_error(settle_window_failure(
                        transition,
                        mempool_change,
                        error,
                    ))),
                    Err(refusal) => {
                        tracing::error!(
                            original = %error.source,
                            refusal = %refusal,
                            "window application failed before follower settlement was refused"
                        );
                        Err(settle_window_refused(
                            transition,
                            mempool_change,
                            WindowCommitError {
                                applied: error.applied,
                                invalidated: error.invalidated,
                                ..refused_window(refusal)
                            },
                        ))
                    }
                }
            }
        }
    }

    fn switch_to_branch(
        &self,
        target: bitcoin_rs_chain::chain::NodeId,
        staged_body: &mut dyn FnMut(Hash256) -> Option<BlockImage>,
        connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), ReorgError> {
        crate::reorg::switch_to_branch(
            &self.handles,
            &self.followers,
            target,
            staged_body,
            connected_body,
        )
        .inspect_err(|error| {
            if matches!(error, ReorgError::ConnectFailed { invalidated, .. } if !invalidated.is_empty()) {
                self.handles.reevaluate_assume_valid();
            }
        })
    }
}

fn refused_window(source: bitcoin_rs_mempool::MempoolError) -> WindowCommitError {
    WindowCommitError {
        applied: 0,
        disposition: WindowApplyDisposition::Fatal,
        invalidated: Box::default(),
        source: SyncChainError::Message(format!("mempool settlement refused: {source}")),
    }
}

fn settle_committed_followers(
    followers: &crate::chain_effects::ChainFollowers,
    payloads: &[&BlockImage],
    committed: &[bitcoin_rs_chain::ConnectOutcome],
) -> core::result::Result<(), bitcoin_rs_mempool::MempoolError> {
    for (payload, outcome) in payloads.iter().zip(committed) {
        followers.on_connect(payload, outcome)?;
    }
    Ok(())
}

fn window_commit_error(error: bitcoin_rs_chain::WindowApplyError) -> WindowCommitError {
    WindowCommitError {
        applied: error.applied,
        disposition: error.disposition,
        invalidated: error.invalidated,
        source: (*error.source).into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin_rs_chain::chain::{BlockTree, NodeStatus, TipSnapshot, regtest_fixture};
    use bitcoin_rs_consensus::primitives::{
        Block, BlockHash, BlockImage, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
    };
    use bitcoin_rs_consensus::script::push_int;
    use bitcoin_rs_storage::{split_chainstate_cache_budget, utxo::UtxoSet};
    use hashbrown::HashMap;
    use parking_lot::{Mutex, RwLock};

    use crate::p2p::sync::chain::{SyncChain, WindowApplyDisposition, WindowCommitError};
    use crate::test_support::TestError;
    use bitcoin_rs_chain::Chainstate;

    fn sync_unit_test_budget() -> Arc<crate::budget::NodeBudget> {
        Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
            split_chainstate_cache_budget(16),
            1,
        ))
    }

    #[test]
    fn window_failure_keeps_committed_followers_and_native_retry_policy()
    -> Result<(), crate::test_support::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let first = regtest_fixture::mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![regtest_fixture::coinbase(1)],
        )?;
        let invalid = regtest_fixture::mined_block_with_prev_hash(
            first.block_hash(),
            2,
            vec![regtest_fixture::coinbase(2), regtest_fixture::coinbase(3)],
        )?;
        let child = regtest_fixture::mined_block_with_prev_hash(
            invalid.block_hash(),
            3,
            vec![regtest_fixture::coinbase(3)],
        )?;
        let invalid_hashes = vec![
            Hash256::from(invalid.block_hash()),
            Hash256::from(child.block_hash()),
        ];
        let mut tree = BlockTree::new();
        let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        for block in [&first, &invalid, &child] {
            parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
        }
        let handles = Arc::new(apply_handles(
            tree.tip_handle(),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(tree)),
        ));
        let followers = crate::chain_effects::ChainFollowers::noop();
        let adapter = super::NodeSyncChain {
            block_tree: handles.block_tree_reader(),
            handles: Arc::clone(&handles),
            followers: followers.clone(),
            assumeutxo: None,
            budget: sync_unit_test_budget(),
        };
        adapter.bootstrap_genesis();
        let mut mutated = invalid.clone();
        mutated.txs.pop();
        for (blocks, disposition, applied, invalidated) in [
            (
                vec![&first, &mutated, &child],
                WindowApplyDisposition::BodyMutated,
                1,
                vec![],
            ),
            (
                vec![&invalid, &child],
                WindowApplyDisposition::Permanent,
                0,
                invalid_hashes,
            ),
        ] {
            let owned_payloads = blocks
                .iter()
                .map(|block| BlockImage::from_local((*block).clone()))
                .collect::<Vec<_>>();
            let payloads: Vec<&BlockImage> = owned_payloads.iter().collect();
            let error = match adapter.commit_window(&payloads) {
                Ok(count) => panic!("invalid window committed {count} blocks"),
                Err(error) => error,
            };
            assert_eq!(error.disposition, disposition);
            assert_eq!(error.applied, applied);
            assert_eq!(error.invalidated.as_ref(), invalidated);
            let tip = adapter
                .applied_tip()
                .ok_or(TestError::Missing("committed tip"))?;
            assert_eq!(
                (tip.height, tip.hash),
                (1, Hash256::from(first.block_hash()))
            );
            let log = followers.block_log();
            let log = log.read();
            assert_eq!(log.len(), 2);
            assert_eq!(
                log.last()
                    .ok_or(TestError::Missing("committed follower"))?
                    .hash,
                first.block_hash()
            );
        }
        Ok(())
    }

    fn apply_handles(
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
    ) -> Chainstate {
        Chainstate::new(
            Network::Regtest,
            chain_tip,
            applied_tip,
            block_tree,
            Arc::new(UtxoSet::new()),
            Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
                bitcoin_rs_storage::utxo::stats::CoinStats::default(),
            )),
            Arc::new(bitcoin_rs_chain::events::ChainEventPublisher::detached(0)),
        )
    }

    const GENESIS_TIME: u32 = 1_296_688_602;

    fn mined_block_with_prev_hash(
        prev_blockhash: BlockHash,
        height: u32,
        txdata: Vec<Tx>,
    ) -> Block {
        use bitcoin_rs_consensus::primitives::CompactTarget;
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash,
                merkle_root: Hash256::default(),
                time: GENESIS_TIME.saturating_add(height),
                bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
                nonce: 0,
            },
            txs: txdata,
        };
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
        if let Err(error) = regtest_fixture::mine_block_to_declared_target(&mut block) {
            panic!("regtest target must be reachable: {error}");
        }
        block
    }

    type MaturedChain = (Chainstate, Vec<Block>, HashMap<Hash256, BlockImage>);

    fn matured_chain(depth: u32) -> Result<MaturedChain, crate::test_support::TestError> {
        use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let subsidy = 5_000_000_000_u64;
        let mut prev_hash = genesis.block_hash();
        let mut blocks: Vec<Block> = Vec::new();
        for height in 1..=depth {
            let mut coinbase = regtest_fixture::coinbase(height);
            if height == 1 {
                coinbase.outputs[0].value = Amount::from_sat(subsidy);
            }
            let mut txs = vec![coinbase];
            if height == depth {
                let first_txid = blocks[0].txs[0].txid();
                txs.push(Tx {
                    version: 2,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::new(first_txid, 0),
                        script_sig: Script::from_bytes(push_int(1)),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    outputs: vec![TxOut {
                        value: Amount::from_sat(subsidy - 100_000),
                        script_pubkey: Script::new(),
                    }],
                    lock_time: LockTime::ZERO,
                });
            }
            let block = mined_block_with_prev_hash(prev_hash, height, txs);
            parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
            prev_hash = block.block_hash();
            blocks.push(block);
        }
        let handles = apply_handles(
            tree.tip_handle(),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(tree)),
        );
        handles.apply_block(&BlockImage::from_local(genesis))?;
        for block in &blocks {
            handles.apply_block(&BlockImage::from_local(block.clone()))?;
        }
        let bodies = blocks
            .iter()
            .map(|block| {
                (
                    Hash256::from_le_bytes(block.block_hash().as_bytes()),
                    BlockImage::from_local(block.clone()),
                )
            })
            .collect();
        Ok((handles, blocks, bodies))
    }

    #[cfg(test)]
    mod staged_branch_switch {
        use super::*;
        use crate::test_support::TestError;

        #[test]
        fn branch_switch_uses_staged_bodies_without_durable_store()
        -> Result<(), crate::test_support::TestError> {
            use bitcoin_rs_consensus::primitives::Script;
            let (handles, main, mut bodies) = matured_chain(101)?;
            assert!(
                handles.block_body_store().is_none(),
                "fixture must not fall back to durable body storage"
            );
            let followers = crate::chain_effects::ChainFollowers::noop();
            let applied_tip = handles.applied_tip_reader();

            let fork_root_hash = main[99].block_hash();
            let mut fork_parent = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
                .ok_or(TestError::Missing("fork root node"))?;
            let mut fork_prev = fork_root_hash;
            let mut fork = Vec::new();
            for height in 101..=103_u32 {
                let mut coinbase = regtest_fixture::coinbase(height);
                coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
                let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
                fork_parent = crate::sync::fixture_insert_header_node(
                    &handles,
                    fork_parent,
                    block.header,
                    NodeStatus::HeaderValid,
                )?;
                fork_prev = block.block_hash();
                bodies.insert(
                    Hash256::from_le_bytes(block.block_hash().as_bytes()),
                    BlockImage::from_local(block.clone()),
                );
                fork.push(block);
            }
            let fork_tip = fork_parent;
            let main_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());

            let staged = &bodies;
            let mut retired = Vec::new();
            crate::reorg::switch_to_branch(
                &handles,
                &followers,
                fork_tip,
                |hash| staged.get(&hash).cloned(),
                |hash| retired.push(hash),
            )?;
            let tip = applied_tip
                .load_full()
                .ok_or(TestError::Missing("published branch-switch tip"))?;
            assert_eq!(
                tip.hash,
                Hash256::from_le_bytes(fork[2].block_hash().as_bytes()),
                "the switch must reach the fork tip using staged bodies alone"
            );
            assert_eq!(
                retired.len(),
                3,
                "every connected body retires once, in connect order"
            );

            let main_target = handles
                .block_tree()
                .read()
                .lookup(main_tip_hash)
                .ok_or(TestError::Missing("original branch tip"))?;
            crate::reorg::switch_to_branch(
                &handles,
                &followers,
                main_target,
                |hash| staged.get(&hash).cloned(),
                |hash| retired.push(hash),
            )?;
            let restored = applied_tip
                .load_full()
                .ok_or(TestError::Missing("published reverse-switch tip"))?;
            assert_eq!(
                restored.hash, main_tip_hash,
                "bounded staging must supply the reverse branch switch without durable storage"
            );
            assert_eq!(
                retired.len(),
                4,
                "the reconnected main body retires as well"
            );
            Ok(())
        }

        #[test]
        fn branch_switch_replans_after_a_competing_connect_before_transition()
        -> Result<(), crate::test_support::TestError> {
            use bitcoin_rs_consensus::primitives::Script;
            let (handles, main, mut bodies) = matured_chain(101)?;
            let followers = crate::chain_effects::ChainFollowers::noop();
            let applied_tip = handles.applied_tip_reader();

            let fork_root_hash = main[99].block_hash();
            let mut fork_parent = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
                .ok_or(TestError::Missing("fork root node"))?;
            let mut fork_prev = fork_root_hash;
            let mut fork = Vec::new();
            for height in 101..=103_u32 {
                let mut coinbase = regtest_fixture::coinbase(height);
                coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
                let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
                fork_parent = crate::sync::fixture_insert_header_node(
                    &handles,
                    fork_parent,
                    block.header,
                    NodeStatus::HeaderValid,
                )?;
                fork_prev = block.block_hash();
                bodies.insert(
                    Hash256::from_le_bytes(block.block_hash().as_bytes()),
                    BlockImage::from_local(block.clone()),
                );
                fork.push(block);
            }

            let main_tip_id = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(main[100].block_hash().as_bytes()))
                .ok_or(TestError::Missing("main branch tip"))?;
            let mut racing_coinbase = regtest_fixture::coinbase(102);
            racing_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
            let racing =
                mined_block_with_prev_hash(main[100].block_hash(), 102, vec![racing_coinbase]);
            crate::sync::fixture_insert_header_node(
                &handles,
                main_tip_id,
                racing.header,
                NodeStatus::HeaderValid,
            )?;
            bodies.insert(
                Hash256::from_le_bytes(racing.block_hash().as_bytes()),
                BlockImage::from_local(racing.clone()),
            );

            let (preloaded_tx, preloaded_rx) = std::sync::mpsc::sync_channel(0);
            let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
            std::thread::scope(|scope| -> Result<(), crate::test_support::TestError> {
                let handles = &handles;
                let bodies = &bodies;
                let worker = scope.spawn(move || {
                    let mut paused = false;
                    crate::reorg::switch_to_branch(
                        handles,
                        &followers,
                        fork_parent,
                        |hash| {
                            let body = bodies.get(&hash).cloned();
                            if !paused {
                                paused = true;
                                assert!(preloaded_tx.send(()).is_ok());
                                assert!(continue_rx.recv().is_ok());
                            }
                            body
                        },
                        |_| {},
                    )
                });
                preloaded_rx
                    .recv()
                    .map_err(|_| TestError::Timeout("branch switch pauses after preloading"))?;
                handles.apply_block(&BlockImage::from_local(racing))?;
                continue_tx
                    .send(())
                    .map_err(|_| TestError::ExpectationFailed("branch switch replans"))?;
                worker.join().map_err(|_| TestError::ThreadPanicked)??;
                Ok(())
            })?;

            let tip = applied_tip
                .load_full()
                .ok_or(TestError::Missing("published branch-switch tip"))?;
            assert_eq!(
                tip.hash,
                Hash256::from_le_bytes(fork[2].block_hash().as_bytes()),
                "the locked replan must absorb the competing connect and still reach the target"
            );
            Ok(())
        }
    }

    #[cfg(test)]
    mod reorg_invalidation {
        use super::*;
        use crate::test_support::TestError;

        use bitcoin_rs_storage::StorageError;
        use bitcoin_rs_storage::block_body::BlockBodyStore;
        use bitcoin_rs_storage::memory_kv::MemoryKvStore;
        use bitcoin_rs_storage::{
            CoinStore, CommitAuthority, KvDurableHeadStore, KvStore, KvUndoStore,
        };
        use parking_lot::Mutex;

        #[derive(Default)]
        struct Bodies {
            bodies: Mutex<HashMap<(u32, Hash256), Vec<u8>>>,
        }

        impl BlockBodyStore for Bodies {
            fn persist_block_body(
                &self,
                height: u32,
                hash: Hash256,
                body: &[u8],
            ) -> Result<(), StorageError> {
                self.bodies.lock().insert((height, hash), body.to_vec());
                Ok(())
            }

            fn load_block_body(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                Ok(self.bodies.lock().get(&(height, hash)).cloned())
            }

            fn sync(&self) -> Result<(), StorageError> {
                Ok(())
            }
        }

        type MaturedBodyStore = (
            Chainstate,
            Vec<Block>,
            HashMap<Hash256, BlockImage>,
            Arc<Bodies>,
        );

        fn matured_chain_with_body_store()
        -> Result<MaturedBodyStore, crate::test_support::TestError> {
            let (_, main, _) = matured_chain(101)?;
            let genesis = Network::Regtest.genesis_block();
            let mut tree = BlockTree::new();
            let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
            for block in &main {
                parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
            }
            let bodies_store = Arc::new(Bodies::default());
            let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
            let mem_store = Arc::new(MemoryKvStore::default());
            let durable_head = Arc::new(KvDurableHeadStore::new(Arc::clone(&mem_store)));
            let undo_store = Arc::new(KvUndoStore::new(Arc::clone(&mem_store)));
            let dyn_store: Arc<dyn KvStore> = mem_store;
            let coins = Arc::new(CoinStore::open(Arc::clone(&dyn_store), 64 * 1024 * 1024));
            let commit_authority = Arc::new(CommitAuthority::new(dyn_store, Arc::clone(&coins)));
            let handles =
                bitcoin_rs_chain::Chainstate::from_parts(bitcoin_rs_chain::ChainstateParts {
                    network: Network::Regtest,
                    block_tree: tree,
                    restored_applied_tip: None,
                    utxo: Arc::new(UtxoSet::new()),
                    coin_stats: Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
                        bitcoin_rs_storage::utxo::stats::CoinStats::default(),
                    )),
                    chain_events: Arc::new(
                        bitcoin_rs_chain::events::ChainEventPublisher::detached(0),
                    ),
                    block_body_store: Some(bodies_store.clone()),
                    undo_store,
                    durable_head,
                    coins,
                    commit_authority,
                    chain_transition: bitcoin_rs_chain::chain::TransitionDomain::new().authority(),
                    assume_valid_height: 0,
                    validation_mode: bitcoin_rs_chain::ValidationMode::AssumeValid,
                    validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
                    script_cache: None,
                    capture_rawtx: false,
                    capture_block_bytes: true,
                    retention: bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention)),
                    window_limits: bitcoin_rs_chain::default_window_limits_source(),
                    history: bitcoin_rs_storage::pruning::HistoryAccess::new(
                        retention,
                        bitcoin_rs_storage::pruning::RetentionBudget::from_blocks(288),
                    ),
                    role: bitcoin_rs_chain::ChainstateRole::Ordinary,
                });
            handles.apply_block(&BlockImage::from_local(genesis))?;
            for block in &main {
                handles.apply_block(&BlockImage::from_local(block.clone()))?;
            }
            let bodies = main
                .iter()
                .map(|block| {
                    (
                        Hash256::from_le_bytes(block.block_hash().as_bytes()),
                        BlockImage::from_local(block.clone()),
                    )
                })
                .collect();
            Ok((handles, main, bodies, bodies_store))
        }

        #[test]
        fn branch_switch_retires_only_the_connected_prefix_after_connect_failure()
        -> Result<(), crate::test_support::TestError> {
            use bitcoin_rs_consensus::primitives::{Amount, Script};
            let (handles, main, mut bodies) = matured_chain(101)?;
            let handles = Arc::new(handles);
            let followers = crate::chain_effects::ChainFollowers::noop();
            let adapter = super::super::NodeSyncChain {
                block_tree: handles.block_tree_reader(),
                handles: Arc::clone(&handles),
                followers,
                assumeutxo: None,
                budget: super::sync_unit_test_budget(),
            };
            let applied_tip = handles.applied_tip_reader();
            let main_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());

            let fork_root_hash = main[99].block_hash();
            let mut fork_parent = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
                .ok_or(TestError::Missing("fork root node"))?;
            let mut fork_prev = fork_root_hash;
            let mut fork = Vec::new();
            for height in 101..=102_u32 {
                let mut coinbase = regtest_fixture::coinbase(height);
                coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
                let mut block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
                fork_parent = crate::sync::fixture_insert_header_node(
                    &handles,
                    fork_parent,
                    block.header,
                    NodeStatus::HeaderValid,
                )?;
                fork_prev = block.block_hash();
                if height == 102 {
                    block.txs[0].outputs[0].value = Amount::from_sat(2);
                }
                bodies.insert(
                    Hash256::from_le_bytes(block.block_hash().as_bytes()),
                    BlockImage::from_local(block.clone()),
                );
                fork.push(block);
            }

            let mut retired = Vec::new();
            let outcome = adapter.switch_to_branch(
                fork_parent,
                &mut |hash| bodies.get(&hash).cloned(),
                &mut |hash| retired.push(hash),
            );
            assert!(
                matches!(
                    outcome,
                    Err(crate::reorg::ReorgError::ConnectFailed {
                        stopped_at: 101,
                        connected: 1,
                        ref disposition,
                        ref invalidated,
                        ..
                    }) if *disposition == bitcoin_rs_chain::WindowApplyDisposition::BodyMutated
                        && invalidated.is_empty()
                ),
                "the mutated second body must fail as BodyMutated after one committed connect, \
         got {outcome:?}"
            );

            let tip = applied_tip
                .load_full()
                .ok_or(TestError::Missing("published partial-switch tip"))?;
            assert_eq!(
                tip.hash,
                Hash256::from_le_bytes(fork[0].block_hash().as_bytes()),
                "the valid prefix must remain committed"
            );
            let first = Hash256::from_le_bytes(fork[0].block_hash().as_bytes());
            let failed = Hash256::from_le_bytes(fork[1].block_hash().as_bytes());
            assert_eq!(
                retired,
                vec![first],
                "only the connected prefix body retires"
            );
            assert!(
                bodies.contains_key(&failed) && bodies.contains_key(&main_tip_hash),
                "the failed and disconnected bodies stay staged for a later switch"
            );
            assert_ne!(
                handles
                    .block_tree()
                    .read()
                    .node_by_hash(failed)
                    .map(|node| node.status),
                Some(NodeStatus::Invalid),
                "a mutated body must not invalidate the header subtree"
            );
            Ok(())
        }

        #[test]
        fn permanent_reorg_failure_invalidates_descendants()
        -> Result<(), crate::test_support::TestError> {
            let (handles, main, mut bodies) = matured_chain(101)?;
            let handles = Arc::new(handles);
            let followers = crate::chain_effects::ChainFollowers::noop();
            let adapter = super::super::NodeSyncChain {
                block_tree: handles.block_tree_reader(),
                handles: Arc::clone(&handles),
                followers,
                assumeutxo: None,
                budget: super::sync_unit_test_budget(),
            };
            let applied_tip = handles.applied_tip_reader();

            let main_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());
            let main_coin = OutPoint::new(main[100].txs[1].txid(), 0);
            let main_coin_before = handles.utxo_reader().get_entry(&main_coin)?;
            let utxo_len_before = handles.utxo().len();
            assert!(main_coin_before.is_some(), "main-tip spend must be live");
            let fork_root_hash = main[99].block_hash();
            let fork_root_id = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
                .ok_or(TestError::Missing("fork root node"))?;
            let invalid = mined_block_with_prev_hash(fork_root_hash, 101, Vec::new());
            let invalid_id = crate::sync::fixture_insert_header_node(
                &handles,
                fork_root_id,
                invalid.header,
                NodeStatus::HeaderValid,
            )?;
            let descendant = mined_block_with_prev_hash(
                invalid.block_hash(),
                102,
                vec![regtest_fixture::coinbase(102)],
            );
            let descendant_id = crate::sync::fixture_insert_header_node(
                &handles,
                invalid_id,
                descendant.header,
                NodeStatus::HeaderValid,
            )?;
            for block in [&invalid, &descendant] {
                let staged = (*block).clone();
                bodies.insert(
                    Hash256::from_le_bytes(staged.block_hash().as_bytes()),
                    BlockImage::from_local(staged),
                );
            }

            let outcome = adapter.switch_to_branch(
                descendant_id,
                &mut |hash| bodies.get(&hash).cloned(),
                &mut |_| {},
            );
            assert!(
                matches!(
                    &outcome,
                    Err(crate::reorg::ReorgError::ConnectFailed {
                        disposition: bitcoin_rs_chain::WindowApplyDisposition::Permanent,
                        invalidated,
                        ..
                    }) if invalidated.len() == 2
                ),
                "an empty-block connect must fail Permanent and report the invalidated subtree, \
         got {outcome:?}"
            );

            {
                let tree = handles.block_tree().read();
                assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
                assert_eq!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
                assert_eq!(
                    tree.tip().map(|tip| tip.hash),
                    Some(main_tip_hash),
                    "the valid main branch must win after subtree invalidation"
                );
            }
            assert_eq!(
                applied_tip.load_full().map(|tip| tip.hash),
                Some(main_tip_hash)
            );
            assert_eq!(handles.utxo().len(), utxo_len_before);
            assert_eq!(
                handles.utxo_reader().get_entry(&main_coin)?,
                main_coin_before
            );
            Ok(())
        }

        #[test]
        fn invalid_first_reorg_body_closes_if_old_body_disappears_during_restoration()
        -> Result<(), crate::test_support::TestError> {
            let (handles, main, mut bodies) = matured_chain(101)?;
            let handles = Arc::new(handles);
            let adapter = super::super::NodeSyncChain {
                block_tree: handles.block_tree_reader(),
                handles: Arc::clone(&handles),
                followers: crate::chain_effects::ChainFollowers::noop(),
                assumeutxo: None,
                budget: super::sync_unit_test_budget(),
            };
            let old_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());
            let fork_root_hash = main[99].block_hash();
            let fork_root_id = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
                .ok_or(TestError::Missing("fork root node"))?;
            let invalid = mined_block_with_prev_hash(fork_root_hash, 101, Vec::new());
            let invalid_id = crate::sync::fixture_insert_header_node(
                &handles,
                fork_root_id,
                invalid.header,
                NodeStatus::HeaderValid,
            )?;
            bodies.insert(
                Hash256::from_le_bytes(invalid.block_hash().as_bytes()),
                BlockImage::from_local(invalid),
            );

            let mut old_body_reads = 0;
            let outcome = adapter.switch_to_branch(
                invalid_id,
                &mut |hash| {
                    if hash == old_tip_hash {
                        old_body_reads += 1;
                        if old_body_reads == 3 {
                            return None;
                        }
                    }
                    bodies.get(&hash).cloned()
                },
                &mut |_| {},
            );
            let Err(crate::reorg::ReorgError::RestorationFailed { source, original }) = outcome
            else {
                panic!("restoration body loss must require recovery, got {outcome:?}");
            };
            assert!(matches!(
                *source,
                crate::reorg::ReorgError::MissingBody { hash, height: 101 }
                    if hash == old_tip_hash
            ));
            assert!(matches!(
                *original,
                crate::reorg::ReorgError::ConnectFailed {
                    disposition: bitcoin_rs_chain::WindowApplyDisposition::Permanent,
                    ..
                }
            ));
            assert_eq!(old_body_reads, 3);
            assert!(handles.is_closed_for_recovery());
            Ok(())
        }

        #[test]
        fn branch_switch_rejects_a_body_for_another_header_before_mutation()
        -> Result<(), crate::test_support::TestError> {
            use bitcoin_rs_consensus::primitives::Script;
            let (handles, main, mut bodies) = matured_chain(101)?;
            let followers = crate::chain_effects::ChainFollowers::noop();
            let applied_tip = handles.applied_tip_reader();
            let applied_before = applied_tip
                .load_full()
                .ok_or(TestError::Missing("applied tip"))?;
            let utxo_len_before = handles.utxo().len();

            let fork_root_hash = main[99].block_hash();
            let fork_root_id = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
                .ok_or(TestError::Missing("fork root node"))?;
            let mut target_coinbase = regtest_fixture::coinbase(101);
            target_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
            let target = mined_block_with_prev_hash(fork_root_hash, 101, vec![target_coinbase]);
            let target_id = crate::sync::fixture_insert_header_node(
                &handles,
                fork_root_id,
                target.header,
                NodeStatus::HeaderValid,
            )?;
            let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
            let mut wrong_coinbase = regtest_fixture::coinbase(101);
            wrong_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
            let wrong = mined_block_with_prev_hash(fork_root_hash, 101, vec![wrong_coinbase]);
            bodies.insert(target_hash, BlockImage::from_local(wrong));

            let outcome = crate::reorg::switch_to_branch(
                &handles,
                &followers,
                target_id,
                |hash| bodies.get(&hash).cloned(),
                |_| {},
            );
            assert!(
                matches!(
                    outcome,
                    Err(crate::reorg::ReorgError::BodyHashMismatch { height: 101, .. })
                ),
                "a body keyed for another header must refuse before mutation, got {outcome:?}"
            );
            assert_eq!(
                applied_tip.load_full().map(|tip| tip.hash),
                Some(applied_before.hash),
                "a pre-mutation refusal must leave the applied tip untouched"
            );
            assert_eq!(
                handles.utxo().len(),
                utxo_len_before,
                "a pre-mutation refusal must leave the UTXO set untouched"
            );
            Ok(())
        }

        #[test]
        fn branch_switch_rejects_malformed_body_before_mutation()
        -> Result<(), crate::test_support::TestError> {
            use bitcoin_rs_consensus::primitives::Script;
            let (handles, main, bodies, bodies_store) = matured_chain_with_body_store()?;
            let followers = crate::chain_effects::ChainFollowers::noop();
            let applied_tip = handles.applied_tip_reader();
            let applied_before = applied_tip
                .load_full()
                .ok_or(TestError::Missing("applied tip"))?;
            let utxo_len_before = handles.utxo().len();

            let fork_root_hash = main[99].block_hash();
            let fork_root_id = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
                .ok_or(TestError::Missing("fork root node"))?;
            let mut target_coinbase = regtest_fixture::coinbase(101);
            target_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
            let target = mined_block_with_prev_hash(fork_root_hash, 101, vec![target_coinbase]);
            let target_id = crate::sync::fixture_insert_header_node(
                &handles,
                fork_root_id,
                target.header,
                NodeStatus::HeaderValid,
            )?;
            let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
            let mut malformed = BlockImage::from_local(target).bytes().clone();
            malformed.truncate(malformed.len() - 1);
            bodies_store
                .persist_block_body(101, target_hash, &malformed)
                .map_err(|_| TestError::ExpectationFailed("malformed fixture persists"))?;

            let outcome = crate::reorg::switch_to_branch(
                &handles,
                &followers,
                target_id,
                |hash| {
                    if hash == target_hash {
                        return None;
                    }
                    bodies.get(&hash).cloned()
                },
                |_| {},
            );
            assert!(
                matches!(
                    outcome,
                    Err(crate::reorg::ReorgError::BodyDecode { height: 101, .. })
                ),
                "malformed body bytes must refuse before mutation, got {outcome:?}"
            );
            assert_eq!(
                applied_tip.load_full().map(|tip| tip.hash),
                Some(applied_before.hash),
                "a pre-mutation refusal must leave the applied tip untouched"
            );
            assert_eq!(
                handles.utxo().len(),
                utxo_len_before,
                "a pre-mutation refusal must leave the UTXO set untouched"
            );
            Ok(())
        }
    }

    #[cfg(test)]
    mod branch_connect_mempool {
        use super::*;
        use crate::test_support::TestError;
        use bitcoin_rs_consensus::ValidationEngine;

        #[test]
        fn mutated_connect_body_through_switch_to_branch_preserves_subtree()
        -> Result<(), crate::test_support::TestError> {
            use bitcoin_rs_consensus::primitives::{Amount, Script};
            let (handles, main, mut bodies) = matured_chain(101)?;
            let fork_root_hash = main[49].block_hash();
            let mut fork_parent = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
                .ok_or(TestError::Missing("fork root node"))?;
            let mut fork_prev = fork_root_hash;
            let mut fork_blocks = Vec::new();
            for height in 51..=52_u32 {
                let mut coinbase = regtest_fixture::coinbase(height);
                coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
                let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
                fork_parent = crate::sync::fixture_insert_header_node(
                    &handles,
                    fork_parent,
                    block.header,
                    NodeStatus::HeaderValid,
                )?;
                fork_prev = block.block_hash();
                fork_blocks.push(block);
            }
            let fork_target = fork_parent;
            let invalid_id = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(
                    fork_blocks[0].block_hash().as_bytes(),
                ))
                .ok_or(TestError::Missing("invalid fork node"))?;
            let descendant_id = handles
                .block_tree()
                .read()
                .lookup(Hash256::from_le_bytes(
                    fork_blocks[1].block_hash().as_bytes(),
                ))
                .ok_or(TestError::Missing("descendant fork node"))?;

            let mut corrupt = fork_blocks[0].clone();
            corrupt.txs[0].outputs[0].value = Amount::from_sat(2);
            fork_blocks[0] = corrupt;
            for block in &fork_blocks {
                bodies.insert(
                    Hash256::from_le_bytes(block.block_hash().as_bytes()),
                    BlockImage::from_local(block.clone()),
                );
            }

            let outcome = crate::reorg::switch_to_branch(
                &handles,
                &crate::chain_effects::ChainFollowers::noop(),
                fork_target,
                |hash| bodies.get(&hash).cloned(),
                |_| {},
            );

            let Err(crate::reorg::ReorgError::ConnectFailed {
                disconnected,
                connected,
                disposition,
                invalidated,
                ..
            }) = outcome
            else {
                panic!("mutated connect body must return ConnectFailed");
            };
            assert_eq!(
                disconnected, 51,
                "the full disconnect prefix must be reported"
            );
            assert_eq!(connected, 0, "nothing connected before the body mutation");
            assert_eq!(
                disposition,
                bitcoin_rs_chain::WindowApplyDisposition::BodyMutated
            );
            assert!(
                invalidated.is_empty(),
                "body mutation cannot poison headers"
            );
            {
                let tree = handles.block_tree().read();
                assert_eq!(tree.node(invalid_id)?.status, NodeStatus::HeaderValid);
                assert_eq!(tree.node(descendant_id)?.status, NodeStatus::HeaderValid);
            }
            let fork_root_id_hash = Hash256::from_le_bytes(fork_root_hash.as_bytes());
            assert_eq!(
                handles.applied_tip().load_full().map(|tip| tip.hash),
                Some(fork_root_id_hash),
                "the applied tip must be the fork root after disconnecting back to it"
            );
            Ok(())
        }

        #[test]
        fn disconnect_readmits_the_package_in_order_and_drops_the_nonfinal_member()
        -> Result<(), crate::test_support::TestError> {
            use bitcoin::hashes::{Hash as _, hash160};
            use bitcoin_rs_consensus::primitives::{
                Amount, LockTime, Script, Sequence, TxIn, TxOut, Witness,
            };
            use bitcoin_rs_mempool::{
                AdmissionOrigin, BodyInterest, Mempool, MempoolGateway, MempoolLimits,
                MempoolObserver, MutationEnvelope,
            };
            use bitcoin_rs_storage::StorageError;
            use bitcoin_rs_storage::block_body::BlockBodyStore;
            use parking_lot::Mutex;

            #[derive(Default)]
            struct Stream(Mutex<Vec<(Txid, bitcoin_rs_mempool::MutationOutcome, AdmissionOrigin)>>);

            impl MempoolObserver for Stream {
                fn on_mutation(&self, envelope: &MutationEnvelope) {
                    let mut seen = self.0.lock();
                    for change in &envelope.result.changes {
                        seen.push((Txid::from(change.txid), change.outcome, envelope.origin));
                    }
                }
            }

            #[derive(Default)]
            struct Bodies {
                bodies: Mutex<HashMap<(u32, Hash256), Vec<u8>>>,
            }

            impl BlockBodyStore for Bodies {
                fn persist_block_body(
                    &self,
                    height: u32,
                    hash: Hash256,
                    body: &[u8],
                ) -> Result<(), StorageError> {
                    self.bodies.lock().insert((height, hash), body.to_vec());
                    Ok(())
                }

                fn load_block_body(
                    &self,
                    height: u32,
                    hash: Hash256,
                ) -> Result<Option<Vec<u8>>, StorageError> {
                    Ok(self.bodies.lock().get(&(height, hash)).cloned())
                }

                fn sync(&self) -> Result<(), StorageError> {
                    Ok(())
                }
            }

            let stream = Arc::new(Stream::default());
            let gateway = Arc::new(MempoolGateway::new(
                Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                Some((stream.clone(), BodyInterest::Metadata)),
                ValidationEngine::Native,
                None,
            ));
            let followers = crate::chain_effects::ChainFollowers::new(
                Arc::new(RwLock::new(bitcoin_rs_index::block_log::BlockLog::new())),
                Arc::new(crate::NoOpZmqPublisher),
                None,
                None,
                Arc::new(crate::mining::MiningGenerationSignal::new()),
                Some(Arc::clone(&gateway)),
            );

            let redeem: Vec<u8> = vec![0x51];
            let p2sh = Script::from_bytes(
                [
                    vec![0xa9, 0x14],
                    hash160::Hash::hash(&redeem).to_byte_array().to_vec(),
                    vec![0x87],
                ]
                .concat(),
            );
            let redeem_sig = Script::from_bytes(bitcoin_rs_consensus::script::push_data(&redeem));

            let genesis = Network::Regtest.genesis_block();
            let mut tree = BlockTree::new();
            let mut parent_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
            let mut prev_hash = genesis.block_hash();
            let mut blocks: Vec<Block> = Vec::new();
            let subsidy = 5_000_000_000_u64;
            let mut parent_tx: Option<Tx> = None;
            for height in 1..=101_u32 {
                let mut coinbase = regtest_fixture::coinbase(height);
                if height == 1 {
                    coinbase.outputs[0].value = Amount::from_sat(subsidy);
                    coinbase.outputs[0].script_pubkey = p2sh.clone();
                }
                let mut txs = vec![coinbase];
                if height == 101 {
                    let first_txid = blocks[0].txs[0].txid();
                    let parent = Tx {
                        version: 2,
                        inputs: vec![TxIn {
                            previous_output: OutPoint::new(first_txid, 0),
                            script_sig: redeem_sig.clone(),
                            sequence: Sequence::MAX,
                            witness: Witness::new(),
                        }],
                        outputs: vec![
                            TxOut {
                                value: Amount::from_sat(2_000_000_000),
                                script_pubkey: p2sh.clone(),
                            },
                            TxOut {
                                value: Amount::from_sat(2_900_000_000),
                                script_pubkey: p2sh.clone(),
                            },
                        ],
                        lock_time: LockTime::ZERO,
                    };
                    let child = Tx {
                        version: 2,
                        inputs: vec![TxIn {
                            previous_output: OutPoint::new(parent.txid(), 0),
                            script_sig: redeem_sig.clone(),
                            sequence: Sequence::MAX,
                            witness: Witness::new(),
                        }],
                        outputs: vec![TxOut {
                            value: Amount::from_sat(1_900_000_000),
                            script_pubkey: p2sh.clone(),
                        }],
                        lock_time: LockTime::ZERO,
                    };
                    txs.push(parent.clone());
                    txs.push(child);
                    parent_tx = Some(parent.clone());
                }
                let block = mined_block_with_prev_hash(prev_hash, height, txs);
                parent_id =
                    tree.insert_node(Some(parent_id), block.header, NodeStatus::HeaderValid)?;
                prev_hash = block.block_hash();
                blocks.push(block);
            }
            let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
            let mem_store = Arc::new(bitcoin_rs_storage::memory_kv::MemoryKvStore::default());
            let durable_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
                &mem_store,
            )));
            let undo_store = Arc::new(bitcoin_rs_storage::KvUndoStore::new(Arc::clone(&mem_store)));
            let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = mem_store;
            let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
                Arc::clone(&dyn_store),
                64 * 1024 * 1024,
            ));
            let commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
                dyn_store,
                Arc::clone(&coins),
            ));
            let handles =
                bitcoin_rs_chain::Chainstate::from_parts(bitcoin_rs_chain::ChainstateParts {
                    network: Network::Regtest,
                    block_tree: tree,
                    restored_applied_tip: None,
                    utxo: Arc::new(UtxoSet::new()),
                    coin_stats: Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
                        bitcoin_rs_storage::utxo::stats::CoinStats::default(),
                    )),
                    chain_events: Arc::new(
                        bitcoin_rs_chain::events::ChainEventPublisher::detached(0),
                    ),
                    block_body_store: Some(Arc::new(Bodies::default())),
                    undo_store,
                    durable_head,
                    coins,
                    commit_authority,
                    chain_transition: bitcoin_rs_chain::chain::TransitionDomain::new().authority(),
                    assume_valid_height: 0,
                    validation_mode: bitcoin_rs_chain::ValidationMode::AssumeValid,
                    validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
                    script_cache: None,
                    capture_rawtx: false,
                    capture_block_bytes: true,
                    retention: bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention)),
                    window_limits: bitcoin_rs_chain::default_window_limits_source(),
                    history: bitcoin_rs_storage::pruning::HistoryAccess::new(
                        retention,
                        bitcoin_rs_storage::pruning::RetentionBudget::from_blocks(288),
                    ),
                    role: bitcoin_rs_chain::ChainstateRole::Ordinary,
                });
            handles.apply_block(&BlockImage::from_local(genesis))?;
            for block in &blocks {
                handles.apply_block(&BlockImage::from_local(block.clone()))?;
            }

            let parent = parent_tx.ok_or(TestError::Missing("built package transaction"))?;
            let tip = &blocks[100];
            let child_txid = tip.txs[2].txid();

            let nonfinal = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent.txid(), 1),
                    script_sig: redeem_sig,
                    sequence: Sequence::from_consensus(0xffff_fffe),
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(2_800_000_000),
                    script_pubkey: p2sh,
                }],
                lock_time: LockTime::from_consensus(GENESIS_TIME + 95),
            };
            let nonfinal_txid = nonfinal.txid();
            let view = bitcoin_rs_wire::context::ChainAdmissionView::new(
                handles.utxo_reader(),
                handles.applied_tip_reader(),
                handles.block_tree_reader(),
                handles.network(),
            );
            let submitted = gateway.submit_transaction(
                Arc::new(nonfinal),
                bitcoin_rs_mempool::AdmissionOrigin::Rpc,
                None,
                bitcoin_rs_consensus::primitives::unix_time_secs(),
                &view,
            );
            assert!(
                submitted.is_ok(),
                "the resident fixture must be admitted before the disconnect, got {submitted:?}"
            );
            assert!(gateway.read().contains_txid(&nonfinal_txid));

            let invalidation = crate::reorg::invalidate_block(
                &handles,
                &followers,
                Hash256::from_le_bytes(tip.block_hash().as_bytes()),
            )
            .map_err(TestError::from)?;
            assert_eq!(
                *invalidation
                    .invalid
                    .first()
                    .ok_or(TestError::Missing("invalidated block"))?,
                Hash256::from_le_bytes(tip.block_hash().as_bytes())
            );
            assert_eq!(
                invalidation.demoted_tip, None,
                "an invalidated old tip is Invalid, never a stale-tip candidate"
            );
            assert_eq!(
                handles.applied_tip().load_full().map(|tip| tip.height),
                Some(100)
            );

            let pool = gateway.read();
            assert!(pool.contains_txid(&parent.txid()));
            assert!(pool.contains_txid(&child_txid));
            assert!(
                !pool.contains_txid(&nonfinal_txid),
                "the resident entry made nonfinal by the lower tip must be swept"
            );
            drop(pool);
            let seen = stream.0.lock().clone();
            let reorg: Vec<(Txid, bitcoin_rs_mempool::MutationOutcome)> = seen
                .iter()
                .filter(|(_, _, origin)| *origin == AdmissionOrigin::Reorg)
                .map(|(txid, outcome, _)| (*txid, *outcome))
                .collect();
            assert_eq!(
                reorg,
                vec![
                    (parent.txid(), bitcoin_rs_mempool::MutationOutcome::Accepted),
                    (child_txid, bitcoin_rs_mempool::MutationOutcome::Accepted),
                    (
                        nonfinal_txid,
                        bitcoin_rs_mempool::MutationOutcome::Removed(
                            bitcoin_rs_mempool::RemovalReason::Reorg,
                        ),
                    ),
                ],
                "one ordered stream: dependency-ordered re-admission, then the sweep"
            );
            Ok(())
        }

        #[test]
        fn admit_headers_reports_the_tip_a_heavier_fork_displaced()
        -> Result<(), crate::test_support::TestError> {
            use crate::p2p::sync::chain::HeaderAdmission;
            let genesis = Network::Regtest.genesis_block();
            let mut tree = BlockTree::new();
            tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
            let handles = Arc::new(apply_handles(
                tree.tip_handle(),
                Arc::new(ArcSwapOption::empty()),
                Arc::new(RwLock::new(tree)),
            ));
            let adapter = super::super::NodeSyncChain {
                block_tree: handles.block_tree_reader(),
                handles: Arc::clone(&handles),
                followers: crate::chain_effects::ChainFollowers::noop(),
                assumeutxo: None,
                budget: super::sync_unit_test_budget(),
            };
            let headers = |heights: std::ops::RangeInclusive<u32>| -> Vec<Header> {
                let mut prev = genesis.block_hash();
                heights
                    .map(|height| {
                        let header = regtest_fixture::mined_regtest_header(prev, height)
                            .unwrap_or_else(|error| panic!("regtest header must mine: {error}"));
                        prev = header.compute_hash();
                        header
                    })
                    .collect()
            };
            let main = headers(1..=2);
            let fork = headers(11..=13);
            let demoted = |batch: &[Header]| match adapter.admit_headers(batch) {
                HeaderAdmission::Accepted { demoted_tip, .. } => demoted_tip,
                HeaderAdmission::Rejected(_) | HeaderAdmission::Refused(_) => {
                    panic!("fixture headers must be accepted")
                }
            };

            assert_eq!(demoted(&main), None, "a linear extension displaces no tip");
            assert_eq!(
                demoted(&fork),
                Some(Hash256::from(main[1].compute_hash())),
                "the heavier fork displaces the tip it overtook"
            );
            Ok(())
        }
    }

    #[cfg(test)]
    mod fatal_halt {
        #![allow(clippy::expect_used)]

        use std::sync::Arc;
        use std::time::Duration;

        use bitcoin_rs_chain::chain::{BlockTree, NodeStatus, regtest_fixture};
        use bitcoin_rs_consensus::primitives::{Block, BlockImage, Network};
        use bitcoin_rs_storage::memory_kv::MemoryKvStore;
        use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget};
        use bitcoin_rs_storage::utxo::UtxoSet;
        use bitcoin_rs_storage::{
            CoinStore, CommitAuthority, KvDurableHeadStore, KvStore, KvUndoStore,
            MandatoryRetention, PersistFault, RetentionRegistry,
        };
        use crossbeam_channel::{bounded, unbounded};

        use crate::event_loop::EventLoop;
        use crate::test_support::TestError;

        fn failing_commit_chain(
            depth: u32,
        ) -> Result<(Arc<bitcoin_rs_chain::Chainstate>, Vec<Block>), TestError> {
            use bitcoin_rs_chain::{Chainstate, ChainstateParts, ChainstateRole, ValidationMode};

            let genesis = Network::Regtest.genesis_block();
            let mut tree = BlockTree::new();
            let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
            let mut blocks = Vec::new();
            let mut prev_hash = genesis.block_hash();
            for height in 1..=depth {
                let block = regtest_fixture::mined_block_with_prev_hash(
                    prev_hash,
                    height,
                    vec![regtest_fixture::coinbase(height)],
                )?;
                prev_hash = block.block_hash();
                parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
                blocks.push(block);
            }
            let retention = Arc::new(RetentionRegistry::new());
            let mem_store = Arc::new(MemoryKvStore::default());
            let durable_head = Arc::new(KvDurableHeadStore::new(Arc::clone(&mem_store)));
            let undo_store = Arc::new(KvUndoStore::new(Arc::clone(&mem_store)));
            let dyn_store: Arc<dyn KvStore> = mem_store.clone();
            let coins = Arc::new(CoinStore::open(Arc::clone(&dyn_store), 64 * 1024 * 1024));
            let commit_authority = Arc::new(CommitAuthority::new(dyn_store, Arc::clone(&coins)));
            let handles = Arc::new(Chainstate::from_parts(ChainstateParts {
                network: Network::Regtest,
                block_tree: tree,
                restored_applied_tip: None,
                utxo: Arc::new(UtxoSet::new()),
                coin_stats: Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
                    bitcoin_rs_storage::utxo::stats::CoinStats::default(),
                )),
                chain_events: Arc::new(bitcoin_rs_chain::events::ChainEventPublisher::detached(0)),
                block_body_store: None,
                undo_store,
                durable_head,
                coins,
                commit_authority,
                chain_transition: bitcoin_rs_chain::chain::TransitionDomain::new().authority(),
                assume_valid_height: 0,
                validation_mode: ValidationMode::AssumeValid,
                validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
                script_cache: None,
                capture_rawtx: false,
                capture_block_bytes: false,
                retention: MandatoryRetention::new(Arc::clone(&retention)),
                window_limits: bitcoin_rs_chain::default_window_limits_source(),
                history: HistoryAccess::new(retention, RetentionBudget::from_blocks(288)),
                role: ChainstateRole::Ordinary,
            }));
            handles
                .apply_block(&BlockImage::from_local(genesis))
                .map_err(|error| TestError::Apply(Box::new(error)))?;
            mem_store.arm_persist_fault(PersistFault::FailApply);
            Ok((handles, blocks))
        }

        // SYNC-04, SYNC-06
        #[test]
        fn failed_durable_commit_halts_apply_and_trips_the_shutdown_latch() -> Result<(), TestError>
        {
            let (handles, blocks) = failing_commit_chain(2)?;
            let followers = crate::chain_effects::ChainFollowers::noop();
            let peers = Arc::new(bitcoin_rs_p2p::PeerTable::new());
            let (_inbound_headers_tx, inbound_headers_rx) = unbounded();
            let (inbound_blocks_tx, inbound_blocks_rx) = unbounded();
            let ibd = Arc::new(bitcoin_rs_chain::chain::InitialBlockDownload::new(
                handles.applied_tip_reader(),
                handles.block_tree_reader(),
            ));
            let sync = Arc::new(crate::sync::block_sync(crate::sync::BlockSyncInputs {
                handles: Arc::clone(&handles),
                followers,
                peer_table: peers,
                inbound_headers_rx,
                inbound_blocks_rx,
                ibd,
                assumeutxo: None,
                budget: super::sync_unit_test_budget(),
            }));

            inbound_blocks_tx
                .send(bitcoin_rs_p2p::InboundBlock::from_local(blocks[0].clone()))
                .map_err(|_| TestError::Missing("inbound block channel closed"))?;
            sync.tick();
            assert!(
                handles.is_closed_for_recovery(),
                "a failed durable commit must settle fatal and close the chainstate for recovery"
            );
            assert_eq!(
                handles.applied_tip_snapshot().map(|tip| tip.height),
                Some(0),
                "failed undo persistence must not publish a tip"
            );

            for block in [&blocks[1], &blocks[0]] {
                inbound_blocks_tx
                    .send(bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
                    .map_err(|_| TestError::Missing("inbound block channel closed"))?;
            }
            sync.tick();
            assert!(
                handles.is_closed_for_recovery(),
                "the recovery closure must stay raised; a closed chainstate never retries apply"
            );
            assert_eq!(
                handles.applied_tip_snapshot().map(|tip| tip.height),
                Some(0),
                "a halted sync must not commit the redelivered blocks"
            );

            let latch = Arc::new(bitcoin_rs_consensus::latch::LatchWriter::new());
            let verify_reader = latch.reader();
            let loop_reader = latch.reader();
            let shutdown_for_request = Arc::clone(&latch);
            let shutdown_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let requests_for_closure = Arc::clone(&shutdown_requests);
            let (wake_tx, wake_rx) = bounded::<()>(1);
            let (requested_tx, requested_rx) = bounded::<()>(1);
            let loop_handle = EventLoop::with_sync_wake(Arc::clone(&sync), wake_rx);
            let spinner = std::thread::Builder::new()
                .name("fatal-halt-spinner".into())
                .spawn(move || {
                    loop_handle.spin(&loop_reader, move || {
                        requests_for_closure.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        shutdown_for_request.trigger();
                        let _ = requested_tx.try_send(());
                    });
                })?;
            wake_tx
                .send(())
                .map_err(|_| TestError::Missing("event loop stopped before the wake"))?;
            match requested_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(()) => {}
                Err(_) => {
                    latch.trigger();
                    let _ = spinner.join();
                    return Err(TestError::Missing(
                        "the apply halt never reached the shutdown latch",
                    ));
                }
            }
            spinner
                .join()
                .map_err(|_| TestError::Missing("event loop thread panicked"))?;
            assert_eq!(
                shutdown_requests.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "one halt settlement must request shutdown exactly once"
            );
            assert!(
                verify_reader.is_triggered(),
                "requesting shutdown must trigger the node shutdown latch"
            );
            Ok(())
        }
    }

    #[test]
    fn with_historical_background_permit_holds_one_permit_during_closure() {
        let budget = crate::budget::NodeBudget::from_chainstate_cache_budget(
            split_chainstate_cache_budget(16),
            4,
        );
        let cpu = budget.cpu();
        let observed =
            super::with_historical_background_permit(&budget, || cpu.background_in_flight());
        assert_eq!(
            observed, 1,
            "historical validation must hold one background CPU permit"
        );
        assert_eq!(
            cpu.background_in_flight(),
            0,
            "the permit releases on return"
        );
    }
    // SYNC-04
    #[test]
    fn fatal_window_settlement_closes_the_chain_for_recovery() -> Result<(), TestError> {
        use bitcoin_rs_chain::{ApplyError, WindowApplyDisposition, WindowApplyError};
        use bitcoin_rs_consensus::ValidationEngine;
        use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits};

        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let handles = apply_handles(
            tree.tip_handle(),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(tree)),
        );
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let followers = crate::chain_effects::ChainFollowers::new(
            Arc::new(RwLock::new(bitcoin_rs_index::block_log::BlockLog::new())),
            Arc::new(crate::NoOpZmqPublisher),
            None,
            None,
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            Some(gateway),
        );
        let transition = handles
            .begin_transition()
            .map_err(|error| TestError::Apply(Box::new(error)))?;
        let change = followers
            .begin_mempool_change()
            .map_err(|error| TestError::Apply(Box::new(error)))?;
        let fatal = WindowApplyError {
            applied: 0,
            committed: Vec::new(),
            source: Box::new(ApplyError::CoinStoreRead(
                bitcoin_rs_storage::StorageError::InvalidOperation("fatal settlement probe"),
            )),
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
        };
        let settled = super::settle_window_failure(transition, change, fatal);
        assert_eq!(settled.disposition, WindowApplyDisposition::Fatal);
        assert!(
            handles.is_closed_for_recovery(),
            "a fatal window failure must close the chain for recovery"
        );
        assert!(
            handles.shutdown_reader().is_triggered(),
            "a fatal window failure must request node shutdown"
        );
        assert!(
            matches!(handles.begin_transition(), Err(ApplyError::Shutdown)),
            "a closed chain must refuse the next transition instead of retrying"
        );
        Ok(())
    }

    struct RefusedWindowObserver {
        gateway: Mutex<Option<Arc<bitcoin_rs_mempool::MempoolGateway>>>,
        adapter: Mutex<Option<Arc<super::NodeSyncChain>>>,
        payloads: Mutex<Vec<BlockImage>>,
        entered: Mutex<Option<crossbeam_channel::Sender<()>>>,
        release: Mutex<Option<crossbeam_channel::Receiver<()>>>,
        outcome: Mutex<Option<ObservedWindow>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ObservedWindow {
        Committed {
            applied: usize,
        },
        Refused {
            applied: usize,
            disposition: WindowApplyDisposition,
            invalidated: Vec<Hash256>,
        },
    }

    impl bitcoin_rs_mempool::MempoolObserver for RefusedWindowObserver {
        fn on_mutation(&self, envelope: &bitcoin_rs_mempool::MutationEnvelope) {
            if envelope.result.sequence_base != 1 {
                return;
            }
            let Some(entered) = self.entered.lock().take() else {
                return;
            };
            if entered.send(()).is_err() {
                return;
            }
            let Some(release) = self.release.lock().take() else {
                return;
            };
            if release.recv().is_err() {
                return;
            }
            let (Some(gateway), Some(adapter)) =
                (self.gateway.lock().clone(), self.adapter.lock().clone())
            else {
                return;
            };
            for index in 0..8u32 {
                if gateway
                    .insert_entry(
                        bitcoin_rs_mempool::AdmissionOrigin::Rpc,
                        bitcoin_rs_mempool::MempoolEntry::new(
                            Arc::new(refusal_probe_tx(40, index)),
                            100,
                            1_000,
                            1,
                            0,
                            0,
                        ),
                    )
                    .is_err()
                {
                    panic!("nested admission must fit under the delivery ceiling");
                }
            }
            let payloads = self.payloads.lock().clone();
            let window: Vec<&BlockImage> = payloads.iter().collect();
            let observed = match adapter.commit_window(&window) {
                Ok(applied) => ObservedWindow::Committed { applied },
                Err(WindowCommitError {
                    applied,
                    disposition,
                    invalidated,
                    ..
                }) => ObservedWindow::Refused {
                    applied,
                    disposition,
                    invalidated: invalidated.to_vec(),
                },
            };
            *self.outcome.lock() = Some(observed);
        }
    }

    fn refusal_probe_tx(thread: u8, index: u32) -> Tx {
        use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence};

        let mut bytes = [thread; 32];
        bytes[0..4].copy_from_slice(&index.to_le_bytes());
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: bitcoin_rs_consensus::primitives::Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::from_bytes(vec![0x51, thread]),
            }],
        }
    }

    struct RefusalWindowFixture {
        handles: Arc<Chainstate>,
        gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
        followers: crate::chain_effects::ChainFollowers,
        adapter: Arc<super::NodeSyncChain>,
        observer: Arc<RefusedWindowObserver>,
        entered: crossbeam_channel::Receiver<()>,
        release: crossbeam_channel::Sender<()>,
    }

    fn refusal_window_fixture(payload_blocks: &[Block]) -> Result<RefusalWindowFixture, TestError> {
        use bitcoin_rs_consensus::ValidationEngine;
        use bitcoin_rs_mempool::{BodyInterest, Mempool, MempoolGateway, MempoolLimits};

        let (entered_tx, entered_rx) = crossbeam_channel::bounded::<()>(1);
        let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
        let observer = Arc::new(RefusedWindowObserver {
            gateway: Mutex::new(None),
            adapter: Mutex::new(None),
            payloads: Mutex::new(Vec::new()),
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            outcome: Mutex::new(None),
        });
        let observer_handle: Arc<dyn bitcoin_rs_mempool::MempoolObserver> = observer.clone();
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some((observer_handle, BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        *observer.gateway.lock() = Some(Arc::clone(&gateway));
        let followers = crate::chain_effects::ChainFollowers::new(
            Arc::new(RwLock::new(bitcoin_rs_index::block_log::BlockLog::new())),
            Arc::new(crate::NoOpZmqPublisher),
            None,
            None,
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            Some(Arc::clone(&gateway)),
        );
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        for block in payload_blocks {
            parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
        }
        let handles = Arc::new(apply_handles(
            tree.tip_handle(),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(tree)),
        ));
        let adapter = Arc::new(super::NodeSyncChain {
            block_tree: handles.block_tree_reader(),
            handles: Arc::clone(&handles),
            followers: followers.clone(),
            assumeutxo: None,
            budget: sync_unit_test_budget(),
        });
        adapter.bootstrap_genesis();
        assert!(
            handles.applied_tip_snapshot().is_some(),
            "genesis must bootstrap before the refusal probe runs"
        );
        assert!(
            gateway.stable_generation().is_some(),
            "bootstrap must settle the mempool fence before the probe floods it"
        );
        Ok(RefusalWindowFixture {
            handles,
            gateway,
            followers,
            adapter,
            observer,
            entered: entered_rx,
            release: release_tx,
        })
    }

    fn drive_refused_window(
        fixture: RefusalWindowFixture,
        payloads: Vec<BlockImage>,
    ) -> Result<(ObservedWindow, RefusalWindowFixture), TestError> {
        *fixture.observer.payloads.lock() = payloads;
        *fixture.observer.adapter.lock() = Some(Arc::clone(&fixture.adapter));
        let parked_gateway = Arc::clone(&fixture.gateway);
        let parked = std::thread::spawn(move || {
            parked_gateway.insert_entry(
                bitcoin_rs_mempool::AdmissionOrigin::Rpc,
                bitcoin_rs_mempool::MempoolEntry::new(
                    Arc::new(refusal_probe_tx(200, 0)),
                    100,
                    1_000,
                    1,
                    0,
                    0,
                ),
            )
        });
        fixture
            .entered
            .recv_timeout(std::time::Duration::from_secs(10))?;
        for index in 0..100u32 {
            fixture.gateway.insert_entry(
                bitcoin_rs_mempool::AdmissionOrigin::Rpc,
                bitcoin_rs_mempool::MempoolEntry::new(
                    Arc::new(refusal_probe_tx(10, index)),
                    100,
                    1_000,
                    1,
                    0,
                    0,
                ),
            )?;
        }
        assert_eq!(
            fixture.gateway.publish_len(),
            100,
            "the flood must park exactly at the delivery bound before release"
        );
        fixture
            .release
            .send(())
            .map_err(|error| TestError::message(error.to_string()))?;
        parked
            .join()
            .map_err(|_| TestError::ThreadPanicked)?
            .map_err(TestError::Mempool)?;
        let observed = fixture
            .observer
            .outcome
            .lock()
            .clone()
            .ok_or(TestError::Missing("window outcome"))?;
        Ok((observed, fixture))
    }

    fn assert_refused_window_state(
        fixture: &RefusalWindowFixture,
        genesis: &Block,
    ) -> Result<(), TestError> {
        assert!(
            fixture.handles.is_closed_for_recovery(),
            "a post-commit follower refusal must close the chain for recovery"
        );
        assert!(
            fixture.handles.shutdown_reader().is_triggered(),
            "a post-commit follower refusal must request node shutdown"
        );
        assert!(
            matches!(
                fixture.handles.begin_transition(),
                Err(bitcoin_rs_chain::ApplyError::Shutdown)
            ),
            "a halted chain must refuse the next transition instead of reopening"
        );
        assert!(
            fixture.gateway.stable_generation().is_none(),
            "a post-commit follower refusal must never finish the mempool generation"
        );
        let log = fixture.followers.block_log();
        let log = log.read();
        assert_eq!(
            log.len(),
            1,
            "the refused window must record no follower entries beyond genesis"
        );
        assert_eq!(
            log.last()
                .ok_or(TestError::Missing("genesis follower record"))?
                .hash,
            genesis.block_hash(),
            "the follower stream must stop at the bootstrapped genesis"
        );
        assert_eq!(
            fixture
                .followers
                .epoch()
                .current()
                .map(|epoch| epoch.tip.hash),
            Some(Hash256::from(genesis.block_hash())),
            "the refused window must not advance the follower epoch"
        );
        Ok(())
    }

    // SYNC-04, SYNC-06, MPL-04
    #[test]
    fn a_fully_committed_window_halts_when_a_follower_refuses_settlement() -> Result<(), TestError>
    {
        let genesis = Network::Regtest.genesis_block();
        let first =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![regtest_fixture::coinbase(1)]);
        let second =
            mined_block_with_prev_hash(first.block_hash(), 2, vec![regtest_fixture::coinbase(2)]);
        let payloads = vec![
            BlockImage::from_local(first.clone()),
            BlockImage::from_local(second.clone()),
        ];
        let fixture = refusal_window_fixture(&[first.clone(), second.clone()])?;
        let (observed, fixture) = drive_refused_window(fixture, payloads)?;
        assert_eq!(
            observed,
            ObservedWindow::Refused {
                applied: 2,
                disposition: WindowApplyDisposition::Fatal,
                invalidated: Vec::new(),
            },
            "a fully committed window reports every durable outcome and settles Fatal"
        );
        let tip = fixture
            .handles
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("committed tip"))?;
        assert_eq!(
            (tip.height, tip.hash),
            (2, Hash256::from(second.block_hash())),
            "the durably committed tip must stand with no rollback"
        );
        assert_refused_window_state(&fixture, &genesis)
    }

    // SYNC-04, SYNC-06, MPL-04
    #[test]
    fn a_partially_committed_window_halts_when_a_follower_refuses_settlement()
    -> Result<(), TestError> {
        let genesis = Network::Regtest.genesis_block();
        let first =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![regtest_fixture::coinbase(1)]);
        let invalid = mined_block_with_prev_hash(
            first.block_hash(),
            2,
            vec![regtest_fixture::coinbase(2), regtest_fixture::coinbase(3)],
        );
        let child =
            mined_block_with_prev_hash(invalid.block_hash(), 3, vec![regtest_fixture::coinbase(3)]);
        let payloads = vec![
            BlockImage::from_local(first.clone()),
            BlockImage::from_local(invalid.clone()),
            BlockImage::from_local(child.clone()),
        ];
        let fixture = refusal_window_fixture(&[first.clone(), invalid.clone(), child.clone()])?;
        let (observed, fixture) = drive_refused_window(fixture, payloads)?;
        assert_eq!(
            observed,
            ObservedWindow::Refused {
                applied: 1,
                disposition: WindowApplyDisposition::Fatal,
                invalidated: vec![
                    Hash256::from(invalid.block_hash()),
                    Hash256::from(child.block_hash()),
                ],
            },
            "a partially committed window keeps its durable applied prefix and invalidated set"
        );
        let tip = fixture
            .handles
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("committed tip"))?;
        assert_eq!(
            (tip.height, tip.hash),
            (1, Hash256::from(first.block_hash())),
            "only the durably committed prefix stands with no rollback"
        );
        assert_refused_window_state(&fixture, &genesis)
    }
}
