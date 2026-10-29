use super::chain::{
    HeaderAdmission, HistoricalAdvance, ReorgError, SyncChain, SyncChainError,
    WindowApplyDisposition, WindowCommitError,
};
use crate::test_support::OrFail;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{
    BlockTree, ChainWork, InitialBlockDownload, NodeId, NodeStatus, TipSnapshot, regtest_fixture,
};
use bitcoin_rs_primitives::{Block, BlockPayload, Hash256, Header, Network, Tx, Txid};
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;

pub(super) struct ScriptedBranchSwitch {
    pub(super) connected: Vec<Hash256>,
    pub(super) error: ReorgError,
}

pub(crate) struct TestChain {
    pub(super) network: Network,
    pub(super) block_tree: Arc<RwLock<BlockTree>>,
    pub(super) chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(super) applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(super) minimum_chain_work: ChainWork,
    pub(super) scripted_commit_failure: Mutex<Option<(Hash256, WindowApplyDisposition)>>,
    pub(super) scripted_branch_switch: Mutex<Option<ScriptedBranchSwitch>>,
    pub(super) scripted_tip_update: Mutex<Option<(Arc<TipSnapshot>, Arc<TipSnapshot>)>>,
    pub(super) historical: Mutex<std::collections::VecDeque<(u32, Hash256)>>,
    pub(super) historical_connected: Mutex<Vec<Hash256>>,
    pub(super) historical_replay_pending: Mutex<bool>,
}

impl TestChain {
    pub(crate) fn new(
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
    ) -> Self {
        Self {
            network: Network::Regtest,
            block_tree,
            chain_tip,
            applied_tip,
            minimum_chain_work: ChainWork::from_be_bytes(Network::Regtest.minimum_chain_work()),
            scripted_commit_failure: Mutex::new(None),
            scripted_branch_switch: Mutex::new(None),
            scripted_tip_update: Mutex::new(None),
            historical: Mutex::new(std::collections::VecDeque::new()),
            historical_connected: Mutex::new(Vec::new()),
            historical_replay_pending: Mutex::new(false),
        }
    }
}

impl TestChain {
    fn body_binding(&self, tree: &BlockTree, block: &Block) -> Result<(), SyncChainError> {
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
        let segwit_active = tree
            .lookup(hash)
            .and_then(|node_id| tree.node(node_id).ok())
            .is_none_or(|node| {
                bitcoin_rs_chain::softfork_state(tree, self.network, node.parent, node.height)
                    .segwit_active
            });
        bitcoin_rs_consensus::check_block_body_binding(block, segwit_active)
            .map_err(|error| -> SyncChainError { Box::new(error) })
    }

    #[must_use]
    pub(crate) const fn with_minimum_chain_work(mut self, minimum: ChainWork) -> Self {
        self.minimum_chain_work = minimum;
        self
    }
}

impl SyncChain for TestChain {
    fn historical_base(&self) -> Option<Hash256> {
        self.historical.lock().back().map(|(_, hash)| *hash)
    }

    fn advance_historical(&self) -> Result<HistoricalAdvance, SyncChainError> {
        if std::mem::take(&mut *self.historical_replay_pending.lock()) {
            return Ok(HistoricalAdvance::ReplayPending);
        }
        Ok(self
            .historical
            .lock()
            .front()
            .copied()
            .map_or(HistoricalAdvance::Complete, |(height, hash)| {
                HistoricalAdvance::MissingBody { height, hash }
            }))
    }

    fn connect_historical(&self, payload: &BlockPayload) -> Result<(), SyncChainError> {
        let hash = payload.block().block_hash().0;
        assert_eq!(
            self.historical.lock().pop_front().map(|(_, hash)| hash),
            Some(hash)
        );
        self.historical_connected.lock().push(hash);
        Ok(())
    }
    fn network(&self) -> Network {
        self.network
    }

    fn block_tree(&self) -> parking_lot::RwLockReadGuard<'_, BlockTree> {
        self.block_tree.read()
    }

    fn chain_tip(&self) -> Option<Arc<TipSnapshot>> {
        let tip = self.chain_tip.load_full();
        let update = self.scripted_tip_update.lock().take();
        if let Some((chain, applied)) = update {
            self.chain_tip.store(Some(chain));
            self.applied_tip.store(Some(applied));
        }
        tip
    }

    fn applied_tip(&self) -> Option<Arc<TipSnapshot>> {
        self.applied_tip.load_full()
    }

    fn bootstrap_genesis(&self) {
        if self.applied_tip.load_full().is_some() {
            return;
        }
        let genesis = self.network.genesis_block();
        let hash = Hash256::from_le_bytes(genesis.block_hash().as_bytes());
        let tree = self.block_tree.read();
        let Some(id) = tree.lookup(hash) else {
            return;
        };
        let Ok(node) = tree.node(id) else {
            return;
        };
        let snapshot = Arc::new(TipSnapshot {
            tip_id: id,
            chain_tx_count: node.chain_tx_count,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        });
        self.applied_tip.store(Some(Arc::clone(&snapshot)));
        if self.chain_tip.load_full().is_none() {
            self.chain_tip.store(Some(snapshot));
        }
    }

    fn minimum_chain_work(&self) -> ChainWork {
        self.minimum_chain_work
    }

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
        let mut tree = self.block_tree.write();
        match bitcoin_rs_chain::accept_headers(
            &mut tree,
            headers,
            self.network,
            bitcoin_rs_chain::current_unix_seconds(),
            bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
        ) {
            Ok(admitted) => {
                let announced_tip = admitted
                    .ids
                    .last()
                    .and_then(|id| tree.node(*id).ok())
                    .map(|node| node.hash);
                let active_height = tree
                    .tip()
                    .zip(announced_tip)
                    .and_then(|(active_tip, hash)| {
                        tree.active_height_of(active_tip.tip_id, hash)
                            .and_then(|height| i32::try_from(height).ok())
                    });
                HeaderAdmission::Accepted {
                    accepted: admitted.ids.len(),
                    announced_tip,
                    active_height,
                    demoted_tip: admitted.demoted_tip,
                }
            }
            Err(error) => HeaderAdmission::Rejected(error),
        }
    }

    fn check_body_binding(&self, block: &Block) -> Result<(), SyncChainError> {
        let tree = self.block_tree.read();
        self.body_binding(&tree, block)
    }

    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
        const MAX_BLOCKS: usize = 1024;
        const MAX_BYTES: usize = 64 << 20;
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        for size in serialized_sizes {
            if count == MAX_BLOCKS {
                break;
            }
            let next = bytes.saturating_add(size);
            if count > 0 && next > MAX_BYTES {
                break;
            }
            bytes = next;
            count += 1;
        }
        count
    }

    fn commit_window(&self, payloads: &[&BlockPayload]) -> Result<usize, WindowCommitError> {
        let mut tree = self.block_tree.write();
        let mut applied = 0_usize;
        for payload in payloads {
            let block = payload.block();
            let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
            let scripted = *self.scripted_commit_failure.lock();
            let failure = match scripted {
                Some((fail_hash, _)) if fail_hash == hash => {
                    self.scripted_commit_failure.lock().take()
                }
                _ => None,
            };
            if let Some((_, disposition)) = failure {
                return Err(WindowCommitError {
                    applied,
                    disposition,
                    invalidated: Box::default(),
                    source: Box::new(std::io::Error::other("scripted commit failure")),
                });
            }
            let Some(node_id) = tree.lookup(hash) else {
                return Err(WindowCommitError {
                    applied,
                    disposition: WindowApplyDisposition::Operational,
                    invalidated: Box::default(),
                    source: Box::new(std::io::Error::other("commit block not in tree")),
                });
            };
            let coinbase_shaped = |tx: &Tx| {
                tx.inputs.len() == 1
                    && tx.inputs[0].previous_output.txid == Txid::default()
                    && tx.inputs[0].previous_output.vout == u32::MAX
            };
            if !block.txs.is_empty() && block.txs.iter().skip(1).any(coinbase_shaped) {
                let invalidated = tree
                    .invalidate_subtree(node_id)
                    .map(|outcome| outcome.invalid.into_boxed_slice())
                    .unwrap_or_default();
                return Err(WindowCommitError {
                    applied,
                    disposition: WindowApplyDisposition::Permanent,
                    invalidated,
                    source: Box::new(std::io::Error::other("extra coinbase")),
                });
            }
            if !block.txs.is_empty() {
                if let Err(source) = self.body_binding(&tree, block) {
                    return Err(WindowCommitError {
                        applied,
                        disposition: WindowApplyDisposition::BodyMutated,
                        invalidated: Box::default(),
                        source,
                    });
                }
            }
            let Ok(node) = tree.node(node_id) else {
                return Err(WindowCommitError {
                    applied,
                    disposition: WindowApplyDisposition::Operational,
                    invalidated: Box::default(),
                    source: Box::new(std::io::Error::other("commit node missing")),
                });
            };
            self.applied_tip.store(Some(Arc::new(TipSnapshot {
                tip_id: node_id,
                chain_tx_count: node.chain_tx_count,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            })));
            applied = applied.saturating_add(1);
        }
        Ok(applied)
    }

    fn switch_to_branch(
        &self,
        _target: NodeId,
        _staged_body: &mut dyn FnMut(Hash256) -> Option<BlockPayload>,
        connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), ReorgError> {
        let scripted = self.scripted_branch_switch.lock().take();
        if let Some(scripted) = scripted {
            for hash in &scripted.connected {
                let tip = {
                    let tree = self.block_tree.read();
                    tree.lookup(*hash).and_then(|node_id| {
                        tree.node(node_id).ok().map(|node| {
                            Arc::new(TipSnapshot {
                                tip_id: node_id,
                                chain_tx_count: node.chain_tx_count,
                                height: node.height,
                                chainwork: node.chainwork,
                                hash: node.hash,
                            })
                        })
                    })
                };
                if let Some(tip) = tip {
                    self.applied_tip.store(Some(tip));
                }
                connected_body(*hash);
            }
            if let ReorgError::ConnectFailed {
                hash,
                disposition: WindowApplyDisposition::Permanent,
                ..
            } = &scripted.error
            {
                let mut tree = self.block_tree.write();
                if let Some(node_id) = tree.lookup(*hash) {
                    let _ = tree.invalidate_subtree(node_id);
                }
            }
            return Err(scripted.error);
        }
        Err(ReorgError::NoAppliedTip)
    }
}

pub(crate) fn synced_ibd_latch() -> Arc<InitialBlockDownload> {
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let genesis = Network::Regtest.genesis_block();
    let recent = Header {
        prev_blockhash: genesis.block_hash(),
        time: u32::try_from(bitcoin_rs_primitives::unix_time_secs()).unwrap_or(u32::MAX),
        ..genesis.header
    };
    {
        let mut tree = block_tree.write();
        let Ok(genesis_id) = tree.insert_node(None, genesis.header, NodeStatus::Active) else {
            unreachable!("regtest genesis is always insertable");
        };
        if tree
            .insert_node(Some(genesis_id), recent, NodeStatus::Active)
            .is_err()
        {
            unreachable!("a valid regtest child is always insertable");
        }
    }
    let tip = block_tree
        .read()
        .tip()
        .unwrap_or_else(|| unreachable!("the chain has a tip"));
    applied_tip.store(Some(Arc::clone(&tip)));
    Arc::new(InitialBlockDownload::new(
        bitcoin_rs_chain::TipReader::new(applied_tip),
        bitcoin_rs_chain::BlockTreeReader::new(block_tree),
    ))
}

pub(crate) fn mined_chain(
    body_height: u32,
    header_only: u32,
) -> Result<(BlockTree, Vec<Block>), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut tip_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let mut prev_hash = genesis.block_hash();
    let mut blocks = Vec::with_capacity(usize::try_from(body_height)?);
    for height in 1..=body_height {
        let block = regtest_fixture::mined_block_with_prev_hash(
            prev_hash,
            height,
            vec![regtest_fixture::coinbase(height)],
        )
        .or_fail("regtest fixture block");
        tip_id = tree.insert_node(Some(tip_id), block.header, NodeStatus::HeaderValid)?;
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    for height in body_height.saturating_add(1)..=body_height.saturating_add(header_only) {
        let header = regtest_fixture::mined_regtest_header(prev_hash, height)
            .or_fail("regtest fixture header");
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        prev_hash = header.compute_hash();
    }
    Ok((tree, blocks))
}
