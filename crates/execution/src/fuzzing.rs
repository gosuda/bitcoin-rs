use std::sync::Arc;

use crate::chain::{BlockTree, ChainError, NodeStatus, TipSnapshot};
use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::primitives::{Block, BlockImage, Hash256, Header, Network};
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::utxo::UtxoReader;
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::events::ChainEventPublisher;
use crate::{ApplyError, Chainstate, DisconnectError, recover_disconnect_marker};

#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum FuzzError {
    #[error(transparent)]
    Apply(#[from] ApplyError),
    #[error(transparent)]
    Disconnect(#[from] DisconnectError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
    #[error("no durable head is committed")]
    MissingDurableHead,
    #[error("durable head is not above the checkpoint tip")]
    HeadBelowCheckpoint,
    #[error("block header {hash} is not retained")]
    MissingHeader { hash: Hash256 },
}

#[doc(hidden)]
pub struct FuzzCheckpoint {
    tip: TipSnapshot,
    coin_count: usize,
    coin_stats: CoinStats,
}

impl FuzzCheckpoint {
    #[must_use]
    pub fn tip(&self) -> &TipSnapshot {
        &self.tip
    }

    #[must_use]
    pub fn coin_count(&self) -> usize {
        self.coin_count
    }
}

#[doc(hidden)]
pub struct FuzzChain {
    chain: Chainstate,
    store: Arc<bitcoin_rs_storage::MemoryKvStore>,
    bodies: Arc<crate::test_support::MemoryBodies>,
    headers: RwLock<HashMap<Hash256, Header>>,
    network: Network,
}

fn over_store(mut chain: Chainstate, store: &Arc<bitcoin_rs_storage::MemoryKvStore>) -> Chainstate {
    let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
    let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
        Arc::clone(&dyn_store),
        64 * 1024 * 1024,
    ));
    coins.track_coin_stats((*chain.coin_stats).clone());
    chain.durable_head = Arc::new(bitcoin_rs_storage::KvDurableHeadStore::new(Arc::clone(
        store,
    )));
    chain.undo_store = Arc::new(bitcoin_rs_storage::KvUndoStore::new(Arc::clone(&dyn_store)));
    chain.commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
        dyn_store,
        Arc::clone(&coins),
    ));
    chain.coins = coins;
    chain
}

impl FuzzChain {
    pub fn new(network: Network) -> Result<Self, FuzzError> {
        let store = Arc::new(bitcoin_rs_storage::MemoryKvStore::new());
        let chain = over_store(
            Chainstate::new(
                network,
                Arc::new(ArcSwapOption::empty()),
                Arc::new(ArcSwapOption::empty()),
                Arc::new(RwLock::new(BlockTree::new())),
                Arc::new(UtxoSet::new()),
                Arc::new(CoinStatsListener::new(CoinStats::default())),
                Arc::new(ChainEventPublisher::detached(0)),
            ),
            &store,
        );
        let mut this = Self {
            chain,
            store,
            bodies: Arc::new(crate::test_support::MemoryBodies::default()),
            headers: RwLock::new(HashMap::new()),
            network,
        };
        this.attach_stores();
        let genesis = network.genesis_block();
        this.apply(&genesis)?;
        Ok(this)
    }

    fn attach_stores(&mut self) {
        self.chain.block_body_store = Some(self.bodies.clone());
    }

    pub fn apply(&self, block: &Block) -> Result<(), FuzzError> {
        let payload = BlockImage::from_local(block.clone());
        self.headers
            .write()
            .insert(Hash256::from(block.block_hash()), block.header);
        let outcome = self.chain.apply_block(&payload)?;
        self.bodies
            .persist_block_body(outcome.height, outcome.hash, payload.bytes())?;
        Ok(())
    }

    pub fn disconnect(&self, block: &Block) -> Result<(), FuzzError> {
        self.chain.disconnect_block(block)?;
        Ok(())
    }

    #[must_use]
    pub fn utxo(&self) -> UtxoReader {
        self.chain.utxo_reader()
    }

    #[must_use]
    pub fn applied_tip(&self) -> Option<TipSnapshot> {
        self.chain.applied_tip_snapshot().as_deref().cloned()
    }

    pub fn durable_head(&self) -> Result<Option<(u32, Hash256)>, FuzzError> {
        Ok(self
            .chain
            .durable_head
            .load()?
            .map(|head| (head.height, head.tip)))
    }

    pub fn flush(&self) -> Result<FuzzCheckpoint, FuzzError> {
        let tip = self.applied_tip().ok_or(FuzzError::MissingDurableHead)?;
        let Some((height, hash)) = self.durable_head()? else {
            return Err(FuzzError::MissingDurableHead);
        };
        if height != tip.height || hash != tip.hash {
            return Err(FuzzError::HeadBelowCheckpoint);
        }
        let coin_count = self.utxo().with_stable_view(|view| view.len())?;
        let coin_stats = self.chain.coin_stats.snapshot();
        Ok(FuzzCheckpoint {
            tip,
            coin_count,
            coin_stats,
        })
    }

    pub fn reopen(&self, checkpoint: &FuzzCheckpoint) -> Result<Self, FuzzError> {
        let Some((head_height, head_hash)) = self.durable_head()? else {
            return Err(FuzzError::MissingDurableHead);
        };
        if head_height < checkpoint.tip.height {
            return Err(FuzzError::HeadBelowCheckpoint);
        }
        if self
            .chain
            .undo_store
            .load_disconnect_marker()?
            .is_some_and(|marker| marker.phase == bitcoin_rs_storage::DisconnectPhase::RolledBack)
        {
            self.chain.undo_store.retire_disconnect_marker()?;
        }
        let headers = self.header_chain(head_hash)?;
        let mut tree = BlockTree::new();
        let mut parent = None;
        for header in &headers {
            parent = Some(tree.insert_node(parent, *header, NodeStatus::HeaderValid)?);
        }
        let restored_tip_id = tree
            .lookup(checkpoint.tip.hash)
            .ok_or(FuzzError::MissingHeader {
                hash: checkpoint.tip.hash,
            })?;
        tree.restore_chain_tx_count(restored_tip_id, checkpoint.tip.chain_tx_count)?;
        let chain_tip = tree.tip_handle();
        let restored_node = tree.node(restored_tip_id)?;
        let restored_tip_snapshot = TipSnapshot {
            tip_id: restored_tip_id,
            height: restored_node.height,
            chainwork: restored_node.chainwork,
            hash: restored_node.hash,
            chain_tx_count: checkpoint.tip.chain_tx_count,
        };
        let restored_tip = Arc::new(ArcSwapOption::new(Some(Arc::new(restored_tip_snapshot))));
        let mut chain = over_store(
            Chainstate::new(
                self.network,
                chain_tip,
                restored_tip,
                Arc::new(RwLock::new(tree)),
                Arc::new(UtxoSet::new()),
                Arc::new(CoinStatsListener::new(checkpoint.coin_stats.clone())),
                Arc::new(ChainEventPublisher::detached(0)),
            ),
            &self.store,
        );
        chain.block_body_store = Some(self.bodies.clone());
        recover_disconnect_marker(&chain)?;
        Ok(Self {
            chain,
            store: Arc::clone(&self.store),
            bodies: Arc::clone(&self.bodies),
            headers: RwLock::new(
                self.headers
                    .read()
                    .iter()
                    .map(|(hash, header)| (*hash, *header))
                    .collect(),
            ),
            network: self.network,
        })
    }

    fn header_chain(&self, tip: Hash256) -> Result<Vec<Header>, FuzzError> {
        let headers = self.headers.read();
        let mut chain = Vec::new();
        let mut cursor = Some(tip);
        while let Some(hash) = cursor {
            let header = headers
                .get(&hash)
                .copied()
                .ok_or(FuzzError::MissingHeader { hash })?;
            cursor = if hash == self.network.genesis_block_hash() {
                None
            } else {
                Some(Hash256::from(header.prev_blockhash))
            };

            chain.push(header);
        }
        chain.reverse();
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::ChainTxCount;
    use crate::chain::regtest_fixture::{
        genesis_time, mined_regtest_child_at, mined_regtest_child_at_time,
    };
    use bitcoin_rs_consensus::primitives::{Hash256, Network, OutPoint};

    use super::FuzzChain;
    use crate::test_fixtures::TestResult;

    #[test]
    fn reopen_keeps_the_certified_tx_count_for_the_next_block() -> TestResult {
        let chain = FuzzChain::new(Network::Regtest)?;
        let genesis = Network::Regtest.genesis_block();
        let first = mined_regtest_child_at(genesis.block_hash(), 1)?;
        chain.apply(&first)?;
        let checkpoint = chain.flush()?;
        let reopened = chain.reopen(&checkpoint)?;
        let second = mined_regtest_child_at(first.block_hash(), 2)?;
        reopened.apply(&second)?;
        let tip = reopened.applied_tip().ok_or("missing tip")?;
        assert_eq!(tip.chain_tx_count, ChainTxCount::established(3));
        Ok(())
    }

    #[test]
    fn reopen_maps_the_checkpoint_tip_onto_the_rebuilt_tree() -> TestResult {
        let chain = FuzzChain::new(Network::Regtest)?;
        let genesis = Network::Regtest.genesis_block();
        let first = mined_regtest_child_at_time(genesis.block_hash(), genesis_time() + 1, 1)?;
        chain.apply(&first)?;
        chain.disconnect(&first)?;
        let alternative = mined_regtest_child_at_time(genesis.block_hash(), genesis_time() + 2, 1)?;
        chain.apply(&alternative)?;
        let checkpoint = chain.flush()?;
        let reopened = chain.reopen(&checkpoint)?;
        let tip = reopened.applied_tip().ok_or("missing tip")?;
        assert_eq!(tip.hash, Hash256::from(alternative.block_hash()));
        let tree = reopened.chain.block_tree_handle();
        assert_eq!(tree.read().node(tip.tip_id)?.hash, tip.hash);
        Ok(())
    }

    #[test]
    fn reopen_keeps_the_undo_record_for_the_next_disconnect() -> TestResult {
        let chain = FuzzChain::new(Network::Regtest)?;
        let genesis = Network::Regtest.genesis_block();
        let first = mined_regtest_child_at(genesis.block_hash(), 1)?;
        chain.apply(&first)?;
        let checkpoint = chain.flush()?;
        let reopened = chain.reopen(&checkpoint)?;
        reopened.disconnect(&first)?;
        let tip = reopened.applied_tip().ok_or("missing tip")?;
        assert_eq!(tip.hash, Hash256::from(genesis.block_hash()));
        assert_eq!(reopened.utxo().with_stable_view(|view| view.len())?, 0);
        Ok(())
    }

    #[test]
    fn flush_and_reopen_read_the_coins_the_engine_committed() -> TestResult {
        let chain = FuzzChain::new(Network::Regtest)?;
        let genesis = Network::Regtest.genesis_block();
        let first = mined_regtest_child_at(genesis.block_hash(), 1)?;
        chain.apply(&first)?;
        let checkpoint = chain.flush()?;
        assert_eq!(checkpoint.coin_count(), first.txs[0].outputs.len());
        let reopened = chain.reopen(&checkpoint)?;
        let outpoint = OutPoint::new(first.txs[0].txid(), 0);
        let coin = reopened
            .utxo()
            .get(&outpoint)
            .map_err(|_| "coin read failed")?;
        assert_eq!(coin.as_ref(), first.txs[0].outputs.first());
        Ok(())
    }

    #[test]
    fn reopen_resumes_coin_stats_for_the_next_committed_block() -> TestResult {
        let chain = FuzzChain::new(Network::Regtest)?;
        let genesis = Network::Regtest.genesis_block();
        let first = mined_regtest_child_at(genesis.block_hash(), 1)?;
        chain.apply(&first)?;
        let checkpoint = chain.flush()?;
        let first_subsidy = first.txs[0].outputs[0].value.to_sat();
        assert_eq!(checkpoint.coin_stats.utxo_count, 1);
        assert_eq!(checkpoint.coin_stats.total_amount, first_subsidy);
        assert_eq!(checkpoint.coin_stats.height, 1);
        assert_eq!(checkpoint.coin_stats.tx_count, 2);
        let reopened = chain.reopen(&checkpoint)?;
        let second = mined_regtest_child_at(first.block_hash(), 2)?;
        reopened.apply(&second)?;
        let second_subsidy = second.txs[0].outputs[0].value.to_sat();
        let stats = reopened.chain.coin_stats.snapshot();
        assert_eq!(stats.utxo_count, 2);
        assert_eq!(stats.total_amount, first_subsidy + second_subsidy);
        assert_eq!(stats.height, 2);
        assert_eq!(stats.tx_count, 3);
        let coin_count = reopened.utxo().with_stable_view(|view| view.len())?;
        assert_eq!(usize::try_from(stats.utxo_count)?, coin_count);
        let first_coin = reopened
            .utxo()
            .get(&OutPoint::new(first.txs[0].txid(), 0))?
            .ok_or("first coin missing after reopen")?;
        let second_coin = reopened
            .utxo()
            .get(&OutPoint::new(second.txs[0].txid(), 0))?
            .ok_or("second coin missing after reopen")?;
        assert_eq!(
            first_coin.value.to_sat() + second_coin.value.to_sat(),
            stats.total_amount
        );
        Ok(())
    }
}
