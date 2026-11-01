//! In-memory chainstate surface for the `chainstate_reorg_model` fuzz target.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, ChainError, NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::{Block, BlockPayload, Hash256, Header, Network};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::{
    DurableHeadStore, InMemoryDurableHeadStore, InMemoryUndoStore, StorageError, UndoStore,
};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd, commit_block_changes};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_utxo::{UtxoCoin, UtxoSet};
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
    Utxo(#[from] bitcoin_rs_utxo::set::UtxoError),
    #[error("no durable head is committed")]
    MissingDurableHead,
    #[error("durable head is not above the checkpoint tip")]
    HeadBelowCheckpoint,
    #[error("block header {hash} is not retained")]
    MissingHeader { hash: Hash256 },
}

#[derive(Default)]
struct FuzzBodies {
    bodies: RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
}

impl BlockBodyStore for FuzzBodies {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies.write().insert((height, hash), body.to_vec());
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.bodies.read().get(&(height, hash)).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[doc(hidden)]
pub struct FuzzCheckpoint {
    tip: TipSnapshot,
    coins: Vec<UtxoCoin>,
}

impl FuzzCheckpoint {
    #[must_use]
    pub fn tip(&self) -> &TipSnapshot {
        &self.tip
    }

    #[must_use]
    pub fn coin_count(&self) -> usize {
        self.coins.len()
    }
}

#[doc(hidden)]
pub struct FuzzChain {
    chain: Chainstate,
    utxo: Arc<UtxoSet>,
    durable: Arc<InMemoryDurableHeadStore>,
    undo: Arc<InMemoryUndoStore>,
    bodies: Arc<FuzzBodies>,
    headers: RwLock<HashMap<Hash256, Header>>,
    network: Network,
}

impl FuzzChain {
    pub fn new(network: Network) -> Result<Self, FuzzError> {
        let utxo = Arc::new(UtxoSet::new());
        let chain = Chainstate::new(
            network,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            Arc::clone(&utxo),
            Arc::new(CoinStatsListener::new(CoinStats::default())),
            Arc::new(ChainEventPublisher::detached(0)),
        );
        let mut this = Self {
            chain,
            utxo,
            durable: Arc::new(InMemoryDurableHeadStore::new()),
            undo: Arc::new(InMemoryUndoStore::default()),
            bodies: Arc::new(FuzzBodies::default()),
            headers: RwLock::new(HashMap::new()),
            network,
        };
        this.attach_stores();
        let genesis = network.genesis_block();
        this.apply(&genesis)?;
        Ok(this)
    }

    fn attach_stores(&mut self) {
        self.chain.durable_head = Arc::clone(&self.durable) as Arc<dyn DurableHeadStore>;
        self.chain.undo_store = Arc::clone(&self.undo) as Arc<dyn UndoStore>;
        self.chain.block_body_store =
            Some(Arc::clone(&self.bodies) as Arc<dyn BlockBodyStore>);
    }

    pub fn apply(&self, block: &Block) -> Result<(), FuzzError> {
        let payload = BlockPayload::from_local(block.clone());
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
    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    #[must_use]
    pub fn applied_tip(&self) -> Option<TipSnapshot> {
        self.chain
            .applied_tip_snapshot()
            .as_deref()
            .cloned()
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
        let coins = self.utxo.with_stable_view(|view| {
            let mut outpoints = Vec::new();
            view.for_each_all(|outpoint, _| outpoints.push(*outpoint));
            outpoints
                .into_iter()
                .filter_map(|outpoint| view.get_entry(&outpoint))
                .collect()
        });
        Ok(FuzzCheckpoint { tip, coins })
    }

    /// The in-memory durable head is the checkpoint that retires a completed
    /// disconnect rollback, so reopening does not need a file checkpoint.
    pub fn reopen(&self, checkpoint: &FuzzCheckpoint) -> Result<Self, FuzzError> {
        let Some((head_height, head_hash)) = self.durable_head()? else {
            return Err(FuzzError::MissingDurableHead);
        };
        if head_height < checkpoint.tip.height {
            return Err(FuzzError::HeadBelowCheckpoint);
        }
        if self
            .undo
            .load_disconnect_marker()?
            .is_some_and(|marker| marker.phase == bitcoin_rs_storage::DisconnectPhase::RolledBack)
        {
            self.undo.retire_disconnect_marker()?;
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
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::with_capacity(checkpoint.coins.len(), 0);
        for coin in &checkpoint.coins {
            changes.add(UtxoAdd::new(
                coin.outpoint,
                coin.txout.clone(),
                coin.coinbase,
                coin.height,
            ));
        }
        commit_block_changes(&utxo, &changes, &checkpoint.tip.hash)?;
        let mut chain = Chainstate::new(
            self.network,
            chain_tip,
            restored_tip,
            Arc::new(RwLock::new(tree)),
            Arc::clone(&utxo),
            Arc::new(CoinStatsListener::new(CoinStats::default())),
            Arc::new(ChainEventPublisher::detached(0)),
        );
        chain.durable_head = Arc::clone(&self.durable) as Arc<dyn DurableHeadStore>;
        chain.undo_store = Arc::clone(&self.undo) as Arc<dyn UndoStore>;
        chain.block_body_store = Some(Arc::clone(&self.bodies) as Arc<dyn BlockBodyStore>);
        recover_disconnect_marker(&chain)?;
        let reopened = Self {
            chain,
            utxo,
            durable: Arc::clone(&self.durable),
            undo: Arc::clone(&self.undo),
            bodies: Arc::clone(&self.bodies),
            headers: RwLock::new(
                self.headers
                    .read()
                    .iter()
                    .map(|(hash, header)| (*hash, *header))
                    .collect(),
            ),
            network: self.network,
        };
        Ok(reopened)
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
    use bitcoin_rs_chain::ChainTxCount;
    use bitcoin_rs_chain::regtest_fixture::{
        genesis_time, mined_regtest_child_at, mined_regtest_child_at_time,
    };
    use bitcoin_rs_primitives::{Hash256, Network};

    use super::FuzzChain;

    #[test]
    fn reopen_keeps_the_certified_tx_count_for_the_next_block() {
        let chain = FuzzChain::new(Network::Regtest).expect("open");
        let genesis = Network::Regtest.genesis_block();
        let first = mined_regtest_child_at(genesis.block_hash(), 1).expect("mine");
        chain.apply(&first).expect("apply");
        let checkpoint = chain.flush().expect("flush");
        let reopened = chain.reopen(&checkpoint).expect("reopen");
        let second = mined_regtest_child_at(first.block_hash(), 2).expect("mine");
        reopened.apply(&second).expect("apply");
        let tip = reopened.applied_tip().expect("tip");
        assert_eq!(tip.chain_tx_count, ChainTxCount::established(3));
    }

    #[test]
    fn reopen_maps_the_checkpoint_tip_onto_the_rebuilt_tree() {
        let chain = FuzzChain::new(Network::Regtest).expect("open");
        let genesis = Network::Regtest.genesis_block();
        let first =
            mined_regtest_child_at_time(genesis.block_hash(), genesis_time() + 1, 1).expect("mine");
        chain.apply(&first).expect("apply");
        chain.disconnect(&first).expect("disconnect");
        let alternative =
            mined_regtest_child_at_time(genesis.block_hash(), genesis_time() + 2, 1).expect("mine");
        chain.apply(&alternative).expect("apply");
        let checkpoint = chain.flush().expect("flush");
        let reopened = chain.reopen(&checkpoint).expect("reopen");
        let tip = reopened.applied_tip().expect("tip");
        assert_eq!(tip.hash, Hash256::from(alternative.block_hash()));
        let tree = reopened.chain.block_tree_handle();
        assert_eq!(
            tree.read().node(tip.tip_id).expect("tip node").hash,
            tip.hash
        );
    }
}
