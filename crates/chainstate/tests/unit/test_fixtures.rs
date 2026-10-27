//! Fixtures and in-memory test doubles shared by in-crate unit tests.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, ChainTxCount, TipSnapshot};
use bitcoin_rs_primitives::{Amount, Hash256, Network, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::chainstate_journal::Coin;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

use crate::{ApplyError, Chainstate, TipStagedHook};

pub(crate) fn journal_coin(marker: u8, height: u32, value: u64) -> Coin {
    Coin {
        outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
        txout: TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51].into(),
        },
        height,
        coinbase: true,
    }
}

/// An empty in-memory chainstate over `utxo`.
pub(crate) fn handles(network: Network, utxo: Arc<UtxoSet>) -> Chainstate {
    Chainstate::new(
        network,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        utxo,
        Arc::new(CoinStatsListener::new(CoinStats::default())),
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    )
}

/// Publishes the regtest genesis as the applied tip with count 1.
pub(crate) fn seed_genesis(handles: &Chainstate) -> Result<TipSnapshot, ApplyError> {
    let genesis = Network::Regtest.genesis_block();
    let tip = crate::connect::applied_header_tip(
        handles,
        Hash256::from(genesis.block_hash()),
        &genesis,
        0,
    )?;
    let tip = TipSnapshot {
        chain_tx_count: ChainTxCount::established(1),
        ..tip
    };
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    Ok(tip)
}

/// What the staged-tip hook observed: the staged tip it was handed, the
/// borrowed block's identity, and the published tip still in the cell.
/// Only hashes and heights cross the hook boundary — never a block clone.
pub(crate) struct StagedFire {
    pub(crate) staged_hash: Hash256,
    pub(crate) staged_height: u32,
    pub(crate) block_hash: Hash256,
    pub(crate) published: Option<(Hash256, u32)>,
}

/// Records every staged-tip fire with the published tip still in the cell.
pub(crate) fn staging_recorder(
    chain: &Chainstate,
    fires: &Arc<Mutex<Vec<StagedFire>>>,
) -> TipStagedHook {
    let fires = Arc::clone(fires);
    let chain = chain.clone();
    Arc::new(move |staged, block| {
        // `applied_tip_snapshot` is a lock-free read; the hook takes no
        // domain write lock and never reenters chainstate mutation.
        let published = chain
            .applied_tip_snapshot()
            .map(|tip| (tip.hash, tip.height));
        fires.lock().push(StagedFire {
            staged_hash: staged.hash,
            staged_height: staged.height,
            block_hash: Hash256::from(block.block_hash()),
            published,
        });
    })
}

#[derive(Default)]
pub(crate) struct MemoryBodies {
    bodies: RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
}

impl BlockBodyStore for MemoryBodies {
    fn load_block_body_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::BoundedReadError> {
        self.bodies
            .read()
            .get(&(height, hash))
            .map(|body| {
                if body.len() > max_bytes {
                    Err(bitcoin_rs_storage::BoundedReadError::Limit {
                        size: body.len(),
                        limit: max_bytes,
                    })
                } else {
                    Ok(body.clone())
                }
            })
            .transpose()
    }

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
