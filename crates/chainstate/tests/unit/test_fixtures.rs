//! Fixtures and in-memory test doubles shared by in-crate unit tests.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, ChainTxCount, TipSnapshot};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Witness,
};
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::{ApplyError, Chainstate};

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

/// A one-satoshi coinbase whose `script_sig` carries the BIP34 height.
pub(crate) fn coinbase(height: u32) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            // `push_int` is the encoding `check_bip34` requires as a prefix;
            // the trailing byte keeps the script_sig at its minimum size at
            // heights that encode as a single opcode.
            script_sig: Script::from_bytes(
                [
                    bitcoin_rs_script::push_int(i64::from(height)).as_slice(),
                    &[0],
                ]
                .concat(),
            ),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    }
}

/// A solved coinbase-only regtest block at `height` on top of `parent`.
pub(crate) fn mined_child(
    parent: BlockHash,
    height: u32,
) -> Result<Block, Box<dyn std::error::Error>> {
    let tx = coinbase(height);
    let mut leaves = vec![*tx.txid().as_bytes()];
    let merkle = bitcoin_rs_consensus::verify_block::compute_merkle_root(&mut leaves)
        .ok_or("coinbase merkle root missing")?;
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash: parent,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: 1_296_688_602_u32.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![tx],
    };
    bitcoin_rs_chain::regtest_fixture::mine_header_to_declared_target(&mut block.header)?;
    Ok(block)
}

#[derive(Default)]
pub(crate) struct MemoryBodies {
    bodies: RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
}

impl BlockBodyStore for MemoryBodies {
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
