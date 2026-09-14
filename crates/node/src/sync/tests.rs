use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_p2p::{InboundHeaders, PeerTable};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_script::push_int;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_utxo::UtxoSet;
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

use super::BlockSync;
use crate::apply::Chainstate;

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles(
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> Chainstate {
    let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
    let mempool_gateway = bitcoin_rs_mempool::MempoolGateway::shared(Arc::clone(&mempool));
    Chainstate::new(
        Network::Regtest,
        chain_tip,
        applied_tip,
        block_tree,
        Arc::new(UtxoSet::new()),
        Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        )),
        mempool,
        mempool_gateway,
        Arc::new(crate::state::ChainEventPublisher::detached(0).0),
    )
}

const GENESIS_TIME: u32 = 1_296_688_602;

fn pow_met(bits: u32, hash: Hash256) -> bool {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
        return false;
    }
    let bytes = hash.as_byte_array();
    let lo = usize::try_from(exponent).unwrap_or(32) - 3;
    let window =
        u32::from(bytes[lo]) | u32::from(bytes[lo + 1]) << 8 | u32::from(bytes[lo + 2]) << 16;
    window <= mantissa
        && bytes[usize::try_from(exponent).unwrap_or(32)..]
            .iter()
            .all(|&byte| byte == 0)
}

fn mined_block_with_prev_hash(prev_blockhash: BlockHash, height: u32, txdata: Vec<Tx>) -> Block {
    use bitcoin_rs_primitives::CompactTarget;
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: GENESIS_TIME.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: txdata,
    };
    block.header.merkle_root = merkle_root(&block.txs);
    while !pow_met(
        block.header.bits.to_consensus(),
        Hash256::from(block.block_hash()),
    ) {
        block.header.nonce = block.header.nonce.saturating_add(1);
    }
    block
}

#[allow(clippy::expect_used)]
fn merkle_root(txs: &[Tx]) -> Hash256 {
    let mut hashes: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if hashes.is_empty() {
        return Hash256::default();
    }
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            let last = hashes.last().expect("odd merkle level has a last leaf");
            hashes.push(*last);
        }
        hashes = hashes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let mut buffer = [0_u8; 64];
                buffer[..32].copy_from_slice(&pair[0]);
                buffer[32..].copy_from_slice(&pair[1]);
                double_sha256(&buffer).to_le_bytes()
            })
            .collect();
    }
    Hash256::from_le_bytes(hashes.first().expect("merkle fold reduces to one root"))
}

fn coinbase_transaction(height: u32) -> Tx {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    let mut script_sig = push_int(i64::from(height));
    script_sig.extend_from_slice(&push_int(1));
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

#[allow(clippy::type_complexity)]
fn sync_with_header_chain(
    height: u32,
) -> Result<
    (
        BlockSync,
        Chainstate,
        crate::chain_effects::ChainFollowers,
        Arc<PeerTable>,
        Arc<RwLock<BlockTree>>,
        Arc<ArcSwapOption<TipSnapshot>>,
        Vec<BlockHash>,
    ),
    Box<dyn std::error::Error>,
> {
    let mut tree = BlockTree::new();
    let genesis = Network::Regtest.genesis_block().header;
    let mut node_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut expected = Vec::new();
    for height in 1..=height {
        let header = mined_block_with_prev_hash(
            BlockHash::from(tree.node(node_id)?.hash),
            height,
            Vec::new(),
        )
        .header;
        node_id = tree.insert_node(Some(node_id), header, NodeStatus::HeaderValid)?;
        expected.push(BlockHash::from(tree.node(node_id)?.hash));
    }
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_headers_tx, headers_rx) = unbounded::<InboundHeaders>();
    let headers_rx = Arc::new(Mutex::new(headers_rx));
    let (_blocks_tx, blocks_rx) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let blocks_rx = Arc::new(Mutex::new(blocks_rx));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let followers = crate::chain_effects::ChainFollowers::noop();
    let sync = crate::sync::block_sync(
        handles.clone(),
        followers.clone(),
        Arc::clone(&peers),
        headers_rx,
        blocks_rx,
    );
    Ok((
        sync,
        handles,
        followers,
        peers,
        block_tree,
        applied_tip,
        expected,
    ))
}

type MaturedChain = (
    Chainstate,
    Vec<Block>,
    HashMap<Hash256, (Block, bytes::Bytes)>,
);

fn matured_chain(depth: u32) -> Result<MaturedChain, Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let subsidy = 5_000_000_000_u64;
    let mut prev_hash = genesis.block_hash();
    let mut blocks: Vec<Block> = Vec::new();
    for height in 1..=depth {
        let mut coinbase = coinbase_transaction(height);
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
                    sequence: Sequence::from_consensus(0xffff_ffff),
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(subsidy - 100_000),
                    script_pubkey: Script::new(),
                }],
                lock_time: LockTime::from_consensus(0),
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
    handles.apply_block(&genesis)?;
    for block in &blocks {
        handles.apply_block(block)?;
    }
    let bodies = blocks
        .iter()
        .map(|block| {
            (
                Hash256::from_le_bytes(block.block_hash().as_bytes()),
                (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
            )
        })
        .collect();
    Ok((handles, blocks, bodies))
}

struct DisarmFailsUndoStore {
    inner: Arc<dyn crate::apply::UndoStore>,
}

impl crate::apply::UndoStore for DisarmFailsUndoStore {
    fn persist_undo(&self, height: u32, hash: Hash256, record: &[u8]) -> Result<(), StorageError> {
        self.inner.persist_undo(height, hash, record)
    }

    fn load_undo(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_undo(height, hash)
    }

    fn arm_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
        self.inner.arm_disconnect(height, hash)
    }

    fn complete_disconnect(&self, _height: u32, _hash: Hash256) -> Result<(), StorageError> {
        Err(StorageError::backend("injected marker-clear failure"))
    }

    fn disarm_disconnect(&self) -> Result<(), StorageError> {
        self.inner.disarm_disconnect()
    }

    fn load_disconnect_marker(
        &self,
    ) -> Result<Option<bitcoin_rs_storage::DisconnectMarker>, StorageError> {
        self.inner.load_disconnect_marker()
    }
}

#[cfg(test)]
mod transitions_5;
#[cfg(test)]
mod transitions_6;
#[cfg(test)]
mod transitions_7;
