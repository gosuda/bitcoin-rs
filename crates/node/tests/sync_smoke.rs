//! Block sync smoke tests.
use hashbrown::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits};
use bitcoin_rs_node::{BlockSync, Network, apply::ApplyHandles};
use bitcoin_rs_primitives::{
    Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid, encode::double_sha256,
};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use crossbeam_channel::unbounded;
use parking_lot::{Mutex, RwLock};

const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

#[test]
fn tick_buffers_out_of_order_blocks_until_parent_arrives() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = regtest_genesis_block()?;
    let block_one = child_coinbase_block(&genesis, 1)?;
    let block_two = child_coinbase_block(&block_one, 2)?;

    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let chain_tip = block_tree.read().tip_handle();
    let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let peer_table = Arc::new(bitcoin_rs_p2p::PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx_raw) =
        unbounded::<bitcoin_rs_p2p::InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let (handles, coin_stats) = apply_handles_with_coin_stats(
        Network::Regtest,
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::new(
        handles,
        Arc::clone(&peer_table),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    inbound_headers_tx.send(bitcoin_rs_p2p::InboundHeaders {
        headers: vec![genesis.header, block_one.header, block_two.header],
        source: None,
    })?;
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
        block_two.clone(),
    ))?;
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
        block_one.clone(),
    ))?;

    sync.tick();

    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    assert_eq!(applied.height, 2);
    assert_eq!(applied.hash, block_two.block_hash().0);
    assert_eq!(
        coin_stats.snapshot(),
        expected_coin_stats(&[&genesis, &block_one, &block_two])?
    );
    assert_eq!(block_tree.read().len(), 3);
    Ok(())
}

#[test]
fn tick_applies_non_coinbase_spend_and_updates_utxo_and_coinstats()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = non_coinbase_spend_chain()?;

    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let chain_tip = block_tree.read().tip_handle();
    let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let peer_table = Arc::new(bitcoin_rs_p2p::PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx_raw) =
        unbounded::<bitcoin_rs_p2p::InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let (handles, coin_stats, utxo) = apply_handles_with_coin_stats_and_utxo(
        Network::Regtest,
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::new(
        handles,
        Arc::clone(&peer_table),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    inbound_headers_tx.send(bitcoin_rs_p2p::InboundHeaders {
        headers: fixture.blocks.iter().map(|block| block.header).collect(),
        source: None,
    })?;
    for block in fixture.blocks.iter().skip(1) {
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
    }

    sync.tick();

    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    assert_eq!(applied.height, 102);
    assert_eq!(
        applied.hash,
        fixture
            .blocks
            .last()
            .ok_or_else(|| std::io::Error::other("missing final block"))?
            .block_hash()
            .0
    );
    assert!(
        utxo.get(&primitive_outpoint(fixture.mature_coinbase_outpoint))
            .is_none(),
        "mature coinbase prevout must be removed by the height-101 spend",
    );
    assert!(
        utxo.get(&primitive_outpoint(fixture.funding_outpoint))
            .is_none(),
        "funding prevout must be removed by the height-102 spend",
    );
    assert!(
        utxo.get(&primitive_outpoint(fixture.spend_outpoint))
            .is_some(),
        "height-102 spend output must remain live",
    );

    let block_refs: Vec<&Block> = fixture.blocks.iter().collect();
    assert_eq!(coin_stats.snapshot(), expected_coin_stats(&block_refs)?);
    Ok(())
}

struct SpendChainFixture {
    blocks: Vec<Block>,
    mature_coinbase_outpoint: OutPoint,
    funding_outpoint: OutPoint,
    spend_outpoint: OutPoint,
}

fn non_coinbase_spend_chain() -> Result<SpendChainFixture, Box<dyn std::error::Error>> {
    let mut blocks = vec![regtest_genesis_block()?];
    let spendable_script = op_true_script();
    for height in 1_u8..=100 {
        let parent = blocks
            .last()
            .ok_or_else(|| std::io::Error::other("missing chain parent"))?;
        blocks.push(child_coinbase_block_with_script(
            parent,
            height,
            spendable_script.clone(),
        )?);
    }

    let mature_coinbase_outpoint = OutPoint::new(blocks[1].txs[0].txid(), 0);
    let mature_coinbase_txout = blocks[1].txs[0].outputs[0].clone();
    let funding_tx =
        spend_to_op_true(mature_coinbase_outpoint, mature_coinbase_txout.value, 1_000)?;
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let funding_txout = funding_tx.outputs[0].clone();
    let funding_block = child_block_with_transactions(
        blocks
            .last()
            .ok_or_else(|| std::io::Error::other("missing funding parent"))?,
        101,
        vec![funding_tx],
    )?;
    blocks.push(funding_block);

    let spend_tx = spend_to_op_true(funding_outpoint, funding_txout.value, 1_000)?;
    let spend_outpoint = OutPoint::new(spend_tx.txid(), 0);
    let spend_block = child_block_with_transactions(
        blocks
            .last()
            .ok_or_else(|| std::io::Error::other("missing spend parent"))?,
        102,
        vec![spend_tx],
    )?;
    blocks.push(spend_block);

    Ok(SpendChainFixture {
        blocks,
        mature_coinbase_outpoint,
        funding_outpoint,
        spend_outpoint,
    })
}

fn expected_coin_stats(blocks: &[&Block]) -> Result<CoinStats, Box<dyn std::error::Error>> {
    let mut stats = CoinStats::default();
    let mut live_outputs = HashMap::<OutPoint, (TxOut, u32, bool)>::new();
    for (height, block) in blocks.iter().enumerate() {
        let height = u32::try_from(height)?;
        if height == 0 {
            stats.finish_block(height, u64::try_from(block.txs.len())?);
            continue;
        }
        for tx in &block.txs {
            let txid = tx.txid();
            for (vout, txout) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint::new(txid, u32::try_from(vout)?);
                stats.insert_utxo(&outpoint, txout, height, is_coinbase(tx));
                live_outputs.insert(outpoint, (txout.clone(), height, is_coinbase(tx)));
            }
            if is_coinbase(tx) {
                continue;
            }
            for input in &tx.inputs {
                let outpoint = input.previous_output;
                let Some((txout, output_height, coinbase)) = live_outputs.remove(&outpoint) else {
                    return Err(std::io::Error::other(format!(
                        "missing expected prevout {outpoint:?}"
                    ))
                    .into());
                };
                stats.remove_utxo(&outpoint, &txout, output_height, coinbase);
            }
        }
        stats.finish_block(height, u64::try_from(block.txs.len())?);
    }
    Ok(stats)
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles_with_coin_stats(
    network: Network,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> (ApplyHandles, Arc<CoinStatsListener>) {
    let (handles, coin_stats, _utxo) =
        apply_handles_with_coin_stats_and_utxo(network, chain_tip, applied_tip, block_tree);
    (handles, coin_stats)
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles_with_coin_stats_and_utxo(
    network: Network,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> (ApplyHandles, Arc<CoinStatsListener>, Arc<UtxoSet>) {
    let coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let mut utxo = UtxoSet::new();
    utxo.set_listener(Box::new((*coin_stats).clone()));
    let utxo = Arc::new(utxo);
    let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
    let mempool_gateway = MempoolGateway::shared(Arc::clone(&mempool));
    let mining_generation = Arc::new(bitcoin_rs_node::mining::MiningGenerationSignal::new());
    let (chain_events, _chain_events_rx) = bitcoin_rs_node::state::ChainEventPublisher::detached(0);
    let handles = ApplyHandles::new(
        network,
        chain_tip,
        applied_tip,
        block_tree,
        Arc::clone(&utxo),
        Arc::clone(&coin_stats),
        None,
        mempool,
        mempool_gateway,
        mining_generation,
        Arc::new(RwLock::new(bitcoin_rs_rpc::context::BlockLog::new())),
        Arc::new(RwLock::new(HashMap::<Txid, Tx>::new())),
        Arc::new(bitcoin_rs_node::NoOpZmqPublisher),
        Arc::new(chain_events),
    );
    (handles, coin_stats, utxo)
}

fn regtest_genesis_block() -> Result<Block, Box<dyn std::error::Error>> {
    let bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    Ok(Block::consensus_decode(&bytes)?)
}

fn child_coinbase_block(parent: &Block, height: u8) -> Result<Block, Box<dyn std::error::Error>> {
    child_coinbase_block_with_script(
        parent,
        height,
        parent.txs[0].outputs[0].script_pubkey.clone(),
    )
}

fn child_coinbase_block_with_script(
    parent: &Block,
    height: u8,
    script_pubkey: Vec<u8>,
) -> Result<Block, Box<dyn std::error::Error>> {
    let mut block = parent.clone();
    block.header.prev_blockhash = parent.block_hash();
    block.header.time = parent.header.time.saturating_add(1);
    block.txs.truncate(1);
    block.txs[0].inputs[0].script_sig = vec![1, height];
    block.txs[0].outputs[0].script_pubkey = script_pubkey;
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| std::io::Error::other("child block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

fn child_block_with_transactions(
    parent: &Block,
    height: u8,
    transactions: Vec<Tx>,
) -> Result<Block, Box<dyn std::error::Error>> {
    let mut block = child_coinbase_block(parent, height)?;
    block.txs.extend(transactions);
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| std::io::Error::other("child block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

fn spend_to_op_true(
    previous_output: OutPoint,
    previous_value: u64,
    fee: u64,
) -> Result<Tx, Box<dyn std::error::Error>> {
    let value = previous_value
        .checked_sub(fee)
        .ok_or_else(|| std::io::Error::other("spend fee exceeds previous output value"))?;
    Ok(Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: op_true_script(),
        }],
    })
}

fn op_true_script() -> Vec<u8> {
    vec![0x51]
}

fn primitive_outpoint(outpoint: OutPoint) -> OutPoint {
    outpoint
}

fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].previous_output.txid == Txid::default()
        && tx.inputs[0].previous_output.vout == u32::MAX
}

fn compute_merkle_root(block: &Block) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if leaves.is_empty() {
        return None;
    }
    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair).to_le_bytes());
        }
        leaves = next;
    }
    Some(Hash256::from_le_bytes(&leaves[0]))
}

fn mine_block_to_declared_target(block: &mut Block) -> Result<(), Box<dyn std::error::Error>> {
    while !pow_met(block.header.bits, block.block_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("exhausted nonce while mining test block"))?;
    }
    Ok(())
}

fn pow_met(bits: u32, hash: Hash256) -> bool {
    let target = uint_be(&compact_to_target(bits));
    if target == [0_u8; 32] {
        return false;
    }
    uint_be(&hash.to_le_bytes()) <= target
}

fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mantissa = u64::from(bits & 0x007f_ffff);
    let mut target = [0_u8; 32];
    if exponent <= 3 {
        let val = mantissa >> (8 * (3 - exponent));
        target[..8].copy_from_slice(&val.to_le_bytes());
    } else {
        let shift = 8 * (exponent - 3);
        if shift < 256 {
            let byte_shift = shift / 8;
            for (offset, &byte) in mantissa.to_le_bytes().iter().enumerate() {
                let position = byte_shift + offset;
                if position < 32 {
                    target[position] = byte;
                }
            }
        }
    }
    if mantissa != 0 && bits & 0x0080_0000 != 0 {
        return [0_u8; 32];
    }
    if mantissa != 0
        && (exponent > 34
            || (mantissa > 0xff && exponent > 33)
            || (mantissa > 0xffff && exponent > 32))
    {
        return [0_u8; 32];
    }
    target
}

fn uint_be(bytes: &[u8; 32]) -> [u8; 32] {
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(bytes);
    arr.reverse();
    arr
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut chunks = hex.as_bytes().chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "odd hex length").into());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in &mut chunks {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex digit").into()),
    }
}
