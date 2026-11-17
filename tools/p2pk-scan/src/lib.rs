use std::collections::HashSet;
use std::io::{self, BufRead, Read};

use bitcoin_rs_consensus::primitives::hex::{HexError, hex_decode, hex_encode};
use bitcoin_rs_consensus::primitives::layout::ParsedBlock;
use bitcoin_rs_consensus::primitives::{Block, BlockHash, OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_storage::utxo::UtxoError;
use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd, populate_block_changes};
use bitcoin_rs_storage::{CoinStore, ColumnFamily, MemoryKvStore};
use serde::Serialize;
use std::sync::Arc;
use thiserror::Error;

pub const MAX_BLOCK_HEX_BYTES: usize = 8_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyShape {
    Compressed,
    Uncompressed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct P2pkCoin {
    pub txid: String,
    pub vout: u32,
    pub height: u32,
    pub value_sat: u64,
    pub key: KeyShape,
    pub pubkey: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    pub blocks: u32,
    pub tip_height: u32,
    pub utxo_outputs: usize,
    pub p2pk_outputs: usize,
    pub p2pk_value_sat: u64,
    pub p2pk: Vec<P2pkCoin>,
}
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("block file read failed: {0}")]
    Io(#[from] io::Error),
    #[error("line {line} is not UTF-8")]
    NotText { line: u64 },
    #[error("line {line} is empty; every line must hold one block")]
    EmptyLine { line: u64 },
    #[error("line {line} exceeds the {MAX_BLOCK_HEX_BYTES}-byte hex limit")]
    LineTooLong { line: u64 },
    #[error("block file holds more than a u32 block count")]
    TooManyBlocks,
    #[error("line {line}: {source}")]
    Hex {
        line: u64,
        #[source]
        source: HexError,
    },
    #[error("line {line}: block decode failed: {source}")]
    Decode {
        line: u64,
        #[source]
        source: bitcoin_rs_consensus::primitives::DecodeError,
    },
    #[error("line {line}: UTXO apply failed: {source}")]
    Apply {
        line: u64,
        #[source]
        source: UtxoError,
    },
    #[error("line {line}: transaction {txid} has more outputs than a vout index can address")]
    VoutOverflow { line: u64, txid: Txid },
    #[error("output {txid}:{vout} left the replayed UTXO set")]
    MissingCoin { txid: Txid, vout: u32 },
    #[error("line {line}: block {found} does not extend {expected}")]
    BrokenChain {
        line: u64,
        expected: BlockHash,
        found: BlockHash,
    },
}

#[derive(Debug)]
enum ApplyFailure {
    Utxo(UtxoError),
    VoutOverflow(Txid),
}

#[must_use]
pub fn p2pk_pubkey(script: &[u8]) -> Option<(&[u8], KeyShape)> {
    if !bitcoin_rs_consensus::script::is_p2pk(script) {
        return None;
    }
    let key = script.get(1..script.len().checked_sub(1)?)?;
    let shape = match key.len() {
        33 => KeyShape::Compressed,
        65 => KeyShape::Uncompressed,
        _ => return None,
    };
    Some((key, shape))
}

pub fn scan_blocks<R: BufRead>(mut reader: R) -> Result<ScanReport, ScanError> {
    let store = Arc::new(MemoryKvStore::new());
    let coin_store = Arc::new(CoinStore::open(store.clone(), 64 * 1024 * 1024));
    let mut line = 0_u64;
    let mut tip_height = 0_u32;
    let mut previous: Option<BlockHash> = None;
    while let Some(text) = read_block_hex(&mut reader, line + 1)? {
        let height = u32::try_from(line).map_err(|_| ScanError::TooManyBlocks)?;
        line += 1;
        let raw = hex_decode(&text).map_err(|source| ScanError::Hex { line, source })?;
        let block = ParsedBlock::parse_exact(&raw)
            .map_err(|source| ScanError::Decode { line, source })?
            .materialize();
        let found = block.header.prev_blockhash;
        let expected = previous.unwrap_or_default();
        if found != expected {
            return Err(ScanError::BrokenChain {
                line,
                expected,
                found,
            });
        }
        previous = Some(block.block_hash());
        if height > 0 {
            apply_block(&coin_store, &block, height).map_err(|failure| match failure {
                ApplyFailure::Utxo(source) => ScanError::Apply { line, source },
                ApplyFailure::VoutOverflow(txid) => ScanError::VoutOverflow { line, txid },
            })?;
        }
        tip_height = height;
    }
    let (utxo_outputs, p2pk) = collect_p2pk(&store)?;
    let p2pk_value_sat = p2pk
        .iter()
        .fold(0_u64, |total, coin| total.saturating_add(coin.value_sat));
    Ok(ScanReport {
        blocks: u32::try_from(line).unwrap_or(u32::MAX),
        tip_height,
        utxo_outputs,
        p2pk_outputs: p2pk.len(),
        p2pk_value_sat,
        p2pk,
    })
}

fn apply_block(coin_store: &CoinStore, block: &Block, height: u32) -> Result<(), ApplyFailure> {
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    let same_block = same_block_spends(block, &txids);
    let mut changes: BlockChanges<&TxOut> = BlockChanges::with_capacity(
        block.txs.iter().map(|tx| tx.outputs.len()).sum(),
        block
            .txs
            .iter()
            .map(|tx| tx.inputs.len())
            .sum::<usize>()
            .saturating_sub(block.txs.len()),
    );
    for (tx, txid) in block.txs.iter().zip(&txids) {
        let coinbase = tx.is_coinbase();
        for (index, txout) in tx.outputs.iter().enumerate() {
            let vout = u32::try_from(index).map_err(|_| ApplyFailure::VoutOverflow(*txid))?;
            let outpoint = OutPoint::new(*txid, vout);
            if same_block.contains(&outpoint) {
                continue;
            }
            let script = txout.script_pubkey.as_bytes();
            if bitcoin_rs_consensus::script::is_op_return(script)
                || script.len() > bitcoin_rs_consensus::script::MAX_SCRIPT_SIZE
            {
                continue;
            }
            changes.add(UtxoAdd::new(outpoint, txout, coinbase, height));
        }
        if coinbase {
            continue;
        }
        for input in &tx.inputs {
            if same_block.contains(&input.previous_output) {
                continue;
            }
            changes.remove(input.previous_output);
        }
    }
    populate_block_changes(coin_store, &changes).map_err(ApplyFailure::Utxo)
}

fn same_block_spends(block: &Block, txids: &[Txid]) -> HashSet<OutPoint> {
    let created: HashSet<Txid> = txids.iter().copied().collect();
    block
        .txs
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .flat_map(|tx| tx.inputs.iter())
        .map(|input| input.previous_output)
        .filter(|outpoint| created.contains(&outpoint.txid))
        .collect()
}

fn collect_p2pk(store: &MemoryKvStore) -> Result<(usize, Vec<P2pkCoin>), ScanError> {
    use bitcoin_rs_storage::KvStore;
    let mut total_outputs = 0;
    let mut coins = Vec::new();
    let iter = store
        .iter_prefix(ColumnFamily::Coins, &[])
        .map_err(|e| ScanError::Apply {
            line: 0,
            source: UtxoError::Storage(e),
        })?;
    for pair in iter {
        let (_key, val) = pair.map_err(|e| ScanError::Apply {
            line: 0,
            source: UtxoError::Storage(e),
        })?;
        let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
            val.to_vec().into_boxed_slice(),
        )
        .map_err(|e| ScanError::Apply { line: 0, source: e })?;
        let txid = record.txid();
        for out in record.outputs() {
            total_outputs += 1;
            if let Some((pubkey, shape)) = p2pk_pubkey(out.script_pubkey) {
                coins.push(P2pkCoin {
                    txid: txid.to_string(),
                    vout: out.vout,
                    height: out.height,
                    value_sat: out.value,
                    key: shape,
                    pubkey: hex_encode(pubkey),
                });
            }
        }
    }
    coins.sort_by(|left, right| {
        (left.height, &left.txid, left.vout).cmp(&(right.height, &right.txid, right.vout))
    });
    Ok((total_outputs, coins))
}

fn read_block_hex<R: BufRead>(reader: &mut R, line: u64) -> Result<Option<String>, ScanError> {
    let limit = u64::try_from(MAX_BLOCK_HEX_BYTES).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    let read = reader
        .by_ref()
        .take(limit + 1)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.last() != Some(&b'\n') && read > MAX_BLOCK_HEX_BYTES {
        return Err(ScanError::LineTooLong { line });
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(ScanError::EmptyLine { line });
    }
    let text = String::from_utf8(bytes).map_err(|_| ScanError::NotText { line })?;
    Ok(Some(text))
}
