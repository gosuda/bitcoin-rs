use std::collections::HashSet;
use std::io::{self, BufRead, Read};

use bitcoin_rs_primitives::hex::{HexError, hex_decode, hex_encode};
use bitcoin_rs_primitives::layout::ParsedBlock;
use bitcoin_rs_primitives::{Block, BlockHash, OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_utxo::UtxoError;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd, commit_block_changes};
use serde::Serialize;
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
        source: bitcoin_rs_primitives::DecodeError,
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
    if !bitcoin_rs_script::is_p2pk(script) {
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
    let set = UtxoSet::new();
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
        if let Some(expected) = previous {
            let found = block.header.prev_blockhash;
            if found != expected {
                return Err(ScanError::BrokenChain {
                    line,
                    expected,
                    found,
                });
            }
        }
        previous = Some(block.block_hash());
        if height > 0 {
            apply_block(&set, &block, height).map_err(|failure| match failure {
                ApplyFailure::Utxo(source) => ScanError::Apply { line, source },
                ApplyFailure::VoutOverflow(txid) => ScanError::VoutOverflow { line, txid },
            })?;
        }
        tip_height = height;
    }
    let utxo_outputs = set.len();
    let p2pk = collect_p2pk(&set)?;
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

fn apply_block(set: &UtxoSet, block: &Block, height: u32) -> Result<(), ApplyFailure> {
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
            if bitcoin_rs_script::is_op_return(script)
                || script.len() > bitcoin_rs_script::MAX_SCRIPT_SIZE
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
    commit_block_changes(set, &changes, &block.block_hash().into()).map_err(ApplyFailure::Utxo)
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

fn collect_p2pk(set: &UtxoSet) -> Result<Vec<P2pkCoin>, ScanError> {
    let mut coins = set.with_stable_view(|view| -> Result<Vec<P2pkCoin>, ScanError> {
        let mut shaped: Vec<(OutPoint, KeyShape, String)> = Vec::new();
        view.for_each_all(|outpoint, script| {
            if let Some((pubkey, shape)) = p2pk_pubkey(script) {
                shaped.push((*outpoint, shape, hex_encode(pubkey)));
            }
        });
        let mut coins = Vec::with_capacity(shaped.len());
        for (outpoint, key, pubkey) in shaped {
            let coin = view.get_entry(&outpoint).ok_or(ScanError::MissingCoin {
                txid: outpoint.txid,
                vout: outpoint.vout,
            })?;
            coins.push(P2pkCoin {
                txid: outpoint.txid.to_string(),
                vout: outpoint.vout,
                height: coin.height,
                value_sat: coin.txout.value.to_sat(),
                key,
                pubkey,
            });
        }
        Ok(coins)
    })?;
    coins.sort_by(|left, right| {
        (left.height, &left.txid, left.vout).cmp(&(right.height, &right.txid, right.vout))
    });
    Ok(coins)
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
