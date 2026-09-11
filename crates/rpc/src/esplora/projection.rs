//! Consistent chain, transaction, and script-activity projections for Esplora.

use core::str::FromStr as _;
use std::sync::Arc;

use crate::script_util::{
    instructions, is_op_return, is_p2pk, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh,
};
use bitcoin::{Address, Network as BitcoinNetwork, Script};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_mempool::ScriptHash as MempoolScriptHash;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxOut, Txid, deserialize,
};

use crate::context::{Context, ScriptHistoryRecord, ScriptIndexRecord, TxQueryError};
use crate::rest::Response;

use super::http::{bad, internal, not_found, query_error, unavailable};
use super::model::{
    BlockValue, ScriptStats, TransactionInput, TransactionOutput, TransactionStatus,
    TransactionValue, UtxoValue,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct Confirmation {
    pub height: u32,
    pub hash: BlockHash,
    pub time: u32,
}

impl From<Confirmation> for TransactionStatus {
    fn from(value: Confirmation) -> Self {
        Self {
            confirmed: true,
            block_height: Some(value.height),
            block_hash: Some(value.hash.to_string()),
            block_time: Some(value.time),
        }
    }
}

#[derive(Clone)]
pub(super) struct ConfirmedActivity {
    pub record: ScriptHistoryRecord,
    pub confirmation: Confirmation,
}

pub(super) struct ScriptActivity {
    pub confirmed: Vec<ConfirmedActivity>,
    pub confirmed_funding: Vec<ScriptIndexRecord>,
    pub confirmed_unspent: Vec<ScriptIndexRecord>,
    pub mempool: Vec<Arc<Tx>>,
}

impl ScriptActivity {
    /// Sums the confirmed funding rows the script index already resolved.
    ///
    /// Reading one transaction per history entry would answer the same
    /// question, but each read is a separate index query with its own budget,
    /// so a script with a long history turns one HTTP request into unbounded
    /// storage I/O. The rows carry the values; the snapshot is the bound.
    pub(super) fn chain_stats(&self) -> ScriptStats {
        let funded_txo_count = u64::try_from(self.confirmed_funding.len()).unwrap_or(u64::MAX);
        let funded_txo_sum = self
            .confirmed_funding
            .iter()
            .fold(0_u64, |sum, output| sum.saturating_add(output.value));
        let unspent_count = u64::try_from(self.confirmed_unspent.len()).unwrap_or(u64::MAX);
        let unspent_sum = self
            .confirmed_unspent
            .iter()
            .fold(0_u64, |sum, output| sum.saturating_add(output.value));
        ScriptStats {
            tx_count: u64::try_from(self.confirmed.len()).unwrap_or(u64::MAX),
            funded_txo_count,
            funded_txo_sum,
            spent_txo_count: funded_txo_count.saturating_sub(unspent_count),
            spent_txo_sum: funded_txo_sum.saturating_sub(unspent_sum),
        }
    }

    pub(super) fn mempool_stats(&self, script_hash: ScriptHash) -> ScriptStats {
        let mut stats = ScriptStats {
            tx_count: u64::try_from(self.mempool.len()).unwrap_or(u64::MAX),
            ..ScriptStats::default()
        };
        let mut target_outputs = std::collections::BTreeMap::new();
        for output in &self.confirmed_unspent {
            target_outputs.insert((output.txid, output.vout), output.value);
        }
        for transaction in &self.mempool {
            let txid = transaction.txid();
            for (vout, output) in transaction.outputs.iter().enumerate() {
                if ScriptHash::new(&output.script_pubkey) != script_hash {
                    continue;
                }
                stats.funded_txo_count = stats.funded_txo_count.saturating_add(1);
                stats.funded_txo_sum = stats.funded_txo_sum.saturating_add(output.value.to_sat());
                if let Ok(vout) = u32::try_from(vout) {
                    target_outputs.insert((txid, vout), output.value.to_sat());
                }
            }
        }
        for input in self
            .mempool
            .iter()
            .flat_map(|transaction| &transaction.inputs)
        {
            if let Some(value) =
                target_outputs.remove(&(input.previous_output.txid, input.previous_output.vout))
            {
                stats.spent_txo_count = stats.spent_txo_count.saturating_add(1);
                stats.spent_txo_sum = stats.spent_txo_sum.saturating_add(value);
            }
        }
        stats
    }
}

pub(super) struct Projection<'a> {
    pub(super) ctx: &'a Context,
}

impl<'a> Projection<'a> {
    pub(super) const fn new(ctx: &'a Context) -> Self {
        Self { ctx }
    }

    pub(super) fn required_transaction(
        &self,
        text_id: &str,
    ) -> Result<(Tx, Option<Confirmation>), Response> {
        let txid = Txid::from_str(text_id).map_err(|_| bad("txid must be 64 hex characters"))?;
        self.transaction(&txid)?.ok_or_else(not_found)
    }

    pub(super) fn transaction(
        &self,
        txid: &Txid,
    ) -> Result<Option<(Tx, Option<Confirmation>)>, Response> {
        if let Some(transaction) = self.ctx.mempool.read().transaction_by_txid(txid) {
            return Ok(Some(((*transaction).clone(), None)));
        }
        if let Some(transaction) = self.ctx.transactions.read().get(txid).cloned() {
            return self
                .cached_confirmation(txid)
                .map(|confirmation| Some((transaction, confirmation)));
        }
        let index = self
            .ctx
            .esplora_tx_index
            .as_ref()
            .ok_or_else(|| unavailable("transaction lookup index is disabled"))?;
        let transaction = index.transaction(txid).map_err(query_error)?;
        transaction.map_or(Ok(None), |transaction| {
            self.confirmation(txid).and_then(|confirmation| {
                confirmation.map_or_else(
                    || Err(unavailable("transaction confirmation unavailable")),
                    |confirmation| Ok(Some((transaction, Some(confirmation)))),
                )
            })
        })
    }

    pub(super) fn confirmed_transaction(&self, txid: &Txid) -> Result<Tx, Response> {
        self.ctx
            .esplora_tx_index
            .as_ref()
            .ok_or_else(|| unavailable("transaction lookup index is disabled"))?
            .transaction(txid)
            .map_err(query_error)?
            .ok_or_else(|| unavailable("confirming transaction unavailable"))
    }

    /// Resolves confirmation only against the current applied chain.
    pub(super) fn confirmation(&self, txid: &Txid) -> Result<Option<Confirmation>, Response> {
        if self.ctx.mempool.read().transaction_by_txid(txid).is_some() {
            return Ok(None);
        }
        if self.ctx.transactions.read().contains_key(txid) {
            return self.cached_confirmation(txid);
        }
        let index = self
            .ctx
            .esplora_tx_index
            .as_ref()
            .ok_or_else(|| unavailable("transaction lookup index is disabled"))?;
        Ok(index
            .transaction_height(txid)
            .map_err(query_error)?
            .and_then(|height| self.confirmation_at_height(height)))
    }

    /// Resolves a broadcast-cached transaction's confirmation, if it can.
    ///
    /// The cache is a broadcast staging area, not chain state: it proves the
    /// node accepted the transaction, never that the chain did or did not
    /// confirm it. Only the transaction index answers that, so with the index
    /// disabled this reports "unconfirmed", which is also the only reason
    /// `/tx/:id` works at all in that configuration.
    fn cached_confirmation(&self, txid: &Txid) -> Result<Option<Confirmation>, Response> {
        let Some(index) = self.ctx.esplora_tx_index.as_ref() else {
            return Ok(None);
        };
        Ok(index
            .transaction_height(txid)
            .map_err(query_error)?
            .and_then(|height| self.confirmation_at_height(height)))
    }

    pub(super) fn confirmation_at_height(&self, height: u32) -> Option<Confirmation> {
        let record = self.ctx.block_by_height(height)?;
        Some(Confirmation {
            height,
            hash: record.hash,
            time: record.time,
        })
    }

    pub(super) fn status_value(confirmation: Option<Confirmation>) -> TransactionStatus {
        confirmation.map_or_else(TransactionStatus::unconfirmed, TransactionStatus::from)
    }

    pub(super) fn transaction_value(
        &self,
        transaction: &Tx,
        confirmation: Option<Confirmation>,
    ) -> Result<TransactionValue, Response> {
        let mut input_value = 0_u64;
        let mut inputs = Vec::with_capacity(transaction.inputs.len());
        for input in &transaction.inputs {
            let previous_output = input.previous_output;
            let coinbase =
                previous_output.txid == Txid::default() && previous_output.vout == u32::MAX;
            let previous = if coinbase {
                None
            } else {
                let output = self
                    .prevout(&previous_output)?
                    .ok_or_else(|| unavailable("previous transaction unavailable"))?;
                input_value = input_value.saturating_add(output.value.to_sat());
                Some(output)
            };
            let (redeem, witness_script) = inner_scripts(input, previous.as_ref());
            inputs.push(TransactionInput {
                txid: previous_output.txid.to_string(),
                vout: previous_output.vout,
                prevout: previous
                    .as_ref()
                    .map(|output| self.transaction_output(output)),
                scriptsig: hex_encode(&input.script_sig),
                scriptsig_asm: script_asm(&input.script_sig),
                witness: (!input.witness.is_empty()).then(|| {
                    input
                        .witness
                        .iter()
                        .map(Vec::as_slice)
                        .map(hex_encode)
                        .collect()
                }),
                is_coinbase: coinbase,
                sequence: input.sequence.to_consensus(),
                inner_redeemscript_asm: redeem.as_deref().map(script_asm),
                inner_witnessscript_asm: witness_script.as_deref().map(script_asm),
            });
        }
        let outputs = transaction
            .outputs
            .iter()
            .map(|output| self.transaction_output(output))
            .collect();
        let output_value = transaction.outputs.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        Ok(TransactionValue {
            txid: transaction.txid().to_string(),
            version: transaction.version.cast_unsigned(),
            locktime: transaction.lock_time.to_consensus(),
            vin: inputs,
            vout: outputs,
            size: u32::try_from(transaction.total_size()).unwrap_or(u32::MAX),
            weight: transaction.weight(),
            fee: input_value.saturating_sub(output_value),
            status: Self::status_value(confirmation),
        })
    }

    pub(super) fn transaction_output(&self, output: &TxOut) -> TransactionOutput {
        let script = &output.script_pubkey;
        TransactionOutput {
            scriptpubkey: hex_encode(script),
            scriptpubkey_asm: script_asm(script),
            scriptpubkey_type: script_type(script),
            scriptpubkey_address: Address::from_script(
                Script::from_bytes(script),
                self.bitcoin_network(),
            )
            .ok()
            .map(|address| address.to_string()),
            value: output.value.to_sat(),
        }
    }

    pub(super) fn prevout(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, Response> {
        if let Some(transaction) = self.ctx.mempool.read().transaction_by_txid(&outpoint.txid) {
            return Ok(transaction
                .outputs
                .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
                .cloned());
        }
        if let Some(transaction) = self.ctx.transactions.read().get(&outpoint.txid) {
            return Ok(transaction
                .outputs
                .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
                .cloned());
        }
        let index = self
            .ctx
            .esplora_tx_index
            .as_ref()
            .ok_or_else(|| unavailable("transaction lookup index is disabled"))?;
        let Some(transaction) = index.transaction(&outpoint.txid).map_err(query_error)? else {
            return Ok(None);
        };
        Ok(transaction
            .outputs
            .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
            .cloned())
    }

    pub(super) fn block_value(
        &self,
        record: &crate::context::BlockRecord,
    ) -> Result<BlockValue, Response> {
        let header = record
            .header_bytes()
            .and_then(|bytes| deserialize::<Header>(bytes).ok())
            .ok_or_else(|| unavailable("block header unavailable"))?;
        let bytes = self
            .ctx
            .block_body_bytes(record)
            .ok_or_else(|| unavailable("block body unavailable"))?;
        let block =
            deserialize::<Block>(&bytes).map_err(|_| internal("stored block body is corrupt"))?;
        Ok(BlockValue {
            id: record.hash.to_string(),
            height: record.height,
            version: header.version.cast_unsigned(),
            timestamp: header.time,
            tx_count: u32::try_from(block.txs.len()).unwrap_or(u32::MAX),
            size: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            weight: block.weight(),
            merkle_root: header.merkle_root.to_string(),
            previousblockhash: (header.prev_blockhash != BlockHash::default())
                .then(|| header.prev_blockhash.to_string()),
            mediantime: self
                .ctx
                .median_time_past_for_hash(Hash256::from(record.hash))
                .unwrap_or(header.time),
            nonce: header.nonce,
            bits: header.bits.to_consensus(),
            difficulty: self.ctx.difficulty_for_bits(header.bits),
        })
    }

    pub(super) fn required_block(
        &self,
        text_hash: &str,
    ) -> Result<(crate::context::BlockRecord, Block), Response> {
        let record = self.required_block_record(text_hash)?;
        let bytes = self
            .ctx
            .block_body_bytes(&record)
            .ok_or_else(|| unavailable("block body unavailable"))?;
        let block = deserialize(&bytes).map_err(|_| internal("stored block body is corrupt"))?;
        Ok((record, block))
    }

    pub(super) fn required_block_record(
        &self,
        text_hash: &str,
    ) -> Result<crate::context::BlockRecord, Response> {
        let hash = bitcoin_rs_primitives::Hash256::from_str(text_hash)
            .map_err(|_| bad("block hash must be 64 hex characters"))?;
        self.ctx.block_by_hash(hash).ok_or_else(not_found)
    }

    pub(super) fn script_activity(
        &self,
        script_hash: ScriptHash,
    ) -> Result<ScriptActivity, Response> {
        let index = self
            .ctx
            .script_index
            .as_ref()
            .ok_or_else(|| unavailable("script index is disabled"))?;
        let snapshot = index.history_snapshot(script_hash).map_err(query_error)?;
        let mut confirmed = snapshot
            .history
            .into_iter()
            .map(|record| {
                let confirmation = self
                    .confirmation_at_height(record.height)
                    .ok_or_else(|| unavailable("confirming block unavailable"))?;
                Ok(ConfirmedActivity {
                    record,
                    confirmation,
                })
            })
            .collect::<Result<Vec<_>, Response>>()?;
        confirmed.sort_by(|left, right| {
            right
                .record
                .height
                .cmp(&left.record.height)
                .then_with(|| right.record.txid.cmp(&left.record.txid))
        });
        confirmed.dedup_by_key(|activity| activity.record.txid);

        let confirmed_unspent = index.unspent_outputs(script_hash).map_err(query_error)?;
        let mempool = self.mempool_activity(script_hash, &confirmed_unspent);
        Ok(ScriptActivity {
            confirmed,
            confirmed_funding: snapshot.funding,
            confirmed_unspent,
            mempool,
        })
    }

    pub(super) fn script_utxos(&self, script_hash: ScriptHash) -> Result<Vec<UtxoValue>, Response> {
        let mut confirmed = self
            .ctx
            .script_index
            .as_ref()
            .ok_or_else(|| unavailable("script index is disabled"))?
            .unspent_outputs(script_hash)
            .map_err(query_error)?;
        let pool = self.ctx.mempool.read();
        confirmed
            .retain(|record| !pool.is_outpoint_spent(&OutPoint::new(record.txid, record.vout)));
        let mut outputs = confirmed
            .into_iter()
            .map(|record| {
                let status = self
                    .confirmation_at_height(record.height)
                    .map(TransactionStatus::from)
                    .ok_or_else(|| unavailable("funding block unavailable"))?;
                Ok(UtxoValue {
                    txid: record.txid.to_string(),
                    vout: record.vout,
                    status,
                    value: record.value,
                })
            })
            .collect::<Result<Vec<_>, Response>>()?;
        let mempool_hash = MempoolScriptHash::from_byte_array(script_hash.to_byte_array());
        for entry in pool.entries_funding_script(mempool_hash) {
            for (vout, output) in entry.tx.outputs.iter().enumerate() {
                let Ok(vout) = u32::try_from(vout) else {
                    continue;
                };
                if MempoolScriptHash::from_script(&output.script_pubkey) == mempool_hash
                    && !pool.is_outpoint_spent(&OutPoint::new(entry.txid, vout))
                {
                    outputs.push(UtxoValue {
                        txid: entry.txid.to_string(),
                        vout,
                        status: TransactionStatus::unconfirmed(),
                        value: output.value.to_sat(),
                    });
                }
            }
        }
        drop(pool);
        Ok(outputs)
    }

    pub(super) fn capture_chain_view(&self) -> Option<Arc<TipSnapshot>> {
        self.ctx.applied_tip.load_full()
    }

    pub(super) fn ensure_chain_view(
        &self,
        expected: Option<&Arc<TipSnapshot>>,
    ) -> Result<(), Response> {
        let current = self.ctx.applied_tip.load_full();
        let unchanged = match (expected, current.as_ref()) {
            (Some(expected), Some(current)) => Arc::ptr_eq(expected, current),
            (None, None) => true,
            _ => false,
        };
        if unchanged {
            Ok(())
        } else {
            Err(query_error(TxQueryError::Retry))
        }
    }

    fn mempool_activity(
        &self,
        script_hash: ScriptHash,
        confirmed_unspent: &[ScriptIndexRecord],
    ) -> Vec<Arc<Tx>> {
        let pool = self.ctx.mempool.read();
        let mempool_hash = MempoolScriptHash::from_byte_array(script_hash.to_byte_array());
        // Keyed by txid so a transaction reached through both the funding index
        // and the spend scan is selected once. The entry is captured here rather
        // than its txid alone: resolving a txid back to an entry afterwards
        // costs a scan of the whole pool per selected transaction.
        let mut selected = std::collections::BTreeMap::new();
        let mut outputs = confirmed_unspent
            .iter()
            .map(|record| (record.txid, record.vout))
            .collect::<std::collections::BTreeSet<_>>();
        for entry in pool.entries_funding_script(mempool_hash) {
            selected.insert(entry.txid, (entry.time, Arc::clone(&entry.tx)));
            for (vout, output) in entry.tx.outputs.iter().enumerate() {
                if MempoolScriptHash::from_script(&output.script_pubkey) == mempool_hash
                    && let Ok(vout) = u32::try_from(vout)
                {
                    outputs.insert((entry.txid, vout));
                }
            }
        }
        for (txid, vout) in &outputs {
            if let Ok(Some(spender)) = pool.outpoint_spender(OutPoint::new(*txid, *vout)) {
                selected.insert(
                    spender.entry.txid,
                    (spender.entry.time, Arc::clone(&spender.entry.tx)),
                );
            }
        }
        drop(pool);
        let mut entries = selected
            .into_iter()
            .map(|(txid, (time, transaction))| (time, txid, transaction))
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1))
        });
        entries
            .into_iter()
            .map(|(_, _, transaction)| transaction)
            .collect()
    }

    pub(super) const fn bitcoin_network(&self) -> BitcoinNetwork {
        match self.ctx.chain_network {
            Network::Mainnet => BitcoinNetwork::Bitcoin,
            Network::Testnet3 => BitcoinNetwork::Testnet,
            Network::Testnet4 => BitcoinNetwork::Testnet4,
            Network::Signet => BitcoinNetwork::Signet,
            Network::Regtest => BitcoinNetwork::Regtest,
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

fn script_asm(script: &[u8]) -> String {
    Script::from_bytes(script).to_asm_string()
}

fn script_type(script: &[u8]) -> &'static str {
    if script.is_empty() {
        "empty"
    } else if is_op_return(script) {
        "op_return"
    } else if is_p2pk(script) {
        "p2pk"
    } else if is_p2pkh(script) {
        "p2pkh"
    } else if is_p2sh(script) {
        "p2sh"
    } else if is_p2wpkh(script) {
        "v0_p2wpkh"
    } else if is_p2wsh(script) {
        "v0_p2wsh"
    } else if is_p2tr(script) {
        "v1_p2tr"
    } else {
        "unknown"
    }
}

fn inner_scripts(
    input: &bitcoin_rs_primitives::TxIn,
    prevout: Option<&TxOut>,
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let redeem = prevout
        .filter(|output| is_p2sh(&output.script_pubkey))
        .and_then(|_| instructions(&input.script_sig).last())
        .and_then(Result::ok)
        .and_then(|instruction| match instruction {
            crate::script_util::Instruction::PushBytes(bytes) => Some(bytes.to_vec()),
            crate::script_util::Instruction::Op(_) => None,
        });
    let is_witness_script = prevout.is_some_and(|output| is_p2wsh(&output.script_pubkey))
        || redeem.as_deref().is_some_and(is_p2wsh);
    let witness_script = is_witness_script
        .then(|| input.witness.last())
        .flatten()
        .cloned();
    (redeem, witness_script)
}
