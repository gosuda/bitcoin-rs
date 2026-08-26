//! Consistent chain, transaction, and script-activity projections for Esplora.

use core::ops::Bound;
use core::str::FromStr as _;
use std::sync::Arc;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::script::Instruction;
use bitcoin::{Block, OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_mempool::ScriptHash as MempoolScriptHash;

use super::model::{
    BlockValue, ScriptStats, TransactionInput, TransactionOutput, TransactionStatus,
    TransactionValue, UtxoValue,
};
use super::{
    Context, Response, ScriptHistoryRecord, ScriptIndexRecord, bad, internal, not_found,
    query_error, unavailable,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct Confirmation {
    pub height: u32,
    pub hash: bitcoin_rs_primitives::Hash256,
    pub time: u32,
}

impl From<Confirmation> for TransactionStatus {
    fn from(value: Confirmation) -> Self {
        Self {
            confirmed: true,
            block_height: Some(value.height),
            block_hash: Some(value.hash.to_string_be()),
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
    pub mempool: Vec<Arc<Transaction>>,
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
            target_outputs.insert(OutPoint::new(output.txid, output.vout), output.value);
        }
        for transaction in &self.mempool {
            let txid = transaction.compute_txid();
            for (vout, output) in transaction.output.iter().enumerate() {
                if ScriptHash::new(&output.script_pubkey) != script_hash {
                    continue;
                }
                stats.funded_txo_count = stats.funded_txo_count.saturating_add(1);
                stats.funded_txo_sum = stats.funded_txo_sum.saturating_add(output.value.to_sat());
                if let Ok(vout) = u32::try_from(vout) {
                    target_outputs.insert(OutPoint::new(txid, vout), output.value.to_sat());
                }
            }
        }
        for input in self
            .mempool
            .iter()
            .flat_map(|transaction| &transaction.input)
        {
            if let Some(value) = target_outputs.remove(&input.previous_output) {
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
    ) -> Result<(Transaction, Option<Confirmation>), Response> {
        let txid = Txid::from_str(text_id).map_err(|_| bad("txid must be 64 hex characters"))?;
        self.transaction(&txid)?.ok_or_else(not_found)
    }

    pub(super) fn transaction(
        &self,
        txid: &Txid,
    ) -> Result<Option<(Transaction, Option<Confirmation>)>, Response> {
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

    pub(super) fn confirmed_transaction(&self, txid: &Txid) -> Result<Transaction, Response> {
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
        transaction: &Transaction,
        confirmation: Option<Confirmation>,
    ) -> Result<TransactionValue, Response> {
        let mut input_value = 0_u64;
        let mut inputs = Vec::with_capacity(transaction.input.len());
        for input in &transaction.input {
            let coinbase = input.previous_output.is_null();
            let previous = if coinbase {
                None
            } else {
                let output = self
                    .prevout(&input.previous_output)?
                    .ok_or_else(|| unavailable("previous transaction unavailable"))?;
                input_value = input_value.saturating_add(output.value.to_sat());
                Some(output)
            };
            let (redeem, witness_script) = inner_scripts(input, previous.as_ref());
            inputs.push(TransactionInput {
                txid: input.previous_output.txid.to_string(),
                vout: input.previous_output.vout,
                prevout: previous
                    .as_ref()
                    .map(|output| self.transaction_output(output)),
                scriptsig: input.script_sig.as_bytes().to_lower_hex_string(),
                scriptsig_asm: input.script_sig.to_asm_string(),
                witness: (!input.witness.is_empty()).then(|| {
                    input
                        .witness
                        .iter()
                        .map(|item| item.to_lower_hex_string())
                        .collect()
                }),
                is_coinbase: coinbase,
                sequence: input.sequence.to_consensus_u32(),
                inner_redeemscript_asm: redeem.map(|script| script.to_asm_string()),
                inner_witnessscript_asm: witness_script.map(|script| script.to_asm_string()),
            });
        }
        let outputs = transaction
            .output
            .iter()
            .map(|output| self.transaction_output(output))
            .collect();
        let output_value = transaction.output.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        Ok(TransactionValue {
            txid: transaction.compute_txid().to_string(),
            version: transaction.version.0.cast_unsigned(),
            locktime: transaction.lock_time.to_consensus_u32(),
            vin: inputs,
            vout: outputs,
            size: u32::try_from(serialize(transaction).len()).unwrap_or(u32::MAX),
            weight: transaction.weight().to_wu(),
            fee: input_value.saturating_sub(output_value),
            status: Self::status_value(confirmation),
        })
    }

    pub(super) fn transaction_output(&self, output: &TxOut) -> TransactionOutput {
        let script = &output.script_pubkey;
        TransactionOutput {
            scriptpubkey: script.as_bytes().to_lower_hex_string(),
            scriptpubkey_asm: script.to_asm_string(),
            scriptpubkey_type: script_type(script),
            scriptpubkey_address: bitcoin::Address::from_script(script, self.bitcoin_network())
                .ok()
                .map(|address| address.to_string()),
            value: output.value.to_sat(),
        }
    }

    pub(super) fn prevout(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, Response> {
        if let Some(transaction) = self.ctx.mempool.read().transaction_by_txid(&outpoint.txid) {
            return Ok(transaction
                .output
                .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
                .cloned());
        }
        if let Some(transaction) = self.ctx.transactions.read().get(&outpoint.txid) {
            return Ok(transaction
                .output
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
            .output
            .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
            .cloned())
    }

    pub(super) fn block_value(
        &self,
        record: &crate::context::BlockRecord,
    ) -> Result<BlockValue, Response> {
        let header = record
            .header_bytes()
            .and_then(|bytes| deserialize::<bitcoin::block::Header>(bytes).ok())
            .ok_or_else(|| unavailable("block header unavailable"))?;
        let bytes = self
            .ctx
            .block_body_bytes(record)
            .ok_or_else(|| unavailable("block body unavailable"))?;
        let block =
            deserialize::<Block>(&bytes).map_err(|_| internal("stored block body is corrupt"))?;
        Ok(BlockValue {
            id: record.hash.to_string_be(),
            height: record.height,
            version: header.version.to_consensus().cast_unsigned(),
            timestamp: header.time,
            tx_count: u32::try_from(block.txdata.len()).unwrap_or(u32::MAX),
            size: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            weight: block.weight().to_wu(),
            merkle_root: header.merkle_root.to_string(),
            previousblockhash: (header.prev_blockhash != bitcoin::BlockHash::all_zeros())
                .then(|| header.prev_blockhash.to_string()),
            mediantime: self
                .ctx
                .median_time_past_for_hash(record.hash)
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
        // Collect spent outpoints under a brief mempool read lock, then drop
        // the lock before resolving confirmation_at_height, which performs
        // block-tree reads. Holding the mempool lock across those reads blocks
        // mempool writers (sendrawtransaction, apply) for the duration of
        // large script-UTXO renders.
        let spent_outpoints: std::collections::HashSet<OutPoint> = {
            let pool = self.ctx.mempool.read();
            confirmed
                .iter()
                .filter(|record| pool.is_outpoint_spent(&OutPoint::new(record.txid, record.vout)))
                .map(|record| OutPoint::new(record.txid, record.vout))
                .collect()
        };
        confirmed
            .retain(|record| !spent_outpoints.contains(&OutPoint::new(record.txid, record.vout)));
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
        // Re-acquire the mempool read lock briefly for the unconfirmed funding
        // scan only.
        let mempool_hash = MempoolScriptHash::from_byte_array(script_hash.to_byte_array());
        let pool = self.ctx.mempool.read();
        for (_, entry_id) in pool.funding.range((
            Bound::Included((mempool_hash, 0)),
            Bound::Included((mempool_hash, u32::MAX)),
        )) {
            let Some(entry) = pool.entry(*entry_id) else {
                continue;
            };
            for (vout, output) in entry.tx.output.iter().enumerate() {
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
            Err(query_error(super::TxQueryError::Retry))
        }
    }

    fn mempool_activity(
        &self,
        script_hash: ScriptHash,
        confirmed_unspent: &[ScriptIndexRecord],
    ) -> Vec<Arc<Transaction>> {
        let pool = self.ctx.mempool.read();
        let mempool_hash = MempoolScriptHash::from_byte_array(script_hash.to_byte_array());
        // Keyed by txid so a transaction reached through both the funding index
        // and the spend scan is selected once. The entry is captured here rather
        // than its txid alone: resolving a txid back to an entry afterwards
        // costs a scan of the whole pool per selected transaction.
        let mut selected = std::collections::BTreeMap::new();
        let mut outputs = confirmed_unspent
            .iter()
            .map(|record| OutPoint::new(record.txid, record.vout))
            .collect::<std::collections::BTreeSet<_>>();
        for (_, entry_id) in pool.funding.range((
            Bound::Included((mempool_hash, 0)),
            Bound::Included((mempool_hash, u32::MAX)),
        )) {
            if let Some(entry) = pool.entry(*entry_id) {
                selected.insert(entry.txid, (entry.time, Arc::clone(&entry.tx)));
                for (vout, output) in entry.tx.output.iter().enumerate() {
                    if MempoolScriptHash::from_script(&output.script_pubkey) == mempool_hash
                        && let Ok(vout) = u32::try_from(vout)
                    {
                        outputs.insert(OutPoint::new(entry.txid, vout));
                    }
                }
            }
        }
        for (_, entry) in &pool.entries {
            if entry
                .tx
                .input
                .iter()
                .any(|input| outputs.contains(&input.previous_output))
            {
                selected.insert(entry.txid, (entry.time, Arc::clone(&entry.tx)));
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

    pub(super) const fn bitcoin_network(&self) -> bitcoin::Network {
        match self.ctx.chain_network {
            bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
            bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
            bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
            bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
            bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
        }
    }
}

fn script_type(script: &Script) -> &'static str {
    if script.is_empty() {
        "empty"
    } else if script.is_op_return() {
        "op_return"
    } else if script.is_p2pk() {
        "p2pk"
    } else if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_p2wpkh() {
        "v0_p2wpkh"
    } else if script.is_p2wsh() {
        "v0_p2wsh"
    } else if script.is_p2tr() {
        "v1_p2tr"
    } else {
        "unknown"
    }
}

fn inner_scripts(
    input: &bitcoin::TxIn,
    prevout: Option<&TxOut>,
) -> (Option<ScriptBuf>, Option<ScriptBuf>) {
    let redeem = prevout
        .filter(|output| output.script_pubkey.is_p2sh())
        .and_then(|_| input.script_sig.instructions().last())
        .and_then(Result::ok)
        .and_then(|instruction| match instruction {
            Instruction::PushBytes(bytes) => Some(ScriptBuf::from_bytes(bytes.as_bytes().to_vec())),
            Instruction::Op(_) => None,
        });
    let is_witness_script = prevout.is_some_and(|output| output.script_pubkey.is_p2wsh())
        || redeem.as_ref().is_some_and(|script| script.is_p2wsh());
    let witness_script = is_witness_script
        .then(|| input.witness.iter().last())
        .flatten()
        .map(|bytes| ScriptBuf::from_bytes(bytes.to_vec()));
    (redeem, witness_script)
}
