use super::{
    capability::{IndexCapabilities, IndexCapability},
    error::IndexError,
    rows::{LiveOp, PendingRows, PositionedHistory, PositionedRow},
};
use crate::{
    types::HashPrefixRow, types::MAX_POSITION_END_BYTES, types::ScriptHash,
    types::ScriptHistoryOccurrence, types::SpendingPrefixRow, types::TxidRow, types::U24_MAX,
    types::encode_height, types::encode_history_height,
};
use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid, encode, layout::ParsedBlock};

pub trait SpentCoinScripts {
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]>;
}

pub(crate) struct NoSpentScripts;

impl SpentCoinScripts for NoSpentScripts {
    fn script_bytes(&self, _txid: &[u8; 32], _vout: u32) -> Option<&[u8]> {
        None
    }
}

pub use bitcoin_rs_consensus::script::MAX_SCRIPT_SIZE as MAX_LIVE_SCRIPT_SIZE;

pub(super) fn pending_rows_for_block_with_header(
    block: &[u8],
    height: u32,
    capabilities: IndexCapabilities,
    spent_scripts: &dyn SpentCoinScripts,
) -> Result<(PendingRows, [u8; crate::types::HEADER_ROW_SIZE]), IndexError> {
    let parsed = ParsedBlock::parse_exact(block).map_err(IndexError::BlockParse)?;
    let header_bytes = parsed
        .span_bytes(parsed.header_span())
        .unwrap_or_else(|| unreachable!("header span belongs to the parsed image"));
    let header_row: [u8; crate::types::HEADER_ROW_SIZE] = header_bytes
        .try_into()
        .unwrap_or_else(|_| unreachable!("the layout parser fixes the header at 80 bytes"));

    let height_bytes = encode_height(height);
    let mut rows = PendingRows::default();
    rows.header_rows.push(header_row);
    let mut live_created: Vec<([u8; 32], u32, Option<ScriptHash>)> = Vec::new();
    let mut live_spent: Vec<([u8; 32], u32)> = Vec::new();
    let mut block_outputs: hashbrown::HashMap<([u8; 32], u32), Option<ScriptHash>> =
        hashbrown::HashMap::new();

    let ctx = BlockContext {
        height,
        height_bytes,
        capabilities,
        spent_scripts,
    };
    for tx in parsed.transactions() {
        process_transaction(
            tx,
            &ctx,
            &mut rows,
            &mut block_outputs,
            &mut live_created,
            &mut live_spent,
        )?;
    }
    if capabilities.contains(IndexCapability::ScriptLive) {
        push_live_ops(&mut rows, live_created, live_spent, height, spent_scripts)?;
    }
    if capabilities.contains(IndexCapability::CompactFilters) {
        let hash = encode::double_sha256(header_bytes).to_le_bytes();
        rows.filter_rows.push((
            hash,
            super::filters::build(&parsed, height, &hash, spent_scripts)?,
        ));
    }
    Ok((rows, header_row))
}

pub(crate) struct CommittedBlockSpentScripts<'a> {
    map: hashbrown::HashMap<([u8; 32], u32), &'a [u8]>,
}

impl<'a> CommittedBlockSpentScripts<'a> {
    #[must_use]
    pub(crate) fn new(block: &'a bitcoin_rs_storage::CommittedBlock) -> Self {
        let mut map = hashbrown::HashMap::new();
        for tx in &block.txs {
            for out in &tx.outputs {
                map.insert((tx.txid, out.vout), out.script.as_ref());
            }
            for input in &tx.inputs {
                map.insert((input.txid, input.vout), input.script.as_ref());
            }
        }
        Self { map }
    }
}

impl SpentCoinScripts for CommittedBlockSpentScripts<'_> {
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]> {
        self.map.get(&(*txid, vout)).copied()
    }
}

// PRJ-01
pub(super) fn pending_rows_for_facts(
    block: &bitcoin_rs_storage::CommittedBlock,
    capabilities: IndexCapabilities,
) -> Result<(PendingRows, [u8; crate::types::HEADER_ROW_SIZE]), IndexError> {
    let header_row = block.header;
    let height_bytes = encode_height(block.height);
    let mut rows = PendingRows::default();
    rows.header_rows.push(header_row);

    let mut live_created: Vec<([u8; 32], u32, Option<ScriptHash>)> = Vec::new();
    let mut live_spent: Vec<([u8; 32], u32)> = Vec::new();
    let spent_scripts = CommittedBlockSpentScripts::new(block);

    for tx in &block.txs {
        let position = crate::types::TxPosition::new(tx.offset, tx.len);
        if capabilities.contains(IndexCapability::TxLookup) {
            rows.txid_rows.push(PositionedRow {
                row: TxidRow::row_bytes(&tx.txid, height_bytes),
                position,
            });
        }
        process_facts_inputs(
            tx,
            block.height,
            height_bytes,
            capabilities,
            position,
            &mut rows,
            &mut live_spent,
        );
        process_facts_outputs(
            tx,
            block.height,
            height_bytes,
            capabilities,
            position,
            &mut rows,
            &mut live_created,
        );
    }

    if capabilities.contains(IndexCapability::ScriptLive) {
        push_live_ops(
            &mut rows,
            live_created,
            live_spent,
            block.height,
            &spent_scripts,
        )?;
    }
    if capabilities.contains(IndexCapability::CompactFilters) {
        rows.filter_rows.push((
            block.hash,
            super::filters::build_from_facts(&block.hash, &block.txs)?,
        ));
    }
    Ok((rows, header_row))
}

fn process_facts_inputs(
    tx: &bitcoin_rs_storage::TxFacts,
    block_height: u32,
    height_bytes: [u8; crate::types::HEIGHT_SIZE],
    capabilities: IndexCapabilities,
    position: crate::types::TxPosition,
    rows: &mut PendingRows,
    live_spent: &mut Vec<([u8; 32], u32)>,
) {
    if !capabilities.contains(IndexCapability::ScriptHistory)
        && !capabilities.contains(IndexCapability::ScriptLive)
    {
        return;
    }
    let mut spent_in_tx = hashbrown::HashSet::<ScriptHash>::new();
    for input in &tx.inputs {
        if capabilities.contains(IndexCapability::ScriptHistory) {
            rows.spending_rows.push(PositionedRow {
                row: SpendingPrefixRow::row_parts(&input.txid, input.vout, height_bytes),
                position,
            });
            let scripthash = ScriptHash::from_script_bytes(&input.script);
            if spent_in_tx.insert(scripthash) {
                rows.funding_rows.push(PositionedHistory {
                    row: HashPrefixRow {
                        prefix: scripthash.prefix(),
                        height: encode_history_height(block_height),
                    },
                    occurrence: ScriptHistoryOccurrence {
                        scripthash,
                        txid: tx.txid,
                        position,
                        flags: ScriptHistoryOccurrence::SPENDING,
                    },
                });
            }
        }
        if capabilities.contains(IndexCapability::ScriptLive) {
            live_spent.push((input.txid, input.vout));
        }
    }
}

fn process_facts_outputs(
    tx: &bitcoin_rs_storage::TxFacts,
    block_height: u32,
    height_bytes: [u8; crate::types::HEIGHT_SIZE],
    capabilities: IndexCapabilities,
    position: crate::types::TxPosition,
    rows: &mut PendingRows,
    live_created: &mut Vec<([u8; 32], u32, Option<ScriptHash>)>,
) {
    if !capabilities.contains(IndexCapability::ScriptHistory)
        && !capabilities.contains(IndexCapability::ScriptLive)
    {
        return;
    }
    let mut funded_in_tx = hashbrown::HashSet::<ScriptHash>::new();
    for output in &tx.outputs {
        let script = output.script.as_ref();
        if capabilities.contains(IndexCapability::ScriptHistory) && !is_op_return_script(script) {
            let scripthash = ScriptHash::from_script_bytes(script);
            if funded_in_tx.insert(scripthash) {
                rows.funding_rows.push(PositionedHistory {
                    row: HashPrefixRow {
                        prefix: scripthash.prefix(),
                        height: encode_history_height(block_height),
                    },
                    occurrence: ScriptHistoryOccurrence {
                        scripthash,
                        txid: tx.txid,
                        position,
                        flags: ScriptHistoryOccurrence::FUNDING,
                    },
                });
            }
        }
        if capabilities.contains(IndexCapability::ScriptLive)
            && height_bytes != [0_u8; crate::types::HEIGHT_SIZE]
        {
            live_created.push((tx.txid, output.vout, live_admission(script)));
        }
    }
}

struct BlockContext<'a> {
    height: u32,
    height_bytes: [u8; crate::types::HEIGHT_SIZE],
    capabilities: IndexCapabilities,
    spent_scripts: &'a dyn SpentCoinScripts,
}

struct TxContext {
    position: crate::types::TxPosition,
    txid: [u8; 32],
}

fn process_transaction(
    tx: &bitcoin_rs_consensus::primitives::layout::ParsedTransaction<'_>,
    ctx: &BlockContext<'_>,
    rows: &mut PendingRows,
    block_outputs: &mut hashbrown::HashMap<([u8; 32], u32), Option<ScriptHash>>,
    live_created: &mut Vec<([u8; 32], u32, Option<ScriptHash>)>,
    live_spent: &mut Vec<([u8; 32], u32)>,
) -> Result<(), IndexError> {
    let span = tx.span();
    let end = u64::from(span.start()).saturating_add(u64::from(span.len()));
    let past_cap = u64::try_from(MAX_POSITION_END_BYTES).map_or(true, |cap| end > cap);
    if span.start() > U24_MAX || span.len() > U24_MAX || past_cap {
        return Err(IndexError::UnaddressablePosition {
            offset: u64::from(span.start()),
        });
    }
    let tx_ctx = TxContext {
        position: crate::types::TxPosition::new(span.start(), span.len()),
        txid: *tx.txid().as_bytes(),
    };

    let mut pending_live: Vec<(u32, Option<ScriptHash>)> = Vec::new();
    process_inputs(tx, ctx, &tx_ctx, rows, block_outputs, live_spent)?;
    process_outputs(tx, ctx, &tx_ctx, rows, block_outputs, &mut pending_live);

    if ctx.capabilities.contains(IndexCapability::TxLookup) || !pending_live.is_empty() {
        for (vout, scripthash) in pending_live {
            live_created.push((tx_ctx.txid, vout, scripthash));
        }
        if ctx.capabilities.contains(IndexCapability::TxLookup) {
            rows.txid_rows.push(PositionedRow {
                row: TxidRow::row_bytes(&tx_ctx.txid, ctx.height_bytes),
                position: tx_ctx.position,
            });
        }
    }
    Ok(())
}

fn process_inputs(
    tx: &bitcoin_rs_consensus::primitives::layout::ParsedTransaction<'_>,
    ctx: &BlockContext<'_>,
    tx_ctx: &TxContext,
    rows: &mut PendingRows,
    block_outputs: &hashbrown::HashMap<([u8; 32], u32), Option<ScriptHash>>,
    live_spent: &mut Vec<([u8; 32], u32)>,
) -> Result<(), IndexError> {
    let mut spent_in_tx = hashbrown::HashSet::<ScriptHash>::new();
    for input in tx.inputs() {
        let outpoint = tx
            .span_bytes(input.outpoint())
            .unwrap_or_else(|| unreachable!("input span belongs to the parsed image"));
        let (prevout_txid, vout_bytes) = outpoint.split_at(32);
        let vout = u32::from_le_bytes(
            vout_bytes
                .try_into()
                .unwrap_or_else(|_| unreachable!("an outpoint vout is four bytes")),
        );
        if is_null_prevout(prevout_txid, vout) {
            continue;
        }
        if ctx.capabilities.contains(IndexCapability::ScriptHistory) {
            rows.spending_rows.push(PositionedRow {
                row: SpendingPrefixRow::row_parts(prevout_txid, vout, ctx.height_bytes),
                position: tx_ctx.position,
            });
            let mut previous_txid = [0_u8; 32];
            previous_txid.copy_from_slice(prevout_txid);
            let scripthash = match block_outputs.get(&(previous_txid, vout)).copied() {
                Some(scripthash) => scripthash,
                None => Some(ScriptHash::from_script_bytes(
                    ctx.spent_scripts.script_bytes(&previous_txid, vout).ok_or(
                        IndexError::MissingSpentCoin {
                            txid: previous_txid,
                            vout,
                            height: ctx.height,
                        },
                    )?,
                )),
            };
            if let Some(scripthash) = scripthash
                && spent_in_tx.insert(scripthash)
            {
                rows.funding_rows.push(PositionedHistory {
                    row: HashPrefixRow {
                        prefix: scripthash.prefix(),
                        height: encode_history_height(ctx.height),
                    },
                    occurrence: ScriptHistoryOccurrence {
                        scripthash,
                        txid: tx_ctx.txid,
                        position: tx_ctx.position,
                        flags: ScriptHistoryOccurrence::SPENDING,
                    },
                });
            }
        }
        if ctx.capabilities.contains(IndexCapability::ScriptLive) {
            let mut txid = [0_u8; 32];
            txid.copy_from_slice(prevout_txid);
            live_spent.push((txid, vout));
        }
    }
    Ok(())
}

fn process_outputs(
    tx: &bitcoin_rs_consensus::primitives::layout::ParsedTransaction<'_>,
    ctx: &BlockContext<'_>,
    tx_ctx: &TxContext,
    rows: &mut PendingRows,
    block_outputs: &mut hashbrown::HashMap<([u8; 32], u32), Option<ScriptHash>>,
    pending_live: &mut Vec<(u32, Option<ScriptHash>)>,
) {
    let mut funded_in_tx = hashbrown::HashSet::<ScriptHash>::new();
    for (index, output) in tx.outputs().iter().enumerate() {
        let script = tx
            .span_bytes(output.script_pubkey())
            .unwrap_or_else(|| unreachable!("output span belongs to the parsed image"));
        if ctx.capabilities.contains(IndexCapability::ScriptHistory) {
            if let Ok(vout) = u32::try_from(index) {
                block_outputs.insert(
                    (tx_ctx.txid, vout),
                    (!is_op_return_script(script)).then(|| ScriptHash::from_script_bytes(script)),
                );
            }
            if !is_op_return_script(script) {
                let scripthash = ScriptHash::from_script_bytes(script);
                if funded_in_tx.insert(scripthash) {
                    rows.funding_rows.push(PositionedHistory {
                        row: HashPrefixRow {
                            prefix: scripthash.prefix(),
                            height: encode_history_height(ctx.height),
                        },
                        occurrence: ScriptHistoryOccurrence {
                            scripthash,
                            txid: tx_ctx.txid,
                            position: tx_ctx.position,
                            flags: ScriptHistoryOccurrence::FUNDING,
                        },
                    });
                }
            }
        }
        if ctx.capabilities.contains(IndexCapability::ScriptLive)
            && ctx.height_bytes != [0_u8; crate::types::HEIGHT_SIZE]
            && let Ok(vout) = u32::try_from(index)
        {
            pending_live.push((vout, live_admission(script)));
        }
    }
}

fn push_live_ops(
    rows: &mut PendingRows,
    created: Vec<([u8; 32], u32, Option<ScriptHash>)>,
    spent: Vec<([u8; 32], u32)>,
    height: u32,
    spent_scripts: &dyn SpentCoinScripts,
) -> Result<(), IndexError> {
    let created_keys: hashbrown::HashSet<([u8; 32], u32)> = created
        .iter()
        .map(|(txid, vout, _)| (*txid, *vout))
        .collect();
    let mut cancelled = hashbrown::HashSet::new();
    let mut deletes = Vec::new();
    for (txid, vout) in spent {
        if created_keys.contains(&(txid, vout)) {
            cancelled.insert((txid, vout));
            continue;
        }
        let script = spent_scripts
            .script_bytes(&txid, vout)
            .ok_or(IndexError::MissingSpentCoin { txid, vout, height })?;
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout);
        deletes.push(LiveOp::Delete(crate::types::ScriptLiveRow::new(
            ScriptHash::from_script_bytes(script),
            &outpoint,
        )));
    }
    for (txid, vout, scripthash) in created {
        if cancelled.contains(&(txid, vout)) {
            continue;
        }
        let Some(scripthash) = scripthash else {
            continue;
        };
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout);
        if let Some(old_script) = spent_scripts.script_bytes(&txid, vout) {
            rows.live_ops
                .push(LiveOp::Delete(crate::types::ScriptLiveRow::new(
                    ScriptHash::from_script_bytes(old_script),
                    &outpoint,
                )));
        }
        rows.live_ops
            .push(LiveOp::Insert(crate::types::ScriptLiveRow::new(
                scripthash, &outpoint,
            )));
    }
    rows.live_ops.extend(deletes);
    Ok(())
}

fn is_null_prevout(prevout_txid: &[u8], vout: u32) -> bool {
    vout == u32::MAX && prevout_txid.iter().all(|byte| *byte == 0)
}

#[inline]
pub(super) fn is_op_return_script(script: &[u8]) -> bool {
    matches!(script.first(), Some(0x6a))
}

fn live_admission(script: &[u8]) -> Option<ScriptHash> {
    let admitted = !is_op_return_script(script) && script.len() <= MAX_LIVE_SCRIPT_SIZE;
    admitted.then(|| ScriptHash::from_script_bytes(script))
}
