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
use bitcoin_rs_consensus::primitives::{
    Hash256, OutPoint, Txid, encode, layout::ByteSpan, layout::ParsedBlock,
    layout::ParsedTransaction,
};

/// Pre-image of a spent coin: the fields a self-contained `ScriptLive` delete
/// must carry so rollback undo can restore the row byte-for-byte (`PRJ-11`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpentCoin<'a> {
    pub script: &'a [u8],
    pub value: u64,
    pub height: u32,
    pub coinbase: bool,
}

pub trait SpentCoins {
    fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>>;
}

pub(crate) struct NoSpentScripts;

impl SpentCoins for NoSpentScripts {
    fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
        None
    }
}
pub use bitcoin_rs_consensus::script::MAX_SCRIPT_SIZE as MAX_LIVE_SCRIPT_SIZE;
pub(super) fn pending_rows_for_block_with_header(
    block: &[u8],
    height: u32,
    capabilities: IndexCapabilities,
    spent_coins: &dyn SpentCoins,
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
    let mut live_created: Vec<LiveCreation> = Vec::new();
    let mut live_spent: Vec<([u8; 32], u32)> = Vec::new();
    let mut block_outputs: hashbrown::HashMap<([u8; 32], u32), Option<ScriptHash>> =
        hashbrown::HashMap::new();

    let ctx = BlockContext {
        height,
        height_bytes,
        capabilities,
        spent_coins,
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
        push_live_ops(&mut rows, live_created, live_spent, height, spent_coins)?;
    }
    if capabilities.contains(IndexCapability::CompactFilters) {
        let hash = encode::double_sha256(header_bytes).to_le_bytes();
        rows.filter_rows.push((
            hash,
            super::filters::build(&parsed, height, &hash, spent_coins)?,
        ));
    }
    Ok((rows, header_row))
}

pub(crate) struct CommittedBlockSpentCoins<'a> {
    map: hashbrown::HashMap<([u8; 32], u32), SpentCoin<'a>>,
}

impl<'a> CommittedBlockSpentCoins<'a> {
    #[must_use]
    pub(crate) fn new(block: &'a bitcoin_rs_storage::CommittedBlock) -> Self {
        let mut map = hashbrown::HashMap::new();
        for tx in &block.txs {
            for out in &tx.outputs {
                map.insert(
                    (tx.txid, out.vout),
                    SpentCoin {
                        script: out.script.as_ref(),
                        value: out.value,
                        height: block.height,
                        coinbase: false,
                    },
                );
            }
            for input in &tx.inputs {
                map.insert(
                    (input.txid, input.vout),
                    SpentCoin {
                        script: input.script.as_ref(),
                        value: input.value,
                        height: input.height,
                        coinbase: input.coinbase,
                    },
                );
            }
        }
        Self { map }
    }
}

impl SpentCoins for CommittedBlockSpentCoins<'_> {
    fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
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

    let mut live_created: Vec<LiveCreation> = Vec::new();
    let mut live_spent: Vec<([u8; 32], u32)> = Vec::new();
    let spent_coins = CommittedBlockSpentCoins::new(block);

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
            &spent_coins,
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
    live_created: &mut Vec<LiveCreation>,
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
            live_created.push(LiveCreation {
                txid: tx.txid,
                vout: output.vout,
                scripthash: live_admission(script),
                value: output.value,
                coinbase: tx.inputs.is_empty(),
            });
        }
    }
}

struct BlockContext<'a> {
    height: u32,
    height_bytes: [u8; crate::types::HEIGHT_SIZE],
    capabilities: IndexCapabilities,
    spent_coins: &'a dyn SpentCoins,
}

struct TxContext {
    position: crate::types::TxPosition,
    txid: [u8; 32],
}

struct LiveCreation {
    txid: [u8; 32],
    vout: u32,
    scripthash: Option<ScriptHash>,
    value: u64,
    coinbase: bool,
}

fn output_value(tx: &ParsedTransaction<'_>, output_value: ByteSpan) -> u64 {
    let bytes = tx
        .span_bytes(output_value)
        .unwrap_or_else(|| unreachable!("output value span belongs to the parsed image"));
    let raw: [u8; 8] = bytes
        .try_into()
        .unwrap_or_else(|_| unreachable!("the layout parser fixes output values at 8 bytes"));
    u64::from_le_bytes(raw)
}

fn transaction_is_coinbase(tx: &ParsedTransaction<'_>) -> bool {
    let Some(first) = tx.inputs().first() else {
        return false;
    };
    if tx.inputs().len() != 1 {
        return false;
    }
    let outpoint = tx
        .span_bytes(first.outpoint())
        .unwrap_or_else(|| unreachable!("input span belongs to the parsed image"));
    let (prevout_txid, vout_bytes) = outpoint.split_at(32);
    let vout = u32::from_le_bytes(
        vout_bytes
            .try_into()
            .unwrap_or_else(|_| unreachable!("an outpoint vout is four bytes")),
    );
    is_null_prevout(prevout_txid, vout)
}

fn process_transaction(
    tx: &ParsedTransaction<'_>,
    ctx: &BlockContext<'_>,
    rows: &mut PendingRows,
    block_outputs: &mut hashbrown::HashMap<([u8; 32], u32), Option<ScriptHash>>,
    live_created: &mut Vec<LiveCreation>,
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
    let coinbase = transaction_is_coinbase(tx);

    let mut pending_live: Vec<(u32, Option<ScriptHash>, u64)> = Vec::new();
    process_inputs(tx, ctx, &tx_ctx, rows, block_outputs, live_spent)?;
    process_outputs(tx, ctx, &tx_ctx, rows, block_outputs, &mut pending_live);

    if ctx.capabilities.contains(IndexCapability::TxLookup) || !pending_live.is_empty() {
        for (vout, scripthash, value) in pending_live {
            live_created.push(LiveCreation {
                txid: tx_ctx.txid,
                vout,
                scripthash,
                value,
                coinbase,
            });
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
                    ctx.spent_coins
                        .spent_coin(&previous_txid, vout)
                        .ok_or(IndexError::MissingSpentCoin {
                            txid: previous_txid,
                            vout,
                            height: ctx.height,
                        })?
                        .script,
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
    tx: &ParsedTransaction<'_>,
    ctx: &BlockContext<'_>,
    tx_ctx: &TxContext,
    rows: &mut PendingRows,
    block_outputs: &mut hashbrown::HashMap<([u8; 32], u32), Option<ScriptHash>>,
    pending_live: &mut Vec<(u32, Option<ScriptHash>, u64)>,
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
            pending_live.push((
                vout,
                live_admission(script),
                output_value(tx, output.value()),
            ));
        }
    }
}

fn push_live_ops(
    rows: &mut PendingRows,
    created: Vec<LiveCreation>,
    spent: Vec<([u8; 32], u32)>,
    height: u32,
    spent_coins: &dyn SpentCoins,
) -> Result<(), IndexError> {
    let created_keys: hashbrown::HashSet<([u8; 32], u32)> = created
        .iter()
        .map(|creation| (creation.txid, creation.vout))
        .collect();
    let mut cancelled = hashbrown::HashSet::new();
    let mut deletes = Vec::new();
    for (txid, vout) in spent {
        if created_keys.contains(&(txid, vout)) {
            cancelled.insert((txid, vout));
            continue;
        }
        let coin = spent_coins
            .spent_coin(&txid, vout)
            .ok_or(IndexError::MissingSpentCoin { txid, vout, height })?;
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout);
        deletes.push(LiveOp::Delete {
            row: crate::types::ScriptLiveRow::new(
                ScriptHash::from_script_bytes(coin.script),
                &outpoint,
            ),
            coin: crate::types::ScriptLiveCoin::new(
                ScriptHash::from_script_bytes(coin.script),
                coin.value,
                coin.height,
                coin.coinbase,
            ),
        });
    }
    for creation in created {
        if cancelled.contains(&(creation.txid, creation.vout)) {
            continue;
        }
        let Some(scripthash) = creation.scripthash else {
            continue;
        };
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&creation.txid)), creation.vout);
        if let Some(old_coin) = spent_coins.spent_coin(&creation.txid, creation.vout) {
            rows.live_ops.push(LiveOp::Delete {
                row: crate::types::ScriptLiveRow::new(
                    ScriptHash::from_script_bytes(old_coin.script),
                    &outpoint,
                ),
                coin: crate::types::ScriptLiveCoin::new(
                    ScriptHash::from_script_bytes(old_coin.script),
                    old_coin.value,
                    old_coin.height,
                    old_coin.coinbase,
                ),
            });
        }
        rows.live_ops.push(LiveOp::Insert {
            row: crate::types::ScriptLiveRow::new(scripthash, &outpoint),
            coin: crate::types::ScriptLiveCoin::new(
                scripthash,
                creation.value,
                height,
                creation.coinbase,
            ),
        });
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
