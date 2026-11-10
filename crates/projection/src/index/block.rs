use super::{
    capability::{IndexCapabilities, IndexCapability},
    error::IndexError,
    rows::{LiveOp, PendingRows},
};
use crate::{
    types::MAX_POSITION_END_BYTES, types::ScriptHash, types::U24_MAX, types::encode_height,
};
use bitcoin_rs_consensus::primitives::{
    BlockImage, Hash256, OutPoint, TransactionView, Txid, layout::ByteSpan,
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

/// `BLK-01`: the fallback path builds one owned block image per body and both
/// the live rows and the committed facts borrow from it.
pub(crate) fn parse_body(block: &[u8]) -> Result<BlockImage, IndexError> {
    BlockImage::from_raw(bitcoin_rs_storage::Bytes::copy_from_slice(block))
        .map_err(IndexError::BlockParse)
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

/// `PRJ-01`: the live rows come from the committed facts the runtime already
/// holds; this path never parses a block.
pub(super) fn pending_rows_for_facts(
    block: &bitcoin_rs_storage::CommittedBlock,
    capabilities: IndexCapabilities,
) -> Result<PendingRows, IndexError> {
    let mut rows = PendingRows::default();
    rows.header_rows.push(block.header);
    if !capabilities.contains(IndexCapability::ScriptLive) {
        return Ok(rows);
    }
    let height_bytes = encode_height(block.height);
    let mut live_created: Vec<LiveCreation> = Vec::new();
    let mut live_spent: Vec<([u8; 32], u32)> = Vec::new();
    for tx in &block.txs {
        for input in &tx.inputs {
            live_spent.push((input.txid, input.vout));
        }
        if height_bytes == [0_u8; crate::types::HEIGHT_SIZE] {
            continue;
        }
        for output in &tx.outputs {
            live_created.push(LiveCreation {
                txid: tx.txid,
                vout: output.vout,
                scripthash: live_admission(output.script.as_ref()),
                value: output.value,
                coinbase: tx.inputs.is_empty(),
            });
        }
    }
    let spent_coins = CommittedBlockSpentCoins::new(block);
    push_live_ops(
        &mut rows,
        live_created,
        live_spent,
        block.height,
        &spent_coins,
        &NoSpentScripts,
    )?;
    Ok(rows)
}

/// `BLK-01`, `BLK-04`: the body fallback derives its live rows from the one
/// block image; the caller passes the same image to `committed_block_from_image`.
pub(super) fn pending_rows_for_image(
    image: &BlockImage,
    height: u32,
    capabilities: IndexCapabilities,
    spent_coins: &dyn SpentCoins,
) -> Result<PendingRows, IndexError> {
    let mut rows = PendingRows::default();
    rows.header_rows.push(image.header_bytes());
    if !capabilities.contains(IndexCapability::ScriptLive) {
        return Ok(rows);
    }
    let height_bytes = encode_height(height);
    let mut live_created: Vec<LiveCreation> = Vec::new();
    let mut live_spent: Vec<([u8; 32], u32)> = Vec::new();
    for index in 0..image.tx_count() {
        let tx = image.tx(index);
        let txid = *tx.txid().as_bytes();
        for input in 0..tx.input_count() {
            let outpoint = tx.input_outpoint(input);
            let prevout_txid = *outpoint.txid.as_bytes();
            if is_null_prevout(&prevout_txid, outpoint.vout) {
                continue;
            }
            live_spent.push((prevout_txid, outpoint.vout));
        }
        if height_bytes == [0_u8; crate::types::HEIGHT_SIZE] {
            continue;
        }
        let coinbase = tx.is_coinbase();
        for output in 0..tx.output_count() {
            let Ok(vout) = u32::try_from(output) else {
                continue;
            };
            let script = output_script_at(&tx, output);
            live_created.push(LiveCreation {
                txid,
                vout,
                scripthash: live_admission(script),
                value: output_value_at(&tx, output),
                coinbase,
            });
        }
    }
    push_live_ops(
        &mut rows,
        live_created,
        live_spent,
        height,
        spent_coins,
        spent_coins,
    )?;
    Ok(rows)
}

struct LiveCreation {
    txid: [u8; 32],
    vout: u32,
    scripthash: Option<ScriptHash>,
    value: u64,
    coinbase: bool,
}

fn output_script_at<'a>(tx: &TransactionView<'a>, vout: usize) -> &'a [u8] {
    tx.output_script(vout)
}

fn output_value_at(tx: &TransactionView<'_>, vout: usize) -> u64 {
    tx.output_value(vout).to_sat()
}

/// `created_lookup` answers only for coins that existed before this block, so
/// the block's own outputs never produce a delete for themselves.
fn push_live_ops(
    rows: &mut PendingRows,
    created: Vec<LiveCreation>,
    spent: Vec<([u8; 32], u32)>,
    height: u32,
    spent_coins: &dyn SpentCoins,
    created_lookup: &dyn SpentCoins,
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
        if let Some(old_coin) = created_lookup.spent_coin(&creation.txid, creation.vout) {
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

pub(crate) struct BodyFacts<'a> {
    pub height: u32,
    pub needs_scripts: bool,
    pub spent_coins: &'a dyn SpentCoins,
}

#[derive(Clone)]
struct CreatedCoin {
    script: bitcoin_rs_storage::Bytes,
    value: u64,
    height: u32,
    coinbase: bool,
}

type CreatedCoins = hashbrown::HashMap<([u8; 32], u32), CreatedCoin>;

fn check_position(span: ByteSpan) -> Result<(), IndexError> {
    let end = u64::from(span.start()).saturating_add(u64::from(span.len()));
    let past_cap = u64::try_from(MAX_POSITION_END_BYTES).map_or(true, |cap| end > cap);
    if span.start() > U24_MAX || span.len() > U24_MAX || past_cap {
        return Err(IndexError::UnaddressablePosition {
            offset: u64::from(span.start()),
        });
    }
    Ok(())
}

pub(crate) fn committed_block_from_image(
    image: &BlockImage,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    facts: &BodyFacts<'_>,
) -> Result<bitcoin_rs_storage::CommittedBlock, IndexError> {
    let mut created = CreatedCoins::new();
    let mut txs = Vec::with_capacity(image.tx_count());
    for index in 0..image.tx_count() {
        let tx = image.tx(index);
        let span = tx.layout().span();
        check_position(span)?;
        let txid = *tx.txid().as_bytes();
        let inputs = committed_inputs(&tx, facts, &created)?;
        let outputs = committed_outputs(&tx, txid, facts.height, &mut created);
        txs.push(bitcoin_rs_storage::committed_facts::TxFacts {
            txid,
            offset: span.start(),
            len: span.len(),
            inputs,
            outputs,
        });
    }
    Ok(bitcoin_rs_storage::CommittedBlock {
        height: facts.height,
        hash,
        parent_hash,
        header: image.header_bytes(),
        txs,
    })
}

fn committed_inputs(
    tx: &TransactionView<'_>,
    facts: &BodyFacts<'_>,
    created: &CreatedCoins,
) -> Result<Vec<bitcoin_rs_storage::committed_facts::SpentPrevout>, IndexError> {
    let mut inputs = Vec::with_capacity(tx.input_count());
    for input in 0..tx.input_count() {
        let outpoint = tx.input_outpoint(input);
        let prev_txid = *outpoint.txid.as_bytes();
        let vout = outpoint.vout;
        if is_null_prevout(&prev_txid, vout) {
            inputs.push(bitcoin_rs_storage::committed_facts::SpentPrevout {
                txid: [0u8; 32],
                vout: u32::MAX,
                value: 0,
                script: bitcoin_rs_storage::Bytes::new(),
                height: facts.height,
                coinbase: true,
            });
            continue;
        }
        let coin = resolve_spent_coin(prev_txid, vout, facts, created)?;
        inputs.push(bitcoin_rs_storage::committed_facts::SpentPrevout {
            txid: prev_txid,
            vout,
            value: coin.value,
            script: coin.script,
            height: coin.height,
            coinbase: coin.coinbase,
        });
    }
    Ok(inputs)
}

fn resolve_spent_coin(
    prev_txid: [u8; 32],
    vout: u32,
    facts: &BodyFacts<'_>,
    created: &CreatedCoins,
) -> Result<CreatedCoin, IndexError> {
    if let Some(coin) = created.get(&(prev_txid, vout)) {
        return Ok(coin.clone());
    }
    if let Some(coin) = facts.spent_coins.spent_coin(&prev_txid, vout) {
        return Ok(CreatedCoin {
            script: bitcoin_rs_storage::Bytes::copy_from_slice(coin.script),
            value: coin.value,
            height: coin.height,
            coinbase: coin.coinbase,
        });
    }
    if facts.needs_scripts {
        return Err(IndexError::MissingSpentCoin {
            txid: prev_txid,
            vout,
            height: facts.height,
        });
    }
    Ok(CreatedCoin {
        script: bitcoin_rs_storage::Bytes::new(),
        value: 0,
        height: 0,
        coinbase: false,
    })
}

fn committed_outputs(
    tx: &TransactionView<'_>,
    txid: [u8; 32],
    height: u32,
    created: &mut CreatedCoins,
) -> Vec<bitcoin_rs_storage::committed_facts::CreatedOutput> {
    let coinbase = tx.is_coinbase();
    let mut outputs = Vec::with_capacity(tx.output_count());
    for index in 0..tx.output_count() {
        let Ok(vout) = u32::try_from(index) else {
            break;
        };
        let script = bitcoin_rs_storage::Bytes::copy_from_slice(output_script_at(tx, index));
        let value = output_value_at(tx, index);
        created.insert(
            (txid, vout),
            CreatedCoin {
                script: script.clone(),
                value,
                height,
                coinbase,
            },
        );
        outputs.push(bitcoin_rs_storage::committed_facts::CreatedOutput {
            vout,
            value,
            script,
        });
    }
    outputs
}

#[cfg(test)]
mod tests {
    use super::pending_rows_for_facts;
    use crate::index::capability::IndexCapabilities;
    use bitcoin_rs_storage::Bytes;
    use bitcoin_rs_storage::CommittedBlock;
    use bitcoin_rs_storage::committed_facts::{CreatedOutput, SpentPrevout, TxFacts};

    fn block_with_spend() -> CommittedBlock {
        CommittedBlock {
            height: 1,
            hash: [3; 32],
            parent_hash: [4; 32],
            header: [5; 80],
            txs: vec![TxFacts {
                txid: [6; 32],
                offset: 0,
                len: 0,
                inputs: vec![SpentPrevout {
                    txid: [7; 32],
                    vout: 0,
                    value: 5,
                    script: Bytes::from_static(&[0x51]),
                    height: 0,
                    coinbase: false,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 4,
                    script: Bytes::from_static(&[0x51]),
                }],
            }],
        }
    }

    // PRJ-03
    #[test]
    fn disabled_projections_allocate_no_live_row_buffers() -> Result<(), crate::portable::TestError>
    {
        let rows = pending_rows_for_facts(&block_with_spend(), IndexCapabilities::NONE)?;
        assert_eq!(
            rows.header_rows.len(),
            1,
            "the header family is always on and keeps its row"
        );
        assert_eq!(
            rows.live_ops.capacity(),
            0,
            "a disabled ScriptLive projection must not allocate its row buffer"
        );
        assert!(rows.live_ops.is_empty());
        Ok(())
    }

    #[test]
    fn enabled_script_live_turns_the_spend_into_a_live_op() -> Result<(), crate::portable::TestError>
    {
        let rows = pending_rows_for_facts(&block_with_spend(), IndexCapabilities::SCRIPT_LIVE)?;
        assert!(
            !rows.live_ops.is_empty(),
            "the spend must produce a live delete when ScriptLive is enabled"
        );
        Ok(())
    }
}
