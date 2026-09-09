//! Shared parse-once block facts for native validation.
//!
//! `BlockFacts` owns identifiers, weight, layout spans, witness presence, and
//! the Merkle result so later validation stages do not derive them again.

use bitcoin_rs_primitives::{
    Tx, TxOut, Txid, Wtxid,
    encode::double_sha256,
    layout::{ByteSpan, ParsedBlock, ParsedTransaction},
};

use crate::verify_block::merkle_root_and_mutation_borrowed;

const HEADER_LEN: u64 = 80;

/// Facts derived once for a decoded block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFacts {
    txids: Vec<Txid>,
    wtxids: Option<Vec<Wtxid>>,
    has_witness: bool,
    weight: u64,
    tx_spans: Vec<ByteSpan>,
    merkle_root: Option<Txid>,
    merkle_mutated: bool,
}

impl BlockFacts {
    /// Derives facts directly from a validated borrowed block layout.
    #[must_use]
    pub fn from_parsed(parsed: &ParsedBlock) -> Self {
        let tx_count = parsed.tx_count();
        let mut txids = Vec::with_capacity(tx_count);
        let mut wtxids: Option<Vec<Wtxid>> = None;
        let mut base_sizes = 0_u64;
        let mut has_witness = false;
        let mut scratch = Vec::new();

        for tx in parsed.transactions() {
            let txid = txid_from_spans(tx, &mut scratch);
            if tx.is_segwit() {
                has_witness = true;
                let ids = wtxids.get_or_insert_with(|| {
                    let mut ids = Vec::with_capacity(tx_count);
                    ids.extend(txids.iter().copied().map(|id: Txid| Wtxid(id.0)));
                    ids
                });
                ids.push(wtxid_from_span(tx));
            } else if let Some(ids) = wtxids.as_mut() {
                ids.push(Wtxid(txid.0));
            }
            base_sizes = base_sizes.saturating_add(base_size_from_spans(tx));
            txids.push(txid);
        }

        let stripped = HEADER_LEN
            .saturating_add(u64::from(parsed.tx_count_span().len()))
            .saturating_add(base_sizes);
        let total = len_u64(parsed.consumed_len());
        let weight = stripped.saturating_mul(3).saturating_add(total);
        let (merkle_root, merkle_mutated) = merkle_root_and_mutation(&txids);

        Self {
            txids,
            wtxids,
            has_witness,
            weight,
            tx_spans: parsed.transaction_spans().to_vec(),
            merkle_root,
            merkle_mutated,
        }
    }

    /// Derives facts from decoded transactions and precomputed transaction IDs.
    #[must_use]
    pub fn from_txids(txs: &[Tx], txids: Vec<Txid>) -> Self {
        debug_assert_eq!(
            txs.len(),
            txids.len(),
            "block facts need one txid per transaction"
        );
        let has_witness = txs
            .iter()
            .any(|tx| tx.inputs.iter().any(|input| !input.witness.is_empty()));
        let weight = decoded_block_weight(txs);
        let (merkle_root, merkle_mutated) = merkle_root_and_mutation(&txids);

        Self {
            txids,
            wtxids: None,
            has_witness,
            weight,
            tx_spans: Vec::new(),
            merkle_root,
            merkle_mutated,
        }
    }

    /// Returns consensus block weight without deriving identifiers or a Merkle root.
    #[must_use]
    pub fn block_weight(txs: &[Tx]) -> u64 {
        decoded_block_weight(txs)
    }

    /// Returns transaction IDs in block order.
    #[must_use]
    pub fn txids(&self) -> &[Txid] {
        &self.txids
    }

    /// Returns the number of transactions described by these facts.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txids.len()
    }

    /// Consumes the facts and returns their transaction IDs.
    #[must_use]
    pub fn into_txids(self) -> Vec<Txid> {
        self.txids
    }

    /// Returns precomputed witness transaction IDs, if available.
    #[must_use]
    pub fn wtxids(&self) -> Option<&[Wtxid]> {
        self.wtxids.as_deref()
    }

    /// Returns whether any transaction contains witness data.
    #[must_use]
    pub const fn has_witness(&self) -> bool {
        self.has_witness
    }

    /// Returns BIP141 block weight.
    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.weight
    }

    /// Returns transaction spans in block order, or an empty slice without a layout.
    #[must_use]
    pub fn transaction_spans(&self) -> &[ByteSpan] {
        &self.tx_spans
    }

    /// Returns the transaction Merkle root, or `None` for an empty tree.
    #[must_use]
    pub const fn merkle_root(&self) -> Option<Txid> {
        self.merkle_root
    }

    /// Returns whether the transaction Merkle tree is mutated.
    #[must_use]
    pub const fn merkle_mutated(&self) -> bool {
        self.merkle_mutated
    }

    pub(crate) fn or_insert_wtxids_from(&mut self, txs: &[Tx]) {
        if self.wtxids.is_none() {
            self.wtxids = Some(txs.iter().map(Tx::wtxid).collect());
        }
    }
}

/// A decoded transaction slice paired with its shared block facts and prevouts.
pub struct BlockView<'b> {
    txs: &'b [Tx],
    facts: BlockFacts,
    resolved: Vec<Vec<Option<TxOut>>>,
}

impl<'b> BlockView<'b> {
    /// Builds a view from decoded transactions and precomputed transaction IDs.
    #[must_use]
    pub fn new(txs: &'b [Tx], txids: Vec<Txid>) -> Self {
        Self::from_facts(txs, BlockFacts::from_txids(txs, txids))
    }

    /// Builds a view from decoded transactions and existing facts.
    #[must_use]
    pub fn from_facts(txs: &'b [Tx], facts: BlockFacts) -> Self {
        debug_assert_eq!(
            txs.len(),
            facts.tx_count(),
            "block view needs one fact row per transaction"
        );
        Self {
            txs,
            facts,
            resolved: Vec::new(),
        }
    }

    /// Returns the shared block facts.
    #[must_use]
    pub const fn facts(&self) -> &BlockFacts {
        &self.facts
    }

    /// Returns decoded transactions in block order.
    #[must_use]
    pub const fn transactions(&self) -> &'b [Tx] {
        self.txs
    }

    /// Returns transaction IDs in block order.
    #[must_use]
    pub fn txids(&self) -> &[Txid] {
        self.facts.txids()
    }

    /// Returns BIP141 block weight.
    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.facts.weight()
    }

    /// Returns transaction spans from the parsed image, when available.
    #[must_use]
    pub fn transaction_spans(&self) -> &[ByteSpan] {
        self.facts.transaction_spans()
    }

    /// Returns whether the transaction Merkle tree is mutated.
    #[must_use]
    pub const fn merkle_mutated(&self) -> bool {
        self.facts.merkle_mutated()
    }

    /// Returns whether the derived Merkle root equals `merkle_root`.
    #[must_use]
    pub fn merkle_root_matches(&self, merkle_root: bitcoin_rs_primitives::Hash256) -> bool {
        self.facts.merkle_root() == Some(Txid(merkle_root))
    }

    /// Returns witness transaction IDs, deriving them once if necessary.
    pub fn witness_ids(&mut self) -> &[Wtxid] {
        self.facts.or_insert_wtxids_from(self.txs);
        self.facts
            .wtxids()
            .unwrap_or_else(|| unreachable!("witness IDs were just computed"))
    }

    /// Returns witness transaction IDs if they are already available.
    #[must_use]
    pub fn computed_witness_ids(&self) -> Option<&[Wtxid]> {
        self.facts.wtxids()
    }

    /// Sets the resolved prevout matrix in block and input order.
    pub fn set_resolved(&mut self, resolved: Vec<Vec<Option<TxOut>>>) {
        self.resolved = resolved;
    }

    /// Consumes the view and returns its transaction IDs.
    #[must_use]
    pub fn into_txids(self) -> Vec<Txid> {
        self.facts.into_txids()
    }

    pub(crate) fn parts_mut(&mut self) -> (&'b [Tx], &mut Vec<Vec<Option<TxOut>>>) {
        (self.txs, &mut self.resolved)
    }
}

fn decoded_block_weight(txs: &[Tx]) -> u64 {
    let count_len = u64::from(compact_size_len(len_u64(txs.len())));
    let mut stripped = HEADER_LEN.saturating_add(count_len);
    let mut total = HEADER_LEN.saturating_add(count_len);
    for tx in txs {
        stripped = stripped.saturating_add(len_u64(tx.base_size()));
        total = total.saturating_add(len_u64(tx.total_size()));
    }
    stripped.saturating_mul(3).saturating_add(total)
}

fn merkle_root_and_mutation(txids: &[Txid]) -> (Option<Txid>, bool) {
    merkle_root_and_mutation_borrowed(txids)
        .map_or((None, false), |(root, mutated)| (Some(root), mutated))
}

fn txid_from_spans(tx: &ParsedTransaction<'_>, scratch: &mut Vec<u8>) -> Txid {
    scratch.clear();
    extend_span(scratch, tx, tx.version_span());
    extend_span(scratch, tx, tx.input_count_span());
    for input in tx.inputs() {
        extend_span(scratch, tx, input.outpoint());
        push_compact(scratch, span_len(input.script_sig()));
        extend_span(scratch, tx, input.script_sig());
        extend_span(scratch, tx, input.sequence());
    }
    extend_span(scratch, tx, tx.output_count_span());
    for output in tx.outputs() {
        extend_span(scratch, tx, output.value());
        push_compact(scratch, span_len(output.script_pubkey()));
        extend_span(scratch, tx, output.script_pubkey());
    }
    extend_span(scratch, tx, tx.lock_time_span());
    Txid(double_sha256(scratch))
}

fn wtxid_from_span(tx: &ParsedTransaction<'_>) -> Wtxid {
    debug_assert!(tx.is_segwit());
    let bytes = tx
        .span_bytes(tx.span())
        .unwrap_or_else(|| unreachable!("span belongs to the parsed image"));
    Wtxid(double_sha256(bytes))
}

fn base_size_from_spans(tx: &ParsedTransaction<'_>) -> u64 {
    let mut size = 4 + u64::from(tx.input_count_span().len()) + 4;
    for input in tx.inputs() {
        size += 36
            + u64::from(compact_size_len(span_len(input.script_sig())))
            + u64::from(input.script_sig().len())
            + 4;
    }
    size += u64::from(tx.output_count_span().len());
    for output in tx.outputs() {
        size += 8
            + u64::from(compact_size_len(span_len(output.script_pubkey())))
            + u64::from(output.script_pubkey().len());
    }
    size
}

fn extend_span(scratch: &mut Vec<u8>, tx: &ParsedTransaction<'_>, span: ByteSpan) {
    scratch.extend_from_slice(
        tx.span_bytes(span)
            .unwrap_or_else(|| unreachable!("span belongs to the parsed image")),
    );
}

fn push_compact(scratch: &mut Vec<u8>, value: u64) {
    match value {
        0..=0xfc => scratch.push(
            u8::try_from(value).unwrap_or_else(|_| unreachable!("value fits u8 by the match arm")),
        ),
        0xfd..=0xffff => {
            scratch.push(0xfd);
            scratch.extend_from_slice(&value.to_le_bytes()[..2]);
        }
        0x1_0000..=0xffff_ffff => {
            scratch.push(0xfe);
            scratch.extend_from_slice(&value.to_le_bytes()[..4]);
        }
        _ => {
            scratch.push(0xff);
            scratch.extend_from_slice(&value.to_le_bytes());
        }
    }
}

const fn compact_size_len(value: u64) -> u32 {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn span_len(span: ByteSpan) -> u64 {
    u64::from(span.len())
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or_else(|_| unreachable!("usize length fits u64"))
}
