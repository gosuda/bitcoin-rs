//! Shared parse-once block facts for native validation.
//!
//! `BlockFacts` owns identifiers, weight, layout spans, witness presence, and
//! the Merkle result so later validation stages do not derive them again.

use bitcoin_rs_primitives::{
    Hash256, Tx, TxOut, Txid, Wtxid,
    encode::double_sha256,
    layout::{ByteSpan, ParsedBlock, ParsedTransaction},
};

use sha2::{Digest, Sha256};

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

        for tx in parsed.transactions() {
            let (txid, base_size) = txid_and_base_size(tx);
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
            base_sizes = base_sizes.saturating_add(base_size);
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
            // BIP141: a witness-free transaction's wtxid is its txid. Reuse
            // the identity already owned by these facts instead of encoding
            // and hashing the same transaction again. Iterate over txs, not
            // a zip: even malformed caller-supplied identity counts must not
            // silently truncate the witness-ID matrix.
            self.wtxids = Some(
                txs.iter()
                    .enumerate()
                    .map(|(index, tx)| {
                        self.txids
                            .get(index)
                            .filter(|_| !tx.has_witness())
                            .map_or_else(|| tx.wtxid(), |txid| Wtxid(txid.0))
                    })
                    .collect(),
            );
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

/// Hash the canonical base serialization without reconstructing its fields.
///
/// The layout parser has already checked `CompactSize` canonicality and wire
/// order. Legacy bytes are contiguous; `SegWit` removes exactly the marker/flag
/// and witness section, leaving version, the input/output range, and lock time.
/// The same borrowed ranges own the stripped-size calculation, so there is no
/// second traversal of input/output metadata and no transaction-sized scratch.
fn txid_and_base_size(tx: &ParsedTransaction<'_>) -> (Txid, u64) {
    let bytes = tx
        .span_bytes(tx.span())
        .unwrap_or_else(|| unreachable!("span belongs to the parsed image"));
    if !tx.is_segwit() {
        return (Txid(double_sha256(bytes)), u64::from(tx.span().len()));
    }

    // An empty final script still ends after its CompactSize prefix. With no
    // outputs, the output-count prefix itself is the end of the base body.
    let body_end = tx.outputs().last().map_or_else(
        || tx.output_count_span().end(),
        |output| output.script_pubkey().end(),
    );
    // Layout offsets are image-relative, not transaction-relative. Subtract
    // the transaction origin before indexing its borrowed byte slice.
    let origin = u64::from(tx.span().start());
    let start = usize::try_from(u64::from(tx.input_count_span().start()) - origin)
        .unwrap_or_else(|_| unreachable!("body start is inside the transaction"));
    let end = usize::try_from(body_end - origin)
        .unwrap_or_else(|_| unreachable!("body end is inside the transaction"));
    let body = &bytes[start..end];
    let version = tx
        .span_bytes(tx.version_span())
        .unwrap_or_else(|| unreachable!("version belongs to the parsed image"));
    let lock_time = tx
        .span_bytes(tx.lock_time_span())
        .unwrap_or_else(|| unreachable!("lock time belongs to the parsed image"));

    let mut engine = Sha256::new();
    engine.update(version);
    engine.update(body);
    engine.update(lock_time);
    let digest: [u8; 32] = Sha256::digest(engine.finalize()).into();
    let base_size = len_u64(version.len()) + len_u64(body.len()) + len_u64(lock_time.len());
    (Txid(Hash256::from_le_bytes(&digest)), base_size)
}

fn wtxid_from_span(tx: &ParsedTransaction<'_>) -> Wtxid {
    debug_assert!(tx.is_segwit());
    let bytes = tx
        .span_bytes(tx.span())
        .unwrap_or_else(|| unreachable!("span belongs to the parsed image"));
    Wtxid(double_sha256(bytes))
}

const fn compact_size_len(value: u64) -> u32 {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or_else(|_| unreachable!("usize length fits u64"))
}
