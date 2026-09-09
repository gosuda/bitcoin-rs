//! Parse-once block state shared by the native apply path.
//!
//! One decoded block drives every validation stage: block rules, BIP30/BIP34,
//! the UTXO overlay walk, and per-input script checks. [`BlockView`] carries
//! that block's transaction slice together with the facts derived once during
//! apply preparation, so later stages consume the same hashes and the same
//! decoded transactions instead of recomputing them.
//!
//! [`BlockFacts`] is the one-pass derivation owner (T06): given a T05 borrowed
//! layout ([`ParsedBlock`]) it produces the transaction identifiers, the
//! block weight, every transaction's byte position, witness presence, and the
//! Merkle root plus mutation flag in a single traversal of the parsed spans.
//! Nothing re-serializes the owned transactions to hash them and nothing
//! decodes a second transaction tree.

use bitcoin_rs_primitives::{
    Tx, TxOut, Txid, Wtxid,
    encode::double_sha256,
    layout::{ByteSpan, ParsedBlock, ParsedTransaction},
};

use crate::verify_block::merkle_root_and_mutation_borrowed;

/// Serialized block header length in bytes.
const HEADER_LEN: u64 = 80;

/// Facts one pass over a block derives: identifiers, weight, byte positions,
/// witness presence, and the Merkle root with its mutation flag.
///
/// Built either from the T05 borrowed layout ([`Self::from_parsed`], the
/// production one-pass path over the raw bytes) or from an already-decoded
/// transaction slice whose identities are known ([`Self::from_txids`], the
/// kernel-parse path and standalone callers). Every consumer — block rules,
/// the window precheck, indexes — reads these instead of re-walking the
/// block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFacts {
    /// Transaction IDs in block order, hashed exactly once.
    txids: Vec<Txid>,
    /// Witness transaction IDs in block order. Populated in the same pass as
    /// the txids whenever the block carries witness data — a witness-free
    /// block never pays for them (BIP141: a legacy transaction's wtxid is
    /// its txid).
    wtxids: Option<Vec<Wtxid>>,
    /// Whether any transaction input carries witness data (Core's
    /// `CBlock::HasWitness`).
    has_witness: bool,
    /// BIP141 block weight: `stripped_size * 3 + total_size`.
    weight: u64,
    /// Byte position of every transaction inside the parsed image, in block
    /// order; empty when the facts were derived without a layout image.
    tx_spans: Vec<ByteSpan>,
    /// Merkle root over `txids` from the production walker; `None` only for
    /// an empty transaction tree.
    merkle_root: Option<Txid>,
    /// Whether two equal *real* adjacent nodes appeared at any level of the
    /// Merkle tree. The odd leftover paired with its duplicate-last copy
    /// never sets this.
    merkle_mutated: bool,
}

impl BlockFacts {
    /// Derives every fact family in one traversal of the T05 borrowed layout.
    ///
    /// Identifiers are hashed straight out of the validated spans: each txid
    /// over the span-assembled non-witness serialization, each segwit
    /// transaction's wtxid over its full serialization span verbatim. Weight
    /// comes from the span lengths, byte positions from the layout, and the
    /// Merkle root and mutation flag from the one reduction over the derived
    /// txids. Nothing materializes or re-serializes the owned form.
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
                let witness_id = wtxid_from_span(tx, txid);
                let ids = wtxids.get_or_insert_with(|| {
                    // Legacy transactions before the first segwit one reuse
                    // their txid as the wtxid (BIP141).
                    let mut ids = Vec::with_capacity(tx_count);
                    ids.extend(txids.iter().copied().map(|id: Txid| Wtxid(id.0)));
                    ids
                });
                ids.push(witness_id);
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

    /// Derives the facts from an already-decoded transaction slice whose
    /// identities were hashed elsewhere (the kernel parse, standalone rule
    /// callers). Weight and the Merkle reduction reuse the same production
    /// walkers as [`Self::from_parsed`]; byte positions are unknown without
    /// the layout image, and witness IDs stay lazy.
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
        let weight = Self::block_weight(txs);
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

    /// Consensus weight of an already-decoded transaction slice, without
    /// transaction identifiers or the Merkle reduction.
    ///
    /// Weight-only callers must not pay for [`Self::from_txids`]'s identifier
    /// clone and Merkle walk. This function owns the weight arithmetic;
    /// [`Self::from_txids`] delegates to it.
    #[must_use]
    pub fn block_weight(txs: &[Tx]) -> u64 {
        let count_len = u64::from(compact_size_len(len_u64(txs.len())));
        let mut stripped = HEADER_LEN.saturating_add(count_len);
        let mut total = HEADER_LEN.saturating_add(count_len);
        for tx in txs {
            stripped = stripped.saturating_add(len_u64(tx.base_size()));
            total = total.saturating_add(len_u64(tx.total_size()));
        }
        stripped.saturating_mul(3).saturating_add(total)
    }

    /// Transaction IDs in block order, hashed exactly once.
    #[must_use]
    pub fn txids(&self) -> &[Txid] {
        &self.txids
    }

    /// Number of transactions the facts describe.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txids.len()
    }

    /// Releases the transaction IDs for consumers that take them by value.
    #[must_use]
    pub fn into_txids(self) -> Vec<Txid> {
        self.txids
    }

    /// Witness transaction IDs if they were derived, without hashing.
    #[must_use]
    pub fn wtxids(&self) -> Option<&[Wtxid]> {
        self.wtxids.as_deref()
    }

    /// Whether any transaction input carries witness data.
    #[must_use]
    pub const fn has_witness(&self) -> bool {
        self.has_witness
    }

    /// BIP141 block weight in weight units.
    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.weight
    }

    /// Byte position of every transaction inside the parsed image, in block
    /// order; empty when the facts carry no layout image.
    #[must_use]
    pub fn transaction_spans(&self) -> &[ByteSpan] {
        &self.tx_spans
    }

    /// Merkle root over the derived txids; `None` for an empty tree.
    #[must_use]
    pub const fn merkle_root(&self) -> Option<Txid> {
        self.merkle_root
    }

    /// Whether the Merkle tree over the derived txids is mutated (two equal
    /// *real* adjacent nodes at some level).
    #[must_use]
    pub const fn merkle_mutated(&self) -> bool {
        self.merkle_mutated
    }

    /// Populates the witness IDs from the decoded transactions when the
    /// single pass did not (a caller that skipped the layout). Hashes at
    /// most once; the standalone rule entry uses it for witness-carrying
    /// blocks under active segwit.
    pub(crate) fn or_insert_wtxids_from(&mut self, txs: &[Tx]) {
        if self.wtxids.is_none() {
            self.wtxids = Some(txs.iter().map(Tx::wtxid).collect());
        }
    }
}

/// A decoded block's transactions and the facts derived once.
///
/// The node hands the derived [`BlockFacts`] in by value; witness IDs are
/// computed lazily at most once for facts that arrived without them, because
/// only witness-carrying blocks under active segwit ever need them (the
/// BIP141 witness-commitment check).
pub struct BlockView<'b> {
    txs: &'b [Tx],
    facts: BlockFacts,
    resolved: Vec<Vec<Option<TxOut>>>,
}

impl<'b> BlockView<'b> {
    /// Binds one decoded block's transactions to identities computed once.
    ///
    /// `txids` must hold one transaction ID per transaction in block order;
    /// the same vector every other stage consumes, so no stage re-hashes.
    /// Weight and the Merkle reduction are derived here through the same
    /// production walkers the layout path uses.
    #[must_use]
    pub fn new(txs: &'b [Tx], txids: Vec<Txid>) -> Self {
        Self::from_facts(txs, BlockFacts::from_txids(txs, txids))
    }

    /// Binds one decoded block's transactions to facts derived in one pass.
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

    /// Returns the derived facts every stage shares.
    #[must_use]
    pub const fn facts(&self) -> &BlockFacts {
        &self.facts
    }

    /// Returns the decoded transactions in block order.
    #[must_use]
    pub const fn transactions(&self) -> &'b [Tx] {
        self.txs
    }

    /// Returns transaction IDs computed once during apply preparation.
    #[must_use]
    pub fn txids(&self) -> &[Txid] {
        self.facts.txids()
    }

    /// Returns the derived BIP141 block weight.
    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.facts.weight()
    }

    /// Returns every transaction's byte position inside the parsed image.
    #[must_use]
    pub fn transaction_spans(&self) -> &[ByteSpan] {
        self.facts.transaction_spans()
    }

    /// Whether the Merkle tree over the derived txids is mutated.
    #[must_use]
    pub const fn merkle_mutated(&self) -> bool {
        self.facts.merkle_mutated()
    }

    /// Whether the derived Merkle root equals `merkle_root`.
    ///
    /// The root-only window precheck consumes this instead of re-walking the
    /// tree: the derivation already reduced the same txids through the same
    /// production walker, so the comparison is the same verdict without the
    /// duplicate traversal. An empty tree matches nothing.
    #[must_use]
    pub fn merkle_root_matches(&self, merkle_root: bitcoin_rs_primitives::Hash256) -> bool {
        self.facts.merkle_root() == Some(Txid(merkle_root))
    }

    /// Returns witness transaction IDs, computing them at most once.
    ///
    /// Facts derived from the layout arrive with them populated in the same
    /// pass; only callers that skipped the layout pay here, and a
    /// witness-free block never reaches this path in production.
    pub fn witness_ids(&mut self) -> &[Wtxid] {
        self.facts.or_insert_wtxids_from(self.txs);
        self.facts
            .wtxids()
            .unwrap_or_else(|| unreachable!("witness IDs were just computed"))
    }

    /// Returns witness IDs if they were already derived, without hashing.
    #[must_use]
    pub fn computed_witness_ids(&self) -> Option<&[Wtxid]> {
        self.facts.wtxids()
    }

    /// Installs the prevout matrix resolved in block order.
    ///
    /// One row per transaction in input order (empty for the coinbase); the
    /// script stage consumes it once via [`Self::parts_mut`].
    pub fn set_resolved(&mut self, resolved: Vec<Vec<Option<TxOut>>>) {
        self.resolved = resolved;
    }

    /// Releases the owned transaction IDs for the commit scratch state.
    ///
    /// The identities were handed in once by the caller and leave through the
    /// same single owner; nothing else clones or recomputes them.
    #[must_use]
    pub fn into_txids(self) -> Vec<Txid> {
        self.facts.into_txids()
    }

    /// Splits the view into its transaction slice and its resolved matrix.
    pub(crate) fn parts_mut(&mut self) -> (&'b [Tx], &mut Vec<Vec<Option<TxOut>>>) {
        (self.txs, &mut self.resolved)
    }
}

/// Runs the production Merkle walker over derived txids, mapping the empty
/// tree to a `None` root with no mutation.
fn merkle_root_and_mutation(txids: &[Txid]) -> (Option<Txid>, bool) {
    match merkle_root_and_mutation_borrowed(txids) {
        Some((root, mutated)) => (Some(root), mutated),
        None => (None, false),
    }
}

/// Computes a transaction id from validated spans: double-SHA256 over the
/// non-witness serialization assembled from the layout.
///
/// The count varints reuse the parsed canonical encodings (for a segwit
/// transaction the stored input-count span is the real count after the
/// marker/flag, so it is byte-identical to the txid-layout encoding); script
/// and value lengths are re-encoded as canonical compact-size prefixes.
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

/// Computes a witness transaction id from the layout: double-SHA256 over the
/// full serialization span verbatim (marker, flag, and witness included); a
/// legacy transaction's wtxid is its txid (BIP141).
fn wtxid_from_span(tx: &ParsedTransaction<'_>, txid: Txid) -> Wtxid {
    if tx.is_segwit() {
        let bytes = tx
            .span_bytes(tx.span())
            .unwrap_or_else(|| unreachable!("span belongs to the parsed image"));
        Wtxid(double_sha256(bytes))
    } else {
        Wtxid(txid.0)
    }
}

/// Non-witness (txid-layout) serialization length from the parsed spans.
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

/// Appends `span`'s bytes from the owning parsed image.
fn extend_span(scratch: &mut Vec<u8>, tx: &ParsedTransaction<'_>, span: ByteSpan) {
    scratch.extend_from_slice(
        tx.span_bytes(span)
            .unwrap_or_else(|| unreachable!("span belongs to the parsed image")),
    );
}

/// Appends the canonical compact-size encoding of `value`.
///
/// The layout rejects non-canonical wire encodings, so re-encoding a parsed
/// length reproduces the wire prefix byte-for-byte.
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

/// Length in bytes of the canonical compact-size encoding of `value`.
const fn compact_size_len(value: u64) -> u32 {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Widens a span length to `u64`.
fn span_len(span: ByteSpan) -> u64 {
    u64::from(span.len())
}

/// Widens a `usize` length into `u64`; slice and vector lengths always fit,
/// mirroring the layout module's widening helper.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or_else(|_| unreachable!("usize length fits u64"))
}
