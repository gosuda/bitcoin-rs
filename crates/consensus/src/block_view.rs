use crate::primitives::{
    BlockImage, Header, Tx, TxOut, TxView, Txid, Wtxid,
    encode::{double_sha256, finalize_double_sha256},
    layout::{ParsedBlock, ParsedTransaction},
    varint,
};
use sha2::{Digest, Sha256};

use crate::verify_block::merkle_root_and_mutation_borrowed;

#[expect(
    clippy::as_conversions,
    reason = "the fixed 80-byte header fits in u64"
)]
pub(crate) const HEADER_LEN: u64 = Header::LEN as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFacts {
    txids: Vec<Txid>,
    wtxids: Option<Vec<Wtxid>>,
    has_witness: bool,
    weight: u64,
    merkle_root: Option<Txid>,
    merkle_mutated: bool,
}

impl BlockFacts {
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
            merkle_root,
            merkle_mutated,
        }
    }
    #[must_use]
    pub fn from_image(image: &BlockImage) -> Self {
        let identities = image.identities();
        let tx_count = identities.len();
        let mut txids = Vec::with_capacity(tx_count);
        let mut wtxids: Option<Vec<Wtxid>> = None;
        let mut base_sizes = 0_u64;
        let mut has_witness = false;

        for id in identities {
            let txid = id.txid();
            if let Some(wtxid) = id.wtxid() {
                has_witness = true;
                let ids = wtxids.get_or_insert_with(|| {
                    let mut ids = Vec::with_capacity(tx_count);
                    ids.extend(txids.iter().copied().map(|id: Txid| Wtxid(id.0)));
                    ids
                });
                ids.push(wtxid);
            } else if let Some(ids) = wtxids.as_mut() {
                ids.push(Wtxid(txid.0));
            }
            base_sizes = base_sizes.saturating_add(u64::from(id.base_size()));
            txids.push(txid);
        }

        let stripped = HEADER_LEN
            .saturating_add(u64::from(image.layout().tx_count().len()))
            .saturating_add(base_sizes);
        let total = len_u64(image.bytes().len());
        let weight = stripped.saturating_mul(3).saturating_add(total);
        let (merkle_root, merkle_mutated) = merkle_root_and_mutation(&txids);

        Self {
            txids,
            wtxids,
            has_witness,
            weight,
            merkle_root,
            merkle_mutated,
        }
    }

    #[must_use]
    pub fn from_txids(txs: &[Tx], txids: Vec<Txid>) -> Self {
        debug_assert_eq!(
            txs.len(),
            txids.len(),
            "block facts need one txid per transaction"
        );
        let has_witness = txs.iter().any(Tx::has_witness);
        let weight = decoded_block_weight(txs);
        let (merkle_root, merkle_mutated) = merkle_root_and_mutation(&txids);

        Self {
            txids,
            wtxids: None,
            has_witness,
            weight,
            merkle_root,
            merkle_mutated,
        }
    }

    #[must_use]
    pub fn txids(&self) -> &[Txid] {
        &self.txids
    }

    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txids.len()
    }

    #[must_use]
    pub fn into_txids(self) -> Vec<Txid> {
        self.txids
    }

    #[must_use]
    pub fn wtxids(&self) -> Option<&[Wtxid]> {
        self.wtxids.as_deref()
    }

    #[must_use]
    pub const fn has_witness(&self) -> bool {
        self.has_witness
    }

    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.weight
    }

    #[must_use]
    pub const fn merkle_root(&self) -> Option<Txid> {
        self.merkle_root
    }

    #[must_use]
    pub const fn merkle_mutated(&self) -> bool {
        self.merkle_mutated
    }

    pub(crate) fn or_insert_wtxids_from(&mut self, txs: &[Tx]) {
        if self.wtxids.is_none() {
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

#[derive(Clone, Copy, Debug)]
pub enum BlockViewSource<'b> {
    Txs(&'b [Tx]),
    Image(&'b BlockImage),
}

pub struct BlockView<'b> {
    source: BlockViewSource<'b>,
    facts: BlockFacts,
    resolved: Vec<Vec<Option<TxOut>>>,
}

impl<'b> BlockView<'b> {
    #[must_use]
    pub fn from_facts(txs: &'b [Tx], facts: BlockFacts) -> Self {
        debug_assert_eq!(
            txs.len(),
            facts.tx_count(),
            "block view needs one fact row per transaction"
        );
        Self {
            source: BlockViewSource::Txs(txs),
            facts,
            resolved: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_image(image: &'b BlockImage, facts: BlockFacts) -> Self {
        debug_assert_eq!(
            image.tx_count(),
            facts.tx_count(),
            "block view needs one fact row per transaction"
        );
        Self {
            source: BlockViewSource::Image(image),
            facts,
            resolved: Vec::new(),
        }
    }

    #[must_use]
    pub const fn facts(&self) -> &BlockFacts {
        &self.facts
    }

    #[must_use]
    pub fn txids(&self) -> &[Txid] {
        self.facts.txids()
    }

    #[must_use]
    pub fn tx_count(&self) -> usize {
        match self.source {
            BlockViewSource::Txs(txs) => txs.len(),
            BlockViewSource::Image(img) => img.tx_count(),
        }
    }

    #[must_use]
    pub fn tx_view(&self, index: usize) -> TxView<'b> {
        match self.source {
            BlockViewSource::Txs(txs) => TxView::Owned(&txs[index]),
            BlockViewSource::Image(img) => TxView::View(img.tx(index)),
        }
    }

    #[must_use]
    pub fn txs(&self) -> Option<&'b [Tx]> {
        match self.source {
            BlockViewSource::Txs(txs) => Some(txs),
            BlockViewSource::Image(_) => None,
        }
    }

    #[must_use]
    pub fn image(&self) -> Option<&'b BlockImage> {
        match self.source {
            BlockViewSource::Image(img) => Some(img),
            BlockViewSource::Txs(_) => None,
        }
    }

    #[must_use]
    pub fn merkle_root_matches(&self, merkle_root: crate::primitives::Hash256) -> bool {
        self.facts.merkle_root() == Some(Txid(merkle_root))
    }

    pub fn witness_ids(&mut self) -> &[Wtxid] {
        match self.source {
            BlockViewSource::Txs(txs) => self.facts.or_insert_wtxids_from(txs),
            BlockViewSource::Image(_) => {}
        }
        self.facts
            .wtxids()
            .unwrap_or_else(|| unreachable!("witness IDs were just computed"))
    }

    pub fn set_resolved(&mut self, resolved: Vec<Vec<Option<TxOut>>>) {
        self.resolved = resolved;
    }

    #[must_use]
    pub fn into_txids(self) -> Vec<Txid> {
        self.facts.into_txids()
    }

    pub(crate) fn parts_mut(&mut self) -> (BlockViewSource<'b>, &mut Vec<Vec<Option<TxOut>>>) {
        (self.source, &mut self.resolved)
    }
}

fn decoded_block_weight(txs: &[Tx]) -> u64 {
    let count_len = len_u64(varint::encoded_len(len_u64(txs.len())));
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

fn txid_and_base_size(tx: &ParsedTransaction<'_>) -> (Txid, u64) {
    let parts = tx.stripped_parts();
    if !tx.is_segwit() {
        return (Txid(double_sha256(parts[0])), u64::from(tx.span().len()));
    }

    let mut engine = Sha256::new();
    let mut base_size = 0;
    for part in parts {
        engine.update(part);
        base_size += len_u64(part.len());
    }
    (Txid(finalize_double_sha256(engine)), base_size)
}

fn wtxid_from_span(tx: &ParsedTransaction<'_>) -> Wtxid {
    debug_assert!(tx.is_segwit());
    let bytes = tx
        .span_bytes(tx.span())
        .unwrap_or_else(|| unreachable!("span belongs to the parsed image"));
    Wtxid(double_sha256(bytes))
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or_else(|_| unreachable!("usize length fits u64"))
}
