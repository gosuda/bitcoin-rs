//! Chain identity capture and exact-identity transaction reads for bundles.

use super::artifact::CANCEL_POLL_RECORDS;
use super::{IndexBundleError, Withheld};
use crate::types::TxPosition;
use bitcoin_rs_chain::{
    BlockBodySource, BlockTreeReader, ChainTxCount, ChainWork, NodeId, NodeStatus, TipSnapshot,
};
use bitcoin_rs_primitives::{
    BlockHash, Hash256, Header, Tx, deserialize, layout::ParsedBlock, varint,
};
use std::collections::{HashMap, VecDeque};

pub(super) struct ChainBase {
    pub(super) height: u32,
    /// Base block hash, little-endian bytes.
    pub(super) hash: [u8; 32],
    pub(super) chainwork: ChainWork,
    /// Genesis block hash, little-endian bytes.
    pub(super) genesis: [u8; 32],
    pub(super) validated: bool,
    anchor_count: u64,
    above: Vec<NodeId>,
    nodes: Vec<NodeId>,
}

pub(super) enum BaseCount {
    Known(u64),
    Withheld(Withheld),
}

impl ChainBase {
    pub(super) fn capture(
        tree: &BlockTreeReader,
        tip: &TipSnapshot,
        base_height: u32,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, IndexBundleError> {
        let identity = |reason: &str| IndexBundleError::Identity(reason.to_owned());
        if cancelled() {
            return Err(IndexBundleError::Cancelled);
        }
        if base_height > tip.height {
            return Err(identity("bundle base is above the applied tip"));
        }
        let guard = tree.read();
        let mut nodes = Vec::new();
        let mut cursor = tip.tip_id;
        let mut expected = tip.height;
        let mut walked = 0_u64;
        loop {
            if walked.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            walked = walked.saturating_add(1);
            let node = guard
                .node(cursor)
                .map_err(|_| identity("applied-tip ancestry is missing from the block tree"))?;
            if node.height != expected {
                return Err(identity("applied-tip ancestry is not contiguous"));
            }
            nodes.push(cursor);
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
            expected = expected
                .checked_sub(1)
                .ok_or_else(|| identity("applied-tip ancestry passes below genesis"))?;
        }
        if expected != 0 {
            return Err(identity("applied-tip ancestry does not reach genesis"));
        }
        nodes.reverse();
        let keep =
            usize::try_from(base_height).map_or(usize::MAX, |height| height.saturating_add(1));
        let mut above = nodes.split_off(keep.min(nodes.len()));
        let base_id = nodes
            .last()
            .copied()
            .ok_or_else(|| identity("bundle base is missing from the applied-tip ancestry"))?;
        let base = guard
            .node(base_id)
            .map_err(|_| identity("bundle base is missing from the applied-tip ancestry"))?;
        let genesis = nodes
            .first()
            .and_then(|&id| guard.node(id).ok())
            .ok_or_else(|| identity("genesis is missing from the applied-tip ancestry"))?;
        let counted = |id: NodeId, count: ChainTxCount| {
            count.get().or_else(|| {
                (id == tip.tip_id)
                    .then_some(tip.chain_tx_count.get())
                    .flatten()
            })
        };
        let anchor_count = if let Some(count) = counted(base_id, base.chain_tx_count) {
            above.clear();
            count
        } else {
            let mut found = None;
            let mut scanned = 0_u64;
            for (index, &id) in above.iter().enumerate() {
                if scanned.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                    return Err(IndexBundleError::Cancelled);
                }
                scanned = scanned.saturating_add(1);
                let node = guard
                    .node(id)
                    .map_err(|_| identity("applied-tip ancestry is missing from the block tree"))?;
                if let Some(count) = counted(id, node.chain_tx_count) {
                    found = Some((index, count));
                    break;
                }
            }
            let (last, count) =
                found.ok_or_else(|| identity("chain transaction count is unknown at the base"))?;
            above.truncate(last.saturating_add(1));
            count
        };
        Ok(Self {
            height: base_height,
            hash: base.hash.to_le_bytes(),
            chainwork: base.chainwork,
            genesis: genesis.hash.to_le_bytes(),
            validated: base.status != NodeStatus::Invalid,
            anchor_count,
            above,
            nodes,
        })
    }

    pub(super) fn counted_base(&self) -> Option<u64> {
        self.above.is_empty().then_some(self.anchor_count)
    }

    pub(super) fn base_count(
        &self,
        tree: &BlockTreeReader,
        source: Option<&dyn BlockBodySource>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<BaseCount, IndexBundleError> {
        if self.above.is_empty() {
            return Ok(BaseCount::Known(self.anchor_count));
        }
        let Some(source) = source else {
            return Ok(BaseCount::Withheld(Withheld::NoBodySource));
        };
        let mut count = self.anchor_count;
        let mut visited = 0_u64;
        for &id in &self.above {
            if visited.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            visited = visited.saturating_add(1);
            let (height, hash) = {
                let guard = tree.read();
                let node = guard.node(id).map_err(|_| {
                    IndexBundleError::Identity(
                        "applied-tip ancestry is missing from the block tree".to_owned(),
                    )
                })?;
                (node.height, node.hash)
            };
            let Some(block_txs) = block_tx_count(source, height, hash)? else {
                return Ok(BaseCount::Withheld(Withheld::BodyUnavailable { height }));
            };
            count = ChainTxCount::established(count)
                .rewind(block_txs)
                .get()
                .ok_or_else(|| {
                    IndexBundleError::Identity(
                        "the receiver's chain transaction counts disagree above the bundle base"
                            .to_owned(),
                    )
                })?;
        }
        Ok(BaseCount::Known(count))
    }

    pub(super) fn hash_at(&self, tree: &BlockTreeReader, height: u32) -> Option<Hash256> {
        let id = *self.nodes.get(usize::try_from(height).ok()?)?;
        tree.read().node(id).ok().map(|node| node.hash)
    }

    /// 80-byte header at `height` on the captured ancestry.
    pub(super) fn header_at(&self, tree: &BlockTreeReader, height: u32) -> Option<[u8; 80]> {
        let id = *self.nodes.get(usize::try_from(height).ok()?)?;
        tree.read().node(id).ok().map(|node| node.header.to_bytes())
    }
}

fn block_tx_count(
    source: &dyn BlockBodySource,
    height: u32,
    hash: Hash256,
) -> Result<Option<u64>, IndexBundleError> {
    let hash = BlockHash::from(hash);
    let malformed = |reason: &str| IndexBundleError::BodyRead {
        height,
        reason: reason.to_owned(),
    };
    if let Some(metadata) = source.block_body_metadata(height, hash) {
        return u64::try_from(metadata.tx_count)
            .map(Some)
            .map_err(|_| malformed("the transaction count does not fit u64"));
    }
    let body = match source.block_body(height, hash) {
        Ok(Some(body)) => body,
        Ok(None) => return Ok(None),
        Err(error) => {
            return Err(IndexBundleError::BodyRead {
                height,
                reason: error.to_string(),
            });
        }
    };
    let (count, _) = body
        .get(Header::LEN..)
        .and_then(|rest| varint::decode(rest).ok())
        .ok_or_else(|| malformed("the body carries no transaction count"))?;
    Ok(Some(count))
}

pub(super) enum Located {
    Found(Tx),
    BodyMissing,
    Mismatch,
}

pub(super) fn is_top_level_span(position: TxPosition, start: u32, len: u32) -> bool {
    position.offset() == start && position.byte_len() == len
}

const BODY_CACHE_BLOCKS: usize = 8;

pub(super) struct BodyReader<'a> {
    source: &'a dyn BlockBodySource,
    bodies: VecDeque<HeldBody>,
    counts: HashMap<(u32, Hash256), u64>,
}

struct HeldBody {
    height: u32,
    hash: Hash256,
    body: Vec<u8>,
    spans: Vec<(u32, u32)>,
}

impl<'a> BodyReader<'a> {
    pub(super) fn new(source: &'a dyn BlockBodySource) -> Self {
        Self {
            source,
            bodies: VecDeque::with_capacity(BODY_CACHE_BLOCKS),
            counts: HashMap::new(),
        }
    }

    pub(super) fn transaction(
        &mut self,
        height: u32,
        hash: Hash256,
        position: TxPosition,
    ) -> Result<Located, IndexBundleError> {
        let Some(held) = self.held_body(height, hash)? else {
            return Ok(Located::BodyMissing);
        };
        let Ok(index) = held
            .spans
            .binary_search_by_key(&position.offset(), |&(start, _)| start)
        else {
            return Ok(Located::Mismatch);
        };
        let (start, len) = held.spans[index];
        if !is_top_level_span(position, start, len) {
            return Ok(Located::Mismatch);
        }
        let bytes = usize::try_from(start)
            .ok()
            .zip(usize::try_from(len).ok())
            .and_then(|(start, len)| held.body.get(start..start.checked_add(len)?))
            .unwrap_or_else(|| unreachable!("parsed span lies inside its body"));
        deserialize::<Tx>(bytes)
            .map(Located::Found)
            .map_err(|error| IndexBundleError::BodyRead {
                height,
                reason: format!("parsed transaction does not decode: {error}"),
            })
    }

    pub(super) fn block_tx_count(
        &mut self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<u64>, IndexBundleError> {
        if let Some(&count) = self.counts.get(&(height, hash)) {
            return Ok(Some(count));
        }
        if let Some(metadata) = self
            .source
            .block_body_metadata(height, BlockHash::from(hash))
        {
            let count =
                u64::try_from(metadata.tx_count).map_err(|_| IndexBundleError::BodyRead {
                    height,
                    reason: "the transaction count does not fit u64".to_owned(),
                })?;
            self.counts.insert((height, hash), count);
            return Ok(Some(count));
        }
        let count = self
            .held_body(height, hash)?
            .map(|held| u64::try_from(held.spans.len()).unwrap_or(u64::MAX));
        if let Some(count) = count {
            self.counts.insert((height, hash), count);
        }
        Ok(count)
    }

    fn held_body(
        &mut self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<&HeldBody>, IndexBundleError> {
        if let Some(index) = self
            .bodies
            .iter()
            .position(|held| held.height == height && held.hash == hash)
        {
            let held = self
                .bodies
                .remove(index)
                .unwrap_or_else(|| unreachable!("cached body index is in bounds"));
            self.bodies.push_front(held);
            return Ok(self.bodies.front());
        }
        {
            let body = match self.source.block_body(height, BlockHash::from(hash)) {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(None),
                Err(error) => {
                    return Err(IndexBundleError::BodyRead {
                        height,
                        reason: error.to_string(),
                    });
                }
            };
            let spans = ParsedBlock::parse_exact(&body)
                .map_err(|error| IndexBundleError::BodyRead {
                    height,
                    reason: format!("block does not parse: {error}"),
                })?
                .transactions()
                .iter()
                .map(|tx| (tx.span().start(), tx.span().len()))
                .collect::<Vec<_>>();
            self.counts
                .entry((height, hash))
                .or_insert_with(|| u64::try_from(spans.len()).unwrap_or(u64::MAX));
            self.bodies.push_front(HeldBody {
                height,
                hash,
                body,
                spans,
            });
            while self.bodies.len() > BODY_CACHE_BLOCKS {
                self.bodies.pop_back();
            }
        }
        Ok(self.bodies.front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::error::Error;
    use std::sync::Arc;

    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_chain::{BlockBodyReadError, BlockTree};
    use bitcoin_rs_primitives::CompactTarget;

    type TestResult = Result<(), Box<dyn Error>>;

    fn fixture_header(prev: BlockHash, height: u32) -> Header {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&height.to_le_bytes());
        Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        }
    }

    #[test]
    fn capture_polls_cancellation_during_chain_walks() -> TestResult {
        const HEIGHT: u32 = 5_000;
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(
            None,
            fixture_header(BlockHash::default(), 0),
            NodeStatus::HeaderValid,
        )?;
        let mut tip_id = genesis;
        let mut prev = BlockHash::from(tree.node(genesis)?.hash);
        for height in 1..=HEIGHT {
            let id = tree.insert_node(
                Some(tip_id),
                fixture_header(prev, height),
                NodeStatus::HeaderValid,
            )?;
            prev = BlockHash::from(tree.node(id)?.hash);
            tip_id = id;
        }
        let node = tree.node(tip_id)?;
        let count = u64::from(HEIGHT) + 1;
        let tip = TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: ChainTxCount::established(count),
        };
        let reader = BlockTreeReader::new(Arc::new(parking_lot::RwLock::new(tree)));

        let chain = ChainBase::capture(&reader, &tip, HEIGHT, &|| false)?;
        assert_eq!(chain.counted_base(), Some(count));

        for (base, quiet) in [(HEIGHT, 2_u32), (0, 4)] {
            let calls = Cell::new(0_u32);
            let cancelled = || {
                let n = calls.get();
                calls.set(n.saturating_add(1));
                n >= quiet
            };
            assert!(matches!(
                ChainBase::capture(&reader, &tip, base, &cancelled),
                Err(IndexBundleError::Cancelled)
            ));
        }
        Ok(())
    }

    struct OneBody {
        height: u32,
        hash: Hash256,
        body: Vec<u8>,
    }

    impl BlockBodySource for OneBody {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, BlockBodyReadError> {
            if height == self.height && hash == BlockHash::from(self.hash) {
                return Ok(Some(self.body.clone()));
            }
            Ok(None)
        }
    }

    fn find_needle(haystack: &[u8], needle: &[u8]) -> Option<u32> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
            .and_then(|index| u32::try_from(index).ok())
    }

    fn unique_tx(seed: u8) -> bitcoin::Transaction {
        let mut prev = [seed; 32];
        prev[0] = 0x9e;
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array(prev),
                    vout: u32::from(seed),
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    #[test]
    fn strict_resolution_rejects_embedded_serialization() -> TestResult {
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;
        let inner = unique_tx(0x7e);
        let inner_bytes = serialize(&inner);
        let _: Tx = deserialize(&inner_bytes)?;

        let mut outer = unique_tx(0x3a);
        outer.output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(inner_bytes.clone());
        let coinbase = unique_tx(0x01);
        let block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::from_byte_array([0_u8; 32]),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase, outer],
        };
        let body = serialize(&block);
        let parsed = ParsedBlock::parse_exact(&body)?;
        assert_eq!(
            parsed.tx_count(),
            2,
            "fixture holds two top-level transactions"
        );

        let height = 7_u32;
        let hash = Hash256::from_le_bytes(&[0xab_u8; 32]);
        let source = OneBody {
            height,
            hash,
            body: body.clone(),
        };
        let mut reader = BodyReader::new(&source);
        for tx in parsed.transactions() {
            let span = tx.span();
            let position = TxPosition::new(span.start(), span.len());
            let expected = tx.materialize().txid().0.to_le_bytes();
            match reader.transaction(height, hash, position)? {
                Located::Found(found) => assert_eq!(
                    found.txid().0.to_le_bytes(),
                    expected,
                    "exact top-level span must resolve to its own transaction"
                ),
                Located::BodyMissing => panic!("fixture body must be available"),
                Located::Mismatch => panic!("exact top-level span must resolve"),
            }
        }

        let inner_len = u32::try_from(inner_bytes.len())?;
        let offset = find_needle(&body, &inner_bytes).ok_or("embedded bytes not in the body")?;
        let embedded = TxPosition::new(offset, inner_len);
        assert!(
            !parsed
                .transactions()
                .iter()
                .map(|tx| (tx.span().start(), tx.span().len()))
                .any(|span| span == (offset, inner_len)),
            "embedded position must differ from every top-level span"
        );
        let start = usize::try_from(offset)?;
        let len = usize::try_from(inner_len)?;
        let _: Tx = deserialize(&body[start..start + len])?;
        assert!(
            matches!(
                reader.transaction(height, hash, embedded)?,
                Located::Mismatch
            ),
            "bytes that merely decode inside a script must not resolve"
        );
        Ok(())
    }
}
