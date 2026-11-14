#![no_main]

use std::collections::HashMap;

use bitcoin_rs_execution::chain::regtest_fixture::{REGTEST_BITS, genesis_time};
use bitcoin_rs_execution::chain::{
    BlockTree, HeaderValidationMode, NodeId, accept_headers, plan_reorg,
};
use bitcoin_rs_consensus::header_rules::ChainWork;
use bitcoin_rs_consensus::primitives::{
    BlockHash, CompactTarget, Hash256, Header, Network, deserialize,
};
use libfuzzer_sys::fuzz_target;

const NOW: u32 = 2_000_000_000;

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn next(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
}

#[derive(Clone, Copy)]
struct Tracked {
    id: NodeId,
    hash: Hash256,
    work: ChainWork,
    children: u32,
}

fn work_for_bits(bits: u32) -> ChainWork {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if exponent > 0x20 || (bits & 0x0080_0000) != 0 || mantissa == 0 {
        return ChainWork::ZERO;
    }
    let target = if exponent <= 3 {
        ChainWork::from(mantissa >> (8 * (3 - exponent)))
    } else {
        ChainWork::from(mantissa) << (8 * usize::try_from(exponent - 3).expect("shift fits"))
    };
    if target == ChainWork::ZERO {
        return ChainWork::ZERO;
    }
    (!target) / (target + ChainWork::from(1_u32)) + ChainWork::from(1_u32)
}

fn mine(header: &mut Header) {
    loop {
        if bitcoin_rs_execution::chain::compact_is_met_by(header.bits, Hash256::from(header.compute_hash())) {
            return;
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
}

fn record(
    tree: &BlockTree,
    ids: &[NodeId],
    tracked: &mut Vec<Tracked>,
    by_hash: &mut HashMap<Hash256, usize>,
) {
    for id in ids {
        let node = tree.node(*id).expect("accepted node must exist");
        if by_hash.contains_key(&node.hash) {
            continue;
        }
        let (work, parent_slot) = match node.parent {
            Some(parent) => {
                let parent_hash = tree.node(parent).expect("parent node must exist").hash;
                let slot = *by_hash
                    .get(&parent_hash)
                    .expect("accepted parent must be tracked");
                (tracked[slot].work + work_for_bits(node.header.bits.to_consensus()), Some(slot))
            }
            None => (work_for_bits(node.header.bits.to_consensus()), None),
        };
        if let Some(slot) = parent_slot {
            tracked[slot].children += 1;
        }
        by_hash.insert(node.hash, tracked.len());
        tracked.push(Tracked {
            id: *id,
            hash: node.hash,
            work,
            children: 0,
        });
    }
}

fn record_prefix(
    tree: &BlockTree,
    headers: &[Header],
    tracked: &mut Vec<Tracked>,
    by_hash: &mut HashMap<Hash256, usize>,
) {
    for header in headers {
        if let Some(id) = tree.lookup(Hash256::from(header.compute_hash())) {
            record(tree, &[id], tracked, by_hash);
        }
    }
}

fn expected_tip(tracked: &[Tracked]) -> Option<&Tracked> {
    let mut best: Option<&Tracked> = None;
    for candidate in tracked {
        if best.is_none_or(|current| candidate.work > current.work) {
            best = Some(candidate);
        }
    }
    best
}

fn check_plan(tree: &BlockTree, old: NodeId, new: NodeId) {
    if old == new {
        return;
    }
    let plan = plan_reorg(tree, old, new).expect("reorg plan must exist");
    let ancestor = tree
        .find_common_ancestor(old, new)
        .expect("common ancestor must exist");
    let ancestor_height = tree.node(ancestor).expect("ancestor node").height;
    assert_eq!(
        plan.disconnect.len(),
        usize::try_from(tree.node(old).expect("old tip").height - ancestor_height).expect("height"),
        "disconnect path length must equal the height gap"
    );
    assert_eq!(
        plan.connect.len(),
        usize::try_from(tree.node(new).expect("new tip").height - ancestor_height).expect("height"),
        "connect path length must equal the height gap"
    );
    if let Some(first) = plan.connect.first() {
        assert_eq!(
            tree.parent_id(*first).expect("parent read"),
            Some(ancestor),
            "connect path must start at the common ancestor"
        );
    } else {
        assert_eq!(ancestor, new, "empty connect path must mean the new tip is the ancestor");
    }
    if let Some(first) = plan.disconnect.first() {
        assert_eq!(*first, old, "disconnect path must start at the old tip");
    } else {
        assert_eq!(ancestor, old, "empty disconnect path must mean the old tip is the ancestor");
    }
    for pair in plan.connect.windows(2) {
        assert_eq!(
            tree.parent_id(pair[1]).expect("parent read"),
            Some(pair[0]),
            "connect path must descend"
        );
    }
    for pair in plan.disconnect.windows(2) {
        assert_eq!(
            tree.parent_id(pair[0]).expect("parent read"),
            Some(pair[1]),
            "disconnect path must ascend"
        );
    }
}

fn verify(tree: &BlockTree, tracked: &[Tracked]) {
    assert_eq!(
        tree.len(),
        tracked.len(),
        "tree must hold exactly the tracked headers"
    );
    match expected_tip(tracked) {
        Some(expected) => {
            let tip = tree.tip().expect("tracked headers must publish a tip");
            assert_eq!(tip.hash, expected.hash, "tip must be the maximum-work header");
            assert_eq!(tip.tip_id, expected.id, "tip node must match the tracked id");
            assert_eq!(tip.chainwork, expected.work, "tip work must match the tracked work");
        }
        None => assert!(tree.tip().is_none(), "empty tree must have no tip"),
    }
}

fn child_header(parent_hash: Hash256, parent_time: u32, delta: u32, nonce: u32) -> Header {
    Header {
        version: 4,
        prev_blockhash: BlockHash(parent_hash),
        merkle_root: Hash256::default(),
        time: parent_time.saturating_add(1).saturating_add(delta),
        bits: CompactTarget::from_consensus(REGTEST_BITS),
        nonce,
    }
}

fn mined_header(tree: &BlockTree, parent: &Tracked, delta: u32, nonce: u32) -> Header {
    let parent_node = tree.node(parent.id).expect("parent node");
    let mut header = child_header(parent.hash, parent_node.header.time, delta % 600, nonce);
    mine(&mut header);
    header
}

fn submit(
    tree: &mut BlockTree,
    headers: &[Header],
) -> Result<Vec<NodeId>, bitcoin_rs_execution::chain::ChainError> {
    accept_headers(
        tree,
        headers,
        Network::Regtest,
        NOW,
        HeaderValidationMode::LiveAdmission,
    )
    .map(|accepted| accepted.ids)
}

fn raw_chunk(
    tree: &mut BlockTree,
    chunk: &[u8; 80],
    tracked: &mut Vec<Tracked>,
    by_hash: &mut HashMap<Hash256, usize>,
) {
    let header: Header = deserialize(chunk).expect("an 80-byte chunk is a header");
    let before_len = tree.len();
    let before_tip = tree.tip().map(|tip| tip.hash);
    match submit(tree, &[header]) {
        Ok(ids) => record(tree, &ids, tracked, by_hash),
        Err(_) => {
            assert_eq!(tree.len(), before_len, "refused header must not add a node");
            assert_eq!(
                tree.tip().map(|tip| tip.hash),
                before_tip,
                "refused header must not move the tip"
            );
        }
    }
    verify(tree, tracked);
}

fn mined_op(
    tree: &mut BlockTree,
    chunk: &[u8; 80],
    tracked: &mut Vec<Tracked>,
    by_hash: &mut HashMap<Hash256, usize>,
) {
    let delta = u32::from_le_bytes([chunk[72], chunk[73], chunk[74], chunk[75]]);
    let slot = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        .checked_rem(u32::try_from(tracked.len()).expect("nonempty"))
        .expect("modulo") as usize;
    let header = mined_header(tree, &tracked[slot], delta, u32::from_le_bytes([
        chunk[76], chunk[77], chunk[78], chunk[79],
    ]));
    let ids = submit(tree, &[header]).expect("mined header must be accepted");
    assert_eq!(ids.len(), 1, "a single-header batch accepts one header");
    record(tree, &ids, tracked, by_hash);
}

fn batch_op(
    tree: &mut BlockTree,
    chunk: &[u8; 80],
    tracked: &mut Vec<Tracked>,
    by_hash: &mut HashMap<Hash256, usize>,
) {
    let count = 1 + usize::from(chunk[0] % 8);
    let corrupt = usize::from(chunk[1]) % (count + 1);
    let corrupt_mode = chunk[2] & 1;
    let slot = u32::from_le_bytes([chunk[3], chunk[4], chunk[5], chunk[6]])
        .checked_rem(u32::try_from(tracked.len()).expect("nonempty"))
        .expect("modulo") as usize;
    let delta = u32::from_le_bytes([chunk[72], chunk[73], chunk[74], chunk[75]]) % 300;
    let mut parent_header = tree.node(tracked[slot].id).expect("parent node").header;
    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let mut header = child_header(
            Hash256::from(parent_header.compute_hash()),
            parent_header.time,
            delta,
            u32::from_be_bytes([chunk[76], chunk[77], chunk[78], chunk[79]])
                .wrapping_add(u32::try_from(index).expect("count fits")),
        );
        if index == corrupt {
            if corrupt_mode == 0 {
                header.time = genesis_time().saturating_sub(1_000);
            } else {
                header.bits = CompactTarget::from_consensus(0);
            }
        } else {
            mine(&mut header);
        }
        parent_header = header;
        headers.push(header);
    }
    let result = submit(tree, &headers);
    if corrupt < count {
        assert!(result.is_err(), "corrupted batch must be refused");
        for header in &headers[..corrupt] {
            assert!(
                tree.lookup(Hash256::from(header.compute_hash())).is_some(),
                "accepted prefix header must be inserted"
            );
        }
        for header in &headers[corrupt..] {
            assert!(
                tree.lookup(Hash256::from(header.compute_hash())).is_none(),
                "refused suffix header must stay absent"
            );
        }
    } else {
        let ids = result.expect("valid batch must be accepted");
        assert_eq!(ids.len(), count, "valid batch accepts every header");
    }
    record_prefix(tree, &headers[..corrupt], tracked, by_hash);
    verify(tree, tracked);
}

fn reorg_op(
    tree: &mut BlockTree,
    chunk: &[u8; 80],
    tracked: &mut Vec<Tracked>,
    by_hash: &mut HashMap<Hash256, usize>,
) {
    let old_tip = tree.tip_id().expect("tip must exist");
    let old_work = tree.tip().expect("tip snapshot").chainwork;
    let pick = match tracked
        .iter()
        .position(|node| node.children == 0 && node.id != old_tip)
    {
        Some(slot) => slot,
        None => u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            .checked_rem(u32::try_from(tracked.len()).expect("nonempty"))
            .expect("modulo") as usize,
    };
    let per_header = work_for_bits(REGTEST_BITS);
    let deficit = old_work.saturating_sub(tracked[pick].work);
    let steps = usize::try_from(deficit / per_header)
        .unwrap_or(usize::MAX)
        .saturating_add(1)
        .min(16);
    let delta = u32::from_le_bytes([chunk[72], chunk[73], chunk[74], chunk[75]]) % 300;
    let mut parent_header = tree.node(tracked[pick].id).expect("parent node").header;
    let mut headers = Vec::with_capacity(steps);
    for index in 0..steps {
        let mut header = child_header(
            Hash256::from(parent_header.compute_hash()),
            parent_header.time,
            delta,
            u32::from_be_bytes([chunk[76], chunk[77], chunk[78], chunk[79]])
                .wrapping_add(u32::try_from(index).expect("steps fit")),
        );
        mine(&mut header);
        parent_header = header;
        headers.push(header);
    }
    let ids = submit(tree, &headers).expect("mined extension must be accepted");
    assert_eq!(ids.len(), steps, "mined extension accepts every header");
    record(tree, &ids, tracked, by_hash);
    if let Some(new_tip) = tree.tip_id() {
        assert!(
            tree.tip().expect("tip snapshot").chainwork >= old_work,
            "tip work must never regress"
        );
        check_plan(tree, old_tip, new_tip);
    }
    verify(tree, tracked);
}

fuzz_target!(|data: &[u8]| {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let mut tree = BlockTree::new();
    let genesis_ids = submit(&mut tree, &[genesis.header]).expect("regtest genesis is admissible");
    let mut tracked: Vec<Tracked> = Vec::new();
    let mut by_hash: HashMap<Hash256, usize> = HashMap::new();
    record(&tree, &genesis_ids, &mut tracked, &mut by_hash);
    verify(&tree, &tracked);

    let mut cursor = Cursor::new(data);
    loop {
        let Some(op) = cursor.next() else {
            break;
        };
        let Some(chunk) = cursor.take(80) else {
            break;
        };
        let mut chunk_bytes = [0_u8; 80];
        chunk_bytes.copy_from_slice(chunk);
        let before_len = tree.len();
        match op % 4 {
            0 => raw_chunk(&mut tree, &chunk_bytes, &mut tracked, &mut by_hash),
            1 => mined_op(&mut tree, &chunk_bytes, &mut tracked, &mut by_hash),
            2 => batch_op(&mut tree, &chunk_bytes, &mut tracked, &mut by_hash),
            _ => reorg_op(&mut tree, &chunk_bytes, &mut tracked, &mut by_hash),
        }
        assert!(
            tree.len() <= data.len() + 1,
            "tree must stay within the input-derived node bound"
        );
        assert!(
            tree.len() >= before_len,
            "header submission must never drop nodes"
        );
        verify(&tree, &tracked);
    }
});
