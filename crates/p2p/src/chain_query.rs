//! Active-chain header walks and hash-addressed block serving.

use crate::inv::native_block_hash;

use std::sync::Arc;

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds};
use bitcoin::blockdata::block::Block as RegistryBlock;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
use bitcoin_rs_chain::{
    BlockBodySource, BlockTree, BlockTreeReader, ChainWork, NodeStatus, TipReader,
};
use bitcoin_rs_primitives::layout::{ParsedBlock, ParsedTransaction};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, consensus_bytes, deserialize,
};
use parking_lot::Mutex;
#[cfg(test)]
use parking_lot::RwLock;

use crate::dispatch::{
    ChainQuery, CommittedTip, FilterRequest, FilterServing, InventoryServing, StaleTipHeaders,
};
use crate::staletip::{
    CompressedHeader, MAX_STALETIP_HEADERS, STALETIP_RECENT_WINDOW, StaleTipAnnouncement,
};
use crate::wire::{Message, PeerError};

const MAX_CMPCTBLOCK_DEPTH: u32 = 5;

const MAX_BLOCKTXN_DEPTH: u32 = 10;

const STALE_RELAY_AGE_LIMIT: u32 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy)]
enum ServingPolicy {
    Announcement,
    Inventory,
    BlockTransactions,
}

type HeldBlock = (Hash256, Arc<Block>);

#[derive(Clone, Default)]
pub struct RecentBlockSlot {
    inner: Arc<Mutex<Option<HeldBlock>>>,
}

impl RecentBlockSlot {
    pub fn store(&self, hash: Hash256, block: Arc<Block>) {
        *self.inner.lock() = Some((hash, block));
    }

    #[must_use]
    pub fn load(&self) -> Option<(Hash256, Arc<Block>)> {
        self.inner.lock().clone()
    }
}

#[derive(Clone)]
pub struct ActiveChainQuery {
    block_tree: BlockTreeReader,
    applied_tip: TipReader,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    network: Network,
    compact_filters: Option<Arc<dyn bitcoin_rs_index::CompactFilterQuery>>,
    recent: RecentBlockSlot,
}

impl ActiveChainQuery {
    #[must_use]
    pub fn new(block_tree: BlockTreeReader, applied_tip: TipReader, network: Network) -> Self {
        Self {
            block_tree,
            applied_tip,
            block_body_source: None,
            network,
            compact_filters: None,
            recent: RecentBlockSlot::default(),
        }
    }

    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    #[must_use]
    pub fn with_compact_filters(
        mut self,
        filters: Option<Arc<dyn bitcoin_rs_index::CompactFilterQuery>>,
    ) -> Self {
        self.compact_filters = filters;
        self
    }

    #[must_use]
    pub fn with_recent_block(mut self, recent: RecentBlockSlot) -> Self {
        self.recent = recent;
        self
    }

    fn serving_position(&self, hash: BlockHash, policy: ServingPolicy) -> Option<(u32, u32)> {
        let tree = self.block_tree.read();
        let tip = self.applied_tip.load_full()?;
        let applied = tree.node(tip.tip_id).ok()?;
        if applied.hash != tip.hash || applied.height != tip.height {
            return None;
        }
        let node_id = tree.lookup(hash.into())?;
        let node = tree.node(node_id).ok()?;
        if node.status == NodeStatus::Invalid {
            return None;
        }
        let on_applied = tree.node_at_height_from(tip.tip_id, node.height) == Some(node_id);
        let allowed = match policy {
            ServingPolicy::Announcement => {
                let best = tree.tip()?;
                on_applied && tree.active_height_of(best.tip_id, hash.into()) == Some(node.height)
            }
            ServingPolicy::BlockTransactions
                if !beyond_depth(tip.height, node.height, MAX_BLOCKTXN_DEPTH) =>
            {
                true
            }
            ServingPolicy::Inventory | ServingPolicy::BlockTransactions => {
                on_applied
                    || (node.chain_tx_count.get().is_some()
                        && stale_block_is_recent(&tree, node, self.network))
            }
        };
        allowed.then_some((tip.height, node.height))
    }

    fn load_block(
        &self,
        height: u32,
        hash: BlockHash,
        include_witness: bool,
        policy: ServingPolicy,
    ) -> Option<(bytes::Bytes, u32)> {
        let bytes = self
            .block_body_source
            .as_ref()?
            .block_body(height, hash)
            .ok()??;
        let header = bytes
            .get(..80)
            .and_then(|header| deserialize::<Header>(header).ok())?;
        if header.compute_hash() != hash {
            return None;
        }
        let block = ParsedBlock::parse_exact(&bytes).ok()?;
        let stripped = if !include_witness
            && block
                .transactions()
                .iter()
                .any(ParsedTransaction::is_segwit)
        {
            let mut payload = Vec::with_capacity(bytes.len());
            payload.extend_from_slice(block.span_bytes(block.header_span())?);
            payload.extend_from_slice(block.span_bytes(block.tx_count_span())?);
            for tx in block.transactions() {
                for part in tx.stripped_parts() {
                    payload.extend_from_slice(part);
                }
            }
            Some(payload)
        } else {
            None
        };
        drop(block);
        let bytes = stripped.unwrap_or(bytes);
        let (tip_height, current_height) = self.serving_position(hash, policy)?;
        (current_height == height).then(|| (bytes::Bytes::from(bytes), tip_height))
    }

    fn full_block_response(
        &self,
        height: u32,
        hash: BlockHash,
        include_witness: bool,
    ) -> Option<Message> {
        self.load_block(height, hash, include_witness, ServingPolicy::Inventory)
            .map(|(body, _)| Message::BlockPayload(body))
    }

    fn recent_body(&self, hash: BlockHash) -> Option<Arc<Block>> {
        let (slot_hash, body) = self.recent.load()?;
        (BlockHash::from(slot_hash) == hash).then_some(body)
    }

    fn held_inventory_eligible(&self, hash: BlockHash) -> bool {
        let tree = self.block_tree.read();
        let Some(tip) = self.applied_tip.load_full() else {
            return false;
        };
        let Ok(applied) = tree.node(tip.tip_id) else {
            return false;
        };
        if applied.hash != tip.hash || applied.height != tip.height {
            return false;
        }
        let Some(node_id) = tree.lookup(hash.into()) else {
            return true;
        };
        let Ok(node) = tree.node(node_id) else {
            return false;
        };
        if node.status == NodeStatus::Invalid {
            return false;
        }
        if node.parent == Some(tip.tip_id)
            && applied.height.checked_add(1) == Some(node.height)
            && stale_block_is_recent(&tree, node, self.network)
        {
            return true;
        }
        false
    }

    /// peer's servable BIP152 profile. Shared by the stored path and the
    fn blocktxn_message(
        payload: &[u8],
        request: &BlockTransactionsRequest,
        compact_version: Option<u64>,
    ) -> Result<Option<Message>, PeerError> {
        let Ok(block) = bitcoin::consensus::encode::deserialize::<RegistryBlock>(payload) else {
            return Ok(None);
        };
        BlockTransactions::from_request(request, &block)
            .map(|mut transactions| {
                if compact_version == Some(1) {
                    strip_witnesses(&mut transactions);
                }
                Some(Message::BlockTxn(BlockTxn { transactions }))
            })
            .map_err(|_| PeerError::Misbehavior("getblocktxn index out of range"))
    }
}

impl core::fmt::Debug for ActiveChainQuery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ActiveChainQuery").finish_non_exhaustive()
    }
}

impl ChainQuery for ActiveChainQuery {
    fn compact_filters_ready(&self) -> bool {
        self.compact_filters
            .as_ref()
            .is_some_and(|index| index.filter_index_info().is_ok_and(|info| info.synced))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep BIP157 bounds, bounded catch-up and streaming in one serving owner"
    )]
    fn serve_compact_filters(
        &self,
        pending: &FilterRequest,
        headroom: &dyn Fn() -> bool,
        send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<FilterServing, PeerError> {
        use bitcoin::bip158::{FilterHash, FilterHeader};
        use bitcoin::p2p::message_filter::{CFCheckpt, CFHeaders, CFilter, GetCFilters};
        let request = &pending.request;
        let Some(index) = &self.compact_filters else {
            return Ok(FilterServing::Done);
        };
        let (kind, start, stop, limit, step) = match request {
            Message::GetCFilters(r) => (r.filter_type, r.start_height, r.stop_hash, 1000, 1),
            Message::GetCFHeaders(r) => (r.filter_type, r.start_height, r.stop_hash, 2000, 1),
            Message::GetCFCheckpt(r) => (r.filter_type, 1000, r.stop_hash, u32::MAX, 1000),
            _ => return Ok(FilterServing::Done),
        };
        if kind != 0 {
            return Ok(FilterServing::Done);
        }
        let stop_hash = Hash256::from_le_bytes(stop.as_byte_array());
        let end = self.applied_tip.load_full().and_then(|tip| {
            self.block_tree
                .read()
                .active_height_of(tip.tip_id, stop_hash)
        });
        if let Some(expected_end) = pending.expected_end
            && end != Some(expected_end)
        {
            return Err(PeerError::Io(std::io::Error::other(
                "compact filter range interrupted",
            )));
        }
        let Some(end) = end else {
            return Ok(FilterServing::Done);
        };
        if step == 1 && (end < start || end - start >= limit) {
            return Ok(FilterServing::Done);
        }
        if !headroom() {
            return Ok(FilterServing::Pending(pending.clone()));
        }
        let mut hashes = Vec::new();
        let mut headers = Vec::new();
        let mut send_error = None;
        let mut emitted = 0_u32;
        let mut halted = false;
        let result = index.for_each_filter(start, stop_hash, step, &mut |hash, filter| {
            if !headroom() {
                halted = true;
                return false;
            }
            match request {
                Message::GetCFilters(_) => {
                    if let Err(error) = send(Message::CFilter(CFilter {
                        filter_type: 0,
                        block_hash: bitcoin::BlockHash::from_byte_array(hash.to_le_bytes()),
                        filter: filter.filter,
                    })) {
                        send_error = Some(error);
                        return false;
                    }
                    emitted += 1;
                }
                Message::GetCFHeaders(_) => hashes.push(FilterHash::from_byte_array(filter.hash)),
                Message::GetCFCheckpt(_) => {
                    headers.push(FilterHeader::from_byte_array(filter.header));
                }
                _ => {}
            }
            true
        });
        if let Some(error) = send_error {
            return Err(error);
        }
        if emitted > 0 && halted {
            return Ok(FilterServing::Pending(FilterRequest {
                request: Message::GetCFilters(GetCFilters {
                    filter_type: 0,
                    start_height: start + emitted,
                    stop_hash: stop,
                }),
                expected_end: Some(end),
            }));
        }
        if emitted > 0 && emitted != end - start + 1 {
            return Err(PeerError::Io(std::io::Error::other(
                "compact filter range interrupted",
            )));
        }
        if emitted == 0 && (halted || matches!(result, Err(bitcoin_rs_index::TxQueryError::Retry)))
        {
            return Ok(FilterServing::Pending(pending.clone()));
        }
        if emitted == 0 && pending.expected_end.is_some() {
            return Err(PeerError::Io(std::io::Error::other(
                "compact filter range interrupted",
            )));
        }
        let Ok(Some(previous_header)) = result else {
            return Ok(FilterServing::Done);
        };
        match request {
            Message::GetCFHeaders(_) => send(Message::CFHeaders(CFHeaders {
                filter_type: 0,
                stop_hash: stop,
                previous_filter_header: FilterHeader::from_byte_array(previous_header),
                filter_hashes: hashes,
            }))?,
            Message::GetCFCheckpt(_) => send(Message::CFCheckpt(CFCheckpt {
                filter_type: 0,
                stop_hash: stop,
                filter_headers: headers,
            }))?,
            _ => {}
        }
        Ok(FilterServing::Done)
    }
    fn headers_after(
        &self,
        locator_hashes: &[BlockHash],
        stop_hash: BlockHash,
        limit: usize,
    ) -> Vec<Header> {
        if limit == 0 {
            return Vec::new();
        }
        let tree = self.block_tree.read();
        if locator_hashes.is_empty() {
            let Some(tip) = tree.tip() else {
                return Vec::new();
            };
            if tip.chainwork < ChainWork::from_be_bytes(self.network.minimum_chain_work()) {
                return Vec::new();
            }
            return header_for_active_stop(&tree, tip.tip_id, stop_hash)
                .into_iter()
                .take(limit)
                .collect();
        }
        let Some(applied) = self.applied_tip.load_full() else {
            return Vec::new();
        };
        let Ok(applied_node) = tree.node(applied.tip_id) else {
            return Vec::new();
        };
        if applied_node.hash != applied.hash || applied_node.height != applied.height {
            return Vec::new();
        }
        if applied_node.chainwork < ChainWork::from_be_bytes(self.network.minimum_chain_work()) {
            return Vec::new();
        }

        let mut height = locator_hashes
            .iter()
            .find_map(|hash| tree.active_height_of(applied.tip_id, (*hash).into()))
            .and_then(|height| height.checked_add(1))
            .unwrap_or(1);
        let has_stop = stop_hash != BlockHash::default();
        let mut headers = Vec::new();

        while height <= applied.height && headers.len() < limit {
            let Some(node_id) = tree.node_at_height_from(applied.tip_id, height) else {
                break;
            };
            let Ok(node) = tree.node(node_id) else {
                break;
            };
            let reached_stop = has_stop && BlockHash::from(node.hash) == stop_hash;
            headers.push(node.header);
            if reached_stop {
                break;
            }
            let Some(next_height) = height.checked_add(1) else {
                break;
            };
            height = next_height;
        }

        headers
    }

    fn best_block_time(&self) -> Option<u32> {
        let tip = self.applied_tip.load_full()?;
        let tree = self.block_tree.read();
        tree.node(tip.tip_id).ok().map(|node| node.header.time)
    }

    fn active_height(&self, hash: BlockHash) -> Option<u32> {
        let tree = self.block_tree.read();
        let tip = tree.tip()?;
        tree.active_height_of(tip.tip_id, hash.into())
    }

    fn compact_block_for(
        &self,
        height: u32,
        hash: BlockHash,
        compact_version: Option<u64>,
    ) -> Option<Message> {
        self.compact_block_for(height, hash, compact_version, ServingPolicy::Announcement)
    }

    fn committed_tip(&self) -> Option<CommittedTip> {
        let tip = self.applied_tip.load_full()?;
        let tree = self.block_tree.read();
        let active_tip = tree.tip()?;
        let node = tree.node(tip.tip_id).ok()?;
        (node.hash == tip.hash
            && tree.active_height_of(active_tip.tip_id, tip.hash) == Some(tip.height))
        .then(|| CommittedTip {
            height: tip.height,
            hash: BlockHash::from(tip.hash),
            prev_hash: node.header.prev_blockhash,
        })
    }

    fn serve_inventory_blocks(
        &self,
        items: &[Inventory],
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError> {
        let mut outcome = InventoryServing::default();
        for item in items {
            let Some(request) = inventory_block_request(item) else {
                outcome.not_found.push(*item);
                continue;
            };
            let Some((tip_height, height)) =
                self.serving_position(request.hash(), ServingPolicy::Inventory)
            else {
                if let BlockRequest::Compact(hash) = request
                    && let Some(version) = compact_version
                    && let Some(body) = self.recent_body(hash)
                    && self.held_inventory_eligible(hash)
                {
                    if !headroom() {
                        outcome.halted = true;
                        return Ok(outcome);
                    }
                    match cmpct_message_from_native(&body, version) {
                        Some(message) => serve(message)?,
                        None => outcome.not_found.push(*item),
                    }
                    continue;
                }
                outcome.not_found.push(*item);
                continue;
            };
            if !headroom() {
                outcome.halted = true;
                return Ok(outcome);
            }
            let response = self.response_for(request, tip_height, height, compact_version);
            match response {
                Some(message) => serve(message)?,
                None => outcome.not_found.push(*item),
            }
        }
        Ok(outcome)
    }

    /// servable BIP152 profile.
    fn block_transactions(
        &self,
        request: &BlockTransactionsRequest,
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        let hash = native_block_hash(request.block_hash);
        if let Some(body) = self.recent_body(hash) {
            if !headroom() {
                return Ok(None);
            }
            return Self::blocktxn_message(
                &consensus_bytes(body.as_ref()),
                request,
                compact_version,
            );
        }
        let Some((tip_height, height)) =
            self.serving_position(hash, ServingPolicy::BlockTransactions)
        else {
            return Ok(None);
        };
        let deep = beyond_depth(tip_height, height, MAX_BLOCKTXN_DEPTH);
        if !headroom() {
            return Ok(None);
        }
        let policy = if deep {
            ServingPolicy::Inventory
        } else {
            ServingPolicy::BlockTransactions
        };
        let Some((payload, tip_height)) = self.load_block(height, hash, true, policy) else {
            return Ok(None);
        };
        if deep || beyond_depth(tip_height, height, MAX_BLOCKTXN_DEPTH) {
            return Ok(Some(Message::BlockPayload(payload)));
        }
        Self::blocktxn_message(payload.as_ref(), request, compact_version)
    }

    fn stale_tip_announcement(
        &self,
        tip: Hash256,
        peer_tips: &[Hash256],
    ) -> Option<StaleTipHeaders> {
        if peer_tips.is_empty() {
            return None;
        }
        let tree = self.block_tree.read();
        let tip_node_id = tree.lookup(tip)?;
        let tip_node = tree.node(tip_node_id).ok()?;
        if tip_node.status == NodeStatus::Invalid {
            return None;
        }
        let active_tip = tree.tip()?;
        if active_tip.height.saturating_sub(tip_node.height) > STALETIP_RECENT_WINDOW {
            return None;
        }
        let active_fork = tree.find_common_ancestor(active_tip.tip_id, tip_node_id)?;
        if active_fork == tip_node_id || active_fork == active_tip.tip_id {
            return None;
        }

        let mut best_ancestor = None;
        for peer_tip_hash in peer_tips {
            let Some(peer_tip_id) = tree.lookup(*peer_tip_hash) else {
                continue;
            };
            let Some(ancestor_id) = tree.find_common_ancestor(tip_node_id, peer_tip_id) else {
                continue;
            };
            let Ok(ancestor_node) = tree.node(ancestor_id) else {
                continue;
            };
            if best_ancestor.is_none_or(|(max_height, _)| ancestor_node.height > max_height) {
                best_ancestor = Some((ancestor_node.height, ancestor_id));
            }
        }

        let (_, fork_id) = best_ancestor?;
        if fork_id == tip_node_id {
            return None;
        }
        let fork_node = tree.node(fork_id).ok()?;
        let distance = tip_node.height.checked_sub(fork_node.height)?;
        if distance > u32::try_from(MAX_STALETIP_HEADERS).unwrap_or(u32::MAX) {
            return Some(StaleTipHeaders::TooMany);
        }

        let mut headers =
            Vec::with_capacity(usize::try_from(distance).unwrap_or(MAX_STALETIP_HEADERS));
        let mut cursor = tip_node_id;
        while cursor != fork_id {
            let node = tree.node(cursor).ok()?;
            headers.push(CompressedHeader::from_header(&node.header));
            cursor = node.parent?;
        }
        headers.reverse();

        let fork_point = fork_node.hash;
        let tip_height = tip_node.height;
        drop(tree);

        let have_block = self
            .block_body_source
            .as_ref()
            .and_then(|source| {
                source
                    .block_body(tip_height, BlockHash::from(tip))
                    .ok()
                    .flatten()
            })
            .is_some();

        Some(StaleTipHeaders::Headers(StaleTipAnnouncement {
            fork_point,
            headers,
            have_block,
        }))
    }
}

fn strip_witnesses(transactions: &mut BlockTransactions) {
    for tx in &mut transactions.transactions {
        for input in &mut tx.input {
            input.witness.clear();
        }
    }
}

impl ActiveChainQuery {
    /// inventory policy at the negotiated BIP152 version.
    fn compact_block_for(
        &self,
        height: u32,
        hash: BlockHash,
        compact_version: Option<u64>,
        policy: ServingPolicy,
    ) -> Option<Message> {
        if let Some(body) = self.recent_body(hash) {
            return cmpct_message_from_native(&body, compact_version?);
        }
        self.serving_position(hash, policy)?;
        let version = u32::try_from(compact_version?).ok()?;
        if version != 1 && version != 2 {
            return None;
        }
        let (payload, tip_height) = self.load_block(height, hash, true, policy)?;
        if beyond_depth(tip_height, height, MAX_CMPCTBLOCK_DEPTH) {
            return Some(Message::BlockPayload(payload));
        }
        let block =
            bitcoin::consensus::encode::deserialize::<RegistryBlock>(payload.as_ref()).ok()?;
        let cmpct = HeaderAndShortIds::from_block(&block, fresh_nonce(), version, &[]).ok()?;
        Some(Message::CmpctBlock(CmpctBlock {
            compact_block: cmpct,
        }))
    }

    fn response_for(
        &self,
        request: BlockRequest,
        tip_height: u32,
        height: u32,
        compact_version: Option<u64>,
    ) -> Option<Message> {
        match request {
            BlockRequest::Full {
                hash,
                include_witness,
            } => self.full_block_response(height, hash, include_witness),
            BlockRequest::Compact(hash)
                if beyond_depth(tip_height, height, MAX_CMPCTBLOCK_DEPTH) =>
            {
                self.full_block_response(height, hash, true)
            }
            BlockRequest::Compact(hash) => {
                self.compact_block_for(height, hash, compact_version, ServingPolicy::Inventory)
            }
        }
    }
}

fn stale_block_is_recent(
    tree: &BlockTree,
    node: &bitcoin_rs_chain::BlockTreeNode,
    network: Network,
) -> bool {
    let Some(best_tip) = tree.tip() else {
        return false;
    };
    let Ok(best) = tree.node(best_tip.tip_id) else {
        return false;
    };
    if best.header.time.saturating_sub(node.header.time) >= STALE_RELAY_AGE_LIMIT {
        return false;
    }
    if node.chainwork >= best.chainwork {
        return true;
    }
    let work = bitcoin_rs_chain::block_work(&best.header);
    work != ChainWork::ZERO
        && (best.chainwork - node.chainwork)
            .checked_mul(ChainWork::from(network.target_spacing_seconds()))
            .is_some_and(|scaled| scaled / work < ChainWork::from(STALE_RELAY_AGE_LIMIT))
}

const fn beyond_depth(tip_height: u32, height: u32, limit: u32) -> bool {
    tip_height.saturating_sub(height) > limit
}

#[derive(Clone, Copy, Debug)]
enum BlockRequest {
    Full {
        hash: BlockHash,
        include_witness: bool,
    },
    Compact(BlockHash),
}

impl BlockRequest {
    const fn hash(self) -> BlockHash {
        match self {
            Self::Full { hash, .. } | Self::Compact(hash) => hash,
        }
    }
}

fn inventory_block_request(item: &Inventory) -> Option<BlockRequest> {
    match *item {
        Inventory::Block(hash) | Inventory::WitnessBlock(hash) => Some(BlockRequest::Full {
            hash: native_block_hash(hash),
            include_witness: matches!(item, Inventory::WitnessBlock(_)),
        }),
        Inventory::CompactBlock(hash) => Some(BlockRequest::Compact(native_block_hash(hash))),
        Inventory::Error
        | Inventory::Transaction(_)
        | Inventory::WTx(_)
        | Inventory::WitnessTransaction(_)
        | Inventory::Unknown { .. } => None,
    }
}

/// Fresh BIP152 serving nonce. `RandomState` draws fresh keys per call, so
/// two responses never share one (BIP152: SHOULD NOT reuse across blocks).
fn fresh_nonce() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// `None` for a non-BIP152 version or an unencodable block.
pub(crate) fn cmpct_message_from_native(block: &Block, version: u64) -> Option<Message> {
    let version = u32::try_from(version).ok()?;
    if version != 1 && version != 2 {
        return None;
    }
    let bytes = consensus_bytes(block);
    let registry = bitcoin::consensus::encode::deserialize::<RegistryBlock>(bytes.as_ref()).ok()?;
    let cmpct = HeaderAndShortIds::from_block(&registry, fresh_nonce(), version, &[]).ok()?;
    Some(Message::CmpctBlock(CmpctBlock {
        compact_block: cmpct,
    }))
}

fn header_for_active_stop(
    tree: &BlockTree,
    tip_id: bitcoin_rs_chain::NodeId,
    stop_hash: BlockHash,
) -> Option<Header> {
    if stop_hash == BlockHash::default() {
        return None;
    }
    let height = tree.active_height_of(tip_id, stop_hash.into())?;
    let node_id = tree.node_at_height_from(tip_id, height)?;
    Some(tree.node(node_id).ok()?.header)
}

#[cfg(test)]
mod tests;
