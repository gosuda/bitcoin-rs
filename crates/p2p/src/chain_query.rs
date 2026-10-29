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
mod tests {
    use super::*;
    use crate::inv::wire_block_hash;
    use bitcoin::{BlockHash as WireBlockHash, Txid as WireTxid};
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::consensus_bytes;
    use bitcoin_rs_primitives::{Block, CompactTarget, Tx};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SingleBlockSource {
        height: u32,
        hash: BlockHash,
        body: Vec<u8>,
    }

    impl BlockBodySource for SingleBlockSource {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
            Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
        }
    }

    struct CountingBodySource {
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
        loads: AtomicUsize,
        tripwire: Option<usize>,
    }

    impl BlockBodySource for CountingBodySource {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
            if let Some(limit) = self.tripwire {
                assert!(
                    self.loads.load(Ordering::Relaxed) < limit,
                    "body loaded beyond the production-gate bound"
                );
            }
            self.loads.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .bodies
                .iter()
                .find(|(entry_height, entry_hash, _)| {
                    *entry_height == height && *entry_hash == hash
                })
                .map(|(_, _, body)| body.clone()))
        }
    }

    fn serve_collect(
        query: &ActiveChainQuery,
        items: &[Inventory],
    ) -> Result<(InventoryServing, Vec<Block>), PeerError> {
        let blocks = RefCell::new(Vec::new());
        let outcome = query.serve_inventory_blocks(items, None, &|| true, &mut |message| {
            let Message::BlockPayload(payload) = message else {
                return Ok(());
            };
            blocks.borrow_mut().push(deserialize::<Block>(&payload)?);
            Ok(())
        })?;
        Ok((outcome, blocks.into_inner()))
    }

    fn canned_filter() -> bitcoin_rs_index::BasicFilter {
        bitcoin_rs_index::BasicFilter {
            filter: vec![0],
            hash: [1; 32],
            header: [2; 32],
        }
    }

    fn getcfilters_request(stop: WireBlockHash, start_height: u32) -> Message {
        Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
            filter_type: 0,
            start_height,
            stop_hash: stop,
        })
    }

    fn getcfheaders_request(stop: WireBlockHash, start_height: u32) -> Message {
        Message::GetCFHeaders(bitcoin::p2p::message_filter::GetCFHeaders {
            filter_type: 0,
            start_height,
            stop_hash: stop,
        })
    }

    fn getcfcheckpt_request(stop: WireBlockHash) -> Message {
        Message::GetCFCheckpt(bitcoin::p2p::message_filter::GetCFCheckpt {
            filter_type: 0,
            stop_hash: stop,
        })
    }

    fn filter_range_requests(
        stop: WireBlockHash,
        checkpoint_stop: WireBlockHash,
        start_height: u32,
    ) -> [Message; 3] {
        [
            getcfilters_request(stop, start_height),
            getcfheaders_request(stop, start_height),
            getcfcheckpt_request(checkpoint_stop),
        ]
    }

    fn parked_cfilter_remainder(
        stop: WireBlockHash,
        resumed_start: u32,
        expected_end: u32,
    ) -> FilterRequest {
        FilterRequest {
            request: getcfilters_request(stop, resumed_start),
            expected_end: Some(expected_end),
        }
    }

    fn collect_filter_responses(
        query: &ActiveChainQuery,
        request: &FilterRequest,
        headroom: &dyn Fn() -> bool,
    ) -> Result<(FilterServing, Vec<Message>), PeerError> {
        let mut responses = Vec::new();
        let outcome = query.serve_compact_filters(request, headroom, &mut |message| {
            responses.push(message);
            Ok(())
        })?;
        Ok((outcome, responses))
    }

    fn assert_complete_filter_range(request: &Message, responses: &[Message]) {
        match (request, responses) {
            (Message::GetCFilters(_), [Message::CFilter(_), Message::CFilter(_)]) => {}
            (Message::GetCFHeaders(_), [Message::CFHeaders(reply)]) => {
                assert_eq!(reply.filter_hashes.len(), 2);
            }
            (Message::GetCFCheckpt(_), [Message::CFCheckpt(reply)]) => {
                assert_eq!(reply.filter_headers.len(), 2);
            }
            _ => panic!("retry must deliver the complete response"),
        }
    }

    #[test]
    fn invalid_compact_filter_requests_are_ignored_without_querying_the_index()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::p2p::message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters};
        use bitcoin_rs_index::{BasicFilter, CompactFilterQuery, DerivedIndexInfo, TxQueryError};

        struct Filters;
        impl CompactFilterQuery for Filters {
            fn block_filter(&self, _: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
                unreachable!("invalid request must not query the index")
            }
            fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
                unreachable!("invalid request must not query the index")
            }
            fn for_each_filter(
                &self,
                _: u32,
                _: Hash256,
                _: u32,
                _: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
            ) -> Result<Option<[u8; 32]>, TxQueryError> {
                unreachable!("invalid request must not query the index")
            }
        }

        let headers = seed_headers(2001);
        let stop = wire_block_hash(headers[2000].compute_hash());
        let query = query_with(headers)?.with_compact_filters(Some(Arc::new(Filters)));
        for command in 0..3 {
            for (kind, start, stop) in [
                (1, 2000, stop),
                (0, 2000, WireBlockHash::all_zeros()),
                (0, 2001, stop),
                (0, 0, stop),
            ] {
                if command == 2 && kind == 0 && stop != WireBlockHash::all_zeros() {
                    continue;
                }
                let request = match command {
                    0 => Message::GetCFilters(GetCFilters {
                        filter_type: kind,
                        start_height: start,
                        stop_hash: stop,
                    }),
                    1 => Message::GetCFHeaders(GetCFHeaders {
                        filter_type: kind,
                        start_height: start,
                        stop_hash: stop,
                    }),
                    _ => Message::GetCFCheckpt(GetCFCheckpt {
                        filter_type: kind,
                        stop_hash: stop,
                    }),
                };
                assert_eq!(
                    query.serve_compact_filters(
                        &FilterRequest::new(request),
                        &|| panic!("invalid request must not consume headroom"),
                        &mut |_| panic!("invalid request must not emit a response"),
                    )?,
                    FilterServing::Done
                );
            }
        }
        Ok(())
    }

    #[test]
    fn compact_filters_wait_for_publication_without_replaying_sent_payloads()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_index::{BasicFilter, CompactFilterQuery, DerivedIndexInfo, TxQueryError};
        use std::sync::atomic::{AtomicBool, Ordering};

        struct Filters {
            ready: AtomicBool,
            moves_after_delivery: bool,
        }
        impl CompactFilterQuery for Filters {
            fn block_filter(&self, _: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
                unreachable!("range serving only")
            }
            fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
                Ok(DerivedIndexInfo {
                    synced: self.ready.load(Ordering::Acquire),
                    best_block_height: 0,
                })
            }
            fn for_each_filter(
                &self,
                _: u32,
                stop: Hash256,
                _: u32,
                emit: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
            ) -> Result<Option<[u8; 32]>, TxQueryError> {
                if !self.ready.load(Ordering::Acquire) {
                    return Err(TxQueryError::Retry);
                }
                if !emit(stop, canned_filter()) {
                    return Ok(None);
                }
                if self.moves_after_delivery {
                    Err(TxQueryError::Retry)
                } else {
                    Ok(Some([0; 32]))
                }
            }
        }
        let header = seed_headers(1)[0];
        for moves_after_delivery in [false, true] {
            let index = Arc::new(Filters {
                ready: AtomicBool::new(false),
                moves_after_delivery,
            });
            let query = query_with(vec![header])?.with_compact_filters(Some(index.clone()));
            assert!(!query.compact_filters_ready());
            let request = getcfilters_request(wire_block_hash(header.compute_hash()), 0);
            let mut responses = Vec::new();
            let pending = FilterRequest::new(request);
            assert_eq!(
                query.serve_compact_filters(&pending, &|| true, &mut |_| {
                    panic!("pending publication must not emit a response")
                })?,
                FilterServing::Pending(pending.clone()),
                "an unpublished range stays pending, unchanged"
            );
            index.ready.store(true, Ordering::Release);
            let (outcome, delivered) = collect_filter_responses(&query, &pending, &|| true)?;
            responses.extend(delivered);
            assert_eq!(outcome, FilterServing::Done);
            assert!(query.compact_filters_ready());
            assert_eq!(responses.len(), 1);
            assert!(matches!(&responses[0], Message::CFilter(filter)
                if filter.filter == [0] && filter.block_hash == wire_block_hash(header.compute_hash())));
            assert_eq!(
                query.serve_compact_filters(&pending, &|| false, &mut |_| {
                    panic!("backpressured peer must not receive a filter")
                })?,
                FilterServing::Pending(pending.clone())
            );
            let headers = seed_headers(2);
            let stop = headers[1].compute_hash();
            let query = query_with(headers)?.with_compact_filters(Some(index));
            let request = getcfilters_request(wire_block_hash(stop), 0);
            assert!(matches!(
                query.serve_compact_filters(
                    &FilterRequest::new(request),
                    &|| true,
                    &mut |_| Ok(())
                ),
                Err(PeerError::Io(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn filter_backpressure_defers_unsent_responses_and_parks_the_remainder_of_a_partial_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_index::{BasicFilter, CompactFilterQuery, DerivedIndexInfo, TxQueryError};
        use std::cell::Cell;

        struct Filters;
        impl CompactFilterQuery for Filters {
            fn block_filter(&self, _: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
                unreachable!("range only")
            }
            fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
                Ok(DerivedIndexInfo {
                    synced: true,
                    best_block_height: 2000,
                })
            }
            fn for_each_filter(
                &self,
                start: u32,
                stop: Hash256,
                step: u32,
                emit: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
            ) -> Result<Option<[u8; 32]>, TxQueryError> {
                let count = if step == 1 { 2 - start } else { 2 };
                for _ in 0..count {
                    if !emit(stop, canned_filter()) {
                        return Ok(None);
                    }
                }
                Ok(Some([0; 32]))
            }
        }
        let headers = seed_headers(2001);
        let stop = wire_block_hash(headers[1].compute_hash());
        let checkpoint_stop = wire_block_hash(headers[2000].compute_hash());
        let query = query_with(headers)?.with_compact_filters(Some(Arc::new(Filters)));
        for request in filter_range_requests(stop, checkpoint_stop, 0) {
            for allowed in 0_u8..=2 {
                let remaining = Cell::new(allowed);
                let mut responses = Vec::new();
                let pending = FilterRequest::new(request.clone());
                let result = query.serve_compact_filters(
                    &pending,
                    &|| {
                        let slots = remaining.get();
                        remaining.set(slots.saturating_sub(1));
                        slots > 0
                    },
                    &mut |message| {
                        responses.push(message);
                        Ok(())
                    },
                );
                if allowed == 2 && matches!(request, Message::GetCFilters(_)) {
                    let FilterServing::Pending(remainder) = result? else {
                        panic!("a halt after a sent prefix must park the remainder");
                    };
                    assert_eq!(responses.len(), 1);
                    assert_eq!(remainder, parked_cfilter_remainder(stop, 1, 1));
                    let (outcome, delivered) =
                        collect_filter_responses(&query, &remainder, &|| true)?;
                    responses.extend(delivered);
                    assert_eq!(outcome, FilterServing::Done);
                    assert!(
                        matches!(&responses[..], [Message::CFilter(_), Message::CFilter(_)]),
                        "the prefix and the remainder are the two filters, once each"
                    );
                    continue;
                }
                assert_eq!(
                    result?,
                    FilterServing::Pending(pending.clone()),
                    "unsent request must remain pending, unchanged"
                );
                assert_eq!(responses, Vec::<Message>::new());
                let (outcome, delivered) = collect_filter_responses(&query, &pending, &|| true)?;
                responses.extend(delivered);
                assert_eq!(outcome, FilterServing::Done);
                assert_complete_filter_range(&request, &responses);
            }
        }
        Ok(())
    }

    #[test]
    fn compact_filters_follow_applied_chain_when_competing_headers_lead()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_index::{BasicFilter, CompactFilterQuery, DerivedIndexInfo, TxQueryError};

        struct Filters(Hash256);
        impl CompactFilterQuery for Filters {
            fn block_filter(&self, _: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
                unreachable!("range only")
            }
            fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
                Ok(DerivedIndexInfo {
                    synced: true,
                    best_block_height: 1,
                })
            }
            fn for_each_filter(
                &self,
                start: u32,
                stop: Hash256,
                step: u32,
                emit: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
            ) -> Result<Option<[u8; 32]>, TxQueryError> {
                assert_eq!(stop, self.0, "only the applied branch has filters");
                if step == 1 {
                    assert_eq!(start, 1);
                    assert!(emit(stop, canned_filter()));
                }
                Ok(Some([0; 32]))
            }
        }
        let headers = seed_headers(2);
        let applied_hash = headers[1].compute_hash();
        let query = query_with(headers.clone())?
            .with_compact_filters(Some(Arc::new(Filters(applied_hash.into()))));
        let fork_tip = {
            let mut tree = query.block_tree.write();
            let genesis = tree
                .lookup(headers[0].compute_hash().into())
                .ok_or("genesis")?;
            let fork = test_header(headers[0].compute_hash(), 100);
            let fork_id = tree.insert_node(Some(genesis), fork, NodeStatus::HeaderValid)?;
            let fork_tip = test_header(fork.compute_hash(), 101);
            tree.insert_node(Some(fork_id), fork_tip, NodeStatus::HeaderValid)?;
            fork_tip.compute_hash()
        };
        assert_eq!(query.active_height(fork_tip), Some(2));
        assert!(query.compact_filters_ready());
        for stop in [applied_hash, fork_tip] {
            let stop_hash = wire_block_hash(stop);
            for request in filter_range_requests(stop_hash, stop_hash, 1) {
                let pending = FilterRequest::new(request.clone());
                let (outcome, replies) = collect_filter_responses(&query, &pending, &|| true)?;
                assert_eq!(outcome, FilterServing::Done);
                if stop == fork_tip {
                    assert!(replies.is_empty(), "unapplied headers have no filters");
                    continue;
                }
                match (&request, &replies[..]) {
                    (Message::GetCFilters(_), [Message::CFilter(reply)]) => {
                        assert_eq!(reply.block_hash, stop_hash);
                        assert_eq!(reply.filter, [0]);
                    }
                    (Message::GetCFHeaders(_), [Message::CFHeaders(reply)]) => {
                        assert_eq!(reply.stop_hash, stop_hash);
                        assert_eq!(reply.filter_hashes.len(), 1);
                    }
                    (Message::GetCFCheckpt(_), [Message::CFCheckpt(reply)]) => {
                        assert_eq!(reply.stop_hash, stop_hash);
                        assert_eq!(reply.filter_headers.len(), 0);
                    }
                    _ => panic!("the applied branch must remain servable"),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn compact_filter_interruptions_that_are_not_backpressure_stay_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::p2p::message_filter::GetCFilters;
        use bitcoin_rs_index::{BasicFilter, CompactFilterQuery, DerivedIndexInfo, TxQueryError};

        struct ShortIndex;
        impl CompactFilterQuery for ShortIndex {
            fn block_filter(&self, _: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
                unreachable!("range only")
            }
            fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
                Ok(DerivedIndexInfo {
                    synced: true,
                    best_block_height: 1,
                })
            }
            fn for_each_filter(
                &self,
                _: u32,
                stop: Hash256,
                _: u32,
                emit: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
            ) -> Result<Option<[u8; 32]>, TxQueryError> {
                if !emit(
                    stop,
                    BasicFilter {
                        filter: vec![0],
                        hash: [1; 32],
                        header: [2; 32],
                    },
                ) {
                    return Ok(None);
                }
                Ok(Some([0; 32]))
            }
        }
        let headers = seed_headers(2);
        let stop = wire_block_hash(headers[1].compute_hash());
        let query = query_with(headers)?.with_compact_filters(Some(Arc::new(ShortIndex)));
        let request = Message::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: 0,
            stop_hash: stop,
        });

        let mut sent = Vec::new();
        let early = query.serve_compact_filters(&FilterRequest::new(request), &|| true, &mut |m| {
            sent.push(m);
            Ok(())
        });
        assert!(matches!(early, Err(PeerError::Io(_))));
        assert_eq!(sent.len(), 1);

        let moved = FilterRequest {
            request: Message::GetCFilters(GetCFilters {
                filter_type: 0,
                start_height: 1,
                stop_hash: stop,
            }),
            expected_end: Some(7),
        };
        let resumed = query.serve_compact_filters(
            &moved,
            &|| panic!("a moved range must not reserve"),
            &mut |_| panic!("a moved range must not emit"),
        );
        assert!(matches!(resumed, Err(PeerError::Io(_))));

        let matching = FilterRequest {
            expected_end: Some(1),
            ..moved
        };
        let mut rest = Vec::new();
        assert_eq!(
            query.serve_compact_filters(&matching, &|| true, &mut |m| {
                rest.push(m);
                Ok(())
            })?,
            FilterServing::Done
        );
        assert_eq!(rest.len(), 1);
        Ok(())
    }

    #[test]
    fn a_resumed_filter_range_that_stops_before_its_first_filter_is_interrupted()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::p2p::message_filter::GetCFilters;
        use bitcoin_rs_index::{
            BasicFilter, CompactFilterQuery, DerivedIndexInfo, TxQueryError, TxUnavailableCause,
        };

        struct StopsAtOnce(Result<Option<[u8; 32]>, TxQueryError>);
        impl CompactFilterQuery for StopsAtOnce {
            fn block_filter(&self, _: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
                unreachable!("range only")
            }
            fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
                Ok(DerivedIndexInfo {
                    synced: true,
                    best_block_height: 1,
                })
            }
            fn for_each_filter(
                &self,
                _: u32,
                _: Hash256,
                _: u32,
                _: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
            ) -> Result<Option<[u8; 32]>, TxQueryError> {
                self.0.clone()
            }
        }

        let headers = seed_headers(2);
        let stop = wire_block_hash(headers[1].compute_hash());
        let first = FilterRequest::new(Message::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: 0,
            stop_hash: stop,
        }));
        let resumed = FilterRequest {
            request: Message::GetCFilters(GetCFilters {
                filter_type: 0,
                start_height: 1,
                stop_hash: stop,
            }),
            expected_end: Some(1),
        };
        let serve = |outcome: Result<Option<[u8; 32]>, TxQueryError>,
                     request: &FilterRequest,
                     open: bool|
         -> Result<FilterServing, PeerError> {
            let query = match query_with(headers.clone()) {
                Ok(query) => query.with_compact_filters(Some(Arc::new(StopsAtOnce(outcome)))),
                Err(error) => panic!("fixture chain: {error}"),
            };
            query.serve_compact_filters(request, &|| open, &mut |_| {
                panic!("an index that delivers nothing must not emit a response")
            })
        };

        for outcome in [
            Ok(None),
            Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
                "index failed".into(),
            ))),
            Err(TxQueryError::Storage("read failed".into())),
        ] {
            assert!(
                matches!(
                    serve(outcome.clone(), &resumed, true),
                    Err(PeerError::Io(_))
                ),
                "{outcome:?}: a resumed range must not end as Done"
            );
            assert_eq!(
                serve(outcome.clone(), &first, true)?,
                FilterServing::Done,
                "{outcome:?}: a first attempt keeps the no-answer behavior"
            );
        }

        assert_eq!(
            serve(Err(TxQueryError::Retry), &resumed, true)?,
            FilterServing::Pending(resumed.clone())
        );
        assert_eq!(
            serve(Ok(None), &resumed, false)?,
            FilterServing::Pending(resumed.clone())
        );
        Ok(())
    }

    #[test]
    fn getheaders_empty_locator_returns_only_active_stop() -> Result<(), Box<dyn std::error::Error>>
    {
        let headers = seed_headers(3);
        let stop = headers[2].compute_hash();
        let query = query_with(headers)?;

        let response = query.headers_after(&[], stop, 2);

        assert_eq!(header_hashes(&response), vec![stop]);
        Ok(())
    }

    #[test]
    fn committed_tip_reads_applied_tip_when_headers_are_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(None, headers[0], NodeStatus::Active)?;
        let applied_id = tree.insert_node(Some(genesis), headers[1], NodeStatus::Active)?;
        let applied = tree.tip().ok_or("missing applied fixture tip")?;
        tree.insert_node(Some(applied_id), headers[2], NodeStatus::Active)?;
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(Some(applied));
        let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);

        assert_eq!(
            query.committed_tip(),
            Some(CommittedTip {
                height: 1,
                hash: headers[1].compute_hash(),
                prev_hash: headers[0].compute_hash(),
            })
        );
        Ok(())
    }

    #[test]
    fn committed_tip_rejects_an_applied_tip_off_the_active_header_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(None, headers[0], NodeStatus::Active)?;
        tree.insert_node(Some(genesis), headers[1], NodeStatus::Active)?;
        let applied = tree.tip().ok_or("missing applied fixture tip")?;

        let fork = test_header(headers[0].compute_hash(), 100);
        let fork_id = tree.insert_node(Some(genesis), fork, NodeStatus::Active)?;
        let fork_tip = test_header(fork.compute_hash(), 101);
        tree.insert_node(Some(fork_id), fork_tip, NodeStatus::Active)?;

        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(Some(applied));
        let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);

        assert_eq!(query.committed_tip(), None);
        Ok(())
    }

    #[test]
    fn getheaders_empty_locator_unknown_or_zero_stop_returns_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let query = query_with(headers)?;

        assert_eq!(query.headers_after(&[], BlockHash::default(), 2), []);
        assert_eq!(
            query.headers_after(&[], BlockHash::from(Hash256::from_le_bytes(&[9; 32])), 2),
            []
        );
        Ok(())
    }

    #[test]
    fn getheaders_unknown_locator_starts_after_genesis() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let expected = vec![headers[1].compute_hash(), headers[2].compute_hash()];
        let query = query_with(headers)?;

        let response = query.headers_after(
            &[BlockHash::from(Hash256::from_le_bytes(&[42; 32]))],
            BlockHash::default(),
            10,
        );

        assert_eq!(header_hashes(&response), expected);
        Ok(())
    }

    #[test]
    fn getheaders_after_locator_stops_at_stop_hash() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(5);
        let locator = headers[1].compute_hash();
        let stop = headers[3].compute_hash();
        let expected = vec![headers[2].compute_hash(), stop];
        let query = query_with(headers)?;

        let response = query.headers_after(&[locator], stop, 10);

        assert_eq!(header_hashes(&response), expected);
        Ok(())
    }

    #[test]
    fn getheaders_ignores_stale_fork_locator_and_stop() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = test_header(BlockHash::default(), 0);
        let active1 = test_header(genesis.compute_hash(), 1);
        let active2 = test_header(active1.compute_hash(), 2);
        let fork1 = test_header(genesis.compute_hash(), 42);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let active1_id = tree.insert_node(Some(genesis_id), active1, NodeStatus::Active)?;
        tree.insert_node(Some(active1_id), active2, NodeStatus::Active)?;
        tree.insert_node(Some(genesis_id), fork1, NodeStatus::Stale)?;
        let query = query_over(tree, Network::Regtest);

        let response = query.headers_after(&[fork1.compute_hash()], BlockHash::default(), 10);

        assert_eq!(
            header_hashes(&response),
            vec![active1.compute_hash(), active2.compute_hash()]
        );
        assert_eq!(query.headers_after(&[], fork1.compute_hash(), 10), []);
        Ok(())
    }

    #[test]
    fn applied_prefix_when_headers_lead() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(4);
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(None, headers[0], NodeStatus::Active)?;
        let applied_id = tree.insert_node(Some(genesis), headers[1], NodeStatus::Active)?;
        let applied = tree.tip().ok_or("applied")?;
        let second = tree.insert_node(Some(applied_id), headers[2], NodeStatus::Active)?;
        tree.insert_node(Some(second), headers[3], NodeStatus::Active)?;
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(Some(applied));
        let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);

        assert_eq!(
            header_hashes(&query.headers_after(
                &[headers[0].compute_hash()],
                BlockHash::default(),
                10
            )),
            vec![headers[1].compute_hash()],
            "only the servable applied prefix replies while headers lead"
        );
        assert_eq!(
            header_hashes(&query.headers_after(
                &[headers[2].compute_hash()],
                BlockHash::default(),
                10
            )),
            vec![headers[1].compute_hash()],
            "a header-best-only locator is not an applied ancestor"
        );
        Ok(())
    }

    #[test]
    fn applied_fork_off_best_serves_own_ancestry() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = test_header(BlockHash::default(), 0);
        let shared = test_header(genesis.compute_hash(), 1);
        let fork_tip = test_header(shared.compute_hash(), 42);
        let main_second = test_header(shared.compute_hash(), 2);
        let main_tip = test_header(main_second.compute_hash(), 3);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let shared_id = tree.insert_node(Some(genesis_id), shared, NodeStatus::Active)?;
        let fork_id = tree.insert_node(Some(shared_id), fork_tip, NodeStatus::Active)?;
        let applied = tree.tip().ok_or("applied fork")?;
        let main_second_id = tree.insert_node(Some(shared_id), main_second, NodeStatus::Active)?;
        tree.insert_node(Some(main_second_id), main_tip, NodeStatus::Active)?;
        assert_ne!(tree.node(fork_id)?.hash, tree.node(main_second_id)?.hash);
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(Some(applied));
        let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);

        assert_eq!(
            header_hashes(&query.headers_after(
                &[genesis.compute_hash()],
                BlockHash::default(),
                10
            )),
            vec![shared.compute_hash(), fork_tip.compute_hash()],
            "an off-best applied tip serves its own ancestry"
        );
        assert_eq!(
            header_hashes(&query.headers_after(&[shared.compute_hash()], BlockHash::default(), 10)),
            vec![fork_tip.compute_hash()]
        );
        Ok(())
    }

    #[test]
    fn best_only_locator_does_not_skip_applied_fork() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = test_header(BlockHash::default(), 0);
        let shared = test_header(genesis.compute_hash(), 1);
        let fork_tip = test_header(shared.compute_hash(), 42);
        let main_second = test_header(shared.compute_hash(), 2);
        let main_tip = test_header(main_second.compute_hash(), 3);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let shared_id = tree.insert_node(Some(genesis_id), shared, NodeStatus::Active)?;
        tree.insert_node(Some(shared_id), fork_tip, NodeStatus::Active)?;
        let applied = tree.tip().ok_or("applied fork")?;
        let main_second_id = tree.insert_node(Some(shared_id), main_second, NodeStatus::Active)?;
        tree.insert_node(Some(main_second_id), main_tip, NodeStatus::Active)?;
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(Some(applied));
        let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);

        assert_eq!(
            header_hashes(&query.headers_after(
                &[main_second.compute_hash()],
                BlockHash::default(),
                10
            )),
            vec![shared.compute_hash(), fork_tip.compute_hash()],
            "a best-only locator falls back instead of skipping the applied fork"
        );
        assert_eq!(
            header_hashes(&query.headers_after(
                &[main_second.compute_hash(), shared.compute_hash()],
                BlockHash::default(),
                10
            )),
            vec![fork_tip.compute_hash()],
            "locator order keeps the first servable applied ancestor"
        );
        Ok(())
    }

    #[test]
    fn stop_hash_bounds_applied_response() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = test_header(BlockHash::default(), 0);
        let shared = test_header(genesis.compute_hash(), 1);
        let fork_tip = test_header(shared.compute_hash(), 42);
        let main_second = test_header(shared.compute_hash(), 2);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let shared_id = tree.insert_node(Some(genesis_id), shared, NodeStatus::Active)?;
        tree.insert_node(Some(shared_id), fork_tip, NodeStatus::Active)?;
        let applied = tree.tip().ok_or("applied fork")?;
        tree.insert_node(Some(shared_id), main_second, NodeStatus::Active)?;
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(Some(applied));
        let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);

        assert_eq!(
            header_hashes(&query.headers_after(
                &[genesis.compute_hash()],
                shared.compute_hash(),
                10
            )),
            vec![shared.compute_hash()],
            "an applied stop ends the range"
        );
        assert_eq!(
            header_hashes(&query.headers_after(
                &[genesis.compute_hash()],
                main_second.compute_hash(),
                10
            )),
            vec![shared.compute_hash(), fork_tip.compute_hash()],
            "a stop off the applied chain does not truncate it"
        );
        assert_eq!(
            header_hashes(&query.headers_after(&[genesis.compute_hash()], BlockHash::default(), 1)),
            vec![shared.compute_hash()],
            "the caller limit still bounds the applied range"
        );
        Ok(())
    }

    #[test]
    fn low_work_chain_serves_no_headers() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = test_header(BlockHash::default(), 0);
        let first = test_header(genesis.compute_hash(), 1);
        let second = test_header(first.compute_hash(), 2);
        let low_work_tree = || -> Result<BlockTree, bitcoin_rs_chain::ChainError> {
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let first_id = tree.insert_node(Some(genesis_id), first, NodeStatus::Active)?;
            tree.insert_node(Some(first_id), second, NodeStatus::Active)?;
            Ok(tree)
        };
        let mainnet = query_over(low_work_tree()?, Network::Mainnet);
        assert!(
            mainnet
                .headers_after(&[genesis.compute_hash()], BlockHash::default(), 10)
                .is_empty(),
            "a below-floor node must answer getheaders with nothing"
        );
        assert!(
            mainnet
                .headers_after(&[], second.compute_hash(), 10)
                .is_empty(),
            "the empty-locator stop-hash path must refuse too"
        );

        let regtest = query_over(low_work_tree()?, Network::Regtest);
        assert_eq!(
            header_hashes(&regtest.headers_after(
                &[genesis.compute_hash()],
                BlockHash::default(),
                10
            )),
            vec![first.compute_hash(), second.compute_hash()],
            "a network with a zero floor must keep serving its chain"
        );
        Ok(())
    }

    #[test]
    fn getdata_decodes_active_body_from_source_and_reports_missing_inventory()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: Vec::new(),
        };
        let body_source = Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: consensus_bytes(&block),
        });
        let txid = WireTxid::all_zeros();
        let missing = Inventory::WitnessBlock(WireBlockHash::from_byte_array([8; 32]));
        let query = query_with(headers)?.with_block_body_source(body_source);

        let (outcome, blocks) = serve_collect(
            &query,
            &[
                Inventory::Block(wire_block_hash(block.block_hash())),
                Inventory::Transaction(txid),
                missing,
            ],
        )?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_hash(), block.block_hash());
        assert_eq!(
            outcome.not_found,
            vec![Inventory::Transaction(txid), missing]
        );
        assert!(!outcome.halted);
        Ok(())
    }

    #[test]
    fn getdata_block_encoding_matches_requested_inventory_on_wire()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::p2p::Magic;
        use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};

        for (tx_count, witness_modulus) in [(2_u8, 0), (2, 1), (3, 2), (253, 2)] {
            let headers = seed_headers(2);
            let mut block = Block {
                header: headers[1],
                txs: (0..tx_count).map(test_tx).collect(),
            };
            for (index, tx) in block.txs.iter_mut().enumerate() {
                if witness_modulus != 0 && index % witness_modulus == 0 {
                    tx.inputs[0].witness = vec![vec![0x51; 32]].into();
                }
                if index % 2 == 0 {
                    tx.outputs.clear();
                } else {
                    tx.outputs[0].script_pubkey.clear();
                }
            }
            let body = consensus_bytes(&block);
            let source = Arc::new(SingleBlockSource {
                height: 1,
                hash: block.block_hash(),
                body: body.clone(),
            });
            let query = query_with(headers)?.with_block_body_source(source.clone());
            let full: RegistryBlock = bitcoin::consensus::deserialize(&body)?;
            let mut stripped = full.clone();
            for tx in &mut stripped.txdata {
                for input in &mut tx.input {
                    input.witness.clear();
                }
            }
            let legacy = Inventory::Block(wire_block_hash(block.block_hash()));
            let witness = Inventory::WitnessBlock(wire_block_hash(block.block_hash()));
            let missing = Inventory::Block(WireBlockHash::from_byte_array([9; 32]));
            for items in [[legacy, witness, legacy], [witness, legacy, witness]] {
                let mut served = Vec::new();
                let mut batch = items.to_vec();
                batch.insert(1, missing);
                let outcome =
                    query.serve_inventory_blocks(&batch, None, &|| true, &mut |message| {
                        let mut bytes = Vec::new();
                        crate::wire::write_message(&mut bytes, Magic::REGTEST, &message)?;
                        served.push(bytes);
                        Ok(())
                    })?;
                assert_eq!(outcome.not_found, vec![missing]);
                assert!(!outcome.halted);
                assert_eq!(served.len(), items.len());
                for (item, actual) in items.iter().zip(served) {
                    let expected = if matches!(item, Inventory::Block(_)) {
                        &stripped
                    } else {
                        &full
                    };
                    let envelope = RawNetworkMessage::new(
                        Magic::REGTEST,
                        NetworkMessage::Block(expected.clone()),
                    );
                    assert_eq!(actual, bitcoin::consensus::serialize(&envelope));
                    assert_eq!(expected.block_hash(), full.block_hash());
                    for (tx, original) in expected.txdata.iter().zip(&full.txdata) {
                        assert_eq!(tx.compute_txid(), original.compute_txid());
                    }
                }
                assert_eq!(
                    source.body, body,
                    "serving never rewrites retained witness data"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn getdata_block_encodings_keep_headroom_and_body_failure_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: vec![test_tx(1)],
        };
        let body = consensus_bytes(&block);
        for item in [
            Inventory::Block(wire_block_hash(block.block_hash())),
            Inventory::WitnessBlock(wire_block_hash(block.block_hash())),
        ] {
            let source = Arc::new(CountingBodySource {
                bodies: vec![(1, block.block_hash(), body.clone())],
                loads: AtomicUsize::new(0),
                tripwire: Some(0),
            });
            let query = query_with(headers.clone())?.with_block_body_source(source.clone());
            let outcome = query.serve_inventory_blocks(&[item], None, &|| false, &mut |_| {
                panic!("denied headroom cannot serve")
            })?;
            assert!(outcome.halted);
            assert_eq!(outcome.not_found, []);
            assert_eq!(source.loads.load(Ordering::Relaxed), 0);

            let mut corrupt = body.clone();
            corrupt.pop();
            let mut wrong_header = body.clone();
            wrong_header[0] ^= 1;
            let mut trailing = body.clone();
            trailing.push(0);
            let mut superfluous_witness = body.clone();
            superfluous_witness.splice(Header::LEN + 5..Header::LEN + 5, [0, 1]);
            superfluous_witness.insert(superfluous_witness.len() - 4, 0);
            let mut unknown_flag = superfluous_witness.clone();
            unknown_flag[Header::LEN + 6] = 2;
            for malformed in [&trailing, &superfluous_witness, &unknown_flag] {
                assert!(deserialize::<Block>(malformed).is_err());
                assert!(bitcoin::consensus::deserialize::<RegistryBlock>(malformed).is_err());
            }
            for unavailable in [
                None,
                Some(corrupt),
                Some(wrong_header),
                Some(trailing),
                Some(superfluous_witness),
                Some(unknown_flag),
            ] {
                let mut query = query_with(headers.clone())?;
                if let Some(body) = unavailable {
                    query = query.with_block_body_source(Arc::new(SingleBlockSource {
                        height: 1,
                        hash: block.block_hash(),
                        body,
                    }));
                }
                let outcome = query.serve_inventory_blocks(&[item], None, &|| true, &mut |_| {
                    panic!("unavailable body cannot serve")
                })?;
                assert_eq!(outcome.not_found, vec![item]);
                assert!(!outcome.halted);
            }
        }
        Ok(())
    }

    #[test]
    fn getdata_block_encodings_recheck_active_chain_after_body_load()
    -> Result<(), Box<dyn std::error::Error>> {
        struct SwitchingSource {
            tree: Arc<RwLock<BlockTree>>,
            body: Vec<u8>,
        }
        impl BlockBodySource for SwitchingSource {
            fn block_body(
                &self,
                _height: u32,
                _hash: BlockHash,
            ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
                *self.tree.write() = BlockTree::new();
                Ok(Some(self.body.clone()))
            }
        }
        let header = seed_headers(1)[0];
        let mut block = Block {
            header,
            txs: vec![test_tx(1)],
        };
        block.txs[0].inputs[0].witness = vec![vec![0x51; 32]].into();
        for item in [
            Inventory::Block(wire_block_hash(block.block_hash())),
            Inventory::WitnessBlock(wire_block_hash(block.block_hash())),
        ] {
            let mut tree = BlockTree::new();
            tree.insert_node(None, header, NodeStatus::Active)?;
            let tree = Arc::new(RwLock::new(tree));
            let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
            applied_tip.store(tree.read().tip());
            let query = ActiveChainQuery::new(
                BlockTreeReader::new(tree.clone()),
                applied_tip,
                Network::Regtest,
            )
            .with_block_body_source(Arc::new(SwitchingSource {
                tree,
                body: consensus_bytes(&block),
            }));
            let outcome = query.serve_inventory_blocks(&[item], None, &|| true, &mut |_| {
                panic!("stale body cannot serve")
            })?;
            assert_eq!(outcome.not_found, vec![item]);
            assert!(!outcome.halted);
        }
        Ok(())
    }

    #[test]
    fn getdata_rejects_pruned_or_missing_body() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let hash = headers[1].compute_hash();
        let query = query_with(headers)?;

        let (outcome, blocks) = serve_collect(&query, &[Inventory::Block(wire_block_hash(hash))])?;

        assert_eq!(blocks, []);
        assert_eq!(
            outcome.not_found,
            vec![Inventory::Block(wire_block_hash(hash))]
        );
        Ok(())
    }

    #[test]
    fn getdata_reads_metadata_only_body_from_source() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: Vec::new(),
        };
        let body_source = Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: consensus_bytes(&block),
        });
        let query = query_with(headers)?.with_block_body_source(body_source);

        let (outcome, blocks) = serve_collect(
            &query,
            &[Inventory::Block(wire_block_hash(block.block_hash()))],
        )?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_hash(), block.block_hash());
        assert_eq!(outcome.not_found, []);
        Ok(())
    }

    #[test]
    fn p2p_chain_streams_each_body_once_in_order() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(4);
        let blocks: Vec<Block> = headers[1..]
            .iter()
            .map(|header| Block {
                header: *header,
                txs: Vec::new(),
            })
            .collect();
        let bodies: Vec<(u32, BlockHash, Vec<u8>)> = (1_u32..)
            .zip(&blocks)
            .map(|(height, block)| (height, block.block_hash(), consensus_bytes(block)))
            .collect();
        let body_source = Arc::new(CountingBodySource {
            bodies,
            loads: AtomicUsize::new(0),
            tripwire: None,
        });
        let unknown_a = Inventory::WitnessBlock(WireBlockHash::from_byte_array([21; 32]));
        let unknown_b = Inventory::WitnessBlock(WireBlockHash::from_byte_array([22; 32]));
        let query = query_with(headers)?.with_block_body_source(body_source.clone());
        let items = vec![
            unknown_a,
            Inventory::WitnessBlock(wire_block_hash(blocks[0].block_hash())),
            unknown_b,
            Inventory::WitnessBlock(wire_block_hash(blocks[1].block_hash())),
            Inventory::WitnessBlock(wire_block_hash(blocks[2].block_hash())),
        ];

        let (outcome, served) = serve_collect(&query, &items)?;

        let served_hashes: Vec<BlockHash> = served.iter().map(Block::block_hash).collect();
        assert_eq!(
            served_hashes,
            vec![
                blocks[0].block_hash(),
                blocks[1].block_hash(),
                blocks[2].block_hash(),
            ],
            "bodies stream in request order"
        );
        assert_eq!(body_source.loads.load(Ordering::Relaxed), 3);
        assert_eq!(outcome.not_found, vec![unknown_a, unknown_b]);
        assert!(!outcome.halted);
        Ok(())
    }

    #[test]
    fn p2p_chain_does_not_gate_unknown_blocks() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let body_source = Arc::new(CountingBodySource {
            bodies: Vec::new(),
            loads: AtomicUsize::new(0),
            tripwire: Some(0),
        });
        let query = query_with(headers)?.with_block_body_source(body_source.clone());
        let unknown = Inventory::WitnessBlock(WireBlockHash::from_byte_array([23; 32]));
        let headroom_calls = AtomicUsize::new(0);
        let served = RefCell::new(Vec::new());

        let outcome = query.serve_inventory_blocks(
            &[unknown],
            None,
            &|| {
                headroom_calls.fetch_add(1, Ordering::Relaxed);
                false
            },
            &mut |message| {
                served.borrow_mut().push(message);
                Ok(())
            },
        )?;

        assert_eq!(outcome.not_found, vec![unknown]);
        assert!(!outcome.halted);
        assert!(served.borrow().is_empty());
        assert_eq!(body_source.loads.load(Ordering::Relaxed), 0);
        assert_eq!(headroom_calls.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn p2p_chain_halts_at_gate_without_loading() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(4);
        let blocks: Vec<Block> = headers[1..]
            .iter()
            .map(|header| Block {
                header: *header,
                txs: Vec::new(),
            })
            .collect();
        let bodies: Vec<(u32, BlockHash, Vec<u8>)> = (1_u32..)
            .zip(&blocks)
            .map(|(height, block)| (height, block.block_hash(), consensus_bytes(block)))
            .collect();
        let body_source = Arc::new(CountingBodySource {
            bodies,
            loads: AtomicUsize::new(0),
            tripwire: Some(2),
        });
        let query = query_with(headers)?.with_block_body_source(body_source.clone());
        let items: Vec<Inventory> = blocks
            .iter()
            .map(|block| Inventory::WitnessBlock(wire_block_hash(block.block_hash())))
            .collect();
        let headroom_calls = AtomicUsize::new(0);
        let served = RefCell::new(Vec::new());

        let outcome = query.serve_inventory_blocks(
            &items,
            None,
            &|| {
                let calls = headroom_calls.fetch_add(1, Ordering::Relaxed);
                calls < 2
            },
            &mut |message| {
                served.borrow_mut().push(message);
                Ok(())
            },
        )?;

        assert!(outcome.halted);
        assert_eq!(served.borrow().len(), 2);
        assert_eq!(body_source.loads.load(Ordering::Relaxed), 2);
        assert_eq!(headroom_calls.load(Ordering::Relaxed), 3);
        Ok(())
    }

    #[test]
    fn getblocktxn_halts_at_gate_without_loading() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(12);
        let deep_block = block_at(&headers, 0)?;
        let body_source = Arc::new(CountingBodySource {
            bodies: vec![(0, deep_block.block_hash(), consensus_bytes(&deep_block))],
            loads: AtomicUsize::new(0),
            tripwire: Some(0),
        });
        let query = query_with(headers)?.with_block_body_source(body_source.clone());
        let request = bitcoin::bip152::BlockTransactionsRequest {
            block_hash: wire_block_hash(deep_block.block_hash()),
            indexes: vec![1],
        };
        let headroom_calls = AtomicUsize::new(0);

        let reply = query.block_transactions(&request, None, &|| {
            headroom_calls.fetch_add(1, Ordering::Relaxed);
            false
        })?;

        assert!(
            reply.is_none(),
            "a saturated gate leaves the request unanswered"
        );
        assert_eq!(
            body_source.loads.load(Ordering::Relaxed),
            0,
            "a saturated gate must not load the block body"
        );
        assert_eq!(headroom_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[test]
    fn getdata_msg_cmpct_block_serves_negotiated_profile_and_notfound_without()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: vec![test_tx(1), test_tx(2)],
        };
        let body_source = Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: consensus_bytes(&block),
        });
        let query = query_with(headers)?.with_block_body_source(body_source);
        let item = Inventory::CompactBlock(wire_block_hash(block.block_hash()));

        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], None, &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert_eq!(outcome.not_found, vec![item]);
        assert_eq!(served, []);

        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert!(outcome.not_found.is_empty() && !outcome.halted);
        let [Message::CmpctBlock(cmpct)] = served.as_slice() else {
            panic!("expected exactly one cmpctblock response");
        };
        assert_eq!(
            native_block_hash(cmpct.compact_block.header.block_hash()),
            block.block_hash()
        );
        assert_eq!(cmpct.compact_block.prefilled_txs.len(), 1);
        assert_eq!(cmpct.compact_block.short_ids.len(), 1);
        Ok(())
    }

    fn chain_at(
        headers: &[Header],
        height: u32,
        block: &Block,
    ) -> Result<ActiveChainQuery, bitcoin_rs_chain::ChainError> {
        let source = SingleBlockSource {
            height,
            hash: block.block_hash(),
            body: consensus_bytes(block),
        };
        Ok(query_with(headers.to_vec())?.with_block_body_source(Arc::new(source)))
    }

    fn block_at(headers: &[Header], height: u32) -> Result<Block, Box<dyn std::error::Error>> {
        let index = usize::try_from(height)?;
        Ok(Block {
            header: headers[index],
            txs: vec![test_tx(1), test_tx(2)],
        })
    }

    fn blocktxn_reply(
        headers: &[Header],
        height: u32,
    ) -> Result<Message, Box<dyn std::error::Error>> {
        let block = block_at(headers, height)?;
        let query = chain_at(headers, height, &block)?;
        let request = bitcoin::bip152::BlockTransactionsRequest {
            block_hash: wire_block_hash(block.block_hash()),
            indexes: vec![1],
        };
        Ok(query
            .block_transactions(&request, None, &|| true)?
            .ok_or("an active body is always answered")?)
    }

    fn compact_reply(
        headers: &[Header],
        height: u32,
    ) -> Result<Message, Box<dyn std::error::Error>> {
        let block = block_at(headers, height)?;
        let query = chain_at(headers, height, &block)?;
        let item = Inventory::CompactBlock(wire_block_hash(block.block_hash()));
        let mut served = Vec::new();
        query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        Ok(served.pop().ok_or("exactly one reply")?)
    }

    fn payload_body(payload: &bytes::Bytes) -> Result<RegistryBlock, Box<dyn std::error::Error>> {
        Ok(bitcoin::consensus::encode::deserialize::<RegistryBlock>(
            payload.as_ref(),
        )?)
    }

    #[test]
    fn getblocktxn_answers_active_body_and_disconnects_on_out_of_range_index()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = block_at(&headers, 1)?;
        let query = chain_at(&headers, 1, &block)?;
        let wire = wire_block_hash(block.block_hash());

        let reply = query.block_transactions(
            &bitcoin::bip152::BlockTransactionsRequest {
                block_hash: wire,
                indexes: vec![1],
            },
            None,
            &|| true,
        )?;
        let Some(Message::BlockTxn(txn)) = &reply else {
            panic!("a shallow request is answered with blocktxn, got {reply:?}");
        };
        assert_eq!(txn.transactions.block_hash, wire);
        assert_eq!(txn.transactions.transactions.len(), 1);

        let out_of_range = query.block_transactions(
            &bitcoin::bip152::BlockTransactionsRequest {
                block_hash: wire,
                indexes: vec![7],
            },
            None,
            &|| true,
        );
        assert!(
            matches!(out_of_range, Err(PeerError::Misbehavior(_))),
            "an out-of-range index is a protocol disconnect"
        );

        let unknown = query.block_transactions(
            &bitcoin::bip152::BlockTransactionsRequest {
                block_hash: bitcoin::BlockHash::from_byte_array([9; 32]),
                indexes: vec![0],
            },
            None,
            &|| true,
        )?;
        assert!(unknown.is_none(), "an unservable block stays unanswered");
        Ok(())
    }

    #[test]
    fn getblocktxn_depth_boundary_uses_full_block_beyond_ten()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(12);

        let at_the_bound = blocktxn_reply(&headers, 1)?;
        let Message::BlockTxn(txn) = &at_the_bound else {
            panic!("a block at the bound is answered with blocktxn, got {at_the_bound:?}");
        };
        assert_eq!(txn.transactions.transactions.len(), 1);

        let one_deeper = blocktxn_reply(&headers, 0)?;
        let Message::BlockPayload(payload) = &one_deeper else {
            panic!("a deeper block is answered with the whole block, got {one_deeper:?}");
        };
        assert_eq!(payload_body(payload)?.txdata.len(), 2, "witnesses retained");
        Ok(())
    }

    #[test]
    fn compact_depth_boundary_uses_full_block_beyond_five() -> Result<(), Box<dyn std::error::Error>>
    {
        let headers = seed_headers(12);

        let at_the_bound = compact_reply(&headers, 6)?;
        assert!(
            matches!(at_the_bound, Message::CmpctBlock(_)),
            "a block at the compact bound is served compact, got {at_the_bound:?}"
        );

        let one_deeper = compact_reply(&headers, 5)?;
        let Message::BlockPayload(payload) = &one_deeper else {
            panic!("a deeper block is served as the whole block, got {one_deeper:?}");
        };
        assert_eq!(payload_body(payload)?.txdata.len(), 2, "witnesses retained");
        Ok(())
    }

    #[test]
    fn compact_prefills_coinbase_under_both_v1_v2() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let block = block_at(&headers, 2)?;
        let expected = consensus_bytes(&block.txs[0]);

        for version in [1_u64, 2] {
            let query = chain_at(&headers, 2, &block)?;
            let item = Inventory::CompactBlock(wire_block_hash(block.block_hash()));
            let mut served = Vec::new();
            query.serve_inventory_blocks(&[item], Some(version), &|| true, &mut |message| {
                served.push(message);
                Ok(())
            })?;
            let [Message::CmpctBlock(cmpct)] = served.as_slice() else {
                panic!("v{version} must be served as a cmpctblock, got {served:?}");
            };
            let prefills = &cmpct.compact_block.prefilled_txs;
            assert_eq!(prefills.len(), 1, "v{version}: the coinbase is prefilled");
            assert_eq!(u64::from(prefills[0].idx), 0, "v{version}: at index zero");
            assert_eq!(
                bitcoin::consensus::encode::serialize(&prefills[0].tx),
                expected,
                "v{version}: the prefilled body is the block's coinbase"
            );
            assert_eq!(cmpct.compact_block.short_ids.len(), 1);
        }
        Ok(())
    }

    #[test]
    fn compact_exchange_keeps_the_mutually_supported_version()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::dispatch::dispatch_inbound_full;
        use crate::peer::{Peer, PeerState};
        use bitcoin::p2p::Magic;
        use bitcoin::p2p::message::NetworkMessage;
        use bitcoin::p2p::message_compact_blocks::{GetBlockTxn, SendCmpct};

        let headers = seed_headers(2);
        let mut block = Block {
            header: headers[1],
            txs: vec![test_tx(1), test_tx(2), test_tx(3)],
        };
        for (index, tx) in block.txs.iter_mut().enumerate() {
            tx.inputs[0].witness = vec![vec![u8::try_from(index)?; 32]].into();
        }
        let body = consensus_bytes(&block);
        let original: RegistryBlock = bitcoin::consensus::deserialize(&body)?;
        let source = Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: body.clone(),
        });
        let query = query_with(headers)?.with_block_body_source(source.clone());
        let hash = wire_block_hash(block.block_hash());
        let compact_item = Inventory::CompactBlock(hash);
        for versions in [[Some(1), Some(2)], [Some(2), Some(1)], [None, Some(99)]] {
            let mut peer = Peer::new(std::io::Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
            peer.state = PeerState::Ready;
            let mut negotiated = None;
            for version in versions {
                if let Some(version) = version {
                    dispatch_inbound_full(
                        &mut peer,
                        &Message::SendCmpct(SendCmpct {
                            send_compact: false,
                            version,
                        }),
                        Some(&query),
                        None,
                        &|| true,
                        &|| true,
                        &mut |_| panic!("sendcmpct does not emit a response"),
                        &mut |_| {},
                        &mut |_| {},
                    )?;
                    if version == crate::peer::COMPACT_BLOCK_VERSION {
                        negotiated = Some(version);
                    }
                }
                assert_eq!(peer.compact_blocks.servable_version(), negotiated);
                let compact = dispatched_wire_response(
                    &mut peer,
                    &query,
                    &Message::GetData(vec![compact_item]),
                )?;
                if negotiated.is_none() {
                    assert_eq!(
                        compact.payload(),
                        &NetworkMessage::NotFound(vec![compact_item])
                    );
                } else {
                    let NetworkMessage::CmpctBlock(compact) = compact.payload() else {
                        panic!("negotiated compact request must produce cmpctblock");
                    };
                    let prefill = &compact.compact_block.prefilled_txs[0].tx;
                    assert!(!prefill.input[0].witness.is_empty());
                    assert_eq!(prefill.compute_txid(), original.txdata[0].compute_txid());
                    assert_eq!(prefill.compute_wtxid(), original.txdata[0].compute_wtxid());
                }

                if negotiated.is_none() {
                    continue;
                }
                let indexes = vec![1, 2];
                let decoded = dispatched_wire_response(
                    &mut peer,
                    &query,
                    &Message::GetBlockTxn(GetBlockTxn {
                        txs_request: BlockTransactionsRequest {
                            block_hash: hash,
                            indexes: indexes.clone(),
                        },
                    }),
                )?;
                let NetworkMessage::BlockTxn(response) = decoded.payload() else {
                    panic!("available request must produce blocktxn");
                };
                assert_blocktxn_profile(&response.transactions, &original, &indexes, false)?;
                assert_eq!(
                    source.body, body,
                    "version selection leaves the stored body intact"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn getblocktxn_versions_preserve_missing_body_and_invalid_index_outcomes()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::dispatch::dispatch_inbound_full;
        use crate::peer::{Peer, PeerState};
        use bitcoin::p2p::Magic;
        use bitcoin::p2p::message_compact_blocks::{GetBlockTxn, SendCmpct};

        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: vec![test_tx(1)],
        };
        let query = query_with(headers)?.with_block_body_source(Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: consensus_bytes(&block),
        }));
        let hash = wire_block_hash(block.block_hash());
        for version in [None, Some(1), Some(2), Some(99)] {
            let mut peer = Peer::new(std::io::Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
            peer.state = PeerState::Ready;
            if let Some(version) = version {
                dispatch_inbound_full(
                    &mut peer,
                    &Message::SendCmpct(SendCmpct {
                        send_compact: false,
                        version,
                    }),
                    Some(&query),
                    None,
                    &|| true,
                    &|| true,
                    &mut |_| panic!("sendcmpct does not emit a response"),
                    &mut |_| {},
                    &mut |_| {},
                )?;
            }
            for (requested_hash, indexes, invalid) in [
                (hash, vec![7], true),
                (hash, Vec::new(), true),
                (WireBlockHash::from_byte_array([9; 32]), vec![1], false),
            ] {
                let expected = if invalid {
                    Some(if indexes.is_empty() {
                        "getblocktxn with empty index list"
                    } else {
                        "getblocktxn index out of range"
                    })
                } else {
                    None
                };
                let result = dispatch_inbound_full(
                    &mut peer,
                    &Message::GetBlockTxn(GetBlockTxn {
                        txs_request: BlockTransactionsRequest {
                            block_hash: requested_hash,
                            indexes,
                        },
                    }),
                    Some(&query),
                    None,
                    &|| true,
                    &|| true,
                    &mut |_| panic!("missing or invalid request cannot emit transactions"),
                    &mut |_| {},
                    &mut |_| {},
                );
                if let Some(expected) = expected {
                    assert!(
                        matches!(result, Err(PeerError::Misbehavior(message)) if message == expected),
                        "invalid request must disconnect, got {result:?}"
                    );
                } else {
                    result?;
                }
            }
        }
        Ok(())
    }

    fn assert_blocktxn_profile(
        response: &BlockTransactions,
        original: &RegistryBlock,
        indexes: &[u64],
        strip_witness: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut expected = Vec::new();
        for index in indexes {
            let mut tx = original.txdata[usize::try_from(*index)?].clone();
            if strip_witness {
                for input in &mut tx.input {
                    input.witness.clear();
                }
            }
            expected.push(tx);
        }
        assert_eq!(response.block_hash, original.block_hash());
        assert_eq!(response.transactions, expected);
        for (tx, index) in response.transactions.iter().zip(indexes) {
            assert_eq!(
                tx.compute_txid(),
                original.txdata[usize::try_from(*index)?].compute_txid()
            );
        }
        Ok(())
    }

    fn dispatched_wire_response(
        peer: &mut crate::peer::Peer<std::io::Cursor<Vec<u8>>>,
        query: &ActiveChainQuery,
        request: &Message,
    ) -> Result<bitcoin::p2p::message::RawNetworkMessage, Box<dyn std::error::Error>> {
        let mut wire = Vec::new();
        crate::dispatch::dispatch_inbound_full(
            peer,
            request,
            Some(query),
            None,
            &|| true,
            &|| true,
            &mut |response| {
                crate::wire::write_message(&mut wire, bitcoin::p2p::Magic::REGTEST, &response)?;
                Ok(())
            },
            &mut |_| {},
            &mut |_| {},
        )?;
        Ok(bitcoin::consensus::deserialize(&wire)?)
    }

    fn test_tx(byte: u8) -> Tx {
        use bitcoin_rs_primitives::{
            Amount, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Txid, Witness,
        };
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                    vout: 0,
                },
                script_sig: vec![byte].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x6A].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn query_over(tree: BlockTree, network: Network) -> ActiveChainQuery {
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(block_tree.read().tip());
        ActiveChainQuery::new(block_tree, applied_tip, network)
    }

    struct StaleFixture {
        query: ActiveChainQuery,
        stale: Block,
        winner: Block,
        source: Arc<CountingBodySource>,
    }

    fn stale_query(depth: u32) -> Result<StaleFixture, Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let stale = block_at(&headers, 1)?;
        let query = query_with(headers)?;
        let winner;
        {
            let mut tree = query.block_tree.write();
            let genesis = tree
                .node_at_height_from(tree.tip_id().ok_or("tip")?, 0)
                .ok_or("genesis")?;
            tree.record_applied_tx_count(genesis, 1)?;
            let stale_id = tree.lookup(stale.block_hash().into()).ok_or("stale")?;
            tree.record_applied_tx_count(stale_id, 2)?;
            let header = test_header(tree.node(genesis)?.hash.into(), 100);
            winner = Block {
                header,
                txs: vec![test_tx(3), test_tx(4)],
            };
            let mut parent = tree.insert_node(Some(genesis), header, NodeStatus::HeaderValid)?;
            tree.record_applied_tx_count(parent, 2)?;
            for nonce in 0..depth {
                let header = test_header(tree.node(parent)?.hash.into(), 101 + nonce);
                parent = tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?;
            }
            query.applied_tip.store(tree.tip());
        }
        let source = Arc::new(CountingBodySource {
            bodies: vec![
                (1, stale.block_hash(), consensus_bytes(&stale)),
                (1, winner.block_hash(), consensus_bytes(&winner)),
            ],
            loads: AtomicUsize::new(0),
            tripwire: None,
        });
        Ok(StaleFixture {
            query: query.with_block_body_source(source.clone()),
            stale,
            winner,
            source,
        })
    }

    #[test]
    fn stored_stale_blocks_are_hash_addressed_without_becoming_announcements()
    -> Result<(), Box<dyn std::error::Error>> {
        let StaleFixture {
            query,
            stale,
            winner,
            source,
        } = stale_query(1)?;
        for block in [&stale, &winner] {
            let wire = wire_block_hash(block.block_hash());
            for item in [
                Inventory::Block(wire),
                Inventory::WitnessBlock(wire),
                Inventory::CompactBlock(wire),
            ] {
                let mut messages = Vec::new();
                let result =
                    query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |m| {
                        messages.push(m);
                        Ok(())
                    })?;
                assert_eq!(result.not_found, []);
                match &messages[0] {
                    Message::BlockPayload(payload) => {
                        assert_eq!(payload_body(payload)?.block_hash(), wire);
                    }
                    Message::CmpctBlock(compact) => {
                        assert_eq!(compact.compact_block.header.block_hash(), wire);
                    }
                    other => panic!("unexpected response {other:?}"),
                }
            }
            let request = BlockTransactionsRequest {
                block_hash: wire,
                indexes: vec![1],
            };
            let Some(Message::BlockTxn(response)) =
                query.block_transactions(&request, Some(2), &|| true)?
            else {
                panic!("stored shallow block must answer");
            };
            assert_eq!(response.transactions.block_hash, wire);
            let expected: RegistryBlock = bitcoin::consensus::deserialize(&consensus_bytes(block))?;
            assert_eq!(
                response.transactions.transactions,
                vec![expected.txdata[1].clone()]
            );
        }
        let before = source.loads.load(Ordering::Relaxed);
        assert!(ChainQuery::compact_block_for(&query, 1, stale.block_hash(), Some(2)).is_none());
        assert_eq!(
            source.loads.load(Ordering::Relaxed),
            before,
            "stale announcements load no body"
        );
        Ok(())
    }

    #[test]
    fn stale_serving_keeps_depth_headroom_and_unknown_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        for (depth, blocktxn) in [(10, true), (11, false)] {
            let StaleFixture {
                query,
                stale,
                source,
                ..
            } = stale_query(depth)?;
            let request = BlockTransactionsRequest {
                block_hash: wire_block_hash(stale.block_hash()),
                indexes: vec![1],
            };
            assert!(
                query
                    .block_transactions(&request, Some(2), &|| false)?
                    .is_none()
            );
            let outcome = query.serve_inventory_blocks(
                &[Inventory::WitnessBlock(request.block_hash)],
                Some(2),
                &|| false,
                &mut |_| panic!("no headroom"),
            )?;
            assert!(outcome.halted);
            assert_eq!(source.loads.load(Ordering::Relaxed), 0);
            let reply = query
                .block_transactions(&request, Some(2), &|| true)?
                .ok_or("stale reply")?;
            assert_eq!(matches!(reply, Message::BlockTxn(_)), blocktxn);
            if let Message::BlockPayload(payload) = reply {
                assert_eq!(payload_body(&payload)?.block_hash(), request.block_hash);
            }
            let unknown = BlockTransactionsRequest {
                block_hash: WireBlockHash::from_byte_array([99; 32]),
                indexes: vec![0],
            };
            assert!(
                query
                    .block_transactions(&unknown, Some(2), &|| panic!(
                        "unknown must not ask for headroom"
                    ))?
                    .is_none()
            );
        }
        Ok(())
    }

    #[test]
    fn stale_inventory_requires_validation_and_core_age_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        for (time_age, work_blocks, validated, allowed) in [
            (2_591_999, 4_319, true, true),
            (2_592_000, 4_319, true, false),
            (2_591_999, 4_320, true, false),
            (0, 0, false, false),
        ] {
            let StaleFixture {
                query,
                stale,
                source,
                ..
            } = stale_query(1)?;
            {
                let mut tree = query.block_tree.write();
                let stale_id = tree.lookup(stale.block_hash().into()).ok_or("stale")?;
                if !validated {
                    tree.restore_chain_tx_count(stale_id, bitcoin_rs_chain::ChainTxCount::UNKNOWN)?;
                }
                let stale_work = tree.node(stale_id)?.chainwork;
                let best_id = tree.tip_id().ok_or("tip")?;
                let best = tree.node_mut(best_id)?;
                best.header.time = stale.header.time + time_age;
                best.chainwork = stale_work + ChainWork::from(work_blocks * 2_u32);
            }
            let hash = wire_block_hash(stale.block_hash());
            let outcome = query.serve_inventory_blocks(
                &[Inventory::WitnessBlock(hash)],
                None,
                &|| true,
                &mut |_| Ok(()),
            )?;
            assert_eq!(outcome.not_found.is_empty(), allowed);
            assert_eq!(source.loads.load(Ordering::Relaxed), usize::from(allowed));
            assert!(
                query
                    .block_transactions(
                        &BlockTransactionsRequest {
                            block_hash: hash,
                            indexes: vec![1]
                        },
                        Some(2),
                        &|| true
                    )?
                    .is_some()
            );
        }
        let StaleFixture {
            query,
            stale,
            source,
            ..
        } = stale_query(11)?;
        {
            let mut tree = query.block_tree.write();
            let tip = tree.tip_id().ok_or("tip")?;
            tree.node_mut(tip)?.header.time = stale.header.time + 2_592_000;
        }
        assert!(
            query
                .block_transactions(
                    &BlockTransactionsRequest {
                        block_hash: wire_block_hash(stale.block_hash()),
                        indexes: vec![1]
                    },
                    Some(2),
                    &|| true
                )?
                .is_none()
        );
        assert_eq!(source.loads.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn stale_invalid_or_missing_bodies_are_not_served() -> Result<(), Box<dyn std::error::Error>> {
        let StaleFixture {
            mut query, stale, ..
        } = stale_query(1)?;
        query.block_body_source = None;
        let request = BlockTransactionsRequest {
            block_hash: wire_block_hash(stale.block_hash()),
            indexes: vec![1],
        };
        assert!(
            query
                .block_transactions(&request, Some(2), &|| true)?
                .is_none()
        );
        let StaleFixture {
            query,
            stale,
            source,
            ..
        } = stale_query(1)?;
        {
            let mut tree = query.block_tree.write();
            let id = tree.lookup(stale.block_hash().into()).ok_or("stale")?;
            tree.invalidate_subtree(id)?;
        }
        assert!(
            query
                .block_transactions(&request, Some(2), &|| true)?
                .is_none()
        );
        let result = query.serve_inventory_blocks(
            &[Inventory::WitnessBlock(request.block_hash)],
            None,
            &|| true,
            &mut |_| panic!("invalid"),
        )?;
        assert_eq!(result.not_found.len(), 1);
        assert_eq!(source.loads.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn serving_depth_uses_applied_tip_when_headers_are_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(15);
        let block = block_at(&headers, 1)?;
        let query = chain_at(&headers[..2], 1, &block)?;
        {
            let mut tree = query.block_tree.write();
            for header in &headers[2..] {
                tree.insert_header(*header, NodeStatus::HeaderValid)?;
            }
        }
        let request = BlockTransactionsRequest {
            block_hash: wire_block_hash(block.block_hash()),
            indexes: vec![1],
        };
        assert!(matches!(
            query.block_transactions(&request, Some(2), &|| true)?,
            Some(Message::BlockTxn(_))
        ));
        let mut messages = Vec::new();
        query.serve_inventory_blocks(
            &[Inventory::CompactBlock(request.block_hash)],
            Some(2),
            &|| true,
            &mut |m| {
                messages.push(m);
                Ok(())
            },
        )?;
        assert!(matches!(messages.as_slice(), [Message::CmpctBlock(_)]));
        Ok(())
    }

    #[test]
    fn serving_rechecks_reorg_invalidation_and_age_after_io()
    -> Result<(), Box<dyn std::error::Error>> {
        struct RacingSource {
            source: Arc<CountingBodySource>,
            tree: BlockTreeReader,
            applied: TipReader,
            change: u8,
        }
        impl BlockBodySource for RacingSource {
            fn block_body(
                &self,
                height: u32,
                hash: BlockHash,
            ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
                let mut tree = self.tree.write();
                match self.change {
                    1 => {
                        let id = tree.lookup(hash.into()).ok_or_else(|| {
                            bitcoin_rs_chain::BlockBodyReadError::Read(
                                "fixture node missing".to_owned(),
                            )
                        })?;
                        tree.invalidate_subtree(id).map_err(|error| {
                            bitcoin_rs_chain::BlockBodyReadError::Read(error.to_string())
                        })?;
                    }
                    2 => {
                        let tip = tree.tip_id().ok_or_else(|| {
                            bitcoin_rs_chain::BlockBodyReadError::Read(
                                "fixture node missing".to_owned(),
                            )
                        })?;
                        tree.node_mut(tip)
                            .map_err(|error| {
                                bitcoin_rs_chain::BlockBodyReadError::Read(error.to_string())
                            })?
                            .header
                            .time = 2_592_001;
                    }
                    _ => {}
                }
                self.applied.store(tree.tip());
                drop(tree);
                self.source.block_body(height, hash)
            }
        }
        for change in 0..3 {
            let StaleFixture {
                mut query,
                stale,
                source,
                ..
            } = stale_query(1)?;
            {
                let tree = query.block_tree.read();
                let id = tree.lookup(stale.block_hash().into()).ok_or("stale")?;
                let n = tree.node(id)?;
                query
                    .applied_tip
                    .store(Some(Arc::new(bitcoin_rs_chain::TipSnapshot {
                        tip_id: id,
                        height: n.height,
                        hash: n.hash,
                        chainwork: n.chainwork,
                        chain_tx_count: n.chain_tx_count,
                    })));
            }
            query.block_body_source = Some(Arc::new(RacingSource {
                source: source.clone(),
                tree: query.block_tree.clone(),
                applied: query.applied_tip.clone(),
                change,
            }));
            let hash = wire_block_hash(stale.block_hash());
            let mut messages = Vec::new();
            let outcome = query.serve_inventory_blocks(
                &[Inventory::WitnessBlock(hash)],
                None,
                &|| true,
                &mut |m| {
                    messages.push(m);
                    Ok(())
                },
            )?;
            assert_eq!(source.loads.load(Ordering::Relaxed), 1);
            if change == 0 {
                assert_eq!(outcome.not_found, []);
                let [Message::BlockPayload(payload)] = messages.as_slice() else {
                    panic!("reorg retains stored stale response");
                };
                assert_eq!(payload_body(payload)?.block_hash(), hash);
            } else {
                assert_eq!(messages, []);
                assert_eq!(outcome.not_found, vec![Inventory::WitnessBlock(hash)]);
            }
        }
        Ok(())
    }

    #[test]
    fn getblocktxn_rechecks_inventory_policy_when_io_crosses_depth_ten()
    -> Result<(), Box<dyn std::error::Error>> {
        struct AdvancingSource {
            source: Arc<CountingBodySource>,
            tree: BlockTreeReader,
            applied: TipReader,
            change: u8,
        }
        impl BlockBodySource for AdvancingSource {
            fn block_body(
                &self,
                height: u32,
                hash: BlockHash,
            ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
                let mut tree = self.tree.write();
                let old_tip = tree.tip_id().ok_or_else(|| {
                    bitcoin_rs_chain::BlockBodyReadError::Read("fixture node missing".to_owned())
                })?;
                let mut header = test_header(
                    tree.node(old_tip)
                        .map_err(|error| {
                            bitcoin_rs_chain::BlockBodyReadError::Read(error.to_string())
                        })?
                        .hash
                        .into(),
                    200,
                );
                if self.change == 2 {
                    header.time = 2_592_001;
                }
                tree.insert_node(Some(old_tip), header, NodeStatus::HeaderValid)
                    .map_err(|error| {
                        bitcoin_rs_chain::BlockBodyReadError::Read(error.to_string())
                    })?;
                if self.change == 1 {
                    let stale_id = tree.lookup(hash.into()).ok_or_else(|| {
                        bitcoin_rs_chain::BlockBodyReadError::Read(
                            "fixture node missing".to_owned(),
                        )
                    })?;
                    tree.restore_chain_tx_count(stale_id, bitcoin_rs_chain::ChainTxCount::UNKNOWN)
                        .map_err(|error| {
                            bitcoin_rs_chain::BlockBodyReadError::Read(error.to_string())
                        })?;
                }
                self.applied.store(tree.tip());
                drop(tree);
                self.source.block_body(height, hash)
            }
        }
        for change in 0..3 {
            let StaleFixture {
                mut query,
                stale,
                source,
                ..
            } = stale_query(10)?;
            query.block_body_source = Some(Arc::new(AdvancingSource {
                source: source.clone(),
                tree: query.block_tree.clone(),
                applied: query.applied_tip.clone(),
                change,
            }));
            let request = BlockTransactionsRequest {
                block_hash: wire_block_hash(stale.block_hash()),
                indexes: vec![1],
            };
            let result = query.block_transactions(&request, Some(2), &|| true)?;
            assert_eq!(source.loads.load(Ordering::Relaxed), 1);
            if change == 0 {
                let Some(Message::BlockPayload(payload)) = result else {
                    panic!("crossing depth ten must use full-block inventory policy");
                };
                assert_eq!(payload_body(&payload)?.block_hash(), request.block_hash);
            } else {
                assert!(
                    result.is_none(),
                    "deep fallback must reject absent validation or stale age"
                );
            }
        }
        Ok(())
    }

    fn query_with(headers: Vec<Header>) -> Result<ActiveChainQuery, bitcoin_rs_chain::ChainError> {
        let mut tree = BlockTree::new();
        let mut parent = None;
        for header in headers {
            parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
        }
        Ok(query_over(tree, Network::Regtest))
    }

    fn seed_headers(count: u32) -> Vec<Header> {
        let mut headers = Vec::new();
        let mut prev = BlockHash::default();
        for nonce in 0..count {
            let header = test_header(prev, nonce);
            prev = header.compute_hash();
            headers.push(header);
        }
        headers
    }

    fn test_header(prev_blockhash: BlockHash, nonce: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: nonce,
            bits: CompactTarget::from_consensus(bitcoin_rs_chain::regtest_fixture::REGTEST_BITS),
            nonce,
        }
    }

    fn header_hashes(headers: &[Header]) -> Vec<BlockHash> {
        headers.iter().map(Header::compute_hash).collect()
    }

    #[test]
    fn held_early_body_answers_before_the_store() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = block_at(&headers, 1)?;
        let slot = RecentBlockSlot::default();
        slot.store(Hash256::from(block.block_hash()), Arc::new(block.clone()));
        let query = query_with(headers)?.with_recent_block(slot);
        let request = bitcoin::bip152::BlockTransactionsRequest {
            block_hash: wire_block_hash(block.block_hash()),
            indexes: vec![1],
        };
        assert!(
            query
                .block_transactions(&request, Some(2), &|| false)?
                .is_none(),
            "a saturated gate must defer the held-body reply"
        );
        let reply = query
            .block_transactions(&request, Some(2), &|| true)?
            .ok_or("held body must answer getblocktxn")?;
        assert!(
            matches!(reply, Message::BlockTxn(_)),
            "expected BlockTxn from the held body, got {reply:?}"
        );
        let compact = ChainQuery::compact_block_for(&query, 1, block.block_hash(), Some(2))
            .ok_or("held body must answer compact getdata")?;
        assert!(
            matches!(compact, Message::CmpctBlock(_)),
            "expected CmpctBlock from the held body, got {compact:?}"
        );
        assert!(
            ChainQuery::compact_block_for(&query, 1, block.block_hash(), Some(99)).is_none(),
            "an invalid compact version must not serve the held body"
        );
        let compact_item = Inventory::CompactBlock(wire_block_hash(block.block_hash()));
        let mut invalid_served = Vec::new();
        let invalid =
            query.serve_inventory_blocks(&[compact_item], Some(99), &|| true, &mut |message| {
                invalid_served.push(message);
                Ok(())
            })?;
        assert_eq!(invalid.not_found, vec![compact_item]);
        assert!(
            invalid_served.is_empty(),
            "an invalid version serves nothing"
        );
        let missing = bitcoin::bip152::BlockTransactionsRequest {
            block_hash: wire_block_hash(BlockHash::default()),
            indexes: vec![0],
        };
        assert!(
            query
                .block_transactions(&missing, Some(2), &|| true)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn held_body_without_serving_position_answers_compact_getdata()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let mut block = block_at(&headers, 1)?;
        block.header.nonce = 0x7a7a_7a7a;
        let hash = block.block_hash();
        let slot = RecentBlockSlot::default();
        slot.store(Hash256::from(hash), Arc::new(block));
        let query = query_with(headers)?.with_recent_block(slot);
        let compact = Inventory::CompactBlock(wire_block_hash(hash));
        let full = Inventory::Block(wire_block_hash(hash));

        let mut served = Vec::new();
        let outcome =
            query.serve_inventory_blocks(&[compact], Some(2), &|| true, &mut |message| {
                served.push(message);
                Ok(())
            })?;
        assert!(outcome.not_found.is_empty(), "{outcome:?}");
        assert!(!outcome.halted);
        assert_eq!(served.len(), 1, "the held body must answer");
        assert!(
            matches!(served[0], Message::CmpctBlock(_)),
            "expected CmpctBlock from the held body, got {:?}",
            served[0]
        );

        let halted =
            query.serve_inventory_blocks(&[compact], Some(2), &|| false, &mut |_| Ok(()))?;
        assert!(halted.halted);
        assert_eq!(
            halted.not_found,
            Vec::<Inventory>::new(),
            "a headroom halt must not report missing inventory"
        );

        let mut full_served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[full], Some(2), &|| true, &mut |message| {
            full_served.push(message);
            Ok(())
        })?;
        assert_eq!(outcome.not_found, vec![full]);
        assert_eq!(
            full_served,
            Vec::<Message>::new(),
            "full requests cannot use the held body"
        );
        Ok(())
    }

    #[test]
    fn held_invalid_body_is_not_served_from_inventory() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = block_at(&headers, 1)?;
        let slot = RecentBlockSlot::default();
        slot.store(Hash256::from(block.block_hash()), Arc::new(block.clone()));
        let query = query_with(headers)?.with_recent_block(slot);
        {
            let mut tree = query.block_tree.write();
            let id = tree.lookup(block.block_hash().into()).ok_or("held")?;
            tree.invalidate_subtree(id)?;
        }
        let item = Inventory::CompactBlock(wire_block_hash(block.block_hash()));
        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert_eq!(outcome.not_found, vec![item]);
        assert!(
            served.is_empty(),
            "an invalid held body must not serve, got {served:?}"
        );
        Ok(())
    }

    #[test]
    fn held_stale_body_past_policy_is_not_served_from_inventory()
    -> Result<(), Box<dyn std::error::Error>> {
        let StaleFixture {
            mut query, stale, ..
        } = stale_query(1)?;
        {
            let mut tree = query.block_tree.write();
            let tip = tree.tip_id().ok_or("tip")?;
            tree.node_mut(tip)?.header.time = stale.header.time + 2_592_000;
        }
        let slot = RecentBlockSlot::default();
        slot.store(Hash256::from(stale.block_hash()), Arc::new(stale.clone()));
        query.recent = slot;
        let item = Inventory::CompactBlock(wire_block_hash(stale.block_hash()));
        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert_eq!(outcome.not_found, vec![item]);
        assert!(
            served.is_empty(),
            "a stale held body past policy must not serve, got {served:?}"
        );
        Ok(())
    }

    #[test]
    fn held_tip_child_body_is_served_from_inventory() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let block = block_at(&headers, 2)?;
        let slot = RecentBlockSlot::default();
        slot.store(Hash256::from(block.block_hash()), Arc::new(block.clone()));
        let query = query_with(headers[..2].to_vec())?.with_recent_block(slot);
        {
            let mut tree = query.block_tree.write();
            let parent = tree
                .lookup(headers[1].compute_hash().into())
                .ok_or("parent")?;
            tree.insert_node(Some(parent), headers[2], NodeStatus::HeaderValid)?;
        }
        let item = Inventory::CompactBlock(wire_block_hash(block.block_hash()));
        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert!(outcome.not_found.is_empty(), "{outcome:?}");
        assert!(
            matches!(served.as_slice(), [Message::CmpctBlock(_)]),
            "a held tip child must answer from the slot, got {served:?}"
        );
        Ok(())
    }

    #[test]
    fn held_stale_tip_child_is_not_served_from_inventory() -> Result<(), Box<dyn std::error::Error>>
    {
        let headers = seed_headers(2);
        let mut child = test_header(headers[1].compute_hash(), 3);
        child.time = 0;
        let block = Block {
            header: child,
            txs: vec![test_tx(1), test_tx(2)],
        };
        let parent_hash = headers[1].compute_hash();
        let slot = RecentBlockSlot::default();
        slot.store(Hash256::from(block.block_hash()), Arc::new(block.clone()));
        let query = query_with(headers)?.with_recent_block(slot);
        {
            let mut tree = query.block_tree.write();
            let parent = tree.lookup(parent_hash.into()).ok_or("parent")?;
            let child_id = tree.insert_node(Some(parent), child, NodeStatus::HeaderValid)?;
            let mut grandchild = test_header(block.block_hash(), 4);
            grandchild.time = 2_592_000;
            tree.insert_node(Some(child_id), grandchild, NodeStatus::HeaderValid)?;
        }
        let item = Inventory::CompactBlock(wire_block_hash(block.block_hash()));
        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert_eq!(outcome.not_found, vec![item]);
        assert!(
            served.is_empty(),
            "a stale tip child must not serve, got {served:?}"
        );
        Ok(())
    }

    #[test]
    fn held_deep_body_uses_full_block_inventory_policy() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(8);
        let block = block_at(&headers, 1)?;
        let slot = RecentBlockSlot::default();
        slot.store(Hash256::from(block.block_hash()), Arc::new(block.clone()));
        let query = chain_at(&headers, 1, &block)?.with_recent_block(slot);
        let item = Inventory::CompactBlock(wire_block_hash(block.block_hash()));
        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert!(outcome.not_found.is_empty(), "{outcome:?}");
        assert!(
            matches!(served.as_slice(), [Message::BlockPayload(_)]),
            "a deep held body must fall back to the full block, got {served:?}"
        );
        Ok(())
    }

    #[test]
    fn stale_tip_announcement_reconstructs_demoted_fork() -> Result<(), Box<dyn std::error::Error>>
    {
        use bitcoin_rs_chain::regtest_fixture::mined_regtest_header;
        let mut tree = BlockTree::new();
        let genesis = Network::Regtest.genesis_block().header;
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;

        let mut main_parent = genesis_id;
        let mut main_headers = Vec::new();
        for i in 1..=5 {
            let prev = tree.node(main_parent)?.hash;
            let header = mined_regtest_header(BlockHash::from(prev), i)?;
            let id = tree.insert_node(Some(main_parent), header, NodeStatus::HeaderValid)?;
            main_parent = id;
            main_headers.push(header);
        }

        let fork_id = tree
            .lookup(Hash256::from(main_headers[2].compute_hash()))
            .ok_or("fork header missing")?;
        let mut stale_parent = fork_id;
        let mut stale_headers = Vec::new();
        for i in 101..=102 {
            let prev = tree.node(stale_parent)?.hash;
            let header = mined_regtest_header(BlockHash::from(prev), i)?;
            let id = tree.insert_node(Some(stale_parent), header, NodeStatus::HeaderValid)?;
            stale_parent = id;
            stale_headers.push(header);
        }
        let stale_tip_hash = Hash256::from(stale_headers[1].compute_hash());

        let query = query_over(tree, Network::Regtest);

        let peer_tips = vec![Hash256::from(main_headers[4].compute_hash())];
        let outcome = query.stale_tip_announcement(stale_tip_hash, &peer_tips);
        let Some(StaleTipHeaders::Headers(announcement)) = outcome else {
            panic!("expected StaleTipHeaders::Headers, got {outcome:?}");
        };
        assert_eq!(
            announcement.fork_point,
            Hash256::from(main_headers[2].compute_hash())
        );
        assert_eq!(announcement.headers.len(), 2);
        let reconstructed = announcement.reconstruct();
        assert_eq!(reconstructed, stale_headers);

        let peer_knows = vec![stale_tip_hash];
        assert_eq!(
            query.stale_tip_announcement(stale_tip_hash, &peer_knows),
            None
        );

        assert_eq!(query.stale_tip_announcement(stale_tip_hash, &[]), None);

        Ok(())
    }

    #[test]
    fn stale_tip_announcement_reports_too_many_above_twenty_headers()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_chain::regtest_fixture::mined_regtest_header;
        let mut tree = BlockTree::new();
        let genesis = Network::Regtest.genesis_block().header;
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;

        let mut parent = genesis_id;
        let mut headers = Vec::new();
        for i in 1..=25 {
            let prev = tree.node(parent)?.hash;
            let header = mined_regtest_header(BlockHash::from(prev), i)?;
            let id = tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?;
            parent = id;
            headers.push(header);
        }

        let mut stale_parent = genesis_id;
        let mut stale_tip = Hash256::default();
        for i in 1001..=1022 {
            let prev = tree.node(stale_parent)?.hash;
            let header = mined_regtest_header(BlockHash::from(prev), i)?;
            let id = tree.insert_node(Some(stale_parent), header, NodeStatus::HeaderValid)?;
            stale_parent = id;
            stale_tip = Hash256::from(header.compute_hash());
        }

        let query = query_over(tree, Network::Regtest);
        let peer_tips = vec![Hash256::from(headers[24].compute_hash())];
        assert_eq!(
            query.stale_tip_announcement(stale_tip, &peer_tips),
            Some(StaleTipHeaders::TooMany)
        );
        Ok(())
    }
}
