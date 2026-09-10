#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE_STAGE = ROOT / "crates/node/src/sync/stage.rs"
P2P_STAGE = ROOT / "crates/p2p/src/block_stager.rs"
NODE_SYNC = ROOT / "crates/node/src/sync.rs"
P2P_LIB = ROOT / "crates/p2p/src/lib.rs"

if P2P_STAGE.exists():
    raise SystemExit("p2p block stager already exists")
src = NODE_STAGE.read_text()

src = """//! Out-of-order block staging bounded by the download-window budget.\n//!\n//! P2P owns downloaded-body staging next to `DownloadWindow`. Node sync may\n//! drive this state, but it no longer defines or aliases the staging policy.\n\n""" + src
src = src.replace("use bitcoin_rs_p2p::SyncBudget;", "use crate::SyncBudget;")
src = src.replace("use bitcoin_rs_p2p::default_sync_budget;", "use crate::default_sync_budget;")
src = src.replace("bitcoin_rs_p2p::download_window::PENDING_BLOCK_BYTE_ESTIMATE", "crate::download_window::PENDING_BLOCK_BYTE_ESTIMATE")

replacements = {
    "#[derive(Debug)]\npub(super) struct BlockStager": "/// Bounded staging set for decoded inbound block bodies.\n#[derive(Debug)]\npub struct BlockStager",
    "#[derive(Clone, Debug)]\npub(super) struct DrainedBlock {\n    pub(super) hash: Hash256,\n    pub(super) block: Block,\n    pub(super) serialized: bytes::Bytes,": "/// A contiguous apply-prefix body drained from staging.\n#[derive(Clone, Debug)]\npub struct DrainedBlock {\n    /// Block identity.\n    pub hash: Hash256,\n    /// Decoded block body.\n    pub block: Block,\n    /// Original wire bytes reused by apply.\n    pub serialized: bytes::Bytes,",
    "#[derive(Clone, Debug)]\npub(super) struct DroppedBlock {\n    pub(super) hash: Hash256,\n}": "/// A staged body dropped for retry or eviction.\n#[derive(Clone, Debug)]\npub struct DroppedBlock {\n    /// Block identity.\n    pub hash: Hash256,\n}",
    "#[derive(Clone, Debug)]\npub(super) enum StagedBlock {\n    AlreadyStaged,\n    Memory {\n        bytes: usize,\n        dropped: Vec<DroppedBlock>,\n    },\n    DroppedForRetry {\n        dropped: DroppedBlock,\n    },\n}": "/// Result of attempting to stage one inbound body.\n#[derive(Clone, Debug)]\npub enum StagedBlock {\n    /// The body was already staged.\n    AlreadyStaged,\n    /// The body is retained in memory.\n    Memory {\n        /// Serialized size of the retained body.\n        bytes: usize,\n        /// Older bodies evicted to satisfy the slot budget.\n        dropped: Vec<DroppedBlock>,\n    },\n    /// The body could not fit and remains eligible for retry.\n    DroppedForRetry {\n        /// Body identity released for retry.\n        dropped: DroppedBlock,\n    },\n}",
    "    pub(super) fn new(budget: SyncBudget) -> Self {": "    /// Creates an empty stager sized by `budget`.\n    #[must_use]\n    pub fn new(budget: SyncBudget) -> Self {",
    "    pub(super) fn received_len(&self) -> usize {": "    /// Returns the number of staged bodies.\n    #[must_use]\n    pub fn received_len(&self) -> usize {",
    "    pub(super) fn received_bytes(&self) -> usize {": "    /// Returns total serialized bytes held by staged bodies.\n    #[must_use]\n    pub fn received_bytes(&self) -> usize {",
    "    pub(super) const fn received_high_water(&self) -> usize {": "    #[must_use]\n    pub const fn received_high_water(&self) -> usize {",
    "    pub(super) const fn received_bytes_high_water(&self) -> usize {": "    #[must_use]\n    pub const fn received_bytes_high_water(&self) -> usize {",
    "    pub(super) fn ready_received_len(&self, next_expected_hash: Option<Hash256>) -> Option<usize> {": "    /// Returns staged count only when the apply frontier is present.\n    #[must_use]\n    pub fn ready_received_len(&self, next_expected_hash: Option<Hash256>) -> Option<usize> {",
    "    pub(super) fn insert(": "    /// Stages one inbound block or releases it for retry under the budget.\n    pub fn insert(",
    "    pub(super) fn contains(&self, hash: &Hash256) -> bool {": "    #[must_use]\n    pub fn contains(&self, hash: &Hash256) -> bool {",
    "    pub(super) fn staged_body(&self, hash: Hash256) -> Option<(Block, bytes::Bytes)> {": "    #[must_use]\n    pub fn staged_body(&self, hash: Hash256) -> Option<(Block, bytes::Bytes)> {",
    "    pub(super) fn retire_applied(&mut self, hash: &Hash256) -> bool {": "    pub fn retire_applied(&mut self, hash: &Hash256) -> bool {",
    "    pub(super) fn drain_expected_prefix(": "    /// Removes the contiguous staged prefix of `expected_hashes`.\n    pub fn drain_expected_prefix(",
    "    pub(super) fn restore_many(&mut self, drained: impl IntoIterator<Item = DrainedBlock>) {": "    /// Restores drained bodies after a partial apply.\n    pub fn restore_many(&mut self, drained: impl IntoIterator<Item = DrainedBlock>) {",
    "    pub(super) fn prune_expired(&mut self, now: Instant) -> Vec<DroppedBlock> {": "    /// Drops bodies whose staging deadline has expired.\n    pub fn prune_expired(&mut self, now: Instant) -> Vec<DroppedBlock> {",
}
for old, new in replacements.items():
    if old not in src:
        raise SystemExit(f"expected stage fragment missing: {old[:80]!r}")
    src = src.replace(old, new, 1)

P2P_STAGE.write_text(src)
NODE_STAGE.unlink()

lib = P2P_LIB.read_text()
needle = "/// Block download window, peer-assignment, stall, and scheduling policy.\npub mod download_window;\n"
if needle not in lib:
    raise SystemExit("p2p module insertion anchor missing")
lib = lib.replace(needle, "/// Out-of-order block-body staging and staging budgets.\npub mod block_stager;\n" + needle, 1)
anchor = "pub use chain_query::ActiveChainQuery;\n"
lib = lib.replace(anchor, anchor + "pub use block_stager::{BlockStager, DrainedBlock, DroppedBlock, StagedBlock};\n", 1)
P2P_LIB.write_text(lib)

sync = NODE_SYNC.read_text()
sync = sync.replace("mod stage;\n\n", "", 1)
sync = sync.replace("use bitcoin_rs_p2p::{InboundBlock, InboundHeaders, Message, PeerTable};", "use bitcoin_rs_p2p::{\n    BlockStager, DrainedBlock, InboundBlock, InboundHeaders, Message, PeerTable, StagedBlock,\n};")
sync = sync.replace("\nuse self::stage::{BlockStager, DrainedBlock, StagedBlock};\n", "\n")
sync = sync.replace("super::StagedBlock::", "StagedBlock::")
sync = sync.replace("super::BlockStager", "BlockStager")
NODE_SYNC.write_text(sync)

# Breaking contract: node must not keep the legacy staging module or alias.
if NODE_STAGE.exists():
    raise SystemExit("legacy node stager still exists")
if "mod stage;" in NODE_SYNC.read_text() or "self::stage" in NODE_SYNC.read_text():
    raise SystemExit("legacy node stage path remains")
