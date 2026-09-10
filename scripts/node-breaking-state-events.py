#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "crates/node/src/state.rs"
EVENTS = ROOT / "crates/node/src/state/events.rs"

src = STATE.read_text()
if EVENTS.exists():
    raise SystemExit("state events split already present")

# Move the event hint bound beside the event owner.
comment_start = src.index("// Bounds chain-event hints between the block-apply commit path")
comment_end = src.index("// Bounds inbound peer transactions", comment_start)
hint_bound = src[comment_start:comment_end].rstrip() + "\n"
src = src[:comment_start] + src[comment_end:]

start = src.index("/// A coherent, non-torn view of the applied chain tip.")
end = src.index("/// Errors produced when applying a block to the node state.", start)
event_body = src[start:end].rstrip() + "\n"
src = src[:start] + src[end:]

event_body = event_body.replace(
    "impl ChainEventPublisher {\n    fn new(",
    "impl ChainEventPublisher {\n    pub(super) fn new(",
    1,
)
event_body = event_body.replace(
    "fn allocate_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64> {",
    "pub(super) fn allocate_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64> {",
    1,
)

prelude = '''//! Applied-chain snapshot publication and process-epoch ownership.\n//!\n//! This module is the sole owner of the coherent snapshot cell, bounded event\n//! hints, and the durable per-data-directory process epoch.\n\nuse std::io::{self, Write as _};\nuse std::sync::atomic::{AtomicU64, Ordering};\n\nuse anyhow::{Context as _, Result, bail};\nuse bitcoin_rs_primitives::Hash256;\nuse crossbeam_channel::{Receiver, Sender};\nuse parking_lot::RwLock;\n\nuse super::INBOUND_BLOCK_CHANNEL_LIMIT;\n\n'''
# Keep the original explanatory comment but derive the bound from the parent
# inbound-block budget exactly as before.
EVENTS.parent.mkdir(parents=True, exist_ok=True)
EVENTS.write_text(prelude + hint_bound + "\n" + event_body)

anchor = "use crate::NodeConfig;\n\n"
if anchor not in src:
    raise SystemExit("state module insertion anchor missing")
src = src.replace(
    anchor,
    anchor
    + "pub mod events;\n\n"
    + "use self::events::{\n"
    + "    ChainEventHint, ChainEventPublisher, ChainSnapshot, HintKind, allocate_process_epoch,\n"
    + "};\n\n",
    1,
)
STATE.write_text(src)

# Migrate repository callers to the new owner. The old state::* event paths
# intentionally disappear; do not add aliases in state.rs or lib.rs.
replacements = {
    "crate::state::ChainEventPublisher": "crate::state::events::ChainEventPublisher",
    "crate::state::ChainEventHint": "crate::state::events::ChainEventHint",
    "crate::state::ChainSnapshot": "crate::state::events::ChainSnapshot",
    "crate::state::HintKind": "crate::state::events::HintKind",
    "bitcoin_rs_node::state::ChainEventPublisher": "bitcoin_rs_node::state::events::ChainEventPublisher",
    "bitcoin_rs_node::state::ChainEventHint": "bitcoin_rs_node::state::events::ChainEventHint",
    "bitcoin_rs_node::state::ChainSnapshot": "bitcoin_rs_node::state::events::ChainSnapshot",
    "bitcoin_rs_node::state::HintKind": "bitcoin_rs_node::state::events::HintKind",
    "use crate::state::{ChainSnapshot, NodeState};": "use crate::state::NodeState;\nuse crate::state::events::ChainSnapshot;",
}
for path in ROOT.rglob("*.rs"):
    if path == EVENTS:
        continue
    text = path.read_text()
    changed = text
    for old, new in replacements.items():
        changed = changed.replace(old, new)
    if changed != text:
        path.write_text(changed)

legacy = (
    "crate::state::ChainEventPublisher",
    "crate::state::ChainEventHint",
    "crate::state::ChainSnapshot",
    "crate::state::HintKind",
    "bitcoin_rs_node::state::ChainEventPublisher",
    "bitcoin_rs_node::state::ChainEventHint",
    "bitcoin_rs_node::state::ChainSnapshot",
    "bitcoin_rs_node::state::HintKind",
)
for path in ROOT.rglob("*.rs"):
    if path == EVENTS:
        continue
    text = path.read_text()
    for old in legacy:
        if old in text:
            raise SystemExit(f"legacy event path remains in {path}: {old}")
