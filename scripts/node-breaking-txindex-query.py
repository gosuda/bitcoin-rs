#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TX = ROOT / "crates/node/src/txindex_worker.rs"
QUERY = ROOT / "crates/node/src/txindex_worker/query.rs"

src = TX.read_text()
if QUERY.exists():
    raise SystemExit("txindex query split already present")

start_marker = "/// Aggregate work budget shared by every operation in one public query."
end_marker = '#[cfg(all(test, feature = "fjall"))]\nmod body_reader_tests {'
start = src.index(start_marker)
end = src.index(end_marker, start)
query_body = src[start:end].rstrip() + "\n"
src = src[:start] + src[end:]

anchor = "mod heartbeat;\nmod namespace;\nmod query_adapter;\nmod scheduling;\n"
if anchor not in src:
    raise SystemExit("txindex submodule anchor missing")
src = src.replace(
    anchor,
    "mod heartbeat;\nmod namespace;\npub(crate) mod query;\nmod query_adapter;\nmod scheduling;\n",
    1,
)

# Parent worker code must name the new query owner explicitly. No private or
# public aliases preserve txindex_worker::IndexBlockSource/QueryEngine paths.
for name in (
    "IndexBlockSource",
    "QueryEngineLive",
    "TxIndexQueryEngine",
    "TxIndexCapability",
    "IndexProgress",
):
    src = src.replace(name, f"query::{name}")
TX.write_text(src)

prelude = '''//! Snapshot-gated txindex reads and capability projection.\n//!\n//! This module owns query budgets, active-chain body resolution, coherent\n//! snapshot gating, and the RPC capability view. The worker drives writes; it\n//! no longer owns these read-side types.\n\n#[allow(clippy::wildcard_imports)]\nuse super::*;\n\n'''
QUERY.parent.mkdir(parents=True, exist_ok=True)
QUERY.write_text(prelude + query_body)

# Migrate sibling callers. The old txindex_worker::* query paths intentionally
# disappear instead of being re-exported.
for path in ROOT.rglob("*.rs"):
    if path in (TX, QUERY):
        continue
    text = path.read_text()
    changed = text
    for name in (
        "IndexBlockSource",
        "QueryEngineLive",
        "TxIndexQueryEngine",
        "TxIndexCapability",
        "IndexProgress",
    ):
        changed = changed.replace(
            f"crate::txindex_worker::{name}",
            f"crate::txindex_worker::query::{name}",
        )
        changed = changed.replace(
            f"bitcoin_rs_node::txindex_worker::{name}",
            f"bitcoin_rs_node::txindex_worker::query::{name}",
        )
    if changed != text:
        path.write_text(changed)

# Child test modules imported their parent implementation wholesale. Point
# them at the new owner for only the names they actually use.
for path in (ROOT / "crates/node/src").glob("txindex_worker_*tests.rs"):
    text = path.read_text()
    used = [
        name
        for name in (
            "IndexBlockSource",
            "QueryEngineLive",
            "TxIndexQueryEngine",
            "TxIndexCapability",
            "IndexProgress",
        )
        if name in text
    ]
    if used and "use super::*;" in text:
        line = "use super::query::{" + ", ".join(used) + "};\n"
        if line not in text:
            text = text.replace("use super::*;\n", "use super::*;\n" + line, 1)
            path.write_text(text)

# Update the contract's owner map without claiming the write-side worker moved.
doc = ROOT / "docs/contracts/indexing.md"
if doc.exists():
    text = doc.read_text()
    text = text.replace(
        "- `TxIndexRuntime`, `TxIndexQueryEngine`, `Worker` in `crates/node/src/txindex_worker.rs`",
        "- `TxIndexRuntime` and `Worker` in `crates/node/src/txindex_worker.rs`; `TxIndexQueryEngine` and query capability projection in `crates/node/src/txindex_worker/query.rs`",
    )
    doc.write_text(text)

legacy = tuple(
    f"crate::txindex_worker::{name}"
    for name in (
        "IndexBlockSource",
        "QueryEngineLive",
        "TxIndexQueryEngine",
        "TxIndexCapability",
        "IndexProgress",
    )
)
for path in ROOT.rglob("*.rs"):
    if path == QUERY:
        continue
    text = path.read_text()
    for old in legacy:
        if old in text:
            raise SystemExit(f"legacy txindex query path remains in {path}: {old}")
