#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APPLY = ROOT / "crates/node/src/apply.rs"
BODY = ROOT / "crates/node/src/apply/body_store.rs"

src = APPLY.read_text()
if "pub(crate) mod body_store;" in src:
    raise SystemExit("apply body-store split already present")

for line in (
    "const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;\n",
    "const SERIALIZED_BLOCK_METADATA_PREFIX_LEN: usize = SERIALIZED_BLOCK_HEADER_LEN + 9;\n",
):
    if line not in src:
        raise SystemExit(f"missing expected constant: {line.strip()}")
    src = src.replace(line, "", 1)

start_marker = "fn decode_block_tx_count(bytes: &[u8]) -> Option<usize> {"
end_marker = "/// Admission barrier shared by every cloned apply handle."
start = src.index(start_marker)
end = src.index(end_marker, start)
body = src[start:end].rstrip() + "\n"
src = src[:start] + src[end:]
src = src.replace("mod scratch;\n", "pub(crate) mod body_store;\nmod scratch;\n", 1)

header = '''//! Durable block-body storage and ordered snapshot readers.\n//!\n//! This is the sole node owner of block-body persistence, flat-file position\n//! decoding, ranged reads, metadata reads, prefetch ordering, and durability.\n\nuse std::sync::Arc;\n\nuse bitcoin_rs_primitives::{Hash256, varint};\nuse bitcoin_rs_storage::{\n    BlockFilePosition, FlatFileBlockReader, FlatFileBlockStore, KvSnapshot, KvStore, StorageError,\n    WriteBatch, block_file_max_height_key, decode_block_file_max_height,\n    encode_block_file_max_height,\n};\n\nconst SERIALIZED_BLOCK_HEADER_LEN: usize = 80;\nconst SERIALIZED_BLOCK_METADATA_PREFIX_LEN: usize = SERIALIZED_BLOCK_HEADER_LEN + 9;\n\n'''
BODY.write_text(header + body)
APPLY.write_text(src)

replacements = {
    "crate::apply::PruneBodyStore": "crate::apply::body_store::PruneBodyStore",
    "crate::apply::PruneBodyReader": "crate::apply::body_store::PruneBodyReader",
    "crate::apply::FlatFilePruneBodyStore": "crate::apply::body_store::FlatFilePruneBodyStore",
    "use crate::apply::{PruneBodyReader, PruneBodyStore};":
        "use crate::apply::body_store::{PruneBodyReader, PruneBodyStore};",
    "use crate::apply::PruneBodyStore;":
        "use crate::apply::body_store::PruneBodyStore;",
    "use crate::apply::{ApplyAdmission, PruneBodyStore, UndoStore};":
        "use crate::apply::body_store::PruneBodyStore;\nuse crate::apply::{ApplyAdmission, UndoStore};",
}

for path in (ROOT / "crates/node").rglob("*.rs"):
    if path == BODY:
        continue
    text = path.read_text()
    changed = text
    for old, new in replacements.items():
        changed = changed.replace(old, new)
    if changed != text:
        path.write_text(changed)

# The ownership cut is intentionally breaking: these names are no longer\n# exported from `crate::apply`; callers must name the body_store owner.\nfor legacy in ("crate::apply::PruneBodyStore", "crate::apply::PruneBodyReader", "crate::apply::FlatFilePruneBodyStore"):
    for path in (ROOT / "crates/node").rglob("*.rs"):
        if legacy in path.read_text():
            raise SystemExit(f"legacy apply path remains in {path}: {legacy}")
