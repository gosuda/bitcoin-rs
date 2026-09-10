#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = ROOT / "crates/node/src/checkpoint.rs"
HEADERS = ROOT / "crates/node/src/checkpoint/headers.rs"
TESTS = ROOT / "crates/node/src/checkpoint/tests.rs"

src = CHECKPOINT.read_text()
if HEADERS.exists() or TESTS.exists():
    raise SystemExit("checkpoint split already present")

header_constants = [
    'const HEADER_MAGIC: [u8; 8] = *b"BRSHEAD\\0";\n',
    'const HEADER_VERSION: u32 = 1;\n',
    'const HEADER_PREFIX_LEN: usize = 56;\n',
    'const HEADER_LEN: usize = 80;\n',
    'const BEST_CHAIN_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/best\\0";\n',
    'const APPLIED_PREFIX_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/applied\\0";\n',
]
for line in header_constants:
    if line not in src:
        raise SystemExit(f"missing header constant {line.strip()}")
    src = src.replace(line, "", 1)

start_marker = "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub(crate) struct HeaderCheckpointConfig"
end_marker = "#[derive(Debug, Deserialize, Serialize)]\n#[serde(deny_unknown_fields)]\nstruct CurrentV1"
start = src.index(start_marker)
end = src.index(end_marker, start)
header_body = src[start:end].rstrip() + "\n"
src = src[:start] + src[end:]

header_prelude = '''//! Canonical header-checkpoint codec and its validation contract.\n\nuse std::io::{Read, Seek, SeekFrom, Write};\n\nuse bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, TipSnapshot, accept_headers};\nuse bitcoin_rs_primitives::{ConsensusEncode, Hash256, Header, Network, deserialize};\nuse thiserror::Error;\n\nconst HEADER_MAGIC: [u8; 8] = *b"BRSHEAD\\0";\nconst HEADER_VERSION: u32 = 1;\nconst HEADER_PREFIX_LEN: usize = 56;\nconst HEADER_LEN: usize = 80;\nconst BEST_CHAIN_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/best\\0";\nconst APPLIED_PREFIX_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/applied\\0";\n\n'''
HEADERS.parent.mkdir(parents=True, exist_ok=True)
HEADERS.write_text(header_prelude + header_body)

module_anchor = "use thiserror::Error;\n\n"
if module_anchor not in src:
    raise SystemExit("checkpoint module anchor missing")
src = src.replace(
    module_anchor,
    module_anchor
    + "pub(crate) mod headers;\n\n"
    + "use self::headers::{\n"
    + "    HeaderCheckpointConfig, HeaderCheckpointMetadata, HeaderCheckpointPoint,\n"
    + "    HeaderCheckpointWrite, RestoredHeaders, read_headers, write_headers,\n"
    + "};\n\n",
    1,
)

# The top-level test module is the final item. Move its body to checkpoint/tests.rs.
test_marker = "#[cfg(test)]\nmod tests {"
test_start = src.index(test_marker)
module_open = test_start + len(test_marker)
if not src.rstrip().endswith("}"):
    raise SystemExit("checkpoint tests are no longer the final module")
trimmed = src.rstrip()
inner = trimmed[module_open:-1]
lines = inner.splitlines()
dedented = []
for line in lines:
    if line.startswith("    "):
        line = line[4:]
    dedented.append(line)
test_body = "\n".join(dedented).lstrip("\n") + "\n"
# Tests need direct visibility of the moved header owner in addition to parent items.
TESTS.write_text("use super::headers::*;\n" + test_body)
src = trimmed[:test_start] + "#[cfg(test)]\nmod tests;\n"
CHECKPOINT.write_text(src)

# Break the old crate-internal HeaderCheckpoint* path and migrate every node caller.
for path in (ROOT / "crates/node").rglob("*.rs"):
    if path == HEADERS:
        continue
    text = path.read_text()
    changed = text.replace("crate::checkpoint::HeaderCheckpoint", "crate::checkpoint::headers::HeaderCheckpoint")
    changed = changed.replace("checkpoint::HeaderCheckpoint", "checkpoint::headers::HeaderCheckpoint")
    if changed != text:
        path.write_text(changed)

for path in (ROOT / "crates/node").rglob("*.rs"):
    if path == HEADERS:
        continue
    text = path.read_text()
    if "crate::checkpoint::HeaderCheckpoint" in text or "checkpoint::HeaderCheckpoint" in text:
        raise SystemExit(f"legacy header checkpoint path remains in {path}")
