#!/usr/bin/env python3
"""Prepare a source-only checkpoint codec cut against a verified input blob."""
from collections import Counter
import hashlib
from pathlib import Path
import re
import subprocess
import textwrap

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'crates/node/src/checkpoint.rs'
HEADERS = SOURCE.with_suffix('') / 'headers.rs'
TESTS = SOURCE.with_suffix('') / 'tests.rs'
EXPECTED = '5e3f6274f90a8c4611b009e0b444c6d9f85247ec'
original = SOURCE.read_bytes()
actual = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
if actual != EXPECTED or HEADERS.exists() or TESTS.exists():
    raise SystemExit(f'checkpoint input changed or split already present: {actual}')
src = original.decode()

def tests_in(text):
    return Counter(re.findall(r'#\[test\]\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)', text))

original_tests = tests_in(src)
constants = [
    'const HEADER_MAGIC: [u8; 8] = *b"BRSHEAD\\0";\n',
    'const HEADER_VERSION: u32 = 1;\n',
    'const HEADER_PREFIX_LEN: usize = 56;\n',
    'const HEADER_LEN: usize = 80;\n',
    'const BEST_CHAIN_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/best\\0";\n',
    'const APPLIED_PREFIX_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/applied\\0";\n',
]
for line in constants:
    if src.count(line) != 1:
        raise SystemExit(f'constant anchor changed: {line!r}')
    src = src.replace(line, '', 1)
start = src.index('#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub(crate) struct HeaderCheckpointConfig')
end = src.index('#[derive(Clone, Debug, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct CurrentV1', start)
codec = src[start:end]
src = src[:start] + src[end:]
marker = '#[cfg(test)]\nmod tests {'
start = src.index(marker)
if not src.rstrip().endswith('}'):
    raise SystemExit('test module is no longer the final item')
tests = textwrap.dedent(src[start + len(marker):].rstrip()[:-1]).strip() + '\n'
production = src[:start]

# Every caller names the actual codec owner; no parent-level aliases survive.
names = re.findall(r'^(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|fn|const)\s+(\w+)', ''.join(constants) + codec, re.M)
moved = set(names)

def strip_moved_imports(match):
    entries = [item.strip() for item in match.group(1).split(',') if item.strip()]
    remaining = [item for item in entries if item not in moved]
    return 'use super::{\n    ' + ', '.join(remaining) + ',\n};'

tests = re.sub(r'use super::\{([^}]+)\};', strip_moved_imports, tests)
# Only helpers actually shared with the parent/test module gain parent visibility.
shared = production + tests
for name in names:
    if re.search(r'\b' + re.escape(name) + r'\b', shared):
        codec = re.sub(r'^fn ' + re.escape(name) + r'\b', 'pub(super) fn ' + name, codec, flags=re.M)
        constants = [re.sub(r'^const ' + re.escape(name) + r'\b', 'pub(super) const ' + name, line) for line in constants]

pattern = re.compile(r'\b(' + '|'.join(map(re.escape, names)) + r')\b')
production = pattern.sub(lambda m: 'headers::' + m.group(), production)
tests = pattern.sub(lambda m: 'headers::' + m.group(), tests)
tests = '//! Checkpoint codec and immutable-publication regressions.\n\nuse super::headers;\n\n' + tests

# Imports that belonged solely to the extracted header codec.
production = production.replace(
    'use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, TipSnapshot, accept_headers};',
    'use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, TipSnapshot};', 1)
production = production.replace('use bitcoin_rs_primitives::{ConsensusEncode, Header, deserialize};\n', '', 1)
if '.seek(' not in production:
    production = production.replace('BufReader, BufWriter, Read, Seek, SeekFrom, Write', 'BufReader, BufWriter, Read, Write', 1)

prelude = '''//! Canonical header-checkpoint representation and validation.
//!
//! Owns the headers-v1 prefix, ancestry serialization, independent best/applied
//! commitments, and consensus-validated reconstruction. The parent owns the
//! immutable generation and CURRENT publication; this codec does not publish,
//! remove, or sync files. Existing wire bytes and typed failures are unchanged.

use std::io::{Read, Seek, SeekFrom, Write};

use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, accept_headers};
use bitcoin_rs_primitives::{ConsensusEncode, Hash256, Header, Network, deserialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

'''
HEADERS.parent.mkdir(parents=True, exist_ok=True)
HEADERS.write_text(prelude + ''.join(constants) + '\n' + codec.rstrip() + '\n')
TESTS.write_text(tests)
SOURCE.write_text('pub(crate) mod headers;\n\n' + production.rstrip() + '\n\n#[cfg(test)]\nmod tests;\n')

# Existing crate-internal consumers migrate, including grouped use statements.
exports = {name for name in names if name.startswith('HeaderCheckpoint') or name in {'RestoredHeaders', 'read_headers', 'write_headers'}}
for path in (ROOT / 'crates/node').rglob('*.rs'):
    if path in {SOURCE, HEADERS, TESTS}:
        continue
    text = path.read_text()
    changed = text
    def migrate_use(match):
        prefix, contents = match.groups()
        entries = [entry.strip() for entry in contents.split(',') if entry.strip()]
        old = [entry for entry in entries if entry.split(' as ')[0] in exports]
        keep = [entry for entry in entries if entry not in old]
        if not old:
            return match.group()
        result = f'use {prefix}::headers::{{' + ', '.join(old) + '};\n'
        if keep:
            result += f'use {prefix}::{{' + ', '.join(keep) + '};'
        return result
    changed = re.sub(r'use ((?:crate::)?checkpoint)::\{([^}]+)\};', migrate_use, changed)
    for name in exports:
        changed = changed.replace('checkpoint::' + name, 'checkpoint::headers::' + name)
    if changed != text:
        path.write_text(changed)

# Verify that extraction did not alter a function body or drop a regression.
normalized = re.sub(r'pub\(super\) fn ', 'fn ', codec)
if normalized != original.decode()[original.decode().index('#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub(crate) struct HeaderCheckpointConfig'):original.decode().index('#[derive(Clone, Debug, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct CurrentV1')]:
    raise SystemExit('codec body changed beyond parent visibility')
if tests_in(SOURCE.read_text()) + tests_in(TESTS.read_text()) + tests_in(HEADERS.read_text()) != original_tests:
    raise SystemExit('checkpoint regression inventory changed')
for path in (ROOT / 'crates/node').rglob('*.rs'):
    text = path.read_text()
    if any('checkpoint::' + name in text for name in exports):
        raise SystemExit(f'legacy codec path remains in {path}')

page = ROOT / 'docs/chainstate-recovery.md'
text = page.read_text()
anchor = '## Target model\n'
if text.count(anchor) != 1:
    raise SystemExit('recovery documentation anchor changed')
section = '''## Current checkpoint implementation

`crates/node/src/checkpoint.rs` owns immutable checkpoint generations and the
`CURRENT` publication. Its `checkpoint/headers.rs` child owns the canonical
header codec: prefix and version, best/applied ancestry commitments, and
consensus-validated header reconstruction. Internal consumers name
`checkpoint::headers` directly; the former parent-level codec paths are removed.
The existing codec and publication regressions live in `checkpoint/tests.rs`.
This separation does not change checkpoint bytes, publication order, recovery
fallbacks, or the status of the planned durable-root model below.

'''
page.write_text(text.replace(anchor, section + anchor, 1))
print(f'Preserved {sum(original_tests.values())} checkpoint tests; codec bodies identical apart from parent visibility.')
for path in (SOURCE, HEADERS, TESTS):
    print(f'{path.relative_to(ROOT)}: {len(path.read_text().splitlines())} lines')
for path in (ROOT / 'crates/node').rglob('*.rs'):
    text = path.read_text()
    if 'checkpoint::headers::' in text:
        print('migrated caller:', path.relative_to(ROOT))
