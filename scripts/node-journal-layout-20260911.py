#!/usr/bin/env python3
"""Prepare the source-only journal layout cut against an immutable baseline."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import textwrap

ROOT = Path.cwd()
JOURNAL = ROOT / 'crates/node/src/chainstate_journal'
WRITER = JOURNAL / 'writer.rs'
FACADE = ROOT / 'crates/node/src/chainstate_journal.rs'
EXPECTED_WRITER = '651e04ad516189e2dd5db725f62d1ee1a88a979c'


def blob(text):
    raw = text.encode()
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def replace_one(text, old, new):
    if text.count(old) != 1:
        raise SystemExit(f'Expected one anchor, found {text.count(old)}: {old[:100]}')
    return text.replace(old, new, 1)


def cut(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(f'Extraction anchors changed: {start!r}, {end!r}')
    a = text.index(start)
    b = text.index(end, a)
    return text[:a] + text[b:], text[a:b]


original = WRITER.read_text()
if blob(original) != EXPECTED_WRITER:
    raise SystemExit('Writer differs from the reviewed baseline')
for relative in ('head.rs', 'segment.rs', 'error.rs', 'head/tests.rs', 'segment/tests.rs', 'writer/tests.rs'):
    if (JOURNAL / relative).exists():
        raise SystemExit(f'Owner already exists: {relative}')

src, head_constants = cut(original, '/// Magic prefix of `head.json` payload bytes', '/// Maximum serialized segment name length sanity bound.')
src, segment_bound = cut(src, '/// Maximum serialized segment name length sanity bound.', 'pub(crate) const FULL_REVALIDATION_MARKER:')
src, names = cut(src, '/// Zero-padded 10-digit generation:', '/// §2.6 crash-injection boundaries')
src, errors = cut(src, '#[derive(Debug, Error)]\npub(crate) enum JournalWriterError', '/// Durable head marker payload')
src, head = cut(src, '/// Durable head marker payload', '/// Cursor of the durable frontier:')
src, reader = cut(src, '/// Journal-directory helpers shared by writer and boot replay (later task).', '#[cfg(test)]\nmod tests {')
src, tests = cut(src, '#[cfg(test)]\nmod tests {', '__EXTRACTION_END__') if False else (src, None)
test_anchor = '#[cfg(test)]\nmod tests {\n'
a = src.index(test_anchor)
test_tail = src[a + len(test_anchor):]
if not test_tail.endswith('}\n'):
    raise SystemExit('Writer tests are no longer the final module')
writer_tests = textwrap.dedent(test_tail[:-2])
src = src[:a] + '#[cfg(test)]\nmod tests;\n'

head_original = head
head = replace_one(head, '    fn serialize(&self)', '    pub(super) fn serialize(&self)')
assert head.replace('    pub(super) fn serialize(&self)', '    fn serialize(&self)', 1) == head_original
reader = reader.replace('/// Journal-directory helpers shared by writer and boot replay (later task).', '/// Reads the framed head shared by writer startup and boot replay.', 1)
for name, argument, result, body in (
    ('segment_name', 'generation: u64', 'String', 'segment_name(generation)'),
    ('parse_segment_name', 'name: &str', 'Option<u64>', 'parse_segment_name(name)'),
):
    wrapper = f"/// Public-to-crate wrapper for the boot replay's segment window reader.\npub(crate) fn {name}_pub({argument}) -> {result} {{\n    {body}\n}}\n\n"
    names = replace_one(names, wrapper, '')
    names = replace_one(names, f'fn {name}(', f'pub(super) fn {name}(')
names = names.replace('/// Zero-padded 10-digit generation: lexicographic order equals numeric order.', '/// Generations are padded to at least ten decimal digits.', 1)

src = replace_one(src, 'use thiserror::Error;\n', '')
src = replace_one(src, 'use super::record::{', 'use super::error::JournalWriterError;\nuse super::head::HeadMarker;\nuse super::segment::{parse_segment_name, segment_name};\n\nuse super::record::{')
# Fully qualify this shared reader so no writer-level binding preserves its old path.
src = re.sub(r'(?<![\w:])read_head_bytes\(', 'crate::chainstate_journal::head::read_head_bytes(', src)
writer_tests = re.sub(r'(?<![\w:])read_head_bytes\(', 'crate::chainstate_journal::head::read_head_bytes(', writer_tests)
WRITER.write_text(src)
(JOURNAL / 'head.rs').write_text('//! Canonical framed journal head and its size-checked file reader.\n//!\n//! This module owns representation, not publication. Only the writer advances\n//! the durable frontier after the storage and segment durability dependencies.\n\nuse super::error::JournalWriterError;\n\n' + head_constants + head + reader + '#[cfg(test)]\nmod tests;\n')
(JOURNAL / 'segment.rs').write_text('//! Shared journal segment filename grammar; no file mutation or cursor state.\n\n' + segment_bound + names + '#[cfg(test)]\nmod tests;\n')
(JOURNAL / 'error.rs').write_text('//! Shared typed failures for journal storage and head decoding.\n\nuse thiserror::Error;\n\n' + errors)
(JOURNAL / 'writer').mkdir()
(JOURNAL / 'writer/tests.rs').write_text(writer_tests)

facade = FACADE.read_text()
first_item = facade.index('// Wire-format surface')
facade = '//! Optional checkpoint-based chainstate journal.\n//!\n//! `record` owns ordered redo bytes; `head` owns the framed head representation\n//! and its size-checked reader; `segment` owns the filename grammar. `writer`\n//! alone appends, truncates, syncs, and publishes the durable frontier. `replay`\n//! authenticates the committed range against the checkpoint before restore.\n//! These are current checkpoint/journal mechanisms, not the planned durable-root\n//! authority described in the recovery contract.\n\n' + facade[first_item:]
facade = replace_one(facade, 'mod writer;\n', 'mod error;\npub(crate) mod head;\nmod segment;\nmod writer;\n\npub(crate) use error::JournalWriterError;\n')
facade = replace_one(facade, 'FULL_REVALIDATION_MARKER, HeadMarker, JOURNAL_DIR_NAME, JournalWriter, JournalWriterError,', 'FULL_REVALIDATION_MARKER, JOURNAL_DIR_NAME, JournalWriter,')
FACADE.write_text(facade)

# Only import trees and qualified paths are rewritten; algorithm bodies stay intact.
def migrate_writer_group(match):
    prefix = match.group(1)
    groups = {'head': [], 'error': [], 'writer': []}
    for item in match.group(2).split(','):
        item = item.strip()
        if not item:
            continue
        symbol = item.split()[0]
        owner = 'head' if symbol in ('HeadMarker', 'read_head_bytes') else 'error' if symbol == 'JournalWriterError' else 'writer'
        groups[owner].append(item)
    return prefix + '{' + ', '.join(owner + '::{' + ', '.join(items) + '}' for owner, items in groups.items() if items) + '}'

changed_callers = []
tracked = subprocess.check_output(['git', 'ls-files', '*.rs'], text=True).splitlines()
for relative in tracked:
    path = ROOT / relative
    text = path.read_text()
    changed = re.sub(r'((?:[A-Za-z_][A-Za-z_0-9]*::)+)writer::\{([^{}]+)\}', migrate_writer_group, text)
    for symbol, owner in (('HeadMarker', 'head'), ('read_head_bytes', 'head'), ('JournalWriterError', 'error')):
        changed = re.sub(r'\bwriter::' + symbol + r'\b', owner + '::' + symbol, changed)
    changed = changed.replace('writer::parse_segment_name_pub', 'segment::parse_segment_name')
    changed = changed.replace('writer::segment_name_pub', 'segment::segment_name')
    changed = changed.replace('chainstate_journal::HeadMarker', 'chainstate_journal::head::HeadMarker')
    changed = re.sub(r'(chainstate_journal::\{)([^{}]*)(\})', lambda m: m[1] + re.sub(r'\bHeadMarker\b', 'head::HeadMarker', m[2]) + m[3], changed)
    if changed != text:
        path.write_text(changed)
        changed_callers.append(relative)

(JOURNAL / 'head').mkdir()
(JOURNAL / 'head/tests.rs').write_text('''//! Representation controls for the current checkpoint journal, not power-loss proof.
//! CONTRACT: docs/chainstate-recovery.md, current journal implementation.

use super::*;

fn marker() -> HeadMarker {
    HeadMarker {
        base_generation: 7,
        base_height: 10,
        base_hash: [1; 32],
        base_chain_tx_count: 11,
        start_gen: 2,
        start_offset: 3,
        journal_gen: 4,
        offset: 5,
        height: 12,
        block_hash: [6; 32],
        prev_hash: [8; 32],
        chain_tx_count: 19,
        record_count: 2,
    }
}

#[test]
fn head_frame_preserves_magic_version_and_every_field() -> Result<(), JournalWriterError> {
    let head = marker();
    let bytes = head.serialize()?;
    // Immutable headers-v1 representation from the pre-cut writer: JRNH, version 1,
    // little-endian CRC32C, then the existing JSON field representation.
    assert_eq!(&bytes[..5], b"JRNH\\x01");
    assert_eq!(HeadMarker::deserialize(&bytes)?, head);
    let payload: serde_json::Value = serde_json::from_slice(&bytes[9..])
        .map_err(|error| JournalWriterError::HeadUnreadable(error.to_string()))?;
    assert_eq!(payload["base_generation"], 7);
    assert_eq!(payload["height"], 12);
    assert_eq!(payload["record_count"], 2);
    assert_eq!(payload.as_object().map(serde_json::Map::len), Some(13));
    Ok(())
}

#[test]
fn head_frame_rejects_short_magic_version_and_checksum_corruption() -> Result<(), JournalWriterError> {
    let bytes = marker().serialize()?;
    for length in 0..9 {
        assert!(matches!(HeadMarker::deserialize(&bytes[..length]), Err(JournalWriterError::HeadUnreadable(_))));
    }
    for position in [0, 4, 5, 9] {
        let mut corrupt = bytes.clone();
        corrupt[position] ^= 1;
        assert!(matches!(HeadMarker::deserialize(&corrupt), Err(JournalWriterError::HeadUnreadable(_))));
    }
    Ok(())
}

#[test]
fn head_reader_distinguishes_absence_and_existing_size_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let dir = cap_std::fs::Dir::open_ambient_dir(temp.path(), cap_std::ambient_authority())?;
    assert_eq!(read_head_bytes(&dir)?, None);
    // File-size checks and frame validity are separate, as on the pre-cut reader.
    dir.write("head.json", vec![0; 4096])?;
    let bytes = read_head_bytes(&dir)?.ok_or("head disappeared")?;
    assert_eq!(bytes.len(), 4096);
    assert!(HeadMarker::deserialize(&bytes).is_err());
    dir.write("head.json", vec![0; 4097])?;
    assert!(matches!(read_head_bytes(&dir), Err(JournalWriterError::HeadUnreadable(_))));
    assert_eq!(dir.metadata("head.json")?.len(), 4097);
    Ok(())
}
''')
(JOURNAL / 'segment').mkdir()
(JOURNAL / 'segment/tests.rs').write_text('''//! CONTRACT: docs/chainstate-recovery.md, current journal filename representation.
use super::*;

#[test]
fn segment_names_round_trip_the_full_generation_range() {
    assert_eq!(segment_name(0), "segment-0000000000.log");
    assert_eq!(segment_name(u64::MAX), "segment-18446744073709551615.log");
    for generation in [0, 9, 10, 9_999_999_999, 10_000_000_000, u64::MAX] {
        assert_eq!(parse_segment_name(&segment_name(generation)), Some(generation));
    }
}

#[test]
fn segment_parser_preserves_existing_decimal_acceptance() {
    // Padding is a writer convention, not an extra recovery rejection rule.
    assert_eq!(parse_segment_name("segment-7.log"), Some(7));
    assert_eq!(parse_segment_name("segment-00000000000000000000000000000000.log"), Some(0));
    for name in [
        "segment-.log", "segment--1.log", "segment-+1.log", "segment-1a.log",
        "segment-18446744073709551616.log", "segment-000000000000000000000000000000000.log",
        "other-0000000001.log", "segment-0000000001.log.tmp",
    ] {
        assert_eq!(parse_segment_name(name), None, "accepted {name}");
    }
}
''')

page = ROOT / 'docs/chainstate-recovery.md'
text = page.read_text()
paragraph = '''## Current journal implementation

The optional checkpoint journal keeps its framed `head.json` codec and file-size
check in `crates/node/src/chainstate_journal/head.rs`; `segment.rs` owns the shared
filename grammar, and `error.rs` owns the shared typed failures. Writer startup
and replay use those owners directly. The former writer-level head paths and
`segment_name_pub` / `parse_segment_name_pub` forwarding wrappers are removed.

`writer.rs` remains the sole mutation and publication owner: storage flush,
segment sync, temporary-head write/sync, rename, then directory sync. Moving the
representation does not change those commit points, the existing JSON/CRC frame,
segment-name acceptance, checkpoint fallback, or operator data. Writer regressions
live in `writer/tests.rs`; head/segment representation controls live with their
owners. These controls are not a power-loss or durable-root acceptance claim.

'''
page.write_text(replace_one(text, '## Target model\n', paragraph + '## Target model\n'))

for path in (ROOT / 'crates/node').rglob('*.rs'):
    text = path.read_text()
    for removed in ('segment_name_pub', 'parse_segment_name_pub', 'writer::HeadMarker', 'writer::read_head_bytes', 'writer::JournalWriterError', 'chainstate_journal::HeadMarker'):
        if removed in text:
            raise SystemExit(f'Retired binding remains in {path}: {removed}')
# Test relocation keeps every pre-existing writer test/helper byte-identical.
assert (JOURNAL / 'writer/tests.rs').read_text() == writer_tests
before_tests = Counter(re.findall(r'\bfn (\w+)\(', test_tail))
after_tests = Counter(re.findall(r'\bfn (\w+)\(', writer_tests))
assert before_tests == after_tests
print('Writer tests retained:', len(re.findall(r'#\[test\]', writer_tests)))
print('New representation controls: 5')
print('Migrated callers:', ', '.join(changed_callers))
changed = subprocess.check_output(['git', 'diff', '--name-only'], text=True).splitlines()
changed += subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines()
Path(os.environ['RUNNER_TEMP'], 'journal-layout-paths.json').write_text(json.dumps(sorted(set(changed))))
for path in sorted(set(changed)):
    print(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), path)
