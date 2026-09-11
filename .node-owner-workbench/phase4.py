"""Separate durability ownership while keeping commit and recovery semantics."""
from pathlib import Path
from support import r, split, remove_items, migration
from persistence_maps import WRITER, WRITER_METHODS, CHECKPOINT, REPLAY, RECOVERY
from persistence_repairs import short_paths, obsolete_api, test_paths, after_fix


def run():
    path = r.ROOT / 'chainstate_journal.rs'
    source = path.read_text()
    for node, raw in r.items(source):
        if node.type == 'use_declaration':
            for dependency, alias in r.use_leaves(source, node):
                symbol = alias or dependency.split('::')[-1]
                r.add_map('chainstate_journal::' + symbol, 'chainstate_journal::' + dependency)
    r.write(path, '''//! Journal recovery: semantic records, append/durability, replay, and emission.
//!
//! The writer owns segment files and the durable head. The record module owns
//! the wire format; replay consumes only the committed range. Emission connects
//! committed chainstate effects to this single writer.

pub(crate) mod delta;
pub(crate) mod emit;
pub(crate) mod record;
pub(crate) mod replay;
pub(crate) mod writer;
''')
    path = r.ROOT / 'chainstate_journal/writer.rs'
    remove_items(path, {'segment_name_pub', 'parse_segment_name_pub'})
    for name in ['segment_name_pub', 'parse_segment_name_pub']:
        r.add_map('chainstate_journal::writer::' + name, 'chainstate_journal::writer::segments::' + name.removesuffix('_pub'))
    text = path.read_text().replace('fn segment_name(', 'pub(crate) fn segment_name(').replace('fn parse_segment_name(', 'pub(crate) fn parse_segment_name(')
    path.write_text(text)
    split('chainstate_journal/writer', 'chainstate_journal/writer', WRITER, {'JournalWriter': WRITER_METHODS})
    split('checkpoint', 'checkpoint', CHECKPOINT)
    split('chainstate_journal/replay', 'chainstate_journal/replay', REPLAY)
    split('recovery_evidence', 'recovery', RECOVERY)
    path = r.ROOT / 'lib.rs'
    path.write_text(path.read_text().replace('mod recovery_evidence;', 'mod recovery;'))
    r.migrate_paths()
    short_paths()
    obsolete_api()
    for path in list(r.ROOT.rglob('*.rs')):
        if 'tests' in path.stem and any(part in path.parts for part in ('checkpoint', 'chainstate_journal', 'recovery')):
            r.test_partition(path)
    test_paths()
    for path in Path('docs').rglob('*.md'):
        text = path.read_text()
        changed = text.replace('crates/node/src/recovery_evidence.rs', 'crates/node/src/recovery.rs')
        if text != changed:
            path.write_text(changed)
    migration('''## Checkpoint, journal, and recovery

Checkpoint metadata, generation management, restoration, atomic publication,
file operations, and failure injection have direct owners under `checkpoint`.
The journal writer separates append, durable-head publication, rewind, compaction,
segment naming, head encoding, and reopen recovery. `recovery_evidence` is removed;
rollback evidence belongs to `recovery::{witness,marker,warnings,detection}`.

Journal forwarding exports, the `segment_name_pub`/`parse_segment_name_pub`
wrappers, unused `JournalEmit::flush_through` and `JournalWriter::flush_to`, the
writer lifecycle getter, and copied `BlockMeta` representation are removed.
Tests exercise the actual durability operation and authoritative record/state
instead of the deleted adapters. The blanket journal `allow(dead_code)` is gone.

Persisted encodings, checksums, file names, flush/fsync/head-publication order,
fail-closed behavior, checkpoint eligibility, and recovery rules are unchanged.
This source API cut does not reset data or require an on-disk migration.
''')
