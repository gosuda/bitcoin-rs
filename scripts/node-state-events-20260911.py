#!/usr/bin/env python3
"""Extract the event/epoch owner without changing publication or disk behavior."""
from collections import Counter
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / 'crates/node/src/state.rs'
EVENTS = STATE.with_suffix('') / 'events.rs'
original = STATE.read_bytes()
actual = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
if actual != 'efbde7f9c673dd0334c542704a66d7b306e8bdef' or EVENTS.exists():
    raise SystemExit(f'state source changed or event owner already exists: {actual}')
src = original.decode()
start = src.index('// Bounds chain-event hints between the block-apply commit path')
end = src.index('// Bounds inbound peer transactions', start)
hint_bound = src[start:end]
src = src[:start] + src[end:]
start = src.index('/// A coherent, non-torn view of the applied chain tip.')
end = src.index('struct NodeStorage {', start)
original_body = src[start:end]
body = original_body
src = src[:start] + src[end:]
body = body.replace('impl ChainEventPublisher {\n    fn new(', 'impl ChainEventPublisher {\n    pub(super) fn new(', 1)
for name in ('allocate_process_epoch', 'load_process_epoch'):
    if re.search(r'\b' + name + r'\b', src):
        body = body.replace('fn ' + name + '(', 'pub(super) fn ' + name + '(', 1)
constants = re.findall(r'^const (PROCESS_EPOCH_\w+)', body, re.M)
for name in constants:
    if re.search(r'\b' + name + r'\b', src):
        body = body.replace('const ' + name + ':', 'pub(super) const ' + name + ':', 1)
if body.replace('pub(super) fn ', 'fn ').replace('pub(super) const ', 'const ') != original_body:
    raise SystemExit('event implementation changed beyond parent visibility')
# Correct the stale body-store owner pointer already changed on main.
body = body.replace('`BlockBodyStore::load_block_body` (`crate::apply`)', '`BlockBodyStore::load_block_body` (`bitcoin_rs_storage::block_body`)')

prelude = '''//! Applied-chain event publication and durable process-epoch allocation.
//!
//! Owns the live coherent snapshot cell, bounded nonblocking hint channel, and
//! serialized on-disk epoch transaction. NodeState composes this owner; apply
//! records committed results, and derived consumers reconcile from snapshots.
//! This move preserves publication order, channel capacity, lock lifetime,
//! epoch filenames, typed failures, and file/directory durability barriers.

use std::io::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_primitives::Hash256;
use crossbeam_channel::{Receiver, Sender};
use parking_lot::RwLock;

use super::INBOUND_BLOCK_CHANNEL_LIMIT;

'''
EVENTS.parent.mkdir(parents=True, exist_ok=True)
EVENTS.write_text(prelude + hint_bound + '\n' + body.rstrip() + '\n')

exports = {'ChainSnapshot', 'ChainEventHint', 'ChainEventPublisher', 'HintKind', 'CHAIN_HINT_CHANNEL_LIMIT'}
internal = exports | set(constants) | {'load_process_epoch', 'allocate_process_epoch'}

def strip_import(match):
    entries = [part.strip() for part in match.group(1).split(',') if part.strip()]
    entries = [entry for entry in entries if entry.split(' as ')[0] not in internal]
    return 'use super::{' + ', '.join(entries) + '};' if entries else ''
src = re.sub(r'use super::\{([^{}]+)\};', strip_import, src)
for name in internal:
    src = re.sub(r'use super::' + re.escape(name) + r';\n', '', src)

# Qualify references at their real owner rather than preserving state::* names.
# Comments and string literals are preserved, except explicit rustdoc links.
protected = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|(?:br|r)(?P<hash>#{0,16})"[\s\S]*?"(?P=hash)|b?"(?:\\[\s\S]|[^"\\])*"')
names = '|'.join(re.escape(name) for name in sorted(internal, key=len, reverse=True))
pattern = re.compile(r'(?<![:\w])(?:super::)?(' + names + r')\b')

def qualify_code(part):
    part = pattern.sub(lambda m: 'crate::state::events::' + m.group(1), part)
    return re.sub(r'(?<![:\w])io::', 'std::io::', part)

parts, last = [], 0
for match in protected.finditer(src):
    parts.extend((qualify_code(src[last:match.start()]), match.group()))
    last = match.end()
parts.append(qualify_code(src[last:]))
src = ''.join(parts)
for name in exports:
    src = src.replace('[`' + name + '`]', '[`events::' + name + '`]')
# The epoch owner now owns the only state-local std::io writer use.
src = src.replace('    io::{self, Write as _},\n', '', 1)
if '.write_all(' in src:
    src = src.replace('use anyhow::', 'use std::io::Write as _;\n\nuse anyhow::', 1)
anchor = 'use anyhow::{Context as _, Result, bail};'
if src.count(anchor) != 1:
    raise SystemExit('state declaration anchor changed')
src = src.replace(anchor, '/// Applied-chain event publication and durable process epochs.\npub mod events;\n\n' + anchor, 1)
STATE.write_text(src)

# Handle standalone, grouped, and nested use trees across every Rust consumer.
# No changes are made to dependencies, feature defaults, or external data.
for root in ('crates', 'bin'):
    for path in (ROOT / root).rglob('*.rs'):
        if path == EVENTS:
            continue
        text = path.read_text()
        def grouped(match):
            entries = [part.strip() for part in match.group(1).split(',') if part.strip()]
            event_entries = [entry for entry in entries if entry.split(' as ')[0] in exports]
            if not event_entries:
                return match.group()
            keep = [entry for entry in entries if entry not in event_entries]
            return 'state::{' + ', '.join(keep + ['events::{' + ', '.join(event_entries) + '}']) + '}'
        changed = re.sub(r'\bstate::\{([^{}]*)\}', grouped, text)
        for name in exports:
            changed = changed.replace('state::' + name, 'state::events::' + name)
        if changed != text:
            path.write_text(changed)

# Preserve every original state regression and reject legacy code paths.
def inventory(text):
    return Counter(re.findall(r'#\[test\]\s*fn\s+(\w+)', text))
if inventory(STATE.read_text()) + inventory(EVENTS.read_text()) != inventory(original.decode()):
    raise SystemExit('state regression inventory changed')
for root in ('crates', 'bin'):
    for path in (ROOT / root).rglob('*.rs'):
        text = path.read_text()
        if any('state::' + name in text for name in exports):
            raise SystemExit(f'legacy event path remains in {path}')

# Keep normative pointers synchronized without editing dated evidence.
for path in [ROOT / 'CONCEPTS.md', *(ROOT / 'docs/contracts').glob('*.md')]:
    text = path.read_text()
    changed = text
    for name in exports:
        changed = changed.replace('state::' + name, 'state::events::' + name)
    if changed != text:
        path.write_text(changed)
print('Event and epoch code preserved apart from parent visibility and the corrected body-store documentation pointer.')
print(f'Preserved {sum(inventory(original.decode()).values())} state tests.')
print(f'Event owner: {len(EVENTS.read_text().splitlines())} lines.')
for path in (ROOT / 'crates/node').rglob('*.rs'):
    if path != EVENTS and 'state::events::' in path.read_text():
        print('migrated:', path.relative_to(ROOT))
