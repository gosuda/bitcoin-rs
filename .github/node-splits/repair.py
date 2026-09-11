"""Repair import resolution before native acceptance; not product source."""
from pathlib import Path
import runpy
import sys

import refactor as r

_original_split = r.split_implementation


def add_imports(path, lines):
    text = path.read_text()
    offset = 0
    for line in text.splitlines(keepends=True):
        if line.startswith('//!') or not line.strip():
            offset += len(line)
        else:
            break
    missing = [line for line in lines if line not in text]
    path.write_text(text[:offset] + '\n'.join(missing) + '\n' + text[offset:])


def split(path, type_name, plan):
    # These four functions have no callers outside recovery_evidence itself.
    # Narrow their old crate-wide visibility before moving their single
    # implementation into child modules. There is no retained public alias.
    if path.stem == 'recovery_evidence':
        names = ['write_bounded', 'read_bounded', 'checkpoint_fallback_warning', 'index_ahead_warning']
        for candidate in path.parents[3].rglob('*.rs'):
            if candidate == path:
                continue
            text = candidate.read_text()
            if any(name in text for name in names):
                raise RuntimeError(f'Recovery helper has a caller requiring explicit migration: {candidate}')
        text = path.read_text()
        for name in names:
            old = 'pub(crate) fn ' + name + '('
            if text.count(old) != 1:
                raise RuntimeError(f'Unexpected recovery helper declaration: {name}')
            text = text.replace(old, 'fn ' + name + '(')
        path.write_text(text)
    made = _original_split(path, type_name, plan)
    if path.stem == 'sync':
        for name in ['branches', 'commit', 'receive']:
            p = path.with_suffix('') / (name + '.rs')
            p.write_text(p.read_text().replace('use bitcoin::hashes::Hash as _;\n', ''))
    elif path.stem == 'checkpoint':
        add_imports(path, ['use sha2::Digest as _;'])
        for module, imports in {
            'io': ['use std::io::Write as _;'],
            'load': ['use sha2::Digest as _;', 'use std::io::Read as _;', 'use std::io::Seek as _;'],
            'publish': ['use std::io::Write as _;', 'use sha2::Digest as _;'],
        }.items():
            add_imports(path.with_suffix('') / (module + '.rs'), imports)
    elif path.stem == 'storage_footprint':
        add_imports(path, ['use anyhow::Context as _;'])
        add_imports(path.with_suffix('') / 'identity.rs', ['use anyhow::Context as _;', 'use std::io::Read as _;'])
        add_imports(path.with_suffix('') / 'scan.rs', ['use rustix::fd::AsFd as _;'])
        for p in [path, path.with_suffix('') / 'budget.rs', path.with_suffix('') / 'scan.rs']:
            p.write_text(p.read_text().replace('use sha2::Digest as _;\n', ''))
    elif path.stem == 'recovery_evidence':
        add_imports(path.with_suffix('') / 'io.rs', ['use std::io::Read as _;', 'use std::io::Write as _;'])
    return made


r.split_implementation = split
if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).with_name('continue.py')), run_name='__main__')
