"""Pinned, one-shot source refactor workbench. Not part of a product commit."""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap

from tree_sitter import Language, Parser
import tree_sitter_rust

BASE = 'a1178cc884e42b953a041d0c139bc47814b7ccae'
PARSER = Parser(Language(tree_sitter_rust.language()))


def command(*args, cwd=None, capture=False, check=True):
    print('+', ' '.join(map(str, args)), flush=True)
    p = subprocess.run(args, cwd=cwd, check=check, text=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None)
    return p.stdout if capture else p.returncode


@dataclass
class Item:
    start: int
    end: int
    node: object
    text: str
    prefix: str

    @property
    def name(self):
        n = self.node.child_by_field_name('name')
        return n.text.decode() if n else None

    @property
    def test(self):
        return bool(re.search(r'#\[\s*test\s*\]', self.prefix))


def line_start(src, at):
    return src.rfind(b'\n', 0, at) + 1


def line_end(src, at):
    end = src.find(b'\n', at)
    return len(src) if end < 0 else end + 1


def items(src, parent):
    pending = None
    for n in parent.named_children:
        text = n.text.decode()
        if n.type in ('line_comment', 'block_comment', 'attribute_item'):
            if text.startswith(('//!', '/*!')):
                pending = None
                continue
            if pending is None:
                pending = line_start(src, n.start_byte)
            continue
        if n.type == 'inner_attribute_item':
            pending = None
            continue
        start = line_start(src, n.start_byte) if pending is None else pending
        end = line_end(src, n.end_byte)
        yield Item(start, end, n, src[start:end].decode(), src[start:n.start_byte].decode())
        pending = None


def parse(src):
    tree = PARSER.parse(src)
    if tree.root_node.has_error:
        errors = []
        def walk(n):
            if n.type == 'ERROR' or n.is_missing:
                errors.append((n.type, n.start_point, n.text[:100].decode(errors='replace')))
            for c in n.children:
                walk(c)
        walk(tree.root_node)
        raise RuntimeError(f'Rust syntax rejected: {errors[:8]}')
    return list(items(src, tree.root_node))


def rewrite(src, edits):
    stop = len(src)
    for start, end, replacement in sorted(edits, reverse=True):
        if not 0 <= start <= end <= stop:
            raise RuntimeError(f'Overlapping/out-of-bounds edits: {start}, {end}, {stop}')
        src = src[:start] + replacement.encode() + src[end:]
        stop = start
    return src


def split_commas(text):
    depth = 0
    start = 0
    for i, c in enumerate(text):
        depth += c == '{'
        depth -= c == '}'
        if c == ',' and depth == 0:
            if text[start:i].strip():
                yield text[start:i].strip()
            start = i + 1
    if text[start:].strip():
        yield text[start:].strip()


def expand_use(text, prefix=''):
    text = text.strip()
    if '{' in text:
        i = text.index('{')
        if not text.endswith('}'):
            raise RuntimeError(f'Unsupported use tree: {text}')
        for member in split_commas(text[i + 1:-1]):
            yield from expand_use(member, prefix + text[:i])
    else:
        full = prefix.rstrip(':') if text == 'self' else prefix + text
        alias = full.split(' as ')[-1].strip() if ' as ' in full else full.split('::')[-1]
        yield alias, full


def identifiers(text):
    # An over-approximation only for import selection. Rust's compiler owns
    # resolution and removes unnecessary imports; it never generates bodies.
    return set(re.findall(r'\b[A-Za-z_][A-Za-z_0-9]*\b', text))


def external_test_text(path, entries):
    found = []
    for item in entries:
        if item.node.type != 'mod_item' or 'test' not in item.prefix:
            continue
        body = item.node.child_by_field_name('body')
        if body:
            found.append(body.text.decode())
        else:
            match = re.search(r'path\s*=\s*"([^"]+)"', item.prefix)
            other = path.parent / match[1] if match else path.with_suffix('') / (item.name + '.rs')
            if other.exists():
                found.append(other.read_text())
    return '\n'.join(found)


def lift_visibility(src, item):
    if any(n.type == 'visibility_modifier' for n in item.node.children):
        return textwrap.dedent(item.text)
    offset = item.node.start_byte - item.start
    raw = item.text.encode()
    return textwrap.dedent((raw[:offset] + b'pub(super) ' + raw[offset:]).decode())


def extract_tests(path):
    src = path.read_bytes()
    edits = []
    made = []
    for item in parse(src):
        if item.node.type != 'mod_item' or 'test' not in item.prefix:
            continue
        body = item.node.child_by_field_name('body')
        if body is None:
            continue
        dest = path.with_suffix('') / (item.name + '.rs')
        if dest.exists():
            raise RuntimeError(f'New test file exists: {dest}')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(textwrap.dedent(src[body.start_byte + 1:body.end_byte - 1].decode()).strip() + '\n')
        edits.append((item.start, item.end, item.prefix + f'mod {item.name};\n'))
        made.append(dest)
    path.write_bytes(rewrite(src, edits))
    return made


def split_implementation(path, type_name, plan):
    src = path.read_bytes()
    entries = parse(src)
    test_text = external_test_text(path, entries)
    imports = []
    edits = []
    declared = {}
    public_imports = set()
    for item in entries:
        if item.name and item.node.type in ('struct_item', 'enum_item', 'type_item', 'const_item', 'static_item', 'trait_item', 'function_item', 'mod_item'):
            declared[item.name] = item
        if item.node.type == 'use_declaration':
            match = re.match(r'(pub(?:\([^)]*\))?\s+)?use\s+(.*);\s*$', item.node.text.decode(), re.S)
            if not match:
                raise RuntimeError(f'Unsupported import: {item.text}')
            attr = re.sub(r'#\[allow\(unused_imports\)\]\s*', '', item.prefix).strip()
            attr = '\n'.join(line for line in attr.splitlines() if not line.lstrip().startswith('//'))
            for name, full in expand_use(match[2]):
                imports.append((name, full, attr))
                if match[1]:
                    public_imports.add(name)
            if not match[1]:
                edits.append((item.start, item.end, ''))
    ownership = {}
    content = {module: [] for module in plan}
    wanted_methods = {name: module for module, spec in plan.items() for name in spec.get('methods', [])}
    wanted_functions = {name: module for module, spec in plan.items() for name in spec.get('functions', [])}
    wanted_traits = {name: module for module, spec in plan.items() for name in spec.get('traits', [])}
    found_methods, found_functions, found_traits = set(), set(), set()
    for item in entries:
        if item.node.type == 'function_item' and item.name in wanted_functions:
            module = wanted_functions[item.name]
            if any(c.type == 'visibility_modifier' for c in item.node.children):
                raise RuntimeError(f'Public function needs an explicit caller migration: {item.name}')
            content[module].append(lift_visibility(src, item))
            edits.append((item.start, item.end, ''))
            ownership[item.name] = module
            found_functions.add(item.name)
        elif item.node.type == 'impl_item':
            target = item.node.child_by_field_name('type')
            trait = item.node.child_by_field_name('trait')
            if target is None or target.text.decode() != type_name:
                continue
            body = item.node.child_by_field_name('body')
            if trait:
                trait_name = trait.text.decode()
                if trait_name in wanted_traits:
                    content[wanted_traits[trait_name]].append(textwrap.dedent(item.text))
                    edits.append((item.start, item.end, ''))
                    found_traits.add(trait_name)
                continue
            moved = {module: [] for module in plan}
            for method in items(src, body):
                if method.node.type == 'function_item' and method.name in wanted_methods:
                    module = wanted_methods[method.name]
                    moved[module].append(lift_visibility(src, method))
                    edits.append((method.start, method.end, ''))
                    found_methods.add(method.name)
            for module, methods in moved.items():
                if methods:
                    content[module].append(f'impl {type_name} {{\n' + '\n'.join(textwrap.indent(m, '    ') for m in methods) + '}\n')
    if found_methods != set(wanted_methods) or found_functions != set(wanted_functions) or found_traits != set(wanted_traits):
        raise RuntimeError(f'Missing extraction targets in {path}: methods={set(wanted_methods)-found_methods}, functions={set(wanted_functions)-found_functions}, traits={set(wanted_traits)-found_traits}')
    remaining = rewrite(src, edits).decode()
    prod_remaining = remaining
    for item in parse(remaining.encode()):
        if item.node.type == 'mod_item' and 'test' in item.prefix:
            prod_remaining = prod_remaining.replace(item.text, '')
    prod_names, test_names = identifiers(prod_remaining), identifiers(test_text)

    def external_lines(body, child=False, root=False):
        names = identifiers(body)
        lines = []
        for name, full, attr in imports:
            if root and name in public_imports:
                continue
            implicit = name in ('_', '*')
            if not implicit and name not in names:
                continue
            adjusted = full
            if child:
                if adjusted.startswith('super::'):
                    adjusted = 'super::' + adjusted
                elif adjusted.startswith('self::'):
                    adjusted = 'super::' + adjusted[6:]
            condition = attr
            if root and name not in prod_names and name in test_names and 'cfg(test)' not in condition:
                condition = '#[cfg(test)]\n' + condition
            # Trait imports can be needed without a named identifier. Clippy
            # removes them when they are actually unused in the built targets.
            line = (condition.strip() + '\n' if condition.strip() else '') + f'use {adjusted};'
            if line not in lines:
                lines.append(line)
        return lines

    root_imports = external_lines(prod_remaining + '\n' + test_text, root=True)
    for function, module in ownership.items():
        if function in prod_names:
            root_imports.append(f'use {module}::{function};')
        elif function in test_names:
            root_imports.append(f'#[cfg(test)]\nuse {module}::{function};')
    made = []
    for module, chunks in content.items():
        body = '\n'.join(chunks)
        needed = identifiers(body)
        local_lines = []
        for name in sorted(needed.intersection(declared)):
            owner = ownership.get(name)
            if owner == module:
                continue
            local_lines.append(f'use super::{owner}::{name};' if owner else f'use super::{name};')
        new = f'//! {plan[module]["doc"]}\n\n' + '\n'.join(external_lines(body, child=True) + local_lines) + '\n\n' + body
        parse(new.encode())
        dest = path.with_suffix('') / (module + '.rs')
        if dest.exists():
            raise RuntimeError(f'New module already exists: {dest}')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(new)
        made.append(dest)
    prefix = []
    for line in remaining.splitlines(keepends=True):
        if line.startswith('//!') or not line.strip():
            prefix.append(line)
        else:
            break
    at = len(''.join(prefix))
    injected = '\n'.join(f'mod {module};' for module in plan) + '\n\n' + '\n'.join(root_imports) + '\n\n'
    path.write_text(remaining[:at] + injected + remaining[at:])
    parse(path.read_bytes())
    made += extract_tests(path)
    return made


MINING = {
    'candidate': {
        'doc': 'Candidate construction, single-flight assembly, and bounded template caching.',
        'methods': ['live_candidate', 'candidate_for_key', 'assemble_for_key', 'assemble_fresh', 'generate_blocks', 'template_from_candidate', 'version_bits_for'],
        'functions': ['snapshot_for_selection', 'snapshot_entry_from_raw', 'generation_race', 'is_generation_race'],
    },
    'long_poll': {
        'doc': 'Generation publication and predicate-checked long-poll waits.',
        'methods': ['publish_generation', 'publish_generation_from', 'notify_shutdown', 'live_generation_key', 'ensure_published', 'wait_for_generation_change'],
        'functions': ['parse_long_poll_id'],
        'traits': ['MempoolSequenceWake'],
    },
    'submission': {
        'doc': 'Proposal and solved-block submission through the authoritative chainstate.',
        'methods': ['propose', 'submit'],
        'functions': ['map_apply_error'],
    },
    'control': {
        'doc': 'Mining control protocol projection over the node-owned coordinator.',
        'methods': ['mining_info_snapshot'],
        'functions': ['signet_info'],
        'traits': ['MiningControl'],
    },
}

SYNC = {
    'headers': {
        'doc': 'Header request ownership, locator construction, and inbound header admission.',
        'methods': ['drain_inbound_headers', 'refresh_active_peer_credit', 'request_headers_from_best_peer', 'send_getheaders', 'has_pending_getheaders', 'build_locator'],
    },
    'requests': {
        'doc': 'Budgeted body requests, prefix probes, and cold-front hedges.',
        'methods': ['send_prefix_probes', 'send_getdata_for_pending_blocks', 'send_cold_front_hedge'],
    },
    'peers': {
        'doc': 'Session reconciliation, useful-peer selection, and stalled-peer retirement.',
        'methods': ['on_peer_ready', 'reconcile_peer_sessions', 'sync_peer_selection', 'disconnect_window_staller', 'disconnect_timed_out_peer', 'select_and_evict_window_peer'],
        'functions': ['is_peer_fault', 'sync_peer_candidate', 'outranks', 'active_demonstrated_height', 'body_capability_height'],
    },
    'receive': {
        'doc': 'Bounded inbound body draining and exact staged-body admission.',
        'methods': ['drain_inbound_blocks', 'fill_inbound_block_chunk', 'indexed_applied_ancestry_tip', 'buffer_received_block_chunk'],
    },
    'branches': {
        'doc': 'Heavier-branch handoff and committed reorganization body retirement.',
        'methods': ['switch_branch_if_outweighed', 'retire_applied_reorg_body', 'outweighed_branch_target'],
    },
    'commit': {
        'doc': 'Ordered staged-block application, generation settlement, and expected-prefix caching.',
        'methods': ['apply_window_followed', 'note_fatal_settlement', 'apply_buffered_blocks', 'expected_apply_horizon', 'expected_block_hashes', 'populate_expected_apply_cache', 'drain_cached_expected_blocks', 'advance_expected_apply_cache', 'next_expected_block_hash', 'ensure_genesis_tip'],
        'functions': ['settle_window_failure', 'settle_window_success', 'restore_split'],
    },
    'telemetry': {
        'doc': 'Read-only synchronization progress and bounded-window metrics.',
        'methods': ['emit_sync_progress', 'record_sync_metrics', 'record_pending_sync_metrics'],
        'functions': ['metric_count'],
    },
}


def test_inventory(root):
    found = Counter()
    for path in root.rglob('*.rs'):
        src = path.read_bytes()
        tree = PARSER.parse(src)
        def walk(parent):
            for item in items(src, parent):
                if item.node.type == 'function_item' and item.test:
                    body = item.node.child_by_field_name('body')
                    digest = hashlib.sha256(re.sub(rb'\s+', b'', body.text)).hexdigest()
                    found[(item.name, digest)] += 1
                if item.node.type == 'mod_item':
                    body = item.node.child_by_field_name('body')
                    if body:
                        walk(body)
        walk(tree.root_node)
    return found


def validate(work, label, before, artifacts):
    # Native compiler suggestions are limited to the touched node files.
    command('cargo', '+1.95.0', 'fmt', '-p', 'bitcoin-rs-node', cwd=work)
    command('cargo', '+1.95.0', 'fix', '--locked', '-p', 'bitcoin-rs-node', '--all-targets', '--no-default-features', '--features', 'fjall,zmq', '--allow-dirty', '--allow-staged', cwd=work)
    command('cargo', '+1.95.0', 'fmt', '-p', 'bitcoin-rs-node', cwd=work)
    command('cargo', '+1.95.0', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--all-targets', '--no-default-features', '--features', 'fjall,zmq', '--', '-D', 'warnings', cwd=work)
    command('git', 'diff', '--check', cwd=work)
    after = test_inventory(work / 'crates/node/src')
    if after != before:
        raise RuntimeError(f'Unit-test body preservation failed: removed={list((before-after).elements())[:5]}, added={list((after-before).elements())[:5]}')
    command('cargo', '+1.95.0', 'test', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq', '--lib', label + '::', '--', '--test-threads=1', cwd=work)
    changed = command('git', 'diff', '--name-only', cwd=work, capture=True).splitlines()
    if any(not p.startswith('crates/node/src/') for p in changed):
        raise RuntimeError(f'Unexpected changes outside node source: {changed}')
    command('git', 'add', '--', 'crates/node/src', cwd=work)
    command('git', 'diff', '--cached', '--stat', cwd=work)
    (artifacts / (label + '.patch')).write_text(command('git', 'diff', '--cached', '--binary', cwd=work, capture=True))


def main():
    root = Path(os.environ['GITHUB_WORKSPACE'])
    artifacts = Path(os.environ['RUNNER_TEMP']) / 'node-split-results'
    artifacts.mkdir(exist_ok=True)
    command('git', 'fetch', 'origin', BASE, cwd=root)
    work = Path(os.environ['RUNNER_TEMP']) / 'node-split-candidate'
    command('git', 'worktree', 'add', '--detach', str(work), BASE, cwd=root)
    command('git', 'config', 'user.name', 'github-actions[bot]', cwd=work)
    command('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com', cwd=work)
    before = test_inventory(work / 'crates/node/src')
    embed = work / 'crates/node/src/embed.rs'
    text = embed.read_text()
    assert text.count(', clippy::unused_async_trait_impl') == 5
    embed.write_text(text.replace(', clippy::unused_async_trait_impl', ''))
    command('cargo', '+1.95.0', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--all-targets', '--no-default-features', '--features', 'fjall,zmq', '--', '-D', 'warnings', cwd=work)
    command('git', 'add', '--', 'crates/node/src/embed.rs', cwd=work)
    command('git', 'commit', '-m', 'fix(node): remove nonexistent embedding lint names', cwd=work)
    results = [{'group': 'embedding-lints', 'sha': command('git', 'rev-parse', 'HEAD', cwd=work, capture=True).strip()}]
    try:
        for label, typename, plan in [('mining', 'MiningCoordinator', MINING), ('sync', 'BlockSync', SYNC)]:
            split_implementation(work / f'crates/node/src/{label}.rs', typename, plan)
            validate(work, label, before, artifacts)
            command('git', 'commit', '-m', f'refactor(node): separate {label} responsibilities and contract tests', cwd=work)
            results.append({'group': label, 'sha': command('git', 'rev-parse', 'HEAD', cwd=work, capture=True).strip()})
    finally:
        (artifacts / 'results.json').write_text(json.dumps(results, indent=2))
        command('git', 'add', '--', 'crates/node/src', cwd=work)
        (artifacts / 'candidate.patch').write_text(command('git', 'diff', '--cached', '--binary', cwd=work, capture=True))
        command('git', 'archive', '--format=tar.gz', '--output=' + str(artifacts / 'last-validated-source.tar.gz'), 'HEAD', cwd=work)
        command('git', 'log', '--oneline', '-4', cwd=work)
        print('VALIDATED_COMMITS', json.dumps(results), flush=True)
    command('git', 'bundle', 'create', str(artifacts / 'validated.bundle'), 'HEAD', cwd=work)


if __name__ == '__main__':
    main()
