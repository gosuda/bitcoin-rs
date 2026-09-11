"""One-shot, pinned-source refactoring workbench; never included in product PRs."""
import collections
import json
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from tree_sitter import Language, Parser
import tree_sitter_rust

PARSER = Parser(Language(tree_sitter_rust.language()))
ROOT = Path('crates/node/src')
MIGRATIONS = {}
CHANGED = set()

def parse(text):
    root = PARSER.parse(text.encode()).root_node
    if root.has_error:
        raise RuntimeError('Rust parse error: ' + text[:200])
    return root

def txt(source, node):
    return source.encode()[node.start_byte:node.end_byte].decode()

def items(source, root=None):
    root = root or parse(source)
    result, pending = [], root.start_byte
    if root.type == 'declaration_list':
        pending += 1
    for node in root.named_children:
        if node.type in ('line_comment', 'block_comment', 'attribute_item', 'inner_attribute_item'):
            continue
        raw = source.encode()[pending:node.end_byte].decode()
        raw = re.sub(r'(?m)^\s*//!.*\n?', '', raw).strip() + '\n'
        result.append((node, raw))
        pending = node.end_byte
    return result

def name_of(source, node):
    name = node.child_by_field_name('name') or node.child_by_field_name('type')
    if name is None:
        return ''
    return re.split(r'[<\s]', txt(source, name), 1)[0]

def is_test(raw):
    return bool(re.search(r'#\[cfg\(test\)\]', raw))

def use_leaves(source, node, prefix=''):
    if node.type == 'use_declaration':
        return use_leaves(source, node.child_by_field_name('argument'), prefix)
    if node.type == 'scoped_use_list':
        path = node.child_by_field_name('path')
        more = txt(source, path) if path else ''
        return use_leaves(source, node.child_by_field_name('list'), prefix + more + ('::' if more else ''))
    if node.type == 'use_list':
        return [leaf for child in node.named_children for leaf in use_leaves(source, child, prefix)]
    if node.type == 'use_as_clause':
        path = txt(source, node.child_by_field_name('path'))
        alias = txt(source, node.child_by_field_name('alias'))
        return [(prefix + path, alias)]
    value = txt(source, node)
    if value == 'self':
        return [(prefix.removesuffix('::'), None)]
    return [(prefix + value, None)]

def replace_paths(text, mapping):
    for old, new in sorted(mapping.items(), key=lambda x: -len(x[0])):
        text = re.sub(r'(?<![\w])' + re.escape(old) + r'(?![\w])', lambda _: new, text)
    return text

def canonical_imports(source, owner, local_mods):
    output = []
    for node, raw in items(source):
        if node.type != 'use_declaration':
            continue
        prefix = raw[:raw.index('use ')]
        prefix = re.sub(r'\bpub(?:\([^)]*\))?\s*$', '', prefix)
        for path, alias in use_leaves(source, node):
            if path.startswith('super::'):
                path = 'crate::' + '::'.join(owner.split('::')[:-1]) + '::' + path[7:]
            elif path.startswith('self::'):
                path = 'crate::' + owner + '::' + path[6:]
            elif path.split('::')[0] in local_mods:
                path = 'crate::' + owner + '::' + path
            output.append(prefix + 'use ' + path + ((' as ' + alias) if alias else '') + ';\n')
    return '\n'.join(output)

def widen(raw, root_scope=False):
    """Only owner-local visibility; never add visibility to enum/trait fields."""
    root = parse(raw)
    edits = []
    for node in root.named_children:
        if node.type in ('function_item', 'struct_item', 'enum_item', 'type_item', 'const_item', 'static_item', 'trait_item'):
            if not root_scope and not any(c.type == 'visibility_modifier' for c in node.children):
                edits.append((node.start_byte, 'pub(super) '))
        if node.type == 'struct_item':
            body = node.child_by_field_name('body')
            if body and body.type == 'field_declaration_list' and not root_scope:
                for field in body.named_children:
                    if field.type == 'field_declaration' and not any(c.type == 'visibility_modifier' for c in field.children):
                        edits.append((field.start_byte, 'pub(super) '))
        if node.type == 'impl_item' and node.child_by_field_name('trait') is None and not root_scope:
            body = node.child_by_field_name('body')
            for method in body.named_children:
                if method.type == 'function_item' and not any(c.type == 'visibility_modifier' for c in method.children):
                    edits.append((method.start_byte, 'pub(super) '))
    data = raw.encode()
    for offset, value in sorted(edits, reverse=True):
        data = data[:offset] + value.encode() + data[offset:]
    return data.decode()

def write(path, text):
    text = text.rstrip() + '\n'
    parse(text) if path.suffix == '.rs' else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    CHANGED.add(path)

def add_map(old, new):
    MIGRATIONS['crate::' + old] = 'crate::' + new
    MIGRATIONS['bitcoin_rs_node::' + old] = 'bitcoin_rs_node::' + new


def split_owner(old, new, groups, method_groups=None):
    """Partition complete AST items/impl methods, retaining bodies and attributes."""
    method_groups = method_groups or {}
    old_path, new_path = ROOT / (old + '.rs'), ROOT / (new + '.rs')
    source = old_path.read_text()
    parsed = items(source)
    owner = new.replace('/', '::')
    old_owner = old.replace('/', '::')
    local_mods = {name_of(source, n) for n, _ in parsed if n.type == 'mod_item'}
    imports = canonical_imports(source, owner, local_mods)
    buckets = collections.defaultdict(list)
    defined = {}
    tests = []
    declarations = []
    for node, raw in parsed:
        if node.type == 'use_declaration':
            continue
        name = name_of(source, node)
        if node.type == 'mod_item':
            body = node.child_by_field_name('body')
            if body is not None and is_test(raw):
                tests.append((name, textwrap.dedent(txt(source, body)[1:-1])))
                prefix = raw[:raw.index('mod ')]
                declarations.append(prefix + 'mod ' + name + ';\n')
            else:
                declarations.append(raw)
            continue
        group = groups.get(name, '')
        if is_test(raw):
            group = 'fixtures'
        if node.type == 'impl_item' and name in method_groups and node.child_by_field_name('trait') is None:
            body = node.child_by_field_name('body')
            methods = collections.defaultdict(list)
            for method, method_raw in items(source, body):
                key = method_groups[name].get(name_of(source, method), group)
                methods[key].append(method_raw)
            header = source.encode()[node.start_byte:body.start_byte + 1].decode()
            for key, members in methods.items():
                buckets[key].append(header + '\n' + '\n'.join(members) + '\n}\n')
        else:
            buckets[group].append(raw)
        if node.type not in ('impl_item', 'macro_invocation') and name:
            defined[name] = group
            if group:
                add_map(old_owner + '::' + name, owner + '::' + group + '::' + name)
    # Existing root error/utility submodules move with their actual owner.
    if old != new:
        if (ROOT / old).exists():
            (ROOT / old).rename(ROOT / new)
        old_path.unlink()
        add_map(old_owner, owner)
    all_groups = sorted(k for k in buckets if k)
    doc = '\n'.join(line for line in source.splitlines() if line.startswith('//!'))
    for group, members in buckets.items():
        content = '\n'.join(widen(m, root_scope=(group == '')) for m in members)
        # Resolve sibling dependencies directly; no public forwarding exports.
        links = []
        identifiers = set(re.findall(r'\b[A-Za-z_][A-Za-z_0-9]*\b', content))
        for symbol, owning_group in sorted(defined.items()):
            if owning_group == group or symbol not in identifiers:
                continue
            path = (('super::' + owning_group) if group else owning_group) if owning_group else 'super'
            guard = '#[cfg(test)]\n' if owning_group == 'fixtures' and group != 'fixtures' else ''
            links.append(guard + 'use ' + path + '::' + symbol + ';')
        if group == '':
            mods = []
            for child in all_groups:
                guard = '#[cfg(test)]\n' if child == 'fixtures' else ''
                visibility = 'pub ' if any(re.search(r'(?m)^pub (?:fn|struct|enum|const|type)\b', m) for m in buckets[child]) else ''
                mods.append(guard + '/// ' + child.replace('_', ' ').capitalize() + ' owned by this subsystem.\n' + visibility + 'mod ' + child + ';')
            text = doc + '\n\n' + '\n'.join(declarations + mods) + '\n' + imports + '\n' + '\n'.join(links) + '\n\n' + content
            write(new_path, text)
        else:
            text = '//! ' + group.replace('_', ' ').capitalize() + ' for ' + owner + '.\n\n' + imports + '\n' + '\n'.join(links) + '\n\n' + content
            write(ROOT / new / (group + '.rs'), text)
    # Tests have their own dependency imports, not production facade aliases.
    for name, body in tests:
        links = ['use super::*;']
        for group in all_groups:
            links.append('use super::' + group + '::*;')
        body = body.replace('use super::*;', '')
        write(ROOT / new / (name + '.rs'), imports + '\n' + '\n'.join(links) + '\n' + body)
    return source


def migrate_paths():
    for path in Path('.').rglob('*'):
        if not path.is_file() or '.git' in path.parts or '.node-owner-workbench' in path.parts or 'target' in path.parts:
            continue
        if path.suffix not in ('.rs', '.md', '.toml', '.sh', '.yml', '.yaml'):
            continue
        text = path.read_text()
        if path.suffix == '.rs':
            changes = []
            def visit(node):
                if node.type == 'use_declaration':
                    old = txt(text, node)
                    visibility = next((txt(text, c) + ' ' for c in node.children if c.type == 'visibility_modifier'), '')
                    leaves = use_leaves(text, node)
                    new_leaves = [(replace_paths(p, MIGRATIONS), a) for p, a in leaves]
                    if new_leaves != leaves:
                        new = '\n'.join(visibility + 'use ' + p + ((' as ' + a) if a else '') + ';' for p, a in new_leaves)
                        changes.append((node.start_byte, node.end_byte, new))
                    return
                for child in node.named_children:
                    visit(child)
            visit(parse(text))
            data = text.encode()
            for start, end, value in sorted(changes, reverse=True):
                data = data[:start] + value.encode() + data[end:]
            text = data.decode()
        text = replace_paths(text, MIGRATIONS)
        if text != path.read_text():
            write(path, text)


def test_partition(path):
    source = path.read_text()
    if source.count('\n') <= 800:
        return
    root = parse(source)
    parsed = items(source, root)
    helpers, tests, imports = [], [], []
    for node, raw in parsed:
        if node.type == 'use_declaration':
            imports.append(raw)
        elif node.type == 'function_item' and re.search(r'#\[(?:test|test_case(?:\(|\]))', raw):
            tests.append((name_of(source, node), raw))
        else:
            helpers.append(raw)
    if not tests:
        return
    categories = ['bip30','bip34','bip68','witness','coinbase','assume_valid','disconnect','reorg','window','cache','staging','fanout','peer','headers','checkpoint','journal','rollback','query','script','budget','storage','utxo','generation']
    buckets = collections.defaultdict(list)
    for name, raw in tests:
        key = next((c for c in categories if c in name), 'contracts')
        buckets[key].append(raw)
    declarations = []
    for key, members in sorted(buckets.items()):
        pages, page, lines = [], [], 0
        for raw in members:
            if page and lines + raw.count('\n') > 700:
                pages.append(page)
                page, lines = [], 0
            page.append(raw)
            lines += raw.count('\n')
        if page:
            pages.append(page)
        for index, page in enumerate(pages):
            name = key + (f'_{index + 1}' if len(pages) > 1 else '')
            declarations.append('mod ' + name + ';')
            # Descendants can use private fixture fields owned by the parent.
            body = '\n'.join(page)
            body = re.sub(r'\bsuper::', 'super::super::', body)
            write(path.with_suffix('') / (name + '.rs'), 'use super::*;\n\n' + body)
    write(path, '\n'.join(imports + helpers + declarations))


def extract_inline_tests(path):
    source = path.read_text()
    edits = []
    for node, raw in items(source):
        if node.type != 'mod_item' or node.child_by_field_name('body') is None or not is_test(raw):
            continue
        name = name_of(source, node)
        body = textwrap.dedent(txt(source, node.child_by_field_name('body'))[1:-1])
        write(path.with_suffix('') / (name + '.rs'), body)
        edits.append((node.start_byte, node.end_byte, 'mod ' + name + ';'))
    data = source.encode()
    for start, end, value in sorted(edits, reverse=True):
        data = data[:start] + value.encode() + data[end:]
    if edits:
        write(path, data.decode())


def phase_chainstate():
    groups = {}
    def assign(group, names):
        groups.update(dict.fromkeys(names.split(), group))
    assign('admission', 'ApplyAdmission TransitionLock begin_chain_transition ChainChangeProof PruneAuthority PruneGuard')
    assign('assume_valid', 'AssumeValidGate')
    assign('disconnect', 'DisconnectPlan plan_disconnect disconnect_block_admitted')
    assign('publication', 'AppliedPublication begin_applied_publication tx_count_delta_for advance_chain_tx_count rewind_chain_tx_count')
    assign('connect', 'ApplyIntent ApplyFinish apply_block_with_serialized_admitted apply_block_inner apply_committed_block_admitted apply_block_admitted')
    assign('window', 'SCRIPT_BATCH_WINDOW SCRIPT_BATCH_MAX_BYTES window_len apply_window_admitted invalidate_failed_subtree WindowApplyError WindowApplyDisposition prove_window')
    assign('failure', 'is_permanent_apply_error')
    assign('preparation', 'BlockValidationContext Bip68Context BlockValidationProof ProvenApply PreparedApply ByteEquality bytes_are_block parse_block_for_apply block_txids prepare_apply')
    assign('headers', 'compact_to_target compact_is_met_by applied_predecessor check_unseen_header_timestamp applied_header_tip check_pow_limit_and_continuity apply_nbits_error compute_verify_flags')
    assign('transactions', 'BlockTxPlan WitnessPresence plan_block_transactions run_non_script_checks_only verify_block_transactions')
    assign('prevouts', 'ResolvedUtxoView resolve_block_prevouts BlockLocalUtxoView')
    assign('rules', 'COINBASE_MATURITY BIP68_DISABLE_FLAG BIP68_TYPE_FLAG BIP68_MASK BIP68_TIME_GRANULARITY_SECONDS BIP34_IMPLIES_BIP30_LIMIT LOCAL_OVERLAY_TXID_SET_THRESHOLD check_coinbase_maturity check_coinbase_maturity_with_tx_plan check_coinbase_input_maturity check_bip68_sequence_locks bip68_prevout_mtp check_bip30_and_bip34 should_scan_bip30_duplicates map_block_change_error')
    split_owner('apply', 'chainstate', groups)
    lib = ROOT / 'lib.rs'
    text = lib.read_text().replace('pub mod apply;', 'pub mod chainstate;')
    text = re.sub(r'pub use apply::\{.*?\};\n', '', text, flags=re.S)
    write(lib, text)
    for symbol in 'ChainTransition Chainstate ChainstateSnapshot ConnectOutcome DisconnectOutcome'.split():
        add_map(symbol, 'chainstate::' + symbol)
    for symbol in ['ApplyError', 'DisconnectError']:
        add_map(symbol, 'chainstate::error::' + symbol)
    for symbol in ['DisconnectPhase', 'KvUndoStore', 'UndoStore']:
        MIGRATIONS['crate::apply::' + symbol] = 'bitcoin_rs_storage::' + symbol
        MIGRATIONS['crate::chainstate::' + symbol] = 'bitcoin_rs_storage::' + symbol
    migrate_paths()
    for path in (ROOT / 'chainstate').rglob('*.rs'):
        if path.name.endswith('tests.rs'):
            test_partition(path)


def phase_sync():
    groups = {}
    def assign(group, names):
        groups.update(dict.fromkeys(names.split(), group))
    assign('peers', 'is_peer_fault sync_peer_candidate outranks active_demonstrated_height body_capability_height')
    assign('application', 'settle_window_failure settle_window_success restore_split')
    assign('telemetry', 'metric_count')
    methods = {}
    def methods_for(group, names):
        methods.update(dict.fromkeys(names.split(), group))
    methods_for('headers', 'drain_inbound_headers request_headers_from_best_peer send_getheaders has_pending_getheaders build_locator ensure_genesis_tip')
    methods_for('peers', 'on_peer_ready reconcile_peer_sessions refresh_active_peer_credit sync_peer_selection send_prefix_probes send_cold_front_hedge disconnect_window_staller disconnect_timed_out_peer select_and_evict_window_peer')
    methods_for('download', 'send_getdata_for_pending_blocks')
    methods_for('staging', 'drain_inbound_blocks fill_inbound_block_chunk indexed_applied_ancestry_tip buffer_received_block_chunk')
    methods_for('branch', 'switch_branch_if_outweighed retire_applied_reorg_body outweighed_branch_target')
    methods_for('application', 'apply_window_followed note_fatal_settlement apply_buffered_blocks')
    methods_for('expected', 'expected_apply_horizon expected_block_hashes populate_expected_apply_cache drain_cached_expected_blocks advance_expected_apply_cache next_expected_block_hash')
    methods_for('telemetry', 'emit_sync_progress record_sync_metrics record_pending_sync_metrics')
    split_owner('sync', 'block_sync', groups, {'BlockSync': methods})
    lib = ROOT / 'lib.rs'
    text = lib.read_text().replace('pub mod sync;', 'pub mod block_sync;').replace('pub use sync::BlockSync;\n', '')
    write(lib, text)
    add_map('BlockSync', 'block_sync::BlockSync')
    for symbol in ['SyncBudget', 'default_sync_budget']:
        MIGRATIONS['crate::sync::' + symbol] = 'bitcoin_rs_p2p::download_window::' + symbol
        MIGRATIONS['bitcoin_rs_node::sync::' + symbol] = 'bitcoin_rs_p2p::download_window::' + symbol
        MIGRATIONS['crate::block_sync::' + symbol] = 'bitcoin_rs_p2p::download_window::' + symbol
        MIGRATIONS['bitcoin_rs_node::block_sync::' + symbol] = 'bitcoin_rs_p2p::download_window::' + symbol
    migrate_paths()
    for path in list((ROOT / 'block_sync').rglob('*.rs')):
        extract_inline_tests(path)
    for path in list((ROOT / 'block_sync').rglob('*.rs')):
        if 'tests' in path.stem:
            test_partition(path)


def main():
    phase = sys.argv[1]
    before = sum(p.read_text().count('#[test]') for p in ROOT.rglob('*.rs'))
    globals()['phase_' + phase]()
    after = sum(p.read_text().count('#[test]') for p in ROOT.rglob('*.rs'))
    if before != after:
        raise RuntimeError(f'test inventory changed: {before} -> {after}')
    subprocess.run(['rustfmt', '--edition', '2024', *[str(p) for p in CHANGED if p.suffix == '.rs' and p.exists()]], check=True)
    print(json.dumps({'phase': phase, 'tests_before': before, 'tests_after': after, 'changed': sorted(str(p) for p in CHANGED)}, indent=2))

if __name__ == '__main__':
    main()
