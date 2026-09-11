"""Native-validated responsibility cuts. Temporary workbench, never product source."""
from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
import base64
import importlib
import json
import os
import re
import subprocess
import sys
import textwrap
import traceback

import refactor as r
c = importlib.import_module('continue')
BASE = 'c4dd58b93c180f55b0be98cf6499cb8678756445'
OLD_MINING = 'f92f3e6674bccc916c52f9a0d638241d7355eed1'
PREFIX = 'refactor/node-split-c4dd58-'
r.BASE = BASE
_real_identifiers = c.syntax_identifiers
# Method lookup needs trait imports even when the trait's name is not written
# in a function body. The compiler, not a lexical guess, removes unused ones.
IMPLICIT_TRAITS = {'Read', 'Write', 'Seek', 'BufRead', 'Digest', 'Context', 'AsFd',
                   'KvStore', 'KvSnapshot', 'WriteBatch', 'ConsensusEncode', 'UtxoView',
                   'SpentOutputLookup', 'Visit', 'Visitor', 'BlockSource', 'IndexReader',
                   'TxIndexSnapshot', 'BlockBodyStore', 'BlockBodyReader'}
r.identifiers = lambda text: _real_identifiers(text) | IMPLICIT_TRAITS


def spec(doc, methods='', functions='', traits=''):
    return dict(doc=doc, methods=methods.split(), functions=functions.split(), traits=traits.split())


APPLY = {
 'connect': spec('Validated block connection and its ordered persistence/publication transaction.',
     functions='apply_block_inner apply_committed_block_admitted apply_block_admitted apply_block_with_serialized_admitted applied_predecessor applied_header_tip map_block_change_error'),
 'disconnect': spec('Preflighted tip disconnection and the durable rollback-marker transaction.',
     functions='plan_disconnect disconnect_block_admitted'),
 'prepare': spec('Exact serialized-body validation, transaction planning, and resolved prevout preparation.',
     functions='bytes_are_block parse_block_for_apply prepare_apply plan_block_transactions resolve_block_prevouts run_non_script_checks_only verify_block_transactions'),
 'contextual': spec('Contextual consensus checks against the admitted chain and resolved coins.',
     functions='compact_to_target compact_is_met_by check_unseen_header_timestamp check_coinbase_maturity_with_tx_plan check_coinbase_input_maturity check_bip68_sequence_locks bip68_prevout_mtp check_bip30_and_bip34 should_scan_bip30_duplicates check_pow_limit_and_continuity apply_nbits_error compute_verify_flags'),
 'window': spec('Bounded script-proof windows, ordered prefix commits, and failure disposition.',
     functions='apply_window_admitted invalidate_failed_subtree is_permanent_apply_error prove_window'),
 'publication': spec('Coherent applied-tip and chain-transaction-count publication.',
     functions='begin_applied_publication tx_count_delta_for advance_chain_tx_count rewind_chain_tx_count'),
 'entrypoints': spec('Chainstate entry points over the single admitted transition capability.',
     methods='snapshot checkpoint apply_block apply_block_with_serialized replay_local_block disconnect_block apply_window validate_block'),
}
QUERY = {
 'query_snapshot': spec('Query health, exact watermark gating, and coherent progress snapshots.',
     methods='query_health require_enabled with_snapshot index_progress_for'),
 'query_transaction': spec('Budgeted, hash-verified transaction and byte-position resolution.',
     methods='resolve_hash_at_height hash_at_height resolve_block resolve_block_body_bytes verify_block validated_positions resolve_positioned_transaction transaction_from_full_block transaction_for locate_transaction_for outpoint_value_for'),
 'query_script': spec('Budgeted script history, spending, and authoritative live-output composition.',
     methods='scan_funding_rows scan_spending_rows scan_live_rows collect_funding_outputs funding_outputs_for spender_for spending_input history_snapshot_for unspent_outputs_for'),
 'query_protocol': spec('RPC query projection over the snapshot-gated query engine.',
     traits='TxIndexQuery ScriptIndexQuery'),
}
WORKER = {
 'reconciliation': spec('Index reconciliation state machine and supplied chain-position decisions.',
     methods='run reconcile_once reconcile_pass reconcile_pending capture_target_watermarks rollback_selection forward_selection watermark_is_on_target_chain rollback_depth_for'),
 'catch_up': spec('Bounded body-reader sessions, parallel preparation, and ordered batch admission.',
     methods='collect_target_chain catch_up_to prepare_and_admit_chunk finish_catch_up'),
 'rollback': spec('Capability rollback, selective rebuilding, live seeding, and recovery evidence.',
     methods='seed_live_from_utxo reset_for_rebuild report_index_ahead rollback_one load_body live_anchor',
     functions='index_ahead_capability_label'),
 'cursor': spec('Fenced row/cursor commits and retained forward-batch settlement.',
     methods='persist_chain_cursor sync_and_commit cursor_for_result commit_pending'),
 'startup': spec('Supervised index backend opening, failure publication, and worker handoff.',
     functions='run_worker_with_open fail_worker publish_lifecycle open_and_run open_tx_index_with_timeout open_tx_index_on_worker open_tx_index_store_on_worker'),
}
WORKER_LIFECYCLE = {
 'lifecycle': spec('Process-owned worker spawning, joining, and explicit abandonment.',
     methods='spawn spawn_with_open is_finished join detach poison_namespace', traits='Drop'),
}
JOURNAL = {
 'open': spec('Journal initialization and recovery of its exact durable append frontier.',
     methods='open initialize restore recover_active_segment'),
 'append': spec('Ordered journal append, partial-write repair, and bounded segment rotation.',
     methods='append next_append_frontier append_record_bytes fail_append maybe_rotate'),
 'durability': spec('Undo flush, segment sync, and atomic durable-head publication in dependency order.',
     methods='advance_durability publish_head_now write_head_atomic flush_to advance_durability_upto try_advance_durability_upto'),
 'retention': spec('Lag backpressure, journal retention, checkpoint compaction, and writer resumption.',
     methods='configure prepare_for_apply flush_due requires_compaction record_lag_metrics record_size_metric journal_size_bytes freeze compact_to_checkpoint resume'),
 'rewind': spec('Authenticated journal fork cursors and fail-closed truncation/rewrite.',
     methods='rewind_to committed_cursor_at truncate_after invalidate_generation', functions='scan_fork_cursor'),
 'failpoints': spec('Typed injection points at the writer\'s persistence boundaries.',
     methods='fail_segment_append fail_segment_sync fail_storage_flush fail_rewind_truncate fail_head_temp_write fail_head_temp_sync fail_head_rename fail_head_dir_sync failpoint inject_failpoint'),
}
REORG = {
 'bodies': spec('Hash-bound branch-body loading and bounded preflight materialization.',
     functions='load_branch_bodies load_available_branch_prefix branch_nodes load_branch_body decode_branch_body validate_branch_body'),
 'execution': spec('Streamed disconnect/connect execution and mempool reconsideration under one transition.',
     functions='preflight_disconnect_bodies applied_tip_height execute_streamed_plan reconsider_disconnected_transactions current_reorg_plan'),
 'settlement': spec('Generation settlement and checkpoint debt after a coherent branch change.',
     functions='settle_disconnect_debt settle_reorg_transition'),
}
GROUPS = [
 ('mining', 'mining.rs', [('MiningCoordinator', r.MINING)], ['mining::'], None),
 ('sync', 'sync.rs', [('BlockSync', r.SYNC)], ['sync::'], None),
 ('checkpoint', 'checkpoint.rs', [('__Free', c.CHECKPOINT)], ['checkpoint::'], None),
 ('storage-footprint', 'storage_footprint.rs', [('__Free', c.FOOTPRINT)], ['storage_footprint::'], None),
 ('recovery-evidence', 'recovery_evidence.rs', [('RecoveryReporter', c.RECOVERY)], ['recovery_evidence::'], None),
 ('apply', 'apply.rs', [('Chainstate', APPLY)], ['apply::'], None),
 ('txindex', 'txindex_worker.rs', [('TxIndexQueryEngine', QUERY), ('Worker', WORKER), ('TxIndexWorker', WORKER_LIFECYCLE)], ['txindex_worker::'], None),
 ('journal', 'chainstate_journal/writer.rs', [('JournalWriter<S>', JOURNAL)], ['chainstate_journal::'], None),
 ('reorg', 'reorg.rs', [('__Free', REORG)], ['reorg::', 'apply::'], 'apply'),
 ('import', 'import.rs', [], ['import::'], None),
 ('tx-ingress', 'tx_ingress.rs', [], ['tx_ingress::'], None),
]


def git(work, *args):
    return r.command('git', *args, cwd=work, capture=True).strip()


def inventory(root):
    # Preserve exact Rust leaf tokens, including whitespace inside string
    # literals, rather than normalizing text inside literal values.
    result = Counter()
    for p in root.rglob('*.rs'):
        src = p.read_bytes()
        tree = r.PARSER.parse(src)
        stack = [tree.root_node]
        while stack:
            parent = stack.pop()
            for item in r.items(src, parent):
                if item.node.type == 'function_item' and item.test:
                    body = item.node.child_by_field_name('body').text.decode()
                    for old, new in [('segment_name_pub', 'segment_name'), ('parse_segment_name_pub', 'parse_segment_name')]:
                        body = re.sub(r'\b' + old + r'\b', new, body)
                    # rustfmt changes layout but not the token sequence.
                    tokens = []
                    queue = [r.PARSER.parse(body.encode()).root_node]
                    while queue:
                        node = queue.pop()
                        if node.type in ('line_comment', 'block_comment'):
                            continue
                        if not node.children or node.type in ('string_literal', 'raw_string_literal', 'char_literal'):
                            tokens.append((node.type, node.text.decode()))
                        else:
                            queue.extend(reversed(node.children))
                    result[(item.name, tuple(tokens))] += 1
                if item.node.type == 'mod_item':
                    body = item.node.child_by_field_name('body')
                    if body:
                        stack.append(body)
    return result


def topic(name):
    for category, keys in [
        ('validation', ['bip', 'pow', 'coinbase', 'script', 'witness', 'merkle', 'prevout', 'duplicate', 'timestamp', 'sigop']),
        ('transitions', ['disconnect', 'reorg', 'branch', 'tip', 'generation', 'transition', 'admission', 'window']),
        ('persistence', ['persist', 'checkpoint', 'restore', 'resume', 'recovery', 'store', 'marker', 'durab', 'flush', 'retention']),
        ('notifications', ['publish', 'zmq', 'notify', 'sequence', 'mining', 'fee']),
    ]:
        if any(key in name for key in keys):
            return category
    return 'behavior'


def partition_tests(path):
    src = path.read_bytes()
    if len(src.splitlines()) <= 550:
        return []
    entries = r.parse(src)
    groups = defaultdict(list)
    for item in entries:
        if item.node.type == 'function_item' and item.test and 'super::super::' not in item.text:
            groups[topic(item.name)].append(item)
    edits, made, declarations = [], [], []
    for category, tests in groups.items():
        chunks, chunk, size = [], [], 0
        for item in tests:
            length = len(item.text.splitlines())
            if chunk and size + length > 450:
                chunks.append(chunk)
                chunk, size = [], 0
            chunk.append(item)
            size += length
        if chunk:
            chunks.append(chunk)
        for number, selected in enumerate(chunks, 1):
            name = f'{category}_{number}'
            dest = path.with_suffix('') / (name + '.rs')
            if dest.exists():
                raise RuntimeError(f'Test destination exists: {dest}')
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text('use super::*;\n\n' + '\n'.join(item.text for item in selected))
            made.append(dest)
            declarations.append(f'#[cfg(test)]\nmod {name};\n')
            edits.extend((item.start, item.end, '') for item in selected)
    path.write_bytes(r.rewrite(src, edits) + ('\n' + '\n'.join(declarations)).encode())
    return made


def narrowed_helpers(work, path, names):
    text = path.read_text()
    for name in names:
        for other in (work / 'crates/node/src').rglob('*.rs'):
            if other == path:
                continue
            if name in _real_identifiers(other.read_text()):
                raise RuntimeError(f'Helper requires a caller migration: {name} in {other}')
        old = 'pub(crate) fn ' + name
        if text.count(old) != 1:
            raise RuntimeError(f'Unexpected helper declaration: {name}')
        text = text.replace(old, 'fn ' + name)
    path.write_text(text)


def available_plan(path, type_name, plan):
    # Concurrent upstream work may have deleted a helper or moved its ownership.
    # Never reintroduce it. Report absent targets and retain every current body.
    src = path.read_bytes()
    entries = r.parse(src)
    functions = {i.name for i in entries if i.node.type == 'function_item'}
    methods, traits = set(), set()
    for item in entries:
        if item.node.type != 'impl_item':
            continue
        target = item.node.child_by_field_name('type')
        if target is None or target.text.decode() != type_name:
            continue
        trait = item.node.child_by_field_name('trait')
        if trait:
            traits.add(trait.text.decode())
        else:
            methods.update(i.name for i in r.items(src, item.node.child_by_field_name('body')) if i.node.type == 'function_item')
    current = {}
    for module, definition in plan.items():
        selected = dict(definition)
        for field, found in [('functions', functions), ('methods', methods), ('traits', traits)]:
            old = selected.get(field, [])
            missing = set(old) - found
            if missing:
                print('UPSTREAM_REMOVED', path.name, field, sorted(missing), flush=True)
            selected[field] = [name for name in old if name in found]
        if any(selected[field] for field in ['functions', 'methods', 'traits']):
            current[module] = selected
    return current


def normalize_imports(path):
    # Give removable anonymous trait imports their actual names so rustc's
    # machine-applicable unused-import fix can remove them before strict Clippy.
    text = path.read_text()
    text = re.sub(r'^(use [^;\n]+) as _;', r'\1;', text, flags=re.M)
    path.write_text(text)


def transform(work, label, relative, stages):
    path = work / 'crates/node/src' / relative
    made, extra = [], []
    if label == 'recovery-evidence':
        narrowed_helpers(work, path, ['write_bounded', 'read_bounded', 'checkpoint_fallback_warning', 'index_ahead_warning'])
    if label == 'apply':
        narrowed_helpers(work, path, ['disconnect_block_admitted', 'apply_block_with_serialized_admitted'])
        text = path.read_text()
        for name in ['bytes_are_block', 'is_permanent_apply_error']:
            text = text.replace('pub(crate) fn ' + name, 'fn ' + name)
        path.write_text(text)
    if label == 'journal':
        src = path.read_bytes()
        obsolete = [i for i in r.parse(src) if i.node.type == 'function_item' and i.name in ('segment_name_pub', 'parse_segment_name_pub')]
        if len(obsolete) != 2:
            raise RuntimeError('Expected exactly two superseded journal forwarding wrappers')
        text = r.rewrite(src, [(i.start, i.end, '') for i in obsolete]).decode()
        for name in ['segment_name', 'parse_segment_name']:
            text = text.replace('fn ' + name + '(', 'pub(crate) fn ' + name + '(')
        path.write_text(text)
        for other in (work / 'crates/node/src').rglob('*.rs'):
            text = other.read_text()
            updated = re.sub(r'\bparse_segment_name_pub\b', 'parse_segment_name', text)
            updated = re.sub(r'\bsegment_name_pub\b', 'segment_name', updated)
            if updated != text:
                other.write_text(updated)
                extra.append(other)
    for type_name, plan in stages:
        current = available_plan(path, type_name, plan)
        made += r.split_implementation(path, type_name, current)
    if not stages:
        made += r.extract_tests(path)
    if label == 'apply':
        for module, name in [('prepare', 'bytes_are_block'), ('window', 'is_permanent_apply_error')]:
            dest = path.with_suffix('') / (module + '.rs')
            text = dest.read_text().replace('pub(super) fn ' + name, 'pub(crate) fn ' + name)
            dest.write_text(text)
            text = path.read_text().replace('mod ' + module + ';', 'pub(crate) mod ' + module + ';')
            path.write_text(text)
            for other in (work / 'crates/node/src').rglob('*.rs'):
                if other == path or other in made:
                    continue
                text = other.read_text()
                updated = text.replace('crate::apply::' + name, 'crate::apply::' + module + '::' + name)
                if updated != text:
                    other.write_text(updated)
                    extra.append(other)
    if label == 'journal':
        for dest in made:
            text = dest.read_text().replace('impl JournalWriter<S> {', 'impl<S: KvStore> JournalWriter<S> {')
            dest.write_text(text)
    # Split contract tests by behavior. Shared fixtures stay private to their
    # original test namespace, so permanent tests retain access without any
    # new production API or test-only production forwarding function.
    test_roots = [p for p in made if 'test' in p.stem]
    if label in ('checkpoint', 'reorg'):
        test_roots.append(path.with_suffix('') / 'tests.rs')
    for test_path in list(dict.fromkeys(test_roots)):
        if test_path.exists():
            made += partition_tests(test_path)
            extra.append(test_path)
    # The apply fixture collection is itself large: move private fixture
    # functions by purpose, retaining the few fixture exports sibling tests use.
    if label == 'apply':
        fixture = path.with_suffix('') / 'consensus_rule_tests.rs'
        if fixture.exists():
            plans = {}
            for item in r.parse(fixture.read_bytes()):
                if item.node.type != 'function_item' or item.test:
                    continue
                if any(n.type == 'visibility_modifier' for n in item.node.children):
                    continue
                key = 'fixtures_' + topic(item.name)
                plans.setdefault(key, spec('Shared contract-test fixture construction.'))['functions'].append(item.name)
            made += r.split_implementation(fixture, '__Free', plans)
            extra.append(fixture)
    for dest in list(dict.fromkeys([path, *made])):
        normalize_imports(dest)
    return set([path, *made, *extra])


def checked(work, artifacts, label, key, args):
    log = artifacts / f'{label}-{key}.log'
    print('CHECK', label, key, ' '.join(args), flush=True)
    with log.open('w') as out:
        p = subprocess.run(args, cwd=work, stdout=out, stderr=subprocess.STDOUT, text=True)
    text = log.read_text()
    if p.returncode:
        print('\n'.join(text.splitlines()[-110:]), flush=True)
        raise RuntimeError(f'{label} {key} failed ({p.returncode}); see {log.name}')
    for line in text.splitlines():
        if line.startswith('test result:'):
            print(label, line, flush=True)
    return text


def validate(work, artifacts, label, expected, before, filters):
    checked(work, artifacts, label, 'format', ['cargo', '+1.95.0', 'fmt', '-p', 'bitcoin-rs-node'])
    checked(work, artifacts, label, 'fix-imports', ['cargo', '+1.95.0', 'fix', '--locked', '-p', 'bitcoin-rs-node', '--all-targets', '--no-default-features', '--features', 'fjall,zmq', '--allow-dirty', '--allow-staged'])
    checked(work, artifacts, label, 'format-final', ['cargo', '+1.95.0', 'fmt', '-p', 'bitcoin-rs-node'])
    checked(work, artifacts, label, 'clippy', ['cargo', '+1.95.0', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--all-targets', '--no-default-features', '--features', 'fjall,zmq', '--', '-D', 'warnings'])
    checked(work, artifacts, label, 'format-check', ['cargo', '+1.95.0', 'fmt', '-p', 'bitcoin-rs-node', '--', '--check'])
    if inventory(work / 'crates/node/src') != before:
        raise RuntimeError('Existing test names, literal-preserving body tokens, or multiplicities changed')
    tests = []
    for number, test_filter in enumerate(filters):
        text = checked(work, artifacts, label, f'tests-{number}', ['cargo', '+1.95.0', 'test', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq', '--lib', test_filter, '--', '--test-threads=1'])
        summary = re.findall(r'test result:.*', text)
        if not summary or all('0 passed;' in line for line in summary):
            raise RuntimeError(f'Vacuous test filter: {test_filter}')
        tests += summary
    r.command('git', 'diff', '--check', cwd=work)
    r.command('git', 'add', '--', 'crates/node/src', cwd=work)
    paths = set(git(work, 'diff', '--cached', '--name-only').splitlines())
    allowed = {str(p.relative_to(work)) for p in expected}
    if not paths or not paths.issubset(allowed):
        raise RuntimeError(f'Unexpected changed paths: {paths - allowed}')
    if any(not p.startswith('crates/node/src/') for p in paths):
        raise RuntimeError('Product commit escaped node source')
    (artifacts / f'{label}.patch').write_text(r.command('git', 'diff', '--cached', '--binary', cwd=work, capture=True))
    return sorted(paths), tests


def record(artifacts, results, failures):
    (artifacts / 'results.json').write_text(json.dumps(results, indent=2))
    (artifacts / 'failures.json').write_text(json.dumps(failures, indent=2))
    print('RESULTS', json.dumps(results), flush=True)
    print('FAILURES', json.dumps(failures), flush=True)


def main():
    root = Path(os.environ['GITHUB_WORKSPACE'])
    temp = Path(os.environ['RUNNER_TEMP'])
    artifacts = temp / 'node-remaining-results'
    artifacts.mkdir(exist_ok=True)
    r.command('git', 'fetch', 'origin', BASE, OLD_MINING, cwd=root)
    r.command('git', 'config', 'user.name', 'github-actions[bot]', cwd=root)
    r.command('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com', cwd=root)
    baseline = temp / 'node-remaining-baseline'
    r.command('git', 'worktree', 'add', '--detach', str(baseline), BASE, cwd=root)
    before = inventory(baseline / 'crates/node/src')
    checked(baseline, artifacts, 'baseline', 'clippy', ['cargo', '+1.95.0', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--all-targets', '--no-default-features', '--features', 'fjall,zmq', '--', '-D', 'warnings'])
    results, failures, by_name = [], [], {}
    try:
        for number, (label, relative, stages, filters, dependency) in enumerate(GROUPS, 1):
            if dependency and dependency not in by_name:
                failures.append({'group': label, 'error': 'unvalidated prerequisite ' + dependency})
                continue
            base = by_name[dependency]['sha'] if dependency else BASE
            work = temp / ('node-remaining-' + label)
            r.command('git', 'worktree', 'add', '--detach', str(work), base, cwd=root)
            try:
                original_lines = len((work / 'crates/node/src' / relative).read_text().splitlines())
                expected = transform(work, label, relative, stages)
                paths, tests = validate(work, artifacts, label, expected, before, filters)
                os.environ['GIT_AUTHOR_DATE'] = f'2026-09-11T11:10:{number:02d}Z'
                os.environ['GIT_COMMITTER_DATE'] = os.environ['GIT_AUTHOR_DATE']
                tree = git(work, 'write-tree')
                message = f'refactor(node): separate {label} responsibilities and contract tests\n\nRelated to #742. Native formatting, strict Clippy, and focused contract\ntests passed before publication. No consensus or durable format changes.'
                parents = ['-p', base]
                branch = PREFIX + label
                expected_old = None
                if label == 'mining':
                    # Fast-forward the existing review rather than force-rebasing
                    # it or discarding the current main's mining improvements.
                    parents = ['-p', OLD_MINING, '-p', BASE]
                    branch = 'refactor/node-split-a1178cc-mining'
                    expected_old = OLD_MINING
                sha = git(work, 'commit-tree', tree, *parents, '-m', message)
                r.command('git', 'reset', '--hard', sha, cwd=work)
                result = {'group': label, 'sha': sha, 'base': base, 'branch': branch, 'expected_old': expected_old, 'dependency': dependency, 'paths': paths, 'tests': tests, 'clippy': 'passed', 'format': 'passed', 'test_tokens': 'unchanged', 'root_lines_before': original_lines, 'root_lines_after': len((work / 'crates/node/src' / relative).read_text().splitlines())}
                results.append(result)
                by_name[label] = result
                (artifacts / f'{label}-tree.json').write_text(json.dumps([{'path': p, 'sha': git(work, 'hash-object', p), 'lines': len((work / p).read_text().splitlines())} for p in paths], indent=2))
            except Exception as error:
                traceback.print_exc()
                failures.append({'group': label, 'error': str(error)})
                r.command('git', 'add', '--', 'crates/node/src', cwd=work)
                (artifacts / f'{label}-candidate.patch').write_text(r.command('git', 'diff', '--cached', '--binary', cwd=work, capture=True))
            record(artifacts, results, failures)
    finally:
        record(artifacts, results, failures)
        r.command('git', 'archive', '--format=tar.gz', '--output=' + str(artifacts / 'baseline-source.tar.gz'), BASE, cwd=root)
    return bool(failures)


def publish():
    if os.environ.get('GITHUB_REPOSITORY') != 'gosuda/bitcoin-rs' or os.environ.get('GITHUB_REF') != 'refs/heads/automation/node-splits-a1178cc-20260911':
        raise RuntimeError('Publisher restricted to the explicit workbench branch')
    root = Path(os.environ['GITHUB_WORKSPACE'])
    artifacts = Path(os.environ['RUNNER_TEMP']) / 'node-remaining-results'
    source = artifacts / 'results.json'
    if not source.exists():
        return
    results = json.loads(source.read_text())
    allowed = {group[0] for group in GROUPS}
    published, errors = [], []
    for item in results:
        try:
            if item['group'] not in allowed or item['clippy'] != 'passed' or item['format'] != 'passed' or not item['tests']:
                raise RuntimeError('Unvalidated source candidate')
            branch = item['branch']
            if branch != PREFIX + item['group'] and not (item['group'] == 'mining' and branch == 'refactor/node-split-a1178cc-mining'):
                raise RuntimeError('Unexpected publication branch')
            paths = git(root, 'diff', '--name-only', item['base'], item['sha']).splitlines()
            if set(paths) != set(item['paths']) or any(not p.startswith('crates/node/src/') for p in paths):
                raise RuntimeError('Unexpected product paths')
            r.command('git', 'merge-base', '--is-ancestor', BASE, item['sha'], cwd=root)
            ref = 'refs/heads/' + branch
            remote = git(root, 'ls-remote', '--heads', 'origin', ref)
            observed = remote.split()[0] if remote else None
            if observed == item['sha']:
                published.append(item)
                continue
            if observed != item['expected_old']:
                raise RuntimeError(f'Refusing changed branch {branch}: observed {observed}')
            if observed:
                r.command('git', 'merge-base', '--is-ancestor', observed, item['sha'], cwd=root)
            env = os.environ.copy()
            token = env.pop('NODE_SPLIT_PUBLISH_TOKEN')
            env['GIT_CONFIG_COUNT'] = '1'
            env['GIT_CONFIG_KEY_0'] = 'http.https://github.com/.extraheader'
            env['GIT_CONFIG_VALUE_0'] = 'AUTHORIZATION: basic ' + base64.b64encode(('x-access-token:' + token).encode()).decode()
            subprocess.run(['git', 'push', '--atomic', 'origin', item['sha'] + ':' + ref], cwd=root, env=env, check=True)
            published.append(item)
            print('PUBLISHED', branch, item['sha'], flush=True)
        except Exception as error:
            errors.append({'group': item['group'], 'error': str(error)})
            print('PUBLICATION_BLOCKED', item['group'], str(error), flush=True)
    (artifacts / 'published.json').write_text(json.dumps(published, indent=2))
    (artifacts / 'publication-errors.json').write_text(json.dumps(errors, indent=2))
    print('PUBLISHED_RESULTS', json.dumps(published), flush=True)
    if errors:
        raise RuntimeError('Some source branches were deliberately not overwritten')


if __name__ == '__main__':
    if sys.argv[1:] == ['publish']:
        publish()
    else:
        sys.exit(main())
