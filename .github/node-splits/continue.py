"""One-shot native validation of independent node responsibility cuts."""
from pathlib import Path
import base64
import json
import os
import re
import subprocess
import sys
import traceback

import refactor as r


def syntax_identifiers(text):
    root = r.PARSER.parse(text.encode()).root_node
    found = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in ('line_comment', 'block_comment', 'string_literal', 'raw_string_literal', 'char_literal'):
            continue
        if node.type in ('identifier', 'type_identifier', 'field_identifier', 'self', 'super', 'crate'):
            found.add(node.text.decode())
        stack.extend(node.children)
    return found


r.identifiers = syntax_identifiers

CHECKPOINT = {
    'load': {
        'doc': 'Authenticated checkpoint loading, strict payload validation, and typed corruption classification.',
        'functions': ['read_current', 'read_manifest', 'load_headers', 'load_payloads', 'load_payloads_inner', 'read_checkpoint_snapshot', 'validate_coinstats_manifest', 'open_regular_file', 'verify_artifact', 'decode_coinstats_artifact', 'parse_tip', 'require_filename', 'classify_checkpoint_error', 'classify_open_error', 'checkpoint_file_error', 'classify_checkpoint_io', 'corrupt_checkpoint'],
    },
    'publish': {
        'doc': 'One checkpoint publication transaction: prepare artifacts, sync, publish CURRENT, then retire old generations.',
        'functions': ['write_checkpoint_inner', 'checkpoint_best_tip_id', 'allocate_generation', 'generation_paths', 'cleanup_after_publication', 'manifest_tip'],
    },
    'io': {
        'doc': 'Failpoint-aware checkpoint writes and filesystem durability barriers.',
        'functions': ['write_file', 'sync_file', 'sync_checkpoint_dir', 'sync_root', 'rename_generation', 'rename_current', 'injected_io'],
    },
    'format': {
        'doc': 'Exact checkpoint generation names, network identity, and digest encoding.',
        'functions': ['generation_name', 'valid_generation_name', 'valid_staging_name', 'valid_current_temp_name', 'network_name', 'hex_encode', 'decode_hex', 'decode_nibble'],
    },
}

FOOTPRINT = {
    'identity': {
        'doc': 'Build, chain, and configuration identity bound into storage evidence.',
        'functions': ['evidence_identity', 'resolve_stop', 'read_witness_from_anchor', 'index_lane', 'script_index_name', 'compiled_features', 'cargo_lock_sha256', 'sha256_file', 'hex_sha256'],
    },
    'scan': {
        'doc': 'Logical ledger collection and exact durable watermark observations.',
        'functions': ['collect_logical', 'scan_store', 'scan_store_with_watermarks', 'watermark_evidence', 'watermark_json', 'io_from_footprint'],
    },
    'budget': {
        'doc': 'Explicit applicability and evaluation of the default unpruned storage budget.',
        'functions': ['budget_evidence', 'is_default_unpruned_mainnet'],
    },
}

RECOVERY = {
    'io': {
        'doc': 'Bounded evidence reads and atomic durable witness/marker publication.',
        'functions': ['write_bounded', 'read_bounded', 'read_and_validate', 'sync_dir'],
    },
    'reporter': {
        'doc': 'Recovery event construction and warning publication after durable evidence succeeds.',
        'methods': ['report_checkpoint_fallback', 'report_index_ahead'],
        'functions': ['checkpoint_fallback_warning', 'index_ahead_warning'],
    },
}

GROUPS = [
    ('mining', 'MiningCoordinator', r.MINING),
    ('sync', 'BlockSync', r.SYNC),
    ('checkpoint', '__NoInherentImpl', CHECKPOINT),
    ('storage_footprint', '__NoInherentImpl', FOOTPRINT),
    ('recovery_evidence', 'RecoveryReporter', RECOVERY),
]
PREFIX = 'refactor/node-split-a1178cc-'


def git(work, *args):
    return r.command('git', *args, cwd=work, capture=True).strip()


def write_results(artifacts, results):
    (artifacts / 'results.json').write_text(json.dumps(results, indent=2))
    print('VALIDATED_RESULTS', json.dumps(results), flush=True)


def main():
    root = Path(os.environ['GITHUB_WORKSPACE'])
    temp = Path(os.environ['RUNNER_TEMP'])
    artifacts = temp / 'node-split-results'
    artifacts.mkdir(exist_ok=True)
    r.command('git', 'fetch', 'origin', r.BASE, cwd=root)
    work = temp / 'node-split-baseline'
    r.command('git', 'worktree', 'add', '--detach', str(work), r.BASE, cwd=root)
    r.command('git', 'config', 'user.name', 'github-actions[bot]', cwd=work)
    r.command('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com', cwd=work)
    os.environ['GIT_AUTHOR_DATE'] = '2026-09-11T10:30:00Z'
    os.environ['GIT_COMMITTER_DATE'] = '2026-09-11T10:30:00Z'
    before = r.test_inventory(work / 'crates/node/src')
    embed = work / 'crates/node/src/embed.rs'
    text = embed.read_text()
    if text.count(', clippy::unused_async_trait_impl') != 5:
        raise RuntimeError('Pinned baseline embedding annotations changed')
    embed.write_text(text.replace(', clippy::unused_async_trait_impl', ''))
    r.command('cargo', '+1.95.0', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--all-targets', '--no-default-features', '--features', 'fjall,zmq', '--', '-D', 'warnings', cwd=work)
    r.command('git', 'diff', '--check', cwd=work)
    r.command('git', 'add', '--', 'crates/node/src/embed.rs', cwd=work)
    r.command('git', 'commit', '-m', 'fix(node): remove nonexistent embedding lint names', cwd=work)
    lint_sha = git(work, 'rev-parse', 'HEAD')
    results = [{'group': 'embedding', 'sha': lint_sha, 'base': r.BASE, 'branch': PREFIX + 'embedding', 'paths': ['crates/node/src/embed.rs'], 'clippy': 'passed'}]
    write_results(artifacts, results)
    failures = []
    for index, (label, typename, plan) in enumerate(GROUPS, 1):
        candidate = temp / ('node-split-' + label)
        r.command('git', 'worktree', 'add', '--detach', str(candidate), lint_sha, cwd=root)
        os.environ['GIT_AUTHOR_DATE'] = f'2026-09-11T10:30:{index:02d}Z'
        os.environ['GIT_COMMITTER_DATE'] = os.environ['GIT_AUTHOR_DATE']
        try:
            path = candidate / f'crates/node/src/{label}.rs'
            original_lines = len(path.read_text().splitlines())
            new_files = r.split_implementation(path, typename, plan)
            expected = {str(p.relative_to(candidate)) for p in [path, *new_files]}
            r.validate(candidate, label, before, artifacts)
            staged = set(git(candidate, 'diff', '--cached', '--name-only').splitlines())
            if staged != expected:
                raise RuntimeError(f'Unexpected staged paths: missing={expected-staged}, extra={staged-expected}')
            r.command('cargo', '+1.95.0', 'fmt', '-p', 'bitcoin-rs-node', '--', '--check', cwd=candidate)
            r.command('git', 'commit', '-m', f'refactor(node): separate {label.replace("_", " ")} responsibilities and contract tests', '-m', 'Related to #742. No compatibility forwarding wrappers or storage format changes.', cwd=candidate)
            result = {'group': label, 'sha': git(candidate, 'rev-parse', 'HEAD'), 'base': lint_sha, 'branch': PREFIX + label.replace('_', '-'), 'paths': sorted(expected), 'clippy': 'passed', 'tests': 'passed', 'test_bodies': 'unchanged', 'root_lines_before': original_lines, 'root_lines_after': len(path.read_text().splitlines())}
            results.append(result)
            (artifacts / (label + '-tree.json')).write_text(json.dumps({'files': [{'path': p, 'sha': git(candidate, 'hash-object', p), 'lines': len((candidate / p).read_text().splitlines())} for p in sorted(expected)]}, indent=2))
            write_results(artifacts, results)
        except Exception as error:
            traceback.print_exc()
            failures.append({'group': label, 'error': str(error)})
            r.command('git', 'add', '--', 'crates/node/src', cwd=candidate)
            (artifacts / (label + '-candidate.patch')).write_text(r.command('git', 'diff', '--cached', '--binary', cwd=candidate, capture=True))
            print('BLOCKED', label, str(error), flush=True)
        (artifacts / 'failures.json').write_text(json.dumps(failures, indent=2))
    write_results(artifacts, results)
    return bool(failures)


def publish():
    if os.environ.get('GITHUB_REPOSITORY') != 'gosuda/bitcoin-rs' or os.environ.get('GITHUB_REF') != 'refs/heads/automation/node-splits-a1178cc-20260911':
        raise RuntimeError('Publisher restricted to its workbench branch')
    root = Path(os.environ['GITHUB_WORKSPACE'])
    artifacts = Path(os.environ['RUNNER_TEMP']) / 'node-split-results'
    result_file = artifacts / 'results.json'
    if not result_file.exists():
        print('No validated source commits to publish')
        return
    results = json.loads(result_file.read_text())
    allowed = {'embedding', *(label for label, _, _ in GROUPS)}
    for entry in results:
        label = entry['group']
        if label not in allowed or entry['clippy'] != 'passed':
            raise RuntimeError(f'Unvalidated publication group: {label}')
        if entry['branch'] != PREFIX + label.replace('_', '-'):
            raise RuntimeError('Unexpected branch name')
        sha = entry['sha']
        if git(root, 'rev-parse', sha + '^') != entry['base']:
            raise RuntimeError('Unexpected source commit parent')
        paths = git(root, 'diff', '--name-only', entry['base'], sha).splitlines()
        if set(paths) != set(entry['paths']) or any(not p.startswith('crates/node/src/') for p in paths):
            raise RuntimeError('Unexpected publication paths')
        r.command('git', 'merge-base', '--is-ancestor', r.BASE, sha, cwd=root)
        ref = 'refs/heads/' + entry['branch']
        remote = git(root, 'ls-remote', '--heads', 'origin', ref)
        if remote:
            existing = remote.split()[0]
            r.command('git', 'fetch', 'origin', existing, cwd=root)
            if existing != sha:
                raise RuntimeError(f'Refusing occupied branch {ref}: {existing} != {sha}')
            entry['published'] = existing
            continue
        env = os.environ.copy()
        token = env.pop('NODE_SPLIT_PUBLISH_TOKEN')
        env['GIT_CONFIG_COUNT'] = '1'
        env['GIT_CONFIG_KEY_0'] = 'http.https://github.com/.extraheader'
        env['GIT_CONFIG_VALUE_0'] = 'AUTHORIZATION: basic ' + base64.b64encode(('x-access-token:' + token).encode()).decode()
        subprocess.run(['git', 'push', '--atomic', 'origin', sha + ':' + ref], cwd=root, env=env, check=True)
        entry['published'] = sha
        print('PUBLISHED', entry['branch'], sha, flush=True)
    (artifacts / 'published.json').write_text(json.dumps(results, indent=2))
    print('PUBLISHED_RESULTS', json.dumps(results), flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['publish']:
        publish()
    else:
        sys.exit(main())
