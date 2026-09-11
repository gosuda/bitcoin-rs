"""Validate embedding lint compatibility and preserve the existing PR graph."""
import hashlib
import json
from pathlib import Path
import subprocess as sp
import sys

PATH = 'crates/node/src/embed.rs'
OLD_BLOB = 'b6e4104e9023c9f3bf54276c2b4f8a5c51bf6640'
NEW_BLOB = 'dcd8bb5a3fb8b76d6af6468fdc864e4e2f6eb5fc'
STAGES = [
    ('validation', 'refactor/node-validation-729f0e86', 'f3284c1fcfbb7fa0bf9298bf0ccfcb97f19bcf49', '6a034dd15e84286c5e7ea495adf31b8c313cf2da'),
    ('txindex', 'refactor/node-txindex-729f0e86', '0e014de740f482a2d25c7d98889e78b5f98c2699', '14dfd0779bcc315b9b8afe63e7d6b5953b16e6c3'),
    ('checkpoint', 'refactor/node-checkpoint-729f0e86', 'c0fc97c3778faacc180ebd04113167b0f24fe08f', 'faba6464dcd7ddfa235631d19c45f1d34e1f4831'),
    ('mining', 'fix/node-mining-capabilities-729f0e86', 'bb069d23c4714ef32fd0a37c5e5083b2639d6519', '485c199bb398edf1bbd5d4e0b4c09e8bac40e869'),
]
OLD = '    #[allow(clippy::unused_async)]'
NEW = '''    #[allow(
        unknown_lints,
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "embedding defers synchronous work until polled; the trait-impl lint is newer than Rust 1.95"
    )]'''
REVIEW_PATHS = ['bin/bitcoin-rs/tests/support/ownership_scan.rs', 'crates/node/src/state/tests/prune.rs', 'docs/contracts/architecture.md']
EXTRA_CHECKS = {'final-workspace-format', 'final-standard-clippy', 'final-redb-clippy', 'final-stable-unit', 'final-stable-integration', 'final-stable-owner-gates'}


def git(*args):
    return sp.check_output(['git', *args])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(argv, name, output):
    print('CHECK', name, flush=True)
    path = output / (name + '.log')
    with path.open('wb') as stream:
        result = sp.run(argv, stdout=stream, stderr=sp.STDOUT, timeout=1200)
    if result.returncode:
        print(path.read_text(errors='replace')[-16000:], flush=True)
        raise sp.CalledProcessError(result.returncode, argv)
    return {'name': name, 'argv': argv, 'rc': 0, 'sha256': sha(path)}


def verify_delta(old, new, previous):
    changed = git('diff', '--name-only', old, new).decode().splitlines()
    if changed != sorted([PATH] + (REVIEW_PATHS if previous else [])):
        raise ValueError('Unexpected change scope')
    before = git('show', old + ':' + PATH).decode()
    after = git('show', new + ':' + PATH).decode()
    if before.count(OLD) != 5 or before.replace(OLD, NEW) != after:
        raise ValueError('Embedding runtime behavior changed')
    if previous:
        merged = git('merge-tree', '--write-tree', old, previous).decode().splitlines()[0]
        if git('rev-parse', new + '^{tree}').decode().strip() != merged:
            raise ValueError('Not the exact non-destructive parent merge')


def prepare(output):
    if git('status', '--porcelain').strip():
        raise ValueError('Dirty input checkout')
    output.mkdir(parents=True, exist_ok=True)
    versions = {t: sp.check_output(['rustc', '+' + t, '-vV']).decode() for t in ('1.95.0', 'stable')}
    records, checks, refs = [], [], []
    previous = None
    node = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
    for label, branch, old, expected_tree in STAGES:
        ref = 'refs/heads/' + branch
        if git('ls-remote', '--heads', 'origin', ref).decode().split() != [old, ref]:
            raise ValueError('Concurrent branch update: ' + branch)
        sp.run(['git', 'checkout', '--detach', old], check=True)
        if previous is None:
            if git('rev-parse', 'HEAD:' + PATH).decode().strip() != OLD_BLOB:
                raise ValueError('Embedding source identity changed')
            p = Path(PATH)
            text = p.read_text()
            if text.count(OLD) != 5:
                raise ValueError('Unexpected async annotation count')
            p.write_text(text.replace(OLD, NEW))
            sp.run(['git', 'add', PATH], check=True)
        else:
            merged = git('merge-tree', '--write-tree', old, previous).decode().splitlines()[0]
            sp.run(['git', 'read-tree', '--reset', '-u', merged], check=True)
        if git('hash-object', PATH).decode().strip() != NEW_BLOB:
            raise ValueError('Reviewed correction differs')
        tree = git('write-tree').decode().strip()
        if tree != expected_tree:
            raise ValueError('Unexpected resulting tree: ' + label + ' ' + tree)
        parents = [old] if previous is None else [old, previous]
        argv = ['git', '-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit-tree', tree]
        for parent in parents:
            argv += ['-p', parent]
        message = 'Keep intentional async embedding lint-compatible across Rust versions' if previous is None else 'Preserve reviewed ownership gates and embedding lint compatibility'
        commit = sp.check_output(argv, input=(message + '\n').encode()).decode().strip()
        verify_delta(old, commit, previous)
        sp.run(['git', 'checkout', '--detach', commit], check=True)
        if git('status', '--porcelain').strip():
            raise ValueError('Reconstruction left uncommitted files')
        checks.append(check(['rustfmt', '+1.95.0', '--edition', '2024', '--config', 'skip_children=true', '--check', PATH], label + '-format', output))
        checks.append(check(['git', 'diff', '--check', old, commit], label + '-whitespace', output))
        for toolchain in ('1.95.0', 'stable'):
            checks.append(check(['cargo', '+' + toolchain, 'clippy', *node, '--all-targets', '--', '-D', 'warnings'], label + '-clippy-' + toolchain, output))
        local = 'refs/heads/checked-async-' + label
        sp.run(['git', 'update-ref', local, commit, '0' * 40], check=True)
        records.append({'label': label, 'branch': branch, 'old': old, 'commit': commit, 'tree': tree, 'parents': parents})
        refs.append(local)
        previous = commit
        print('VALIDATED', label, commit, tree, flush=True)
    checks.append(check(['cargo', '+stable', 'fmt', '--all', '--', '--check'], 'final-workspace-format', output))
    checks.append(check(['bash', 'scripts/ci-pr.sh', 'clippy'], 'final-standard-clippy', output))
    checks.append(check(['cargo', '+stable', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'redb,zmq', '--all-targets', '--', '-D', 'warnings'], 'final-redb-clippy', output))
    checks.append(check(['cargo', '+stable', 'test', *node, '--lib', '--', '--test-threads=1'], 'final-stable-unit', output))
    checks.append(check(['cargo', '+stable', 'test', *node, '--test', 'mining', '--test', 'embed', '--test', 'shutdown', '--', '--test-threads=1'], 'final-stable-integration', output))
    checks.append(check(['cargo', '+stable', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--test', 'overhaul_evidence', '--test', 'g18_hot_path_ledger', '--', '--nocapture'], 'final-stable-owner-gates', output))
    if git('status', '--porcelain').strip():
        raise ValueError('Validation modified source')
    bundle = output / 'sources.bundle'
    sp.run(['git', 'bundle', 'create', str(bundle), *refs, *['^' + old for _, _, old, _ in STAGES]], check=True)
    record = {'validated': True, 'versions': versions, 'stages': records, 'checks': checks, 'bundle_sha256': sha(bundle)}
    (output / 'publication.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)


def stage(root):
    record = json.loads((root / 'publication.json').read_text())
    if record['validated'] is not True or len(record['stages']) != len(STAGES):
        raise ValueError('Incomplete source record')
    required = {label + '-' + suffix for label, *_ in STAGES for suffix in ('format', 'whitespace', 'clippy-1.95.0', 'clippy-stable')} | EXTRA_CHECKS
    if {c['name'] for c in record['checks']} != required:
        raise ValueError('Missing native checks')
    for c in record['checks']:
        if c['rc'] != 0 or sha(root / (c['name'] + '.log')) != c['sha256']:
            raise ValueError('Invalid native evidence')
    bundle = root / 'sources.bundle'
    if sha(bundle) != record['bundle_sha256']:
        raise ValueError('Source bundle differs')
    previous = None
    for s, (label, branch, old, tree) in zip(record['stages'], STAGES):
        if (s['label'], s['branch'], s['old'], s['tree']) != (label, branch, old, tree):
            raise ValueError('Unexpected destination')
        ref = 'refs/heads/' + branch
        if git('ls-remote', '--heads', 'origin', ref).decode().split() != [old, ref]:
            raise ValueError('Concurrent update; refusing to overwrite')
        local = 'refs/heads/checked-async-' + label
        sp.run(['git', 'fetch', str(bundle), local + ':' + local], check=True)
        commit = git('rev-parse', local).decode().strip()
        parents = [old] if previous is None else [old, previous]
        if s['commit'] != commit or s['parents'] != parents or git('rev-list', '--parents', '-1', commit).decode().split() != [commit, *parents]:
            raise ValueError('Invalid fast-forward graph')
        if git('rev-parse', commit + '^{tree}').decode().strip() != tree:
            raise ValueError('Unexpected source tree')
        verify_delta(old, commit, previous)
        sp.run(['git', 'merge-base', '--is-ancestor', old, commit], check=True)
        previous = commit
    ref = 'refs/heads/agent/node-async-validated-v2-20260911'
    if git('ls-remote', '--heads', 'origin', ref).strip():
        raise ValueError('Validation ref already exists')
    sp.run(['git', 'push', '--atomic', 'origin', previous + ':' + ref], check=True)
    for s in record['stages']:
        print('VALIDATED FOR FAST-FORWARD', s['branch'], s['old'], s['commit'], s['tree'], flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare(Path(sys.argv[2]).resolve())
    elif sys.argv[1] == 'stage':
        stage(Path(sys.argv[2]).resolve())
    else:
        raise ValueError('Unknown mode')
