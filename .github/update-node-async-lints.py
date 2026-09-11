"""Validate the annotation-only correction and fast-forward the existing PR stack."""
import hashlib
import json
from pathlib import Path
import subprocess as sp
import sys

PATH = 'crates/node/src/embed.rs'
OLD_BLOB = 'b6e4104e9023c9f3bf54276c2b4f8a5c51bf6640'
NEW_BLOB = 'dcd8bb5a3fb8b76d6af6468fdc864e4e2f6eb5fc'
STAGES = [
    ('validation', 'refactor/node-validation-729f0e86', '11ac6140ce7a8c60d5e72d393829485b90a29a11', '703b3aaec8e399b926c7b054969cc96181c7449d'),
    ('txindex', 'refactor/node-txindex-729f0e86', '0e014de740f482a2d25c7d98889e78b5f98c2699', '2d1a2d90eded31aba847c98ec6242bc8bf92fe11'),
    ('checkpoint', 'refactor/node-checkpoint-729f0e86', 'c0fc97c3778faacc180ebd04113167b0f24fe08f', 'a7dd95871214e18a0e9de44add73c91953d9ccf2'),
    ('mining', 'fix/node-mining-capabilities-729f0e86', 'bb069d23c4714ef32fd0a37c5e5083b2639d6519', '9bafee1d51a5ac65b6143a8318cad976fc9303fb'),
]
OLD = '    #[allow(clippy::unused_async)]'
NEW = '''    #[allow(
        unknown_lints,
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "embedding defers synchronous work until polled; the trait-impl lint is newer than Rust 1.95"
    )]'''


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
        if git('rev-parse', 'HEAD:' + PATH).decode().strip() != OLD_BLOB:
            raise ValueError('Embedding source identity changed')
        p = Path(PATH)
        text = p.read_text()
        if text.count(OLD) != 5:
            raise ValueError('Unexpected async annotation count')
        updated = text.replace(OLD, NEW)
        if updated.replace(NEW, OLD) != text:
            raise ValueError('Non-annotation source change')
        p.write_text(updated)
        if git('hash-object', PATH).decode().strip() != NEW_BLOB:
            raise ValueError('Reviewed correction differs')
        sp.run(['git', 'add', PATH], check=True)
        tree = git('write-tree').decode().strip()
        if tree != expected_tree or git('diff', '--cached', '--name-only').decode().splitlines() != [PATH]:
            raise ValueError('Unexpected changed source tree')
        checks.append(check(['rustfmt', '+1.95.0', '--edition', '2024', '--config', 'skip_children=true', '--check', PATH], label + '-format', output))
        checks.append(check(['git', 'diff', '--cached', '--check'], label + '-whitespace', output))
        for toolchain in ('1.95.0', 'stable'):
            checks.append(check(['cargo', '+' + toolchain, 'clippy', *node, '--all-targets', '--', '-D', 'warnings'], label + '-clippy-' + toolchain, output))
        parents = [old] if previous is None else [old, previous]
        argv = ['git', '-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit-tree', tree]
        for parent in parents:
            argv += ['-p', parent]
        message = 'Keep intentional async embedding lint-compatible across Rust versions' if previous is None else 'Propagate validated embedding lint compatibility through node cleanup'
        commit = sp.check_output(argv, input=(message + '\n').encode()).decode().strip()
        sp.run(['git', 'update-ref', 'refs/heads/checked-async-' + label, commit, '0' * 40], check=True)
        sp.run(['git', 'checkout', '--detach', commit], check=True)
        records.append({'label': label, 'branch': branch, 'old': old, 'commit': commit, 'tree': tree, 'parents': parents})
        refs.append('refs/heads/checked-async-' + label)
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


def publish(root):
    record = json.loads((root / 'publication.json').read_text())
    if record['validated'] is not True or len(record['stages']) != len(STAGES):
        raise ValueError('Incomplete source record')
    required = {label + '-' + suffix for label, *_ in STAGES for suffix in ('format', 'whitespace', 'clippy-1.95.0', 'clippy-stable')}
    required |= {'final-workspace-format', 'final-standard-clippy', 'final-redb-clippy', 'final-stable-unit', 'final-stable-integration', 'final-stable-owner-gates'}
    if {c['name'] for c in record['checks']} != required:
        raise ValueError('Missing native checks')
    for c in record['checks']:
        if c['rc'] != 0 or sha(root / (c['name'] + '.log')) != c['sha256']:
            raise ValueError('Invalid native evidence')
    bundle = root / 'sources.bundle'
    if sha(bundle) != record['bundle_sha256']:
        raise ValueError('Source bundle differs')
    previous = None
    pushes = []
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
        if git('diff', '--name-only', old, commit).decode().splitlines() != [PATH]:
            raise ValueError('Unexpected source scope')
        before = git('show', old + ':' + PATH).decode()
        after = git('show', commit + ':' + PATH).decode()
        if before.count(OLD) != 5 or before.replace(OLD, NEW) != after:
            raise ValueError('Correction changes runtime behavior')
        sp.run(['git', 'merge-base', '--is-ancestor', old, commit], check=True)
        pushes.append(commit + ':' + ref)
        previous = commit
    for start in range(0, len(pushes), 3):
        sp.run(['git', 'push', '--atomic', 'origin', *pushes[start:start + 3]], check=True)
    for s in record['stages']:
        ref = 'refs/heads/' + s['branch']
        if git('ls-remote', '--heads', 'origin', ref).decode().split() != [s['commit'], ref]:
            raise ValueError('Published ref changed')
        print('UPDATED', s['branch'], s['commit'], s['tree'], flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare(Path(sys.argv[2]).resolve())
    elif sys.argv[1] == 'publish':
        publish(Path(sys.argv[2]).resolve())
    else:
        raise ValueError('Unknown mode')
