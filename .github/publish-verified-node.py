"""Publish already-validated node trees with current source-reference metadata."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess as sp
import sys

BASE = '729f0e8691ec25401b8150ea9934c890a37e988a'
RECORD_SHA = '71d3a0fdc0a06f5c3684f0f4fc8ee78b01c28ce8b0a589856bf16a26cd7585db'
STAGES = [
    ('validation', 'refactor/node-validation-729f0e86', '11ac6140ce7a8c60d5e72d393829485b90a29a11', 'c42b9dafde6d39db5c2cc5807c082996607471bd'),
    ('txindex', 'refactor/node-txindex-729f0e86', '5b6063572d9bbece279a62cda729ef38361e155a', '8f63df52c9c90ca25014aa9ec29e8945d5666387'),
    ('checkpoint', 'refactor/node-checkpoint-729f0e86', 'd58063bc3d9cd7649e9f7d48a050425bfc9c0ff7', '87834d08049fc5bb87b2a17a0c87bdc142e63ca7'),
    ('mining', 'fix/node-mining-capabilities-729f0e86', 'e73f74dce63e8027c1281822c06db78e6e7d6b43', 'e04d9caa08b630b02e9cc15903348e815ce1f3dc'),
]
DOCS = ['crates/rpc/README.md', 'docs/benchmarks/hot-path-ledger.toml', 'docs/benchmarks/index-rollback-rebuild-cutover.md', 'docs/contracts/recovery.md']


def git(*args):
    return sp.check_output(['git', *args])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def original(root):
    path = root / 'publication.json'
    if sha(path) != RECORD_SHA:
        raise ValueError('Validated publication record changed')
    record = json.loads(path.read_text())
    if not record['validated'] or record['base'] != BASE or len(record['stages']) != 4:
        raise ValueError('Invalid validation identity')
    if sha(root / 'sources.bundle') != record['bundle_sha256']:
        raise ValueError('Validated bundle checksum mismatch')
    for s, (label, branch, commit, _) in zip(record['stages'], STAGES):
        if (s['label'], s['branch'], s['commit']) != (label, branch, commit):
            raise ValueError('Unexpected original stage')
        for c in s['checks']:
            if c['rc'] != 0 or sha(root / (c['name'] + '.log')) != c['sha256']:
                raise ValueError('Invalid original test evidence')
        sp.run(['git', 'fetch', str(root / 'sources.bundle'), 'refs/heads/' + branch + ':refs/remotes/validated/' + label], check=True)
        if git('rev-parse', commit + '^{tree}').decode().strip() != s['tree']:
            raise ValueError('Original source tree changed')
    return record


def fix_docs(checkpoint):
    def change(path, old, new, count):
        p = Path(path)
        text = p.read_text()
        if text.count(old) != count:
            raise ValueError('Source reference changed: ' + path)
        p.write_text(text.replace(old, new))
    change('crates/rpc/README.md', 'crates/node/src/txindex_worker.rs', 'crates/node/src/txindex/query.rs', 1)
    change('docs/contracts/recovery.md', 'crates/node/src/txindex_worker_recovery_tests.rs', 'crates/node/src/txindex/recovery_tests.rs', 2)
    path = 'docs/benchmarks/index-rollback-rebuild-cutover.md'
    change(path, 'runtime that applies it moves from `crates/node/src/txindex_worker.rs`', 'runtime that applies it moves from `crates/node/src/txindex/worker/reconcile.rs`', 1)
    change(path, '`txindex_worker::DEFAULT_ROLLBACK_REBUILD_CUTOVER` (`crates/node/src/txindex_worker.rs`)', '`txindex::DEFAULT_ROLLBACK_REBUILD_CUTOVER` (`crates/node/src/txindex/worker.rs`)', 1)
    change(path, 'crates/node/src/txindex_worker_recovery_tests.rs', 'crates/node/src/txindex/recovery_tests.rs', 1)
    change(path, 'Retained verbatim from the pre-rewrite document. Headings are demoted one level.', 'Historical results are retained from the pre-rewrite document. Headings are demoted one level; source references follow the current module layout.', 1)
    path = 'docs/benchmarks/hot-path-ledger.toml'
    change(path, '"crates/node/src/txindex_worker.rs", "crates/index/src/index.rs"', '"crates/node/src/txindex/worker.rs", "crates/node/src/txindex/query.rs", "crates/index/src/index.rs"', 1)
    if checkpoint:
        change(path, 'crates/node/src/checkpoint_worker.rs', 'crates/node/src/checkpoint/worker.rs', 1)


def check(argv, name, output):
    print('CHECK', name, flush=True)
    path = output / (name + '.log')
    with path.open('wb') as stream:
        result = sp.run(argv, stdout=stream, stderr=sp.STDOUT, timeout=1200)
    if result.returncode:
        print(path.read_text(errors='replace')[-16000:], flush=True)
        raise sp.CalledProcessError(result.returncode, argv)
    return {'name': name, 'argv': argv, 'rc': 0, 'sha256': sha(path)}


def prepare(inputs, output):
    if git('status', '--porcelain').strip():
        raise ValueError('Dirty checkout')
    stamp = git('show', '-s', '--format=%cI', 'HEAD').decode().strip()
    original(inputs)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(inputs, output / 'original-evidence')
    parent = BASE
    records = []
    checks = []
    refs = []
    for label, branch, old, expected in STAGES:
        sp.run(['git', 'checkout', '--detach', old], check=True)
        if label != 'validation':
            fix_docs(label != 'txindex')
            sp.run(['git', 'add', *DOCS], check=True)
        tree = git('write-tree').decode().strip()
        if tree != expected:
            raise ValueError('Unexpected final tree: ' + label + ' ' + tree)
        changed = git('diff', '--cached', '--name-only', old).decode().splitlines()
        if changed != ([] if label == 'validation' else DOCS):
            raise ValueError('Non-documentation change after native validation')
        checks.append(check(['git', 'diff', '--cached', '--check'], label + '-whitespace', output))
        checks.append(check(['cargo', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'g18_hot_path_ledger', '--', '--nocapture'], label + '-ledger', output))
        if label == 'validation':
            commit = old
        else:
            env = dict(os.environ, GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)
            commit = sp.check_output(['git', '-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit-tree', tree, '-p', parent], input=git('show', '-s', '--format=%B', old), env=env).decode().strip()
        ref = 'refs/heads/' + branch
        sp.run(['git', 'update-ref', ref, commit, '0' * 40], check=True)
        sp.run(['git', 'checkout', '--detach', commit], check=True)
        records.append({'label': label, 'branch': branch, 'commit': commit, 'parent': parent, 'tree': tree, 'original': old})
        refs.append(ref)
        parent = commit
        print('PREPARED', label, commit, tree, flush=True)
    node = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
    checks.append(check(['cargo', 'fmt', '-p', 'bitcoin-rs-node', '--', '--check'], 'final-format', output))
    checks.append(check(['cargo', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,redb,zmq', '--all-targets', '--', '-D', 'warnings'], 'final-clippy', output))
    checks.append(check(['cargo', 'test', *node, '--lib', '--', '--test-threads=1'], 'final-native-tests', output))
    checks.append(check(['cargo', 'test', *node, '--test', 'mining', '--test', 'embed', '--test', 'shutdown', '--', '--test-threads=1'], 'final-integration', output))
    if git('status', '--porcelain').strip():
        raise ValueError('Validation changed source')
    bundle = output / 'sources.bundle'
    sp.run(['git', 'bundle', 'create', str(bundle), *refs, '^' + BASE], check=True)
    record = {'base': BASE, 'validated': True, 'stages': records, 'checks': checks, 'bundle_sha256': sha(bundle), 'original_run': 34602393344}
    (output / 'publication.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)


def publish(root):
    original(root / 'original-evidence')
    record = json.loads((root / 'publication.json').read_text())
    if record['base'] != BASE or record['validated'] is not True or len(record['stages']) != 4:
        raise ValueError('Invalid publication record')
    required = {label + '-' + suffix for label, *_ in STAGES for suffix in ('whitespace', 'ledger')}
    required |= {'final-format', 'final-clippy', 'final-native-tests', 'final-integration'}
    if {c['name'] for c in record['checks']} != required:
        raise ValueError('Missing final checks')
    for c in record['checks']:
        if c['rc'] != 0 or sha(root / (c['name'] + '.log')) != c['sha256']:
            raise ValueError('Final evidence changed')
    bundle = root / 'sources.bundle'
    if sha(bundle) != record['bundle_sha256']:
        raise ValueError('Final bundle changed')
    refs = []
    parent = BASE
    for s, (label, branch, old, tree) in zip(record['stages'], STAGES):
        if (s['label'], s['branch'], s['original'], s['tree'], s['parent']) != (label, branch, old, tree, parent):
            raise ValueError('Unexpected final stage')
        ref = 'refs/heads/' + branch
        sp.run(['git', 'fetch', str(bundle), ref + ':' + ref], check=True)
        commit = git('rev-parse', ref).decode().strip()
        if commit != s['commit'] or git('rev-parse', commit + '^{tree}').decode().strip() != tree:
            raise ValueError('Unexpected source commit')
        if git('rev-list', '--parents', '-1', commit).decode().split() != [commit, parent]:
            raise ValueError('Unexpected parent graph')
        changed = git('diff', '--name-only', old, commit).decode().splitlines()
        if changed != ([] if label == 'validation' else DOCS):
            raise ValueError('Changed runtime sources after native checks')
        remote = git('ls-remote', '--heads', 'origin', ref).decode().split()
        if remote and remote != [commit, ref]:
            raise ValueError('Destination exists; refusing to overwrite')
        if not remote:
            refs.append(commit + ':' + ref)
        parent = commit
    # Repository policy allows at most three refs in each push. Every branch
    # already represents a complete validated stage before either atomic batch.
    for start in range(0, len(refs), 3):
        sp.run(['git', 'push', '--atomic', 'origin', *refs[start:start + 3]], check=True)
    for s in record['stages']:
        ref = 'refs/heads/' + s['branch']
        if git('ls-remote', '--heads', 'origin', ref).decode().split() != [s['commit'], ref]:
            raise ValueError('Published ref does not match')
        print('PUBLISHED', s['branch'], s['commit'], s['tree'], flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare(Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve())
    elif sys.argv[1] == 'publish':
        publish(Path(sys.argv[2]).resolve())
    else:
        raise ValueError('Unknown mode')
