"""Rebuild the reviewed consolidated node tree without overwriting PR history."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess as sp
import sys
import zlib

BASE = '953395c1797f4ab911a1a6a136132bb9fe8b0a91'
OLD = '250ce87287fe751a82e315775d81e45d2bae8fd8'
TREE = 'd335a8f2f563de29b40d583b5aca6d714904b370'
PLAN_SHA = 'dbabe2cca3aefce31997635c175f97dad2e7c03e1912bf094912f2e18e8344ae'
BRANCH = 'refactor/node-txindex-729f0e86'
STAGING = 'agent/node-consolidated-validated-20260911'
EXTRAS = {
    'bin/bitcoin-rs/tests/support/ownership_scan.rs',
    'crates/rpc/README.md',
    'docs/benchmarks/hot-path-ledger.toml',
    'docs/benchmarks/index-rollback-rebuild-cutover.md',
    'docs/contracts/external-api.md',
    'docs/contracts/indexing.md',
    'docs/contracts/recovery.md',
}
CHECKS = {'format', 'clippy-195', 'clippy-stable', 'redb-clippy', 'node-tests', 'integration', 'owner-gates', 'whitespace'}


def git(*args):
    return sp.check_output(['git', *args])


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(argv, name, output):
    print('CHECK', name, flush=True)
    path = output / (name + '.log')
    with path.open('wb') as log:
        result = sp.run(argv, stdout=log, stderr=sp.STDOUT, timeout=1200)
    print('RESULT', name, result.returncode, flush=True)
    if result.returncode:
        print(path.read_text(errors='replace')[-16000:], flush=True)
        raise sp.CalledProcessError(result.returncode, argv)
    return {'name': name, 'argv': argv, 'rc': 0, 'sha256': sha(path)}


def prepare(plan_path, output):
    if git('status', '--porcelain').strip():
        raise ValueError('Dirty input checkout')
    encoded = plan_path.read_bytes()
    # Repair the one identified transport transcription, then verify the
    # canonical payload and every reconstructed source byte independently.
    if blob(encoded) == 'c7cae6bcb49228995d23f0dc6fd0cf577e947f77':
        encoded = encoded.replace(b'BD2Tan', b'BD3Tan', 1)
    if blob(encoded) != '2711d8f5040531a169b5609cdeb83d1267aa0d58':
        raise ValueError('Unknown payload transport identity')
    raw = zlib.decompress(base64.b64decode(encoded.strip(), validate=True))
    if hashlib.sha256(raw).hexdigest() != PLAN_SHA:
        raise ValueError('Reviewed plan differs')
    plan = json.loads(raw)
    if (plan['base'], plan['old'], plan['tree']) != (BASE, OLD, TREE) or len(plan['files']) != 96:
        raise ValueError('Unexpected merge identity or scope')
    sp.run(['git', 'checkout', '--detach', BASE], check=True)
    for path, spec in plan['files'].items():
        p = Path(path)
        if not (path.startswith('crates/node/') or path in EXTRAS) or p.is_absolute() or '..' in p.parts:
            raise ValueError('Unexpected destination: ' + path)
        if p.is_symlink() or any(q.is_symlink() for q in p.parents):
            raise ValueError('Symlink destination')
        if spec is None:
            if not p.is_file():
                raise ValueError('Missing retired source')
            p.unlink()
            continue
        if 'blob' in spec:
            expected = spec['blob']
            data = git('cat-file', 'blob', expected)
        else:
            source = git('cat-file', 'blob', spec['base'])
            if blob(source) != spec['base']:
                raise ValueError('Original blob differs')
            lines = source.decode().splitlines(True)
            parts = []
            for op in spec['ops']:
                if isinstance(op, str):
                    parts.append(op)
                else:
                    a, b = op
                    if type(a) is not int or type(b) is not int or not 0 <= a <= b <= len(lines):
                        raise ValueError('Invalid source slice')
                    parts.extend(lines[a:b])
            data = ''.join(parts).encode()
            expected = spec['sha']
        if blob(data) != expected:
            raise ValueError('Reconstructed blob differs: ' + path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    sp.run(['git', 'add', '--all'], check=True)
    if git('write-tree').decode().strip() != TREE:
        raise ValueError('Reviewed full tree differs')
    paths = git('diff', '--cached', '--no-renames', '--name-only').decode().splitlines()
    if paths != sorted(plan['files']):
        raise ValueError('Unexpected changed files')
    output.mkdir(parents=True, exist_ok=True)
    versions = {v: sp.check_output(['rustc', '+' + v, '-vV']).decode() for v in ('1.95.0', 'stable')}
    node = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
    checks = [
        check(['cargo', '+stable', 'fmt', '--all', '--', '--check'], 'format', output),
        check(['cargo', '+1.95.0', 'clippy', *node, '--all-targets', '--', '-D', 'warnings'], 'clippy-195', output),
        check(['cargo', '+stable', 'clippy', *node, '--all-targets', '--', '-D', 'warnings'], 'clippy-stable', output),
        check(['cargo', '+stable', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'redb,zmq', '--all-targets', '--', '-D', 'warnings'], 'redb-clippy', output),
        check(['cargo', '+stable', 'test', *node, '--lib', '--', '--test-threads=1'], 'node-tests', output),
        check(['cargo', '+stable', 'test', *node, '--test', 'mining', '--test', 'embed', '--test', 'shutdown', '--', '--test-threads=1'], 'integration', output),
        check(['cargo', '+stable', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--test', 'overhaul_evidence', '--test', 'g18_hot_path_ledger', '--', '--nocapture'], 'owner-gates', output),
        check(['git', 'diff', '--cached', '--check'], 'whitespace', output),
    ]
    if git('diff', '--name-only').strip() or git('write-tree').decode().strip() != TREE:
        raise ValueError('Validation changed source')
    commit = sp.check_output(['git', '-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit-tree', TREE, '-p', OLD, '-p', BASE], input=b'Reconcile node cleanup with merged owners and repair validation\n').decode().strip()
    ref = 'refs/heads/checked-consolidated-node'
    sp.run(['git', 'update-ref', ref, commit, '0' * 40], check=True)
    bundle = output / 'sources.bundle'
    sp.run(['git', 'bundle', 'create', str(bundle), ref, '^' + OLD, '^' + BASE], check=True)
    result = {'validated': True, 'base': BASE, 'old': OLD, 'commit': commit, 'tree': TREE, 'paths': paths, 'checks': checks, 'versions': versions, 'bundle_sha256': sha(bundle)}
    (output / 'publication.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)


def stage(root):
    record = json.loads((root / 'publication.json').read_text())
    if record['validated'] is not True or (record['base'], record['old'], record['tree']) != (BASE, OLD, TREE):
        raise ValueError('Unexpected validated identity')
    if {c['name'] for c in record['checks']} != CHECKS:
        raise ValueError('Missing native evidence')
    for c in record['checks']:
        if c['rc'] != 0 or sha(root / (c['name'] + '.log')) != c['sha256']:
            raise ValueError('Evidence changed')
    bundle = root / 'sources.bundle'
    if sha(bundle) != record['bundle_sha256']:
        raise ValueError('Bundle changed')
    local = 'refs/heads/checked-consolidated-node'
    sp.run(['git', 'fetch', str(bundle), local + ':' + local], check=True)
    commit = git('rev-parse', local).decode().strip()
    if commit != record['commit'] or git('rev-parse', commit + '^{tree}').decode().strip() != TREE:
        raise ValueError('Unexpected source tree')
    if git('rev-list', '--parents', '-1', commit).decode().split() != [commit, OLD, BASE]:
        raise ValueError('Unexpected merge graph')
    if git('diff', '--no-renames', '--name-only', BASE, commit).decode().splitlines() != record['paths']:
        raise ValueError('Unexpected changed scope')
    ref = 'refs/heads/' + STAGING
    if git('ls-remote', '--heads', 'origin', ref).strip():
        raise ValueError('Staging branch already exists')
    sp.run(['git', 'push', '--atomic', 'origin', commit + ':' + ref], check=True)
    print('VALIDATED FOR FAST-FORWARD', BRANCH, OLD, commit, TREE, flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare(Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve())
    elif sys.argv[1] == 'stage':
        stage(Path(sys.argv[2]).resolve())
    else:
        raise ValueError('Unknown mode')
