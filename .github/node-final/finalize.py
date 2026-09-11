"""Validate five immutable node refactors and bundle their refs. Never pushes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess as sp

BASE = '5db428fbbb47688c55e22cd6d490b5406a32e6be'
LABELS = ('apply', 'sync', 'mining', 'checkpoint', 'txindex')

def git(*args):
    return sp.check_output(['git', *args])

def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def checked_path(path):
    p = Path(path)
    allowed = path.startswith('crates/node/') or path in {
        'bin/bitcoin-rs/tests/support/ownership_scan.rs',
        'docs/contracts/architecture.md', 'docs/contracts/indexing.md',
    }
    if not allowed or p.is_absolute() or '..' in p.parts:
        raise ValueError('Out-of-scope path: ' + path)
    if p.is_symlink() or any(x.is_symlink() for x in p.parents):
        raise ValueError('Unexpected symlink: ' + path)
    return p

def restore(stage):
    sources = {}
    for path, sha in stage['sources'].items():
        checked_path(path)
        raw = git('show', 'HEAD:' + path)
        if blob(raw) != sha:
            raise ValueError('Unexpected parent source: ' + path)
        sources[path] = raw.decode('utf-8').splitlines(True)
    for path, spec in stage['files'].items():
        p = checked_path(path)
        if spec is None:
            p.unlink()
            continue
        indent = spec['dedent']
        if indent not in (0, 4, 8):
            raise ValueError('Invalid indentation')
        prefix = ' ' * indent
        before = sources[spec['source']] if spec['source'] else []
        before = [x[indent:] if indent and x.startswith(prefix) else x for x in before]
        result = []
        for op in spec['ops']:
            if isinstance(op, str):
                result.append(op)
            else:
                a, b = op
                if type(a) is not int or type(b) is not int or not 0 <= a <= b <= len(before):
                    raise ValueError('Invalid source range')
                result.extend(before[a:b])
        raw = ''.join(result).encode('utf-8')
        if blob(raw) != spec['sha']:
            raise ValueError('Reconstructed blob mismatch: ' + path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
    sp.run(['git', 'add', '--all'], check=True)
    if git('write-tree').decode().strip() != stage['tree']:
        raise ValueError('Reconstructed tree mismatch: ' + stage['label'])

def run_check(argv, name, output):
    print('CHECK', name, ' '.join(argv), flush=True)
    path = output / (name + '.log')
    with path.open('wb') as log:
        result = sp.run(argv, stdout=log, stderr=sp.STDOUT)
    if result.returncode:
        print(path.read_text(errors='replace')[-24000:], flush=True)
        raise sp.CalledProcessError(result.returncode, argv)
    return {'name': name, 'argv': argv, 'returncode': 0,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    plan = json.loads(Path(args.plan).read_text())
    if plan['base'] != BASE or tuple(s['label'] for s in plan['stages']) != LABELS:
        raise ValueError('Unexpected refactor base or scopes')
    if git('status', '--porcelain').strip():
        raise ValueError('Refusing a dirty checkout')
    sp.run(['git', 'checkout', '--detach', BASE], check=True)
    node = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
    records = []
    for stage in plan['stages']:
        label = stage['label']
        if stage['branch'] != 'agent/node-' + label + '-final-5db428fb':
            raise ValueError('Unexpected destination branch')
        parent = git('rev-parse', 'HEAD').decode().strip()
        restore(stage)
        checks = []
        rust = [p for p, spec in stage['files'].items() if spec is not None and p.endswith('.rs')]
        checks.append(run_check(['rustfmt', '--edition', '2024', '--config', 'skip_children=true', '--check', *rust], label + '-fmt', output))
        checks.append(run_check(['git', 'diff', '--cached', '--check'], label + '-diff', output))
        if not args.verify_only:
            checks.append(run_check(['cargo', 'clippy', *node, '--all-targets', '--', '-D', 'warnings'], label + '-clippy', output))
            scope = label + '::' if label != 'checkpoint' else 'checkpoint'
            checks.append(run_check(['cargo', 'test', *node, '--lib', scope, '--', '--test-threads=1'], label + '-tests', output))
        sp.run(['git', 'add', '--all'], check=True)
        if git('write-tree').decode().strip() != stage['tree']:
            raise ValueError('Validation modified the expected tree')
        commit = sp.check_output([
            'git', '-c', 'user.name=Node Refactor',
            '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
            'commit-tree', stage['tree'], '-p', parent,
        ], input=(stage['message'] + '\n').encode()).decode().strip()
        sp.run(['git', 'checkout', '--detach', commit], check=True)
        records.append({'label': label, 'branch': stage['branch'], 'commit': commit,
                        'parent': parent, 'tree': stage['tree'], 'checks': checks})
        print('VERIFIED', label, commit, stage['tree'], flush=True)
    final = []
    if not args.verify_only:
        final.append(run_check(['cargo', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,redb,zmq', '--all-targets', '--', '-D', 'warnings'], 'final-backends-clippy', output))
        final.append(run_check(['cargo', 'test', *node, '--lib', '--', '--test-threads=1'], 'final-library-tests', output))
        final.append(run_check(['cargo', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--', '--nocapture'], 'final-ownership', output))
        final.append(run_check(['cargo', 'test', *node, '--test', 'mining', '--test', 'embed', '--test', 'shutdown', '--', '--test-threads=1'], 'final-integration', output))
    if git('status', '--porcelain').strip():
        raise ValueError('Validation left uncommitted changes')
    refs = []
    for record in records:
        ref = 'refs/heads/' + record['branch']
        # Creation only: an existing local ref is an error, never overwritten.
        sp.run(['git', 'update-ref', ref, record['commit'], '0' * 40], check=True)
        refs.append(ref)
    bundle = output / 'node-refactors.bundle'
    sp.run(['git', 'bundle', 'create', str(bundle), *refs, '^' + BASE], check=True)
    result = {'base': BASE, 'validated': not args.verify_only, 'stages': records, 'final_checks': final,
              'bundle_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest()}
    (output / 'publication.json').write_text(json.dumps(result, indent=2) + '\n')
    print('All five exact trees verified; bundle ready.', flush=True)

if __name__ == '__main__':
    main()
