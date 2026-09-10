"""Reconstruct exact source trees, validate, then publish atomic branches."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import zlib


def run(*args):
    print('+', ' '.join(args), flush=True)
    subprocess.run(args, check=True)


def git(*args):
    return subprocess.check_output(['git', *args])


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def checked_path(path):
    p = PurePosixPath(path)
    allowed = path.startswith('crates/node/') or path in {
        'bin/bitcoin-rs/tests/support/ownership_scan.rs',
        'docs/contracts/architecture.md',
    }
    if p.is_absolute() or '..' in p.parts or not allowed:
        raise ValueError('Out-of-scope path: ' + path)
    target = Path(path)
    if target.is_symlink() or any(parent.is_symlink() for parent in target.parents):
        raise ValueError('Symlink path: ' + path)
    return target


plan = json.loads(Path('.github/node-scopes-plan.json').read_text())
payloads = {s['label']: json.loads(zlib.decompress(base64.b64decode(
    Path('.github/node-scopes', s['label'] + '.b64').read_bytes(), validate=False
))) for s in plan['stages']}
run('git', 'checkout', '--detach', plan['base'])
if git('status', '--porcelain').strip():
    raise RuntimeError('Expected a clean base checkout')
report = {'base': plan['base'], 'stages': [], 'published': False}
flags = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
refs = []
for stage in plan['stages']:
    branch = stage['branch']
    if not branch.startswith('agent/node-') or branch in {'agent/node-mod-workbench', 'agent/node-state-owners'}:
        raise ValueError('Invalid new branch')
    if git('ls-remote', '--heads', 'origin', 'refs/heads/' + branch).strip():
        raise RuntimeError('Branch exists; refusing to overwrite: ' + branch)
    payload = payloads[stage['label']]
    if git('rev-parse', 'HEAD^{tree}').decode().strip() != payload['base_tree']:
        raise ValueError('Parent tree differs from validated source')
    sources = {}
    for path, expected in payload['sources'].items():
        checked_path(path)
        raw = git('show', 'HEAD:' + path)
        if blob(raw) != expected:
            raise ValueError('Source blob mismatch: ' + path)
        sources[path] = raw.decode()
    outputs = {}
    for path, spec in payload['files'].items():
        checked_path(path)
        if spec is None:
            outputs[path] = None
            continue
        raw = sources[spec['source']]
        if spec['dedent'] == 4:
            raw = ''.join(line[4:] if line.startswith('    ') else line for line in raw.splitlines(True))
        elif spec['dedent'] != 0:
            raise ValueError('Unknown indentation transform')
        lines = raw.splitlines(True)
        pieces = []
        for op in spec['ops']:
            if isinstance(op, str):
                pieces.append(op)
            else:
                a, b = op
                if not (0 <= a <= b <= len(lines)):
                    raise ValueError('Invalid source slice')
                pieces.extend(lines[a:b])
        data = ''.join(pieces).encode()
        if blob(data) != spec['sha']:
            raise ValueError('Output blob mismatch: ' + path)
        outputs[path] = data
    for path, data in outputs.items():
        target = checked_path(path)
        if data is None:
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    changed = sorted(outputs)
    run('git', 'add', '--', *changed)
    if set(git('diff', '--cached', '--no-renames', '--name-only').decode().splitlines()) != set(changed):
        raise ValueError('Unexpected staged scope')
    if git('write-tree').decode().strip() != payload['tree']:
        raise ValueError('Candidate tree differs from locally validated tree')
    rust = [p for p in changed if p.endswith('.rs') and outputs[p] is not None]
    run('rustfmt', '--edition', '2024', '--check', *rust)
    run('git', 'diff', '--cached', '--check')
    run('cargo', 'clippy', *flags, '--all-targets', '--', '-D', 'warnings')
    for test in stage['tests']:
        run('cargo', 'test', *flags, '--lib', test, '--', '--test-threads=1')
    if stage.get('ownership'):
        run('cargo', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--', '--nocapture')
    run('git', 'diff', '--exit-code')
    if git('write-tree').decode().strip() != payload['tree']:
        raise ValueError('Checks changed the candidate')
    parent = git('rev-parse', 'HEAD').decode().strip()
    run('git', '-c', 'user.name=Node Refactor', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit', '-m', stage['message'])
    head = git('rev-parse', 'HEAD').decode().strip()
    refs.append(head + ':refs/heads/' + branch)
    report['stages'].append({'label': stage['label'], 'branch': branch, 'parent': parent, 'head': head, 'tree': payload['tree'], 'paths': changed, 'tests': stage['tests']})
    Path('/tmp/node-scopes-report.json').write_text(json.dumps(report, indent=2))
# No branch is published before all scopes in this batch pass. No force updates.
run('git', 'push', '--atomic', 'origin', *refs)
report['published'] = True
Path('/tmp/node-scopes-report.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
