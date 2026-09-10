"""Reconstruct hash-pinned, locally validated refactors; check before publication."""
import base64
import hashlib
import json
import os
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
    if p.is_absolute() or '..' in p.parts or not path.startswith('crates/node/'):
        raise ValueError('Out-of-scope path: ' + path)
    return Path(path)


plan = json.loads(Path('.github/node-publish-plan.json').read_text())
payloads = {
    stage['payload']: json.loads(zlib.decompress(base64.b64decode(
        Path('.github/node-payloads', stage['payload'] + '.b64').read_text(), validate=False
    ))) for stage in plan['stages']
}
run('git', 'checkout', '--detach', plan['base'])
report = {'base': plan['base'], 'stages': []}
flags = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
for stage in plan['stages']:
    branch = stage['branch']
    if not branch.startswith('agent/node-') or branch == 'agent/node-mod-workbench':
        raise ValueError('Invalid publication branch')
    if git('ls-remote', '--heads', 'origin', 'refs/heads/' + branch).strip():
        raise RuntimeError('Publication branch already exists; refusing to overwrite: ' + branch)
    payload = payloads[stage['payload']]
    sources = {}
    for path, expected in payload['sources'].items():
        checked_path(path)
        raw = git('show', 'HEAD:' + path)
        if blob(raw) != expected:
            raise ValueError('Source identity mismatch: ' + path)
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
            raise ValueError('Unsupported indentation transform')
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
            raise ValueError('Candidate identity mismatch: ' + path)
        outputs[path] = data
    for path, data in outputs.items():
        target = checked_path(path)
        if data is None:
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    changed = sorted(outputs)
    rust = [p for p in changed if p.endswith('.rs') and outputs[p] is not None]
    run('rustfmt', '--edition', '2024', '--check', *rust)
    run('git', 'diff', '--check')
    run('cargo', 'clippy', *flags, '--all-targets', '--', '-D', 'warnings')
    for test in stage['tests']:
        run('cargo', 'test', *flags, '--lib', test, '--', '--test-threads=1')
    for path, spec in payload['files'].items():
        if spec is not None and blob(Path(path).read_bytes()) != spec['sha']:
            raise ValueError('Validation changed candidate: ' + path)
    parent = git('rev-parse', 'HEAD').decode().strip()
    run('git', 'add', '--', *changed)
    if set(git('diff', '--cached', '--name-only').decode().splitlines()) != set(changed):
        raise ValueError('Staged scope does not match validated payload')
    run('git', '-c', 'user.name=Node Refactor', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit', '-m', stage['message'])
    head = git('rev-parse', 'HEAD').decode().strip()
    run('git', 'push', '--atomic', 'origin', 'HEAD:refs/heads/' + branch)
    report['stages'].append({'branch': branch, 'parent': parent, 'head': head, 'paths': changed, 'tests': stage['tests']})
    Path('/tmp/node-publication.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
