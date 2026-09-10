"""Validate exact source trees before publishing an atomic refactor stack."""
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
    allowed = path.startswith('crates/node/') or path == 'bin/bitcoin-rs/tests/support/ownership_scan.rs'
    if p.is_absolute() or '..' in p.parts or not allowed:
        raise ValueError('Out-of-scope path: ' + path)
    return Path(path)


plan = json.loads(Path('.github/node-publish-plan.json').read_text())
payloads = {}
for stage in plan['stages']:
    if 'payload' in stage:
        raw = b''.join(Path('.github/node-payloads', stage['payload'] + '-' + str(i) + '.txt').read_bytes() for i in range(stage['chunks']))
        if blob(raw) != stage['payload_sha']:
            raise ValueError('Uploaded recipe differs from the locally verified recipe')
        payloads[stage['payload']] = json.loads(zlib.decompress(base64.b64decode(raw)))
    branch = stage['branch']
    if not branch.startswith('agent/node-'):
        raise ValueError('Invalid publication branch')
    remote = git('ls-remote', '--heads', 'origin', 'refs/heads/' + branch).decode().split()
    if (remote[0] if remote else None) != stage.get('expected_head'):
        raise RuntimeError('Publication target moved or already exists: ' + branch)
object_branch = plan['object_branch']
if not object_branch.startswith('agent/node-validated-'):
    raise ValueError('Invalid object staging branch')
if git('ls-remote', '--heads', 'origin', 'refs/heads/' + object_branch).strip():
    raise RuntimeError('Object branch already exists')
run('git', 'checkout', '--detach', plan['base'])
report = {'base': plan['base'], 'stages': [], 'published': False}
flags = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
for stage in plan['stages']:
    outputs = {}
    if 'copy_commit' in stage:
        paths = git('diff', '--no-renames', '--name-only', stage['copy_parent'], stage['copy_commit']).decode().splitlines()
        replacements = 0
        for path in paths:
            checked_path(path)
            raw = git('show', stage['copy_commit'] + ':' + path)
            old = b'crate::checkpoint::HeaderCheckpointConfig'
            replacements += raw.count(old)
            outputs[path] = raw.replace(old, b'crate::checkpoint::headers::HeaderCheckpointConfig')
        if replacements != 3 or len(paths) != 16:
            raise ValueError('Unexpected state integration scope')
    else:
        payload = payloads[stage['payload']]
        sources = {}
        for path, expected in payload['sources'].items():
            checked_path(path)
            raw = git('show', 'HEAD:' + path)
            if blob(raw) != expected:
                raise ValueError('Source identity mismatch: ' + path)
            sources[path] = raw.decode()
        for path, spec in payload['files'].items():
            checked_path(path)
            if spec is None:
                outputs[path] = None
                continue
            n = spec['dedent']
            if n not in (0, 4, 8):
                raise ValueError('Unsupported indentation transform')
            lines = ''.join(line[n:] if n and line.startswith(' ' * n) else line for line in sources[spec['source']].splitlines(True)).splitlines(True)
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
    run('git', 'add', '--', *changed)
    if set(git('diff', '--cached', '--no-renames', '--name-only').decode().splitlines()) != set(changed):
        raise ValueError('Staged scope does not match the validated scope')
    tree = git('write-tree').decode().strip()
    if tree != stage['tree']:
        raise ValueError('Complete candidate tree differs from the locally tested tree: ' + tree)
    run('rustfmt', '--edition', '2024', '--check', *[p for p in changed if p.endswith('.rs') and outputs[p] is not None])
    run('git', 'diff', '--cached', '--check')
    run('cargo', 'clippy', *flags, '--all-targets', '--', '-D', 'warnings')
    for test in stage['tests']:
        run('cargo', 'test', *flags, '--lib', test, '--', '--test-threads=1')
    if git('diff').strip() or git('write-tree').decode().strip() != tree:
        raise ValueError('Validation changed the candidate')
    parent = git('rev-parse', 'HEAD').decode().strip()
    parents = [stage['expected_head'], parent] if stage.get('expected_head') else [parent]
    args = ['git', '-c', 'user.name=Node Refactor', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit-tree', tree]
    for sha in parents:
        args += ['-p', sha]
    head = subprocess.check_output(args + ['-m', stage['message']]).decode().strip()
    run('git', 'checkout', '--detach', head)
    report['stages'].append({'branch': stage['branch'], 'parent': parent, 'head': head, 'tree': tree, 'paths': changed, 'tests': stage['tests']})
    Path('/tmp/node-publication.json').write_text(json.dumps(report, indent=2))
run('cargo', 'test', *flags, '--lib', '--', '--test-threads=1')
run('cargo', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--', '--nocapture')
run('git', 'push', '--atomic', 'origin', 'HEAD:refs/heads/' + object_branch)
report['published'] = True
report['object_branch'] = object_branch
Path('/tmp/node-publication.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
