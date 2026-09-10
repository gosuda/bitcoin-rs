"""Reconstruct exact reviewed trees, validate every scope, then publish refs atomically."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zlib

REPORT = Path('/tmp/node-owner-publication.json')
LOGS = Path('/tmp/node-owner-validation')
LOGS.mkdir(exist_ok=True)
report = {'published': False, 'stages': []}
FLAGS = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']


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
    if Path(path).is_symlink():
        raise ValueError('Symlink output is not allowed: ' + path)
    return Path(path)


def check(label, *args):
    print('+', ' '.join(args), flush=True)
    with (LOGS / (label + '.log')).open('wb') as output:
        result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT)
    text = (LOGS / (label + '.log')).read_text(errors='replace')
    print(text[-12000:], flush=True)
    report.setdefault('checks', []).append({'label': label, 'argv': list(args), 'exit': result.returncode})
    if result.returncode:
        raise RuntimeError(label + ' failed with exit ' + str(result.returncode))


def reconstruct(payload):
    sources = {}
    for path, expected in payload['sources'].items():
        checked_path(path)
        data = git('show', 'HEAD:' + path)
        if blob(data) != expected:
            raise ValueError('Source identity mismatch: ' + path)
        sources[path] = data.decode()
    outputs = {}
    for path, spec in payload['files'].items():
        checked_path(path)
        if spec is None:
            outputs[path] = None
            continue
        text = sources[spec['source']]
        if spec['dedent'] == 4:
            text = ''.join(line[4:] if line.startswith('    ') else line for line in text.splitlines(True))
        elif spec['dedent'] != 0:
            raise ValueError('Invalid dedent')
        lines = text.splitlines(True)
        parts = []
        for op in spec['ops']:
            if isinstance(op, str):
                parts.append(op)
            else:
                a, b = op
                if not (isinstance(a, int) and isinstance(b, int) and 0 <= a <= b <= len(lines)):
                    raise ValueError('Invalid source range')
                parts.extend(lines[a:b])
        data = ''.join(parts).encode()
        if blob(data) != spec['sha']:
            raise ValueError('Output identity mismatch: ' + path)
        outputs[path] = data
    return outputs


def main():
    plan = json.loads(Path('.github/node-owner-plan.json').read_text())
    report['base'] = plan['base']
    payloads = {}
    for stage in plan['stages']:
        label = stage['payload']
        branch = stage['branch']
        if not re.fullmatch(r'agent/node-(apply|sync|mining|checkpoint|txindex)-owners', branch):
            raise ValueError('Invalid publication branch')
        if git('ls-remote', '--heads', 'origin', 'refs/heads/' + branch).strip():
            raise RuntimeError('Branch already exists; refusing overwrite: ' + branch)
        encoded = Path('.github/node-owner-payloads', label + '.b64').read_bytes()
        if blob(encoded) != stage['transport_sha']:
            raise ValueError('Transport identity mismatch: ' + label)
        # Two explicitly identified transcription corrections to scratch transport only.
        # Candidate bytes and complete trees are independently hash-checked below.
        for old, new in stage.get('transport_repairs', []):
            if encoded.count(old.encode()) != 1:
                raise ValueError('Transport repair is not unique')
            encoded = encoded.replace(old.encode(), new.encode(), 1)
        if blob(encoded) != stage['payload_sha']:
            raise ValueError('Payload identity mismatch: ' + label)
        payloads[label] = json.loads(zlib.decompress(base64.b64decode(encoded.strip(), validate=True)))
    subprocess.run(['git', 'checkout', '--detach', plan['base']], check=True)
    if git('rev-parse', 'HEAD^{tree}').decode().strip() != plan['base_tree']:
        raise ValueError('Base tree mismatch')
    for stage in plan['stages']:
        label = stage['payload']
        payload = payloads[label]
        outputs = reconstruct(payload)
        for path, data in outputs.items():
            target = checked_path(path)
            if data is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        changed = sorted(outputs)
        subprocess.run(['git', 'add', '--', *changed], check=True)
        if set(git('diff', '--cached', '--name-only').decode().splitlines()) != set(changed):
            raise ValueError('Staged scope mismatch')
        if git('write-tree').decode().strip() != payload['tree']:
            raise ValueError('Complete candidate tree mismatch: ' + label)
        rust = [p for p in changed if p.endswith('.rs') and outputs[p] is not None]
        check(label + '-format', 'rustfmt', '--edition', '2024', '--check', *rust)
        check(label + '-diff', 'git', 'diff', '--cached', '--check')
        check(label + '-clippy', 'cargo', 'clippy', *FLAGS, '--all-targets', '--', '-D', 'warnings')
        for test in stage['tests']:
            check(label + '-test-' + test.replace(':', '_'), 'cargo', 'test', *FLAGS, '--lib', test, '--', '--test-threads=1')
        if label == 'txindex':
            check('all-node-tests', 'cargo', 'test', *FLAGS, '--lib', '--', '--test-threads=1')
            check('node-integration', 'cargo', 'test', *FLAGS, '--test', 'chainstate_journal', '--test', 'embed', '--test', 'shutdown', '--test', 'sync_smoke', '--test', 'state_storage', '--', '--test-threads=1')
            check('ownership', 'cargo', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--test', 'g17_dependency_direction', '--', '--nocapture')
            check('redb-clippy', 'cargo', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'redb,zmq', '--all-targets', '--', '-D', 'warnings')
            check('workspace-format', 'cargo', 'fmt', '--all', '--', '--check')
        for path, spec in payload['files'].items():
            if spec is not None and blob(Path(path).read_bytes()) != spec['sha']:
                raise ValueError('Validation changed output: ' + path)
        if git('write-tree').decode().strip() != payload['tree'] or git('diff', '--name-only').strip():
            raise ValueError('Validation changed candidate tree')
        parent = git('rev-parse', 'HEAD').decode().strip()
        subprocess.run(['git', '-c', 'user.name=Node Refactor', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit', '-m', stage['message']], check=True)
        head = git('rev-parse', 'HEAD').decode().strip()
        report['stages'].append({'label': label, 'branch': stage['branch'], 'parent': parent, 'head': head, 'tree': payload['tree'], 'paths': changed})
        REPORT.write_text(json.dumps(report, indent=2))
    refs = [s['head'] + ':refs/heads/' + s['branch'] for s in report['stages']]
    check('atomic-push', 'git', 'push', '--atomic', 'origin', *refs)
    report['published'] = True
    for s in report['stages']:
        remote = git('ls-remote', '--heads', 'origin', 'refs/heads/' + s['branch']).decode().split()[0]
        if remote != s['head']:
            raise ValueError('Published ref mismatch')


try:
    main()
except Exception as error:
    report['error'] = str(error)
    raise
finally:
    REPORT.write_text(json.dumps(report, indent=2))
