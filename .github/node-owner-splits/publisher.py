"""Materialize exact reviewed commits; validate without credentials; push new refs only."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import os
import subprocess
import sys
import zlib

TOOLS = Path(__file__).resolve().parent
WORK = Path(os.environ['RUNNER_TEMP']) / 'node-owner-source'
RECEIPT = Path(os.environ['RUNNER_TEMP']) / 'node-owner-validated.json'


def git(*args, cwd=WORK, data=None, env=None):
    return subprocess.check_output(['git', *args], cwd=cwd, input=data, env=env).decode().strip()


def safe_path(raw):
    p = PurePosixPath(raw)
    if p.is_absolute() or '..' in p.parts or not (raw == 'Cargo.lock' or p.parts[0] in ('crates', 'bin', 'docs')):
        raise ValueError(f'Unapproved product path: {raw}')
    dest = WORK / p
    if any(parent.is_symlink() for parent in [dest, *dest.parents]):
        raise ValueError(f'Symlink in destination: {raw}')
    return dest


def blob(text):
    raw = text.encode()
    return hashlib.sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest()


def materialize(recipe):
    if git('rev-parse', 'HEAD') != recipe['base']:
        raise ValueError('Recipe parent differs from current source')
    original = {}
    for path, expected in recipe['sources'].items():
        safe_path(path)
        raw = subprocess.check_output(['git', 'show', f"{recipe['base']}:{path}"], cwd=WORK).decode()
        if blob(raw) != expected:
            raise ValueError(f'Original source hash differs: {path}')
        original[path] = raw.splitlines(keepends=True)
    for path, spec in recipe['files'].items():
        parts = []
        for part in spec['parts']:
            if isinstance(part, str):
                parts.append(part)
                continue
            source, start, end, indent = part
            for line in original[source][start:end]:
                if not line.strip():
                    parts.append(line)
                elif indent >= 0:
                    parts.append(' ' * indent + line)
                else:
                    parts.append(line[-indent:])
        text = ''.join(parts)
        if blob(text) != spec['blob']:
            raise ValueError(f'Reconstructed source hash differs: {path}')
        dest = safe_path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    for path in recipe['delete']:
        safe_path(path).unlink()
    paths = sorted(set(recipe['files']) | set(recipe['delete']))
    git('add', '--', *paths)
    git('diff', '--cached', '--check')
    if git('write-tree') != recipe['tree']:
        raise ValueError('Product tree differs from the locally reviewed tree')
    commit = git('hash-object', '-t', 'commit', '-w', '--stdin', data=recipe['commit'].encode())
    git('switch', '--detach', commit)
    return commit


def validate():
    plan = json.loads((TOOLS / 'publish.json').read_text())
    if WORK.exists():
        raise ValueError('Refusing occupied source worktree')
    git('worktree', 'add', '--detach', str(WORK), plan['base'], cwd=Path(os.environ['GITHUB_WORKSPACE']))
    results = []
    for entry in plan['entries']:
        recipe = json.loads(zlib.decompress(base64.b64decode((TOOLS / entry['recipe']).read_text())))
        commit = materialize(recipe)
        if commit != entry['commit']:
            raise ValueError('Commit identity differs')
        rust_files = [p for p in recipe['files'] if p.endswith('.rs')]
        if rust_files:
            subprocess.run(['rustfmt', '--edition', '2024', '--config', 'skip_children=true', '--check', *rust_files], cwd=WORK, check=True)
        subprocess.run(['cargo', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--all-targets', '--no-default-features', '--features', 'fjall', '--', '-D', 'warnings'], cwd=WORK, check=True)
        subprocess.run(['cargo', 'test', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall', '--lib', '--', '--test-threads=1'], cwd=WORK, check=True)
        if git('status', '--porcelain'):
            raise ValueError('Validation changed the source tree')
        results.append({'branch': entry['branch'], 'commit': commit, 'tree': recipe['tree']})
    RECEIPT.write_text(json.dumps(results, indent=2))


def publish():
    env = dict(os.environ)
    auth = base64.b64encode(('x-access-token:' + env.pop('GH_TOKEN')).encode()).decode()
    env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraheader', GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + auth)
    results = json.loads(RECEIPT.read_text())
    for entry in results:
        branch, commit = entry['branch'], entry['commit']
        if not branch.startswith('refactor/node-owner-') or '..' in branch:
            raise ValueError('Unapproved publication branch')
        if git('rev-parse', commit + '^{tree}') != entry['tree']:
            raise ValueError('Validated commit changed')
        ref = 'refs/heads/' + branch
        existing = git('ls-remote', '--heads', 'origin', ref, env=env)
        if existing:
            if existing.split()[0] != commit:
                raise ValueError(f'Refusing to change existing branch: {branch}')
        else:
            subprocess.run(['git', 'push', 'origin', commit + ':' + ref], cwd=WORK, env=env, check=True)
        print('PUBLISHED', branch, commit, flush=True)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
        f.write('## Validated source-only branches\n```json\n' + json.dumps(results, indent=2) + '\n```\n')


if __name__ == '__main__':
    if os.environ.get('GITHUB_REPOSITORY') != 'gosuda/bitcoin-rs' or os.environ.get('GITHUB_REF') != 'refs/heads/automation/node-owner-splits-20260910':
        raise ValueError('Wrong repository or workbench ref')
    {'validate': validate, 'publish': publish}[sys.argv[1]]()
