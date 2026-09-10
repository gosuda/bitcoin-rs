"""Reconstruct already locally validated commits; never merge or force-push."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import subprocess

REPO = 'gosuda/bitcoin-rs'
BRANCH = 'refs/heads/automation/node-remaining-publish-20260910'
ROOT = Path(os.environ['GITHUB_WORKSPACE'])


def git(*args, cwd=ROOT, input=None):
    return subprocess.check_output(['git', *args], cwd=cwd, input=input)


def safe_path(path):
    value = PurePosixPath(path)
    if value.is_absolute() or '..' in value.parts or not value.parts:
        raise RuntimeError('unsafe source path')
    if value.parts[0] not in {'Cargo.lock', 'Cargo.toml', 'crates', 'bin', 'docs'}:
        raise RuntimeError('unexpected product path: ' + path)
    return path


def publish(file):
    m = json.loads(file.read_text())
    branch = m['branch']
    if not branch.startswith('refactor/node-remaining-'):
        raise RuntimeError('unexpected destination branch')
    existing = git('ls-remote', '--heads', 'origin', 'refs/heads/' + branch).decode().strip()
    if existing:
        if existing.split()[0] != m['head']:
            raise RuntimeError('destination advanced independently: ' + branch)
        return {'branch': branch, 'sha': m['head'], 'state': 'already published'}
    work = Path(os.environ['RUNNER_TEMP']) / file.stem
    if work.exists():
        raise RuntimeError('occupied worktree')
    git('worktree', 'add', '--detach', str(work), m['base'])
    sources = []
    for source in m['sources']:
        path = safe_path(source['path'])
        blob = git('rev-parse', m['base'] + ':' + path).decode().strip()
        if blob != source['blob']:
            raise RuntimeError('original blob mismatch: ' + path)
        sources.append(git('show', m['base'] + ':' + path).decode().splitlines(keepends=True))
    for name, spec in m['files'].items():
        path = work / safe_path(name)
        if any(p.is_symlink() for p in [path, *path.parents] if p != work.parent):
            raise RuntimeError('symlink in product path: ' + name)
        if spec is None:
            path.unlink()
            continue
        pieces = []
        for part in spec['parts']:
            if isinstance(part, str):
                pieces.append(part)
                continue
            sid, start, end, indent = part
            lines = sources[sid]
            if not 0 <= start <= end <= len(lines):
                raise RuntimeError('invalid source range')
            for line in lines[start:end]:
                if indent < 0 and not line.startswith(' ' * -indent):
                    raise RuntimeError('invalid indentation removal')
                pieces.append(' ' * indent + line if indent >= 0 else line[-indent:])
        content = ''.join(pieces).encode()
        if hashlib.sha256(content).hexdigest() != spec['sha256']:
            raise RuntimeError('reconstructed file mismatch: ' + name)
        if spec['mode'] not in {'100644', '100755'}:
            raise RuntimeError('unexpected file mode')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o755 if spec['mode'] == '100755' else 0o644)
    git('add', '--', *m['files'], cwd=work)
    git('diff', '--cached', '--check', cwd=work)
    tree = git('write-tree', cwd=work).decode().strip()
    if tree != m['tree']:
        raise RuntimeError('validated product tree mismatch')
    sha = git('hash-object', '-t', 'commit', '-w', '--stdin', input=m['commit'].encode()).decode().strip()
    if sha != m['head']:
        raise RuntimeError('commit identity mismatch')
    if git('rev-parse', sha + '^{tree}').decode().strip() != tree:
        raise RuntimeError('commit references a different tree')
    git('push', 'origin', sha + ':refs/heads/' + branch)
    return {'branch': branch, 'sha': sha, 'tree': tree, 'state': 'published', 'local_validation': m.get('validation', {})}


if os.environ.get('GITHUB_REPOSITORY') != REPO or os.environ.get('GITHUB_REF') != BRANCH:
    raise RuntimeError('publisher is restricted to its isolated repository branch')
results = []
for file in sorted((ROOT / '.github/node-publish').glob('*.json')):
    result = publish(file)
    results.append(result)
    print(json.dumps(result), flush=True)
with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
    f.write('## Source-only publication\n\nThese are exact locally validated trees. This job checks reconstruction and publication; it does not claim to execute the reported local Rust checks.\n\n```json\n' + json.dumps(results, indent=2) + '\n```\n')
