"""One-shot publisher. Never modifies main or force-pushes a branch."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
DATA = {'base_commit': 'f599c9d5906f999e35fed86ab6cd1f247d051a3a', 'source_blobs': {'crates/node/src/txindex_worker.rs': 'c67bceda53b2bebb8a9b86f8e167be5cacd446f5', 'crates/node/src/state.rs': 'b84060141e46fca71b3fb0f92e62f694389aef44', 'crates/node/src/txindex_worker_lifecycle_tests.rs': '682b973fa5dd7c5c7ec664ff717fc7b3d6b76252', 'crates/index/src/lib.rs': '749a2c61e6a0e8128a6c77ba5c8590f3f36d660e', 'crates/index/Cargo.toml': '19c5836f10e13c2b30efbb1d860ed291bb512f48'}}
DATA['groups'] = {name: json.loads((ROOT / (name + '.json')).read_text()) for name in ['index-owner', 'worker-modules', 'chain-events']}
BASE = DATA['base_commit']
NAMES = {
    'index-owner': 'refactor(index): own reconciliation state and fenced writer interface',
    'worker-modules': 'refactor(node): isolate index worker process helpers',
    'chain-events': 'refactor(node): isolate committed chain-event publication',
}


def run(*args, cwd, capture=False):
    print('+', ' '.join(args), flush=True)
    result = subprocess.run(args, cwd=cwd, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else ''


def apply_group(work, name):
    original = {}
    for path, expected in DATA['source_blobs'].items():
        file = work / path
        if file.is_symlink() or run('git', 'hash-object', path, cwd=work, capture=True) != expected:
            raise RuntimeError(f'Original source differs: {path}')
        original[path] = file.read_text().splitlines(keepends=True)
    group = DATA['groups'][name]
    for path, edits in group['edits'].items():
        lines = original[path][:]
        for start, count, replacement in sorted(edits, key=lambda edit: edit[0], reverse=True):
            lines[start:start + count] = replacement.splitlines(keepends=True)
        (work / path).write_text(''.join(lines))
    for path, spec in group['new_files'].items():
        file = work / path
        if file.exists() or file.is_symlink():
            raise RuntimeError(f'New path already exists: {path}')
        text = ''.join(part if isinstance(part, str) else
                       ''.join(original[part[0]][part[1]:part[2]]) for part in spec['parts'])
        if hashlib.sha256(text.encode()).hexdigest() != spec['sha256']:
            raise RuntimeError(f'Reconstructed source checksum differs: {path}')
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
    return sorted(set(group['edits']) | set(group['new_files']))


def main():
    if os.environ.get('GITHUB_REPOSITORY') != 'gosuda/bitcoin-rs':
        raise RuntimeError('Publisher is restricted to gosuda/bitcoin-rs')
    if os.environ.get('GITHUB_REF') != 'refs/heads/automation/node-cleanup-publish-20260910':
        raise RuntimeError('Publisher is restricted to its one-shot branch')
    checkout = Path(os.environ['GITHUB_WORKSPACE'])
    temp = Path(os.environ['RUNNER_TEMP'])
    results = {}
    for name, message in NAMES.items():
        work = temp / f'node-cleanup-{name}'
        if work.exists():
            raise RuntimeError(f'Refusing occupied worktree: {work}')
        run('git', 'worktree', 'add', '--detach', str(work), BASE, cwd=checkout)
        try:
            paths = apply_group(work, name)
            run('cargo', 'fmt', '--all', cwd=work)
            changed = run('git', 'diff', '--name-only', cwd=work, capture=True).splitlines()
            unexpected = set(changed) - set(paths)
            if unexpected:
                raise RuntimeError(f'Formatting changed unrelated paths: {sorted(unexpected)}')
            run('cargo', 'fmt', '--all', '--', '--check', cwd=work)
            run('git', 'diff', '--check', cwd=work)
            run('cargo', 'clippy', '--locked', '-p', 'bitcoin-rs-index', '-p', 'bitcoin-rs-node',
                '--all-targets', '--no-default-features', '--features', 'fjall', '--', '-D', 'warnings', cwd=work)
            if name == 'index-owner':
                run('cargo', 'test', '--locked', '-p', 'bitcoin-rs-index', '--no-default-features',
                    '--features', 'fjall', cwd=work)
            test_filter = 'state::events::' if name == 'chain-events' else 'txindex_worker::'
            run('cargo', 'test', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features',
                '--features', 'fjall', '--lib', test_filter, '--', '--test-threads=1', cwd=work)
            run('git', 'add', '--', *paths, cwd=work)
            staged = run('git', 'diff', '--cached', '--name-only', cwd=work, capture=True).splitlines()
            if set(staged) != set(paths):
                raise RuntimeError(f'Unexpected staged set: {staged}')
            run('git', 'config', 'user.name', 'github-actions[bot]', cwd=work)
            run('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com', cwd=work)
            run('git', 'commit', '-m', message, '-m', 'Related to #742 and #645. Source-only atomic refactor; no schema or consensus changes.', cwd=work)
            branch = f'refactor/node-cleanup-{name}'
            existing = run('git', 'ls-remote', '--heads', 'origin', f'refs/heads/{branch}', cwd=work, capture=True)
            if existing:
                sha = existing.split()[0]
                run('git', 'fetch', 'origin', sha, cwd=work)
                run('git', 'diff', '--exit-code', sha, 'HEAD', cwd=work)
                print(f'Existing branch has the identical validated tree: {branch}', flush=True)
            else:
                run('git', 'push', 'origin', f'HEAD:refs/heads/{branch}', cwd=work)
                sha = run('git', 'rev-parse', 'HEAD', cwd=work, capture=True)
            results[name] = {'branch': branch, 'sha': sha, 'result': 'published', 'paths': paths}
            print('PUBLISHED', json.dumps(results[name]), flush=True)
        except (subprocess.CalledProcessError, RuntimeError) as error:
            results[name] = {'result': 'blocked', 'error': str(error)}
            print(f'::error title={name}::{error}', flush=True)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write('## Atomic node cleanup publication\n\n```json\n' + json.dumps(results, indent=2) + '\n```\n')
    (temp / 'node-cleanup-results.json').write_text(json.dumps(results, indent=2))
    if any(result['result'] != 'published' for result in results.values()):
        return 1
    # Remove only this exact temporary branch, and only if nobody advanced it.
    temporary = 'refs/heads/automation/node-cleanup-publish-20260910'
    remote = run('git', 'ls-remote', '--heads', 'origin', temporary, cwd=checkout, capture=True)
    if remote and remote.split()[0] == os.environ['GITHUB_SHA']:
        run('git', 'push', 'origin', ':' + temporary, cwd=checkout)
    return 0


if __name__ == '__main__':
    sys.exit(main())
