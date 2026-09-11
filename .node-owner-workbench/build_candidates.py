"""Build and validate atomic candidates; this script never pushes any ref."""
from pathlib import Path
import importlib
import json
import os
import subprocess
import sys
import tarfile
from support import r, BASE
from lint_helpers import cleanup_imports, normalize, print_errors

OUTPUT = Path(os.environ['OWNER_EVIDENCE'])
OUTPUT.mkdir(parents=True, exist_ok=True)
PHASES = [
    ('chainstate', 'refactor(node)!: replace apply monolith with chainstate and reorg owners'),
    ('block-sync', 'refactor(node)!: replace sync monolith with block-sync owners'),
    ('index-runtime', 'refactor(node)!: replace txindex worker monolith with index-runtime owners'),
    ('durability', 'refactor(node)!: separate durability owners and delete journal adapters'),
    ('mining-storage', 'refactor(node)!: separate mining and storage measurement owners'),
]
CARGO = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq', '--all-targets']
manifest = {'base': BASE, 'phases': [], 'checks': {}, 'complete': False}


def command(arguments, label, required=True):
    log = OUTPUT / (label + '.log')
    print('RUN', label, flush=True)
    with log.open('w') as handle:
        result = subprocess.run(arguments, stdout=handle, stderr=subprocess.STDOUT)
    print('EXIT', label, result.returncode, flush=True)
    manifest['checks'][label] = result.returncode
    if result.returncode:
        print(log.read_text()[-16000:], flush=True)
        if required:
            raise RuntimeError(label + ' failed')
    return log, result.returncode


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


try:
    assert git('rev-parse', 'HEAD') == BASE
    command(['rustc', '--version', '--verbose'], 'rust-toolchain')
    for index, (owner, title) in enumerate(PHASES, 1):
        r.MIGRATIONS.clear()
        r.CHANGED.clear()
        phase = importlib.import_module('phase' + str(index))
        print('TRANSFORM', index, owner, flush=True)
        phase.run()
        log, code = command(['cargo', 'check', *CARGO, '--message-format=json'], f'phase{index}-check', False)
        if code:
            print_errors(log)
            raise RuntimeError('type checking failed for phase ' + str(index))
        cleanup_imports(log)
        command(['cargo', 'fix', *CARGO, '--allow-dirty', '--allow-staged'], f'phase{index}-fix')
        if hasattr(phase, 'after_fix'):
            phase.after_fix()
        normalize()
        command(['cargo', 'fmt', '--all', '--', '--check'], f'phase{index}-fmt')
        command(['cargo', 'clippy', *CARGO, '--', '-D', 'warnings'], f'phase{index}-clippy')
        command(['git', 'diff', '--check'], f'phase{index}-whitespace')
        subprocess.run(['git', 'add', '-A'], check=True)
        changed = git('diff', '--cached', '--name-only').splitlines()
        assert changed and all(not path.startswith(('.github/', '.node-owner-workbench/')) for path in changed)
        env = dict(os.environ, GIT_AUTHOR_DATE=f'2026-09-11T10:0{index}:00Z', GIT_COMMITTER_DATE=f'2026-09-11T10:0{index}:00Z')
        subprocess.run(['git', 'commit', '-m', title], check=True, env=env)
        branch = 'refactor/node-' + owner + '-breaking-20260911'
        subprocess.run(['git', 'branch', branch], check=True)
        manifest['phases'].append({'number': index, 'owner': owner, 'title': title, 'branch': branch, 'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'), 'changed_files': changed})
        (OUTPUT / 'manifest.json').write_text(json.dumps(manifest, indent=2))

    command(['cargo', 'test', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq', '--lib'], 'node-unit-tests')
    command(['cargo', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--', '--nocapture'], 'ownership-gates')
    inventory = sorted([(str(path), len(path.read_text().splitlines())) for path in r.ROOT.rglob('*.rs')], key=lambda entry: -entry[1])
    (OUTPUT / 'source-inventory.json').write_text(json.dumps(inventory, indent=2))
    print('LARGEST SOURCE FILES', inventory[:15], flush=True)
    manifest['complete'] = True
finally:
    (OUTPUT / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    if manifest['phases']:
        subprocess.run(['git', 'bundle', 'create', str(OUTPUT / 'candidates.bundle'), *['refs/heads/' + phase['branch'] for phase in manifest['phases']]], check=True)
    # Preserve the partial working tree as well as validated commits after any
    # failure, so an interrupted editing session does not lose completed work.
    paths = set(subprocess.check_output(['git', 'ls-files', '-co', '--exclude-standard'], text=True).splitlines())
    with tarfile.open(OUTPUT / 'working-source.tar.gz', 'w:gz') as archive:
        for name in sorted(paths):
            path = Path(name)
            if path.is_file() and not name.startswith(('.git/', 'target/', '.node-owner-workbench/')):
                archive.add(path, arcname=name, recursive=False)
    print(json.dumps(manifest, indent=2), flush=True)
