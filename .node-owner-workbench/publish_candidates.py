"""Publish only validated feature refs; never merge, force-push, or write main."""
from pathlib import Path
import json
import os
import subprocess
import sys

folder = Path(sys.argv[1]).resolve()
manifest = json.loads((folder / 'manifest.json').read_text())
assert manifest['complete'] is True
assert len(manifest['phases']) == 5
assert all(code == 0 for code in manifest['checks'].values())
expected = ['chainstate', 'block-sync', 'index-runtime', 'durability', 'mining-storage']
refs = []
parent = manifest['base']
for index, (phase, owner) in enumerate(zip(manifest['phases'], expected), 1):
    branch = 'refactor/node-' + owner + '-breaking-20260911'
    assert phase['number'] == index and phase['owner'] == owner and phase['branch'] == branch
    subprocess.run(['git', 'fetch', str(folder / 'candidates.bundle'), 'refs/heads/' + branch], check=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'FETCH_HEAD'], text=True).strip()
    assert commit == phase['commit']
    actual_parent = subprocess.check_output(['git', 'rev-parse', commit + '^'], text=True).strip()
    assert actual_parent == parent
    tree = subprocess.check_output(['git', 'rev-parse', commit + '^{tree}'], text=True).strip()
    assert tree == phase['tree']
    parent = commit
    refs.append(commit + ':refs/heads/' + branch)
# Atomic non-forced publication rejects unexpected existing divergent refs.
subprocess.run(['git', 'push', '--atomic', 'origin', *refs], check=True)
print(json.dumps({'published': [{'branch': p['branch'], 'commit': p['commit'], 'tree': p['tree']} for p in manifest['phases']]}, indent=2))
