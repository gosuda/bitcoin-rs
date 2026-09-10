"""Add hash-checked rename deletions to the temporary publication driver."""
from pathlib import Path

source = Path('.github/publish-node-owners.py').read_text()
changes = {
    "    report['base'] = plan['base']": """    deletions = json.loads(Path('.github/node-owner-deletions.json').read_text())
    for stage in plan['stages']:
        stage['deletions'] = deletions.get(stage['payload'], {})
    report['base'] = plan['base']""",
    "        outputs = reconstruct(payload)": """        outputs = reconstruct(payload)
        for path, expected in stage.get('deletions', {}).items():
            checked_path(path)
            if blob(git('show', 'HEAD:' + path)) != expected:
                raise ValueError('Deletion source identity mismatch: ' + path)
            if path in outputs:
                raise ValueError('Deletion duplicates an output: ' + path)
            outputs[path] = None""",
}
for old, new in changes.items():
    if source.count(old) != 1:
        raise ValueError('Publication driver boundary changed')
    source = source.replace(old, new, 1)
compile(source, 'publish-node-owners.py', 'exec')
Path('/tmp/publish-node-owners.py').write_text(source)
