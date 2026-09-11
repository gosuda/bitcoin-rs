"""Resume from the exact previously verified four-commit artifact."""
from pathlib import Path


def patch(root):
    path = root / 'build_candidates.py'
    source = path.read_text()
    needle = "    assert git('rev-parse', 'HEAD') == BASE\n"
    replacement = needle + '''    previous = Path(os.environ['OWNER_PREVIOUS'])
    saved = json.loads((previous / 'manifest.json').read_text())
    expected = [
        '526255e65507dcf4b292937b40b1f5a58ca7d030',
        '572cc63827a54b6f525cd93490663e6328ea1841',
        'acc73ec309f4a36c26a383e31c55f40c0ddd1ce4',
        '05dcae6716f2bf8f9f5c6c14f809934c4d3987ce',
    ]
    assert saved['base'] == BASE
    assert [phase['commit'] for phase in saved['phases']] == expected
    assert saved['phases'][-1]['tree'] == 'e371624e6257d129dd16d620e1079e91aaff491b'
    # The earlier attempt stopped at phase5 type checking. Phases1-4 each
    # passed check, fix, formatting, Clippy, and whitespace validation.
    assert saved['checks'].pop('phase5-check') != 0
    assert all(code == 0 for code in saved['checks'].values())
    for phase in saved['phases']:
        ref = 'refs/heads/' + phase['branch']
        subprocess.run(['git', 'fetch', str(previous / 'candidates.bundle'), ref + ':' + ref], check=True)
        assert git('rev-parse', ref) == phase['commit']
        assert git('rev-parse', ref + '^{tree}') == phase['tree']
    subprocess.run(['git', 'checkout', '--detach', expected[-1]], check=True)
    manifest.update(saved)
    manifest['complete'] = False
    manifest['resumed_from_run'] = 34589557615
    for log in previous.glob('phase[1-4]-*.log'):
        (OUTPUT / log.name).write_bytes(log.read_bytes())
'''
    assert needle in source
    source = source.replace(needle, replacement)
    needle = '    for index, (owner, title) in enumerate(PHASES, 1):\n'
    assert needle in source
    source = source.replace(needle, needle + '        if index <= 4:\n            continue\n')
    path.write_text(source)
