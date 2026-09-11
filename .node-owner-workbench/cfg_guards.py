"""Keep test-only dependencies gated across owner and import migrations."""
from pathlib import Path

root = Path(__file__).resolve().parent
path = root / 'refactor_patched.py'
source = path.read_text()
source = source.replace('    defined = {}\n', "    defined = {}\n    test_symbols = {name_of(source, node) for node, raw in parsed if is_test(raw)}\n")
old = "guard = '#[cfg(test)]\\n' if owning_group == 'fixtures' and group != 'fixtures' else ''"
new = "guard = '#[cfg(test)]\\n' if (owning_group == 'fixtures' or symbol in test_symbols) and group != 'fixtures' else ''"
assert old in source
source = source.replace(old, new)
path.write_text(source)
path = root / 'phase1.py'
source = path.read_text()
source += '\nfrom phase1_imports import after_fix\n'
path.write_text(source)
path = root / 'build_candidates.py'
source = path.read_text()
old = '        cleanup_imports(log)\n        command('
new = "        cleanup_imports(log)\n        if hasattr(phase, 'after_fix'):\n            phase.after_fix()\n        command("
assert old in source
path.write_text(source.replace(old, new))
