"""Keep test-only dependencies gated across owner and import migrations."""
from pathlib import Path

root = Path(__file__).resolve().parent
path = root / 'refactor_patched.py'
source = path.read_text()
source = source.replace('    defined = {}\n', "    defined = {}\n    test_symbols = {name_of(source, node) for node, raw in parsed if is_test(raw)} - {name_of(source, node) for node, raw in parsed if not is_test(raw)}\n")
old = "guard = '#[cfg(test)]\\n' if owning_group == 'fixtures' and group != 'fixtures' else ''"
new = "guard = '#[cfg(test)]\\n' if (owning_group == 'fixtures' or symbol in test_symbols) and group != 'fixtures' else ''"
assert old in source
path.write_text(source.replace(old, new))
path = root / 'phase1.py'
path.write_text(path.read_text() + '\nfrom phase1_imports import after_fix\n')
path = root / 'build_candidates.py'
source = path.read_text()
old = '        cleanup_imports(log)\n        command('
new = "        cleanup_imports(log)\n        if hasattr(phase, 'after_fix'):\n            phase.after_fix()\n        command("
assert old in source
path.write_text(source.replace(old, new))
# AST offsets count UTF-8 bytes; convert to a character offset before slicing
# documentation. Keep every real import regardless of its original ordering.
path = root / 'phase5.py'
source = path.read_text()
old = "first_import = text.index('use anyhow')"
new = "first_import = len(text.encode()[:next(node.start_byte for node in r.parse(text).named_children if node.type not in ('line_comment', 'block_comment'))].decode())"
assert old in source
path.write_text(source.replace(old, new))
path = root / 'lint_helpers.py'
source = path.read_text()
needle = "        subprocess.run(['rustfmt', '--edition', '2024', *rust], check=True)"
assert needle in source
path.write_text(source.replace(needle, needle + "\n    subprocess.run(['cargo', 'fmt', '--all'], check=True)"))
from resume_candidates import patch
patch(root)
