"""Keep a test-only item's imports gated when its owner is split."""
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
source = source.replace("if 'use arc_swap::ArcSwap;' not in text:", "if 'ArcSwap::' in text and 'use arc_swap::ArcSwap;' not in text:")
path.write_text(source)
