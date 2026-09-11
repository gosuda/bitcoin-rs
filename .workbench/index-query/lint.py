from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve()
path = root / 'crates/index/src/query/tests/source.rs'
text = path.read_text()
old = 'removed node BlockLog'
assert text.count(old) == 1
path.write_text(text.replace(old, 'removed node `BlockLog`'))
