from pathlib import Path
p=Path('crates/node/src/storage_backend.rs')
s=p.read_text()
old='''            "storage_footprint.rs",
            include_str!("storage_footprint.rs"),
            Some("mod tests {"),'''
assert old in s
assert 'mod tests;' in Path('crates/node/src/storage_footprint.rs').read_text()
s=s.replace(old,old.replace('mod tests {','mod tests;'))
p.write_text(s)
print('Corrected the stale storage_footprint test-module cutoff without weakening its constructor scan')
