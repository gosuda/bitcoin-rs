from pathlib import Path

# Validation-only repairs for compile blockers already present on main.
# Final refactor branches must not include these files.
p = Path('crates/consensus/src/verify_block_impl.rs')
s = p.read_text()
needle = "pub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {\n    let Some(commitment)"
replacement = "pub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {\n    let Some(coinbase) = block.txs.first() else {\n        return false;\n    };\n    let Some(commitment)"
assert needle in s
p.write_text(s.replace(needle, replacement, 1))

p = Path('crates/consensus/src/block_view.rs')
s = p.read_text(); assert '    Hash256, Tx,' in s
p.write_text(s.replace('    Hash256, Tx,', '    Tx,', 1))

p = Path('crates/p2p/src/wire.rs')
s = p.read_text()
needle = "            let envelope = other.envelope();\n            bitcoin::consensus::Encodable::consensus_encode(&envelope, &mut std::io::sink())?"
replacement = "            let envelope = other.envelope();\n            let mut encoded = Vec::new();\n            bitcoin::consensus::Encodable::consensus_encode(&envelope, &mut encoded)?;\n            encoded.len()"
assert needle in s; p.write_text(s.replace(needle, replacement, 1))

p = Path('crates/node/src/chainstate_journal/record.rs')
s = p.read_text()
needle = 'self.len = self.len.checked_add(bytes.len()).ok_or(io::ErrorKind::Other.into())?;'
replacement = 'self.len = self.len.checked_add(bytes.len()).ok_or_else(|| io::Error::from(io::ErrorKind::Other))?;'
assert needle in s; p.write_text(s.replace(needle, replacement, 1))
