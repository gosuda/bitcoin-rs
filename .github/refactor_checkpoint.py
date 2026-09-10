from pathlib import Path
import re

def patch_baseline():
    p=Path('crates/consensus/src/verify_block_impl.rs'); s=p.read_text(); n="pub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {\n    let Some(commitment)"; r="/// Validates the BIP141 witness commitment for a decoded block.\npub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {\n    let Some(coinbase) = block.txs.first() else {\n        return false;\n    };\n    let Some(commitment)"; assert n in s; p.write_text(s.replace(n,r,1))
    p=Path('crates/consensus/src/block_view.rs'); s=p.read_text(); assert '    Hash256, Tx,' in s; p.write_text(s.replace('    Hash256, Tx,','    Tx,',1))
    p=Path('crates/p2p/src/wire.rs'); s=p.read_text(); n="        other => {\n            let envelope = other.envelope();\n            bitcoin::consensus::Encodable::consensus_encode(&envelope, &mut std::io::sink())?\n        }"; r="        other => encode_payload(other)?.len(),"; assert n in s; p.write_text(s.replace(n,r,1))
    p=Path('crates/node/src/chainstate_journal/record.rs'); s=p.read_text(); n='self.len = self.len.checked_add(bytes.len()).ok_or(io::ErrorKind::Other.into())?;'; r='self.len = self.len.checked_add(bytes.len()).ok_or_else(|| io::Error::from(io::ErrorKind::Other))?;'; assert n in s; p.write_text(s.replace(n,r,1))
patch_baseline()

p=Path('crates/node/src/checkpoint.rs'); orig=p.read_text(); lines=orig.splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel,body):
 q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')
def localize_fns(body): return re.sub(r'(?m)^fn ', 'pub(super) fn ', body)

header=localize_fns(sl(23,29)+sl(56,428))
header=re.sub(r'(?m)^const ', 'pub(super) const ', header)
write('checkpoint/headers.rs','//! Canonical header-checkpoint codec and commitments.\n\nuse super::*;\n\n'+header)
write('checkpoint/io.rs','//! Durable checkpoint file publication primitives and failpoints.\n\nuse super::*;\n\n'+localize_fns(sl(1064,1215)))
write('checkpoint/load.rs','//! Manifest validation, artifact loading, and generation discovery.\n\nuse super::*;\n\n'+localize_fns(sl(1216,1601)))
write('checkpoint/housekeeping.rs','//! Best-effort cleanup of superseded checkpoint generations.\n\nuse super::*;\n\n'+localize_fns(sl(1602,1652)))
write('checkpoint/codec.rs','//! Small manifest text and hex conversion helpers.\n\nuse super::*;\n\n'+localize_fns(sl(1653,1728)))
write('checkpoint/tests.rs','use super::*;\nuse super::headers::*;\nuse super::io::*;\nuse super::load::*;\n\n'+sl(1731,len(lines)-1))
root=sl(1,22)+sl(30,55)+'''\nmod codec;\nmod headers;\nmod housekeeping;\nmod io;\nmod load;\n#[cfg(test)]\nmod tests;\n\npub(crate) use headers::{HeaderCheckpointConfig, HeaderCheckpointError, HeaderCheckpointMetadata, HeaderCheckpointPoint, HeaderCheckpointTip, HeaderCheckpointWrite, RestoredHeaders, read_headers, write_headers};\nuse headers::write_selected_headers;\nuse codec::*;\nuse housekeeping::*;\nuse io::*;\nuse load::*;\n\n'''+sl(430,1063)
p.write_text(root.rstrip()+'\n')
