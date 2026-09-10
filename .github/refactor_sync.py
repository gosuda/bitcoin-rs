from pathlib import Path
import re

def patch_baseline():
    p=Path('crates/consensus/src/verify_block_impl.rs'); s=p.read_text(); n="pub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {\n    let Some(commitment)"; r="/// Validates the BIP141 witness commitment for a decoded block.\npub fn block_witness_commitment_matches(block: &Block, wtxids: &[Wtxid]) -> bool {\n    let Some(coinbase) = block.txs.first() else {\n        return false;\n    };\n    let Some(commitment)"; assert n in s; p.write_text(s.replace(n,r,1))
    p=Path('crates/consensus/src/block_view.rs'); s=p.read_text(); assert '    Hash256, Tx,' in s; p.write_text(s.replace('    Hash256, Tx,','    Tx,',1))
    p=Path('crates/p2p/src/wire.rs'); s=p.read_text(); n="        other => {\n            let envelope = other.envelope();\n            bitcoin::consensus::Encodable::consensus_encode(&envelope, &mut std::io::sink())?\n        }"; r="        other => encode_payload(other)?.len(),"; assert n in s; p.write_text(s.replace(n,r,1))
    p=Path('crates/node/src/chainstate_journal/record.rs'); s=p.read_text(); n='self.len = self.len.checked_add(bytes.len()).ok_or(io::ErrorKind::Other.into())?;'; r='self.len = self.len.checked_add(bytes.len()).ok_or_else(|| io::Error::from(io::ErrorKind::Other))?;'; assert n in s; p.write_text(s.replace(n,r,1))
    p=Path('crates/node/src/metrics/evidence/digest.rs'); s=p.read_text(); s=s.replace('use serde::Deserialize as _;\n','',1); p.write_text(s)
    p=Path('crates/node/src/reorg.rs'); s=p.read_text(); s=s.replace('let (root, target) = {','let (_root, target) = {',1); p.write_text(s)
patch_baseline()

p=Path('crates/node/src/sync.rs'); lines=p.read_text().splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel,body):
 q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')
def localize_methods(body): return re.sub(r'(?m)^    fn ', '    pub(super) fn ', body)
def localize_fns(body): return re.sub(r'(?m)^fn ', 'pub(super) fn ', body)
write('sync/peers.rs','//! Peer fault classification and demonstrated-height capability policy.\n\nuse super::*;\n\n'+localize_fns(sl(112,179)))
write('sync/settlement.rs','//! Apply-window settlement and drained-block restoration policy.\n\nuse super::*;\n\n'+localize_fns(sl(180,244)))
for name,a,b,extra in [
 ('orchestrator.rs',247,457,'use super::settlement::*;\n'),
 ('headers.rs',458,607,'use super::peers::*;\n'),
 ('blocks.rs',608,1073,'use super::settlement::*;\n'),
 ('expected.rs',1075,1250,''),
 ('requests.rs',1252,1693,'use super::peers::*;\n'),
 ('telemetry.rs',1694,1811,''),
]:
 body=localize_methods(sl(a,b)); body=localize_fns(body)
 write('sync/'+name,'use super::*;\n'+extra+'\nimpl BlockSync {\n'+body+'\n}\n')
telemetry_path = p.parent / 'sync/telemetry.rs'
telemetry_path.write_text(telemetry_path.read_text().rstrip()+'\n\n'+localize_fns(sl(1814,1816)).rstrip()+'\n')
write('sync/tests.rs',sl(1820,len(lines)-1))
root=sl(1,111)+'''\nmod blocks;\nmod expected;\nmod headers;\nmod orchestrator;\nmod peers;\nmod requests;\nmod settlement;\nmod telemetry;\n#[cfg(test)]\nmod tests;\n\nuse telemetry::metric_count;\n\n'''
p.write_text(root.rstrip()+'\n')
