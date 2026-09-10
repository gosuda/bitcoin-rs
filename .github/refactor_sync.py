from pathlib import Path
import re
p=Path('crates/node/src/sync.rs'); orig=p.read_text(); lines=orig.splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel,body):
 q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')
def localize_methods(body): return re.sub(r'(?m)^    fn ', '    pub(super) fn ', body)
def localize_fns(body): return re.sub(r'(?m)^fn ', 'pub(super) fn ', body)
write('sync/peers.rs','//! Peer fault classification and demonstrated-height capability policy.\n\nuse super::*;\n\n'+localize_fns(sl(112,179)))
write('sync/settlement.rs','//! Apply-window settlement and drained-block restoration policy.\n\nuse super::*;\n\n'+localize_fns(sl(180,244)))
for name,a,b,extra in [
 ('core.rs',247,457,'use super::settlement::*;\n'),
 ('headers.rs',458,607,'use super::peers::*;\n'),
 ('blocks.rs',608,1086,'use super::settlement::*;\n'),
 ('expected.rs',1087,1251,''),
 ('requests.rs',1252,1693,'use super::peers::*;\n'),
 ('metrics.rs',1694,1811,''),
]:
 body=localize_methods(sl(a,b)); body=localize_fns(body)
 write('sync/'+name,'use super::*;\n'+extra+'\nimpl BlockSync {\n'+body+'\n}\n')
metrics_path = p.parent / 'sync/metrics.rs'
metrics_path.write_text(metrics_path.read_text().rstrip() + '\n\n' + localize_fns(sl(1814,1816)).rstrip() + '\n')
write('sync/tests.rs', sl(1820,len(lines)-1))
root=sl(1,111)+'''\nmod blocks;\nmod core;\nmod expected;\nmod headers;\nmod metrics;\nmod peers;\nmod requests;\nmod settlement;\n#[cfg(test)]\nmod tests;\n\n'''
p.write_text(root.rstrip()+'\n')
