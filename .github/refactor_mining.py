from pathlib import Path
import re
p=Path('crates/node/src/mining.rs'); orig=p.read_text(); lines=orig.splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel,body):
 q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')

gen=sl(52,227)
gen=gen.replace('struct InFlight {','pub(super) struct InFlight {').replace('    key: GenerationKey,','    pub(super) key: GenerationKey,').replace('    result: Option<Result<Arc<Candidate>, MiningControlError>>,','    pub(super) result: Option<Result<Arc<Candidate>, MiningControlError>>,')
gen=gen.replace('struct CoordinatorState {','pub(super) struct CoordinatorState {')
for field in ['published','cache','cache_order','in_flight','last_candidate']:
 gen=gen.replace(f'    {field}:', f'    pub(super) {field}:')
gen=re.sub(r'(?m)^    fn (new|cache_get|cache_insert|invalidate_key)\(', r'    pub(super) fn \1(', gen)
write('mining/generation.rs','//! Candidate generation identity, cache state, and mutation wake signals.\n\nuse super::*;\n\n'+gen)
write('mining/coordinator.rs','//! Mining coordinator construction, template lifecycle, and MiningControl implementation.\n\nuse super::*;\nuse super::generation::*;\nuse super::util::*;\n\n'+sl(234,914))
util=sl(915,1223)
util=re.sub(r'(?m)^fn ', 'pub(super) fn ', util)
write('mining/util.rs','//! Mining request parsing, hash-rate estimation, and small conversion helpers.\n\nuse super::*;\n\n'+util)
write('mining/tests.rs','use super::*;\nuse super::generation::*;\nuse super::util::*;\n\n'+sl(1224,len(lines)))
root=sl(1,50)+'''\nmod coordinator;\nmod generation;\nmod util;\n#[cfg(test)]\nmod tests;\n\npub use coordinator::MiningCoordinator;\npub use generation::{GenerationKey, MempoolSequenceWake, MiningGenerationSignal};\n\n'''
p.write_text(root.rstrip()+'\n')
