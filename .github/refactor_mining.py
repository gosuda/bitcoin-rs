from pathlib import Path
import re
p=Path('crates/node/src/mining.rs'); orig=p.read_text(); lines=orig.splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel,body):
 q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')

gen=sl(52,225)
gen=gen.replace('''struct InFlight {
    key: GenerationKey,
    result: Option<Result<Arc<Candidate>, MiningControlError>>,
}''','''pub(super) struct InFlight {
    pub(super) key: GenerationKey,
    pub(super) result: Option<Result<Arc<Candidate>, MiningControlError>>,
}''')
gen=gen.replace('''struct CoordinatorState {
    /// Last generation published to long-poll waiters.
    published: Option<GenerationKey>,
    /// Bounded LRU of assembled candidates keyed by template id.
    cache: HashMap<TemplateId, Arc<Candidate>>,
    /// Insertion order for deterministic eviction of the oldest entry.
    cache_order: VecDeque<TemplateId>,
    /// Single in-flight assembly, if any.
    in_flight: Option<InFlight>,
    /// Facts from the most recently assembled candidate.
    last_candidate: Option<LastCandidateInfo>,
}''','''pub(super) struct CoordinatorState {
    /// Last generation published to long-poll waiters.
    pub(super) published: Option<GenerationKey>,
    /// Bounded LRU of assembled candidates keyed by template id.
    pub(super) cache: HashMap<TemplateId, Arc<Candidate>>,
    /// Insertion order for deterministic eviction of the oldest entry.
    pub(super) cache_order: VecDeque<TemplateId>,
    /// Single in-flight assembly, if any.
    pub(super) in_flight: Option<InFlight>,
    /// Facts from the most recently assembled candidate.
    pub(super) last_candidate: Option<LastCandidateInfo>,
}''')
gen=re.sub(r'(?m)^    fn (new|cache_get|cache_insert|invalidate_key)\(', r'    pub(super) fn \1(', gen)
write('mining/generation.rs','//! Candidate generation identity, cache state, and mutation wake signals.\n\nuse super::*;\n\n'+gen)
write('mining/coordinator.rs','//! Mining coordinator construction, template lifecycle, and MiningControl implementation.\n\nuse super::*;\nuse super::generation::*;\nuse super::util::*;\n\n'+sl(227,914))
util=re.sub(r'(?m)^fn ', 'pub(super) fn ', sl(915,1223))
write('mining/util.rs','//! Mining request parsing, hash-rate estimation, and small conversion helpers.\n\nuse super::*;\n\n'+util)
write('mining/tests.rs','use super::*;\nuse super::generation::*;\nuse super::util::*;\n\n'+sl(1224,len(lines)))
root=sl(1,50)+'''\nmod coordinator;\nmod generation;\nmod util;\n#[cfg(test)]\nmod tests;\n\npub use coordinator::MiningCoordinator;\npub use generation::{GenerationKey, MempoolSequenceWake, MiningGenerationSignal};\n\n'''
p.write_text(root.rstrip()+'\n')
