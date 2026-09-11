from pathlib import Path
import re,sys
root=Path(sys.argv[1]); node=root/'crates/node/src'; qp=node/'txindex_worker/query.rs'; q=qp.read_text()
def part(text,a,b): return text[text.index(a):text.index(b)].strip()+'\n'
def methods(code):
    body=code[code.index('{')+1:code.rfind('}')]; out={}; pos=0
    for m in re.finditer(r'^    (?:pub(?:\([^)]*\))? )?fn (\w+)\b',body,re.M):
        e=re.search(r'^    }$',body[m.end():],re.M); assert e
        end=m.end()+e.end(); out[m[1]]=body[pos:end].strip('\n')+'\n'; pos=end
    assert not body[pos:].strip(); return out
ms=methods(part(q,'impl TxIndexQueryEngine {','/// One coherent read'))
transactions=['resolve_hash_at_height','hash_at_height','resolve_block','resolve_block_body_bytes','verify_block','validated_positions','resolve_positioned_transaction','transaction_from_full_block','transaction_for','locate_transaction_for','outpoint_value_for']
scripts=['scan_funding_rows','scan_spending_rows','scan_live_rows','collect_funding_outputs','funding_outputs_for','spender_for','spending_input','history_snapshot_for','unspent_outputs_for']
kept=[k for k in ms if k not in transactions+scripts]
header=q[:q.index('/// Aggregate work budget')]
imports=re.search(r'use super::\{(.*?)\};',header,re.S)[1]
names=[n.strip() for n in imports.replace('\n',' ').split(',') if n.strip()]+['QueryBudget','TxIndexQueryEngine']
def child_imports(code):
    defined=set(re.findall(r'\b(?:struct|enum|fn) (\w+)',code))
    selected=[n for n in names if n not in defined and re.search(r'\b'+n+r'\b',code)]
    return 'use super::{'+', '.join(selected)+'};\n\n'
def impl(keys):
    parts=[]
    for k in keys:
        code=ms[k]
        other='\n'.join(v for name,v in ms.items() if name not in keys)+q[q.index('impl TxIndexQuery for TxIndexQueryEngine {'):]
        if keys!=kept and re.search(r'\b'+k+r'\b',other): code=code.replace('    fn '+k,'    pub(super) fn '+k,1)
        parts.append(code.rstrip())
    return 'impl TxIndexQueryEngine {\n'+'\n\n'.join(parts)+'\n}\n'
budget=part(q,'/// Aggregate work budget','/// Authoritative Live query sources:')
budget=budget.replace('struct QueryBudget','pub(super) struct QueryBudget').replace('    const fn new','    pub(super) const fn new')
budget=re.sub(r'^    fn ','    pub(super) fn ',budget,flags=re.M)
a=budget.index('        if scan.rows.len() > self.remaining_rows'); b=budget.index('    pub(super) fn reserve_body_read',a)
budget=budget[:a]+'''        self.charge_scan(scan.rows.len(), scan.encoded_bytes)?;
        Ok(scan.rows)
    }

    pub(super) fn accept_live_scan(
        &mut self,
        scan: ScriptLiveScan,
    ) -> Result<Vec<bitcoin_rs_index::ScriptLiveRow>, TxQueryError> {
        if !scan.complete {
            return Err(TxQueryError::Unavailable("txindex live prefix scan truncated".into()));
        }
        self.charge_scan(scan.rows.len(), scan.encoded_bytes)?;
        Ok(scan.rows)
    }

    fn charge_scan(&mut self, rows: usize, encoded_bytes: usize) -> Result<(), TxQueryError> {
        if rows > self.remaining_rows || encoded_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable("txindex query work budget exceeded".into()));
        }
        self.remaining_rows -= rows;
        self.remaining_bytes -= encoded_bytes;
        Ok(())
    }

'''+budget[b:]
ms['scan_live_rows']=ms['scan_live_rows'][:ms['scan_live_rows'].index('        if !scan.complete')]+'''        budget.accept_live_scan(scan)
    }
'''
source=part(q,'/// Private index-side `BlockSource`:','impl TxIndexQuery for TxIndexQueryEngine {')
source=source.replace('    fn resolve_block_by_hash','    pub(super) fn resolve_block_by_hash')
base=qp.with_suffix(''); base.mkdir(parents=True,exist_ok=True)
for name,code,doc in [
    ('budget',budget,'//! Fail-closed aggregate work accounting for one public query.'),
    ('transactions',impl(transactions),'//! Exact-identity block reads and transaction position verification.'),
    ('scripts',impl(scripts),'//! Script history, spending, and live-view reads under the shared snapshot gate.'),
    ('block_source',source,'//! Resolve block bodies against captured chain identity, never height alone.')]:
    (base/(name+'.rs')).write_text(doc+'\n\n'+child_imports(code)+code+ ('\n#[cfg(test)]\nmod tests;\n' if name=='budget' else ''))
header=header.replace('//! Snapshot-gated txindex queries and the index-side block source.','''//! One snapshot gate for transaction, history, and live-view queries.
//! Resolution and script traversal stay in private child modules; all public
//! entrypoints retain health, revision, watermark, and chain-transition checks.''')
qp.write_text(header+'''mod block_source;
mod budget;
mod scripts;
mod transactions;

pub(crate) use block_source::IndexBlockSource;
use budget::QueryBudget;

'''+part(q,'/// Authoritative Live query sources:','impl TxIndexQueryEngine {')+'\n'+impl(kept)+'\n'+part(q,'/// One coherent read','/// Private index-side `BlockSource`:')+'\n'+q[q.index('impl TxIndexQuery for TxIndexQueryEngine {'):])
bt=base/'budget/tests.rs'; bt.parent.mkdir(parents=True,exist_ok=True); bt.write_text((Path(__file__).parent/'budget_tests.rs').read_text())
f=node/'txindex_worker.rs'; s=f.read_text(); a=s.index('\n}\n',s.index('impl PendingForward {'))
s=s[:a]+'''

    /// Transfers retained rows without changing their fence or flush deadline.
    fn take(&mut self, limits: PreparedBatchLimits) -> Self {
        let replacement = Self {
            fence: self.fence,
            watermarks: self.watermarks,
            capabilities: self.capabilities,
            durable: self.durable,
            batch: PreparedBatch::new(limits),
            deadline: self.deadline,
        };
        std::mem::replace(self, replacement)
    }
'''+s[a:]; f.write_text(s)
f=node/'txindex_worker/catch_up.rs'; s=f.read_text(); count=0
for indent in ['                ','                        ']:
    marker=indent+'let replacement = PendingForward {\n'
    while marker in s:
        a=s.index(marker); b=s.index(indent+'};\n',a)+len(indent+'};\n'); s=s[:a]+s[b:]; count+=1
assert count==3
s=s.replace('std::mem::replace(state, replacement)','state.take(self.batch_limits)'); f.write_text(s)
f=node/'txindex_worker/startup.rs'; s=f.read_text(); s=s.replace('use compact_str::CompactString;\n','')
a=s.index('    runtime.publish_failed(reason);'); b=s.index('\n/// Publishes a lifecycle transition',a)
s=s[:a]+'''    runtime.publish_failed(reason);
    publish_lifecycle(lifecycle, generation, TxIndexLifecycle::Failed(reason.into()));
}
'''+s[b:]; f.write_text(s)
f=node/'txindex_worker_lifecycle_tests.rs'; s=f.read_text(); s+='''
/// IDX-07: revocation fences publication, not this worker's failure signal.
#[test]
fn revoked_failure_stops_runtime_without_replacing_lifecycle_snapshot() {
    let lifecycle = Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::Opening));
    let before = lifecycle.load_full();
    let generation = Generation::new(1);
    let runtime = TxIndexRuntime::new(crossbeam_channel::bounded(1).0);
    generation.revoke();
    fail_worker(&runtime, &lifecycle, &generation, "detached failure");
    assert!(runtime.should_stop());
    assert_eq!(runtime.failure_message().as_deref(), Some("detached failure"));
    assert!(Arc::ptr_eq(&before, &lifecycle.load_full()));
}
'''; f.write_text(s)
f=root/'docs/contracts/indexing.md'; s=f.read_text(); s=s.replace('- `TxIndexRuntime`, `TxIndexQueryEngine`, `Worker` in `crates/node/src/txindex_worker.rs`','''- `TxIndexRuntime` and worker state in `crates/node/src/txindex_worker.rs`;
  reconciliation, cursor commits, bounded preparation, and rollback in its
  `reconciliation.rs`, `cursor.rs`, `catch_up.rs`, and `rollback.rs` modules.
- `TxIndexQueryEngine` in `crates/node/src/txindex_worker/query.rs` owns the shared
  snapshot gate and public query entrypoints. Its `query/transactions.rs`,
  `query/scripts.rs`, `query/block_source.rs`, and `query/budget.rs` modules own
  exact transaction resolution, script traversal, block identity, and aggregate
  work accounting respectively.
- Worker supervision and backend opening in `txindex_worker/lifecycle.rs` and
  `txindex_worker/startup.rs`; startup owns generation-checked publication.''')
s+='''
### Query-budget regression evidence

`crates/node/src/txindex_worker/query/budget/tests.rs` exercises the shared
historical/live byte budget, independent row/scan/body-read admission limits,
rejection of truncated scans, and non-consuming rejection of over-budget work
(`IDX-03`, `CL-14`). No query limit or persisted representation changes.
'''; f.write_text(s)
print('Query owner:',len(qp.read_text().splitlines()),'lines; extracted',len(transactions)+len(scripts),'methods; added seven regressions.')
