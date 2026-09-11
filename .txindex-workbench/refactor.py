from pathlib import Path
import re, sys, hashlib, textwrap
root = Path(sys.argv[1]).resolve()
node = root / 'crates/node/src'
p = node / 'txindex_worker.rs'
s = p.read_text()
assert hashlib.sha1(b'blob '+str(len(s.encode())).encode()+b'\0'+s.encode()).hexdigest() == 'd6df8fe97a182a92b3da66c31b5dbd4287b58042'
def cut(a,b): return s[s.index(a):s.index(b)].strip()+'\n'
def methods(code):
    body=code[code.index('{')+1:code.rfind('}')]; out={}; pos=0
    for m in re.finditer(r'^    (?:pub(?:\([^)]*\))? )?fn (\w+)\b',body,re.M):
        e=re.search(r'^    }$',body[m.end():],re.M); assert e
        end=m.end()+e.end(); part=body[pos:end].strip('\n')+'\n'
        assert len(re.findall(r'^    (?:pub(?:\([^)]*\))? )?fn ',part,re.M))==1
        out[m[1]]=part; pos=end
    assert not body[pos:].strip()
    return out
wm=methods(cut('impl Worker {','\nenum CursorCommit'))
qm=methods(cut('impl TxIndexQueryEngine {','/// One coherent read of index progress'))
groups={
'':['run','reconcile_once','reconcile_pass','reconcile_pending','capture_target_watermarks','persist_chain_cursor','cursor_for_result','commit_pending'],
'forward':['collect_target_chain','catch_up_to','prepare_and_admit_chunk','finish_catch_up','sync_and_commit'],
'rollback':['reset_for_rebuild','report_index_ahead','rollback_selection','forward_selection','watermark_is_on_target_chain','rollback_depth_for','rollback_one','load_body'],
'live':['seed_live_from_utxo','live_anchor']}
assert set(sum(groups.values(),[]))==set(wm)
shared={'catch_up_to','sync_and_commit','reset_for_rebuild','report_index_ahead','rollback_selection','forward_selection','watermark_is_on_target_chain','rollback_depth_for','rollback_one','seed_live_from_utxo','live_anchor'}
def impl(name,ms,keys,expose=()):
    return 'impl '+name+' {\n'+'\n\n'.join(ms[k].replace('    fn '+k,'    pub(super) fn '+k,1).rstrip() if k in expose else ms[k].rstrip() for k in keys)+'\n}\n'
ext={
'arc_swap':'ArcSwap',
'bitcoin_rs_chain':'BlockBodySource BlockTree TipSnapshot',
'bitcoin_rs_index':'BlockSource ConsumerCursorUpdate IndexCapabilities IndexCapability IndexError IndexReader IndexWatermark IndexWatermarks IndexWriteFence NoSpentScripts PreparedBatch PreparedBatchLimits PreparedBlock ScriptHash ScriptLiveScan TxIndexScan TxIndexScanRow TxIndexSnapshot',
'bitcoin_rs_index::reconcile':'ReconcileLeg ReconcilePhase SelectedWatermark selected_watermark',
'bitcoin_rs_index::recovery':'open_writer',
'bitcoin_rs_index::types':'TxPosition TxPositionValue',
'bitcoin_rs_index::writer':'TxIndexWriter',
'bitcoin_rs_primitives':'Block BlockHash Hash256 OutPoint Tx Txid deserialize',
'bitcoin_rs_rpc::capabilities':'CapabilityState CapabilityStatus TxIndexCapabilitySource txindex_status',
'bitcoin_rs_rpc::context':'BlockLog ScriptHistoryRecord ScriptIndexQuery ScriptIndexRecord ScriptIndexSnapshot SpendingRecord TxIndexInfo TxIndexQuery TxQueryError record_at_height',
'bitcoin_rs_storage':'PrefixScanLimit',
'bitcoin_rs_storage::block_body':'BlockBodyReader BlockBodyStore',
'compact_str':'CompactString','crossbeam_channel':'Receiver Sender','parking_lot':'Mutex RwLock',
'std::path':'Path PathBuf','std::sync':'Arc','std::sync::atomic':'AtomicBool AtomicU64 Ordering','std::thread':'JoinHandle','std::time':'Duration Instant'}
internal={'runtime':'TxIndexRuntime','lifecycle':'TxIndexLifecycle Generation fail_worker publish_lifecycle','query_adapter':'TxIndexQueryAdapter','query':'QueryEngineLive TxIndexQueryEngine IndexProgress','block_source':'IndexBlockSource','capability':'TxIndexCapability','store':'OpenTxIndex open_tx_index_with_timeout TXINDEX_OPEN_TIMEOUT','error':'TxIndexWorkerError','heartbeat':'Heartbeat','namespace':'NAMESPACE_REGISTRY NamespaceRegistry','scheduling':'BatchWait wait_for_batch_deadline wait_for_revision_quiet','':'Worker PendingForward ReconcileAction REVISION_QUIET_PERIOD FORWARD_BATCH_DELAY'}
def imports(code,module):
    clean=re.sub(r'//[^\n]*','',code); clean=re.sub(r'"(?:[^"\\]|\\.)*"','""',clean,flags=re.S)
    defined=set(re.findall(r'\b(?:struct|enum|trait|type|const|fn) (\w+)',clean))
    def used(n): return n not in defined and re.search(r'(?<![:\w])'+re.escape(n)+r'\b',clean)
    out=[]
    def add(path,names):
        if names: out.append('use '+path+'::'+(names[0] if len(names)==1 else '{'+', '.join(names)+'}')+';')
    for path,names in ext.items():
        selected=[n for n in names.split() if used(n)]
        if module=='supervisor' and path=='bitcoin_rs_index' and 'PreparedBatchLimits' in selected:
            selected.remove('PreparedBatchLimits'); out.append('#[cfg(test)]\nuse bitcoin_rs_index::PreparedBatchLimits;')
        if module=='supervisor' and path=='bitcoin_rs_index::writer':
            out.append('#[cfg(test)]\nuse bitcoin_rs_index::writer::TxIndexWriter;'); selected=[]
        if module=='rollback' and path=='bitcoin_rs_index::reconcile': selected=[n for n in selected if n!='selected_watermark']
        add(path,selected)
    if re.search(r'(?<![:\w])thread::',clean): out.append('use std::thread;')
    if '.par_iter()' in code or '.into_par_iter()' in code: out.append('use rayon::prelude::*;')
    for path,names in internal.items():
        if path==module: continue
        selected=[n for n in names.split() if used(n)]
        prefix=('' if module=='' else 'super::')+(path+'::' if path else '')
        if selected:
            assert prefix
            out.append('use '+prefix+(selected[0] if len(selected)==1 else '{'+', '.join(selected)+'}')+';')
    return '\n'.join(out)+'\n\n'
def write(name,code,doc,extra='',tail=''):
    f=p if not name else node/'txindex_worker'/(name+'.rs'); f.parent.mkdir(parents=True,exist_ok=True)
    f.write_text(doc.rstrip()+'\n\n'+imports(code,name)+extra+code.rstrip()+'\n'+tail)
runtime=cut('/// Shared wake/revision/health state','/// Monotonic publication token.')
runtime=runtime.replace('    /// Returns true once a failure or shutdown has been published.','''    /// Returns whether failure has been published, independently of shutdown.
    pub(super) fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    /// Returns whether graceful shutdown has been requested.
    pub(super) fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Returns true once a failure or shutdown has been published.''')
write('runtime',runtime,'//! Shared revision, wake, health, and reconciliation-phase publication.\n//! This is the only runtime state shared by apply, the worker, and readers.')
lifecycle=cut('/// Monotonic publication token.','/// Stable outer query adapter').replace('    fn query_payload(','    pub(super) fn query_payload(').replace('    fn unavailable_reason(','    pub(super) fn unavailable_reason(')
open_marker='/// Opens the store, constructs the engine, publishes lifecycle, and runs.'
publish=cut('/// Publishes a lifecycle transition',open_marker).replace('fn publish_lifecycle(','pub(super) fn publish_lifecycle(')
fail=cut('/// Fails the worker as one unit:','/// Publishes a lifecycle transition')
fail=fail[:fail.index('    runtime.publish_failed(reason);')]+'''    runtime.publish_failed(reason);
    publish_lifecycle(lifecycle, generation, TxIndexLifecycle::Failed(reason.into()));
}
'''
fail=fail.replace('fn fail_worker(','pub(super) fn fail_worker(')
write('lifecycle',lifecycle+'\n'+fail+'\n'+publish,'//! Atomic lifecycle snapshots and revocable publication generations.',tail='\n#[cfg(test)]\nmod tests;\n')
f=node/'txindex_worker/query_adapter.rs'
f.write_text(f.read_text().replace('use super::TxIndexQueryAdapter;','use std::sync::Arc;\nuse arc_swap::ArcSwap;\nuse super::lifecycle::TxIndexLifecycle;\nuse super::query::TxIndexQueryEngine;\n\n'+cut('/// Stable outer query adapter','/// Immutable specification for worker-owned store open.').rstrip()))
supervisor=cut('/// Immutable specification for worker-owned store open.','/// Result of opening the txindex store:')+'\n'+cut('/// Worker-owned open: opens the store','/// Fails the worker as one unit:')+'\n'+cut(open_marker,'/// Opens the txindex store with a bounded deadline.')
write('supervisor',supervisor,'//! Worker supervision: namespace ownership, store-open handoff, and shutdown.\n//! Construction and reconciliation remain behind the existing panic boundary.',tail='\n#[cfg(test)]\nmod tests;\n')
store=cut('/// Writer-side batch limits.','/// Default fork depth')+'\n'+'''/// Upper bound on the worker's wait for backend recovery. A timeout isolates
/// the index failure from the node; it does not prove recovery stopped making
/// progress. The open helper is detached because a running backend call cannot
/// be cancelled safely.
pub(super) const TXINDEX_OPEN_TIMEOUT: Duration = Duration::from_mins(30);
'''
store+='\n'+cut('/// Result of opening the txindex store:','/// Worker-owned open: opens the store')+'\n'+cut('/// Opens the txindex store with a bounded deadline.','/// Exact spent-coin script anchor')
store=store.replace('fn open_tx_index_with_timeout(','pub(super) fn open_tx_index_with_timeout(').replace('fn open_tx_index_on_worker(','pub(super) fn open_tx_index_on_worker(')
write('store',store,'//! Backend composition and bounded store opening.\n//! Storage recovery and format decisions stay in the index/storage owners.')
live=cut('/// Exact spent-coin script anchor','/// Detached publisher for test worker construction;').replace('pub(crate) struct UndoScripts','pub(super) struct UndoScripts').replace('    pub(crate) fn from_undo_bytes','    fn from_undo_bytes')+'\n'+impl('Worker',wm,groups['live'],shared)
write('live',live,'//! ScriptLive rebuilds from one stable UTXO view; undo supplies spent scripts.')
support=cut('/// Detached publisher for test worker construction;','\nstruct Worker {').replace('#[cfg(test)]\n','')
write('test_support',support,'//! Shared test construction for chain-event and recovery-evidence owners.')
forward=cut('const IDENTITY_CHUNK_BLOCKS:','const REVISION_QUIET_PERIOD:')+'\n'+cut('/// Identity of one block on the active chain,','impl Worker {')+'\n'+impl('Worker',wm,groups['forward'],shared)
for indent in ['                ','                        ']:
    block=indent+'let replacement = PendingForward {\n'
    while block in forward:
        begin=forward.index(block); end=forward.index(indent+'};\n',begin)+len(indent+'};\n'); forward=forward[:begin]+forward[end:]
forward=forward.replace('std::mem::replace(state, replacement)','state.take(self.batch_limits)'); assert 'replacement' not in forward
write('forward',forward,'//! Bounded body-reader sessions, parallel preparation, and fenced forward commits.')
rollback=cut('fn index_ahead_capability_label(','/// Identity of one block on the active chain,')+'\n'+impl('Worker',wm,groups['rollback'],shared)
write('rollback',rollback,'//! Capability selection, exact-identity rollback, and selective rebuild routing.')
error=cut('#[derive(Debug, thiserror::Error)]\nenum TxIndexWorkerError','/// Aggregate work budget shared by').replace('enum TxIndexWorkerError','pub(super) enum TxIndexWorkerError').replace('    fn requires_capability_rebuild','    pub(super) fn requires_capability_rebuild')
write('error',error,'//! Typed worker failures and the narrow set eligible for capability rebuild.')
budget=cut('/// Bounded scan limits used by the query engine.','/// Writer-side batch limits.').replace('const MAX_SERIALIZED_BLOCK_BYTES: usize = 4_000_000;\n','').replace('const QUERY_SCAN_COUNT_LIMIT:','pub(super) const QUERY_SCAN_COUNT_LIMIT:')+'\n'+cut('/// Aggregate work budget shared by','/// Authoritative Live query sources:')
budget=budget.replace('struct QueryBudget','pub(super) struct QueryBudget').replace('    const fn new(','    pub(super) const fn new('); budget=re.sub(r'^    fn ','    pub(super) fn ',budget,flags=re.M)
a=budget.index('        if scan.rows.len() > self.remaining_rows'); b=budget.index('\n    pub(super) fn reserve_body_read',a)
budget=budget[:a]+'''        self.charge_scan(scan.rows.len(), scan.encoded_bytes)?;
        Ok(scan.rows)
    }

    pub(super) fn accept_live_scan(
        &mut self,
        scan: ScriptLiveScan,
    ) -> Result<Vec<bitcoin_rs_index::ScriptLiveRow>, TxQueryError> {
        if !scan.complete {
            return Err(TxQueryError::Unavailable(
                "txindex live prefix scan truncated".into(),
            ));
        }
        self.charge_scan(scan.rows.len(), scan.encoded_bytes)?;
        Ok(scan.rows)
    }

    fn charge_scan(&mut self, rows: usize, encoded_bytes: usize) -> Result<(), TxQueryError> {
        if rows > self.remaining_rows || encoded_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exceeded".into(),
            ));
        }
        self.remaining_rows -= rows;
        self.remaining_bytes -= encoded_bytes;
        Ok(())
    }
'''+budget[b:]
f=node/'txindex_worker/query/budget.rs'; f.parent.mkdir(parents=True,exist_ok=True); f.write_text('//! Aggregate, fail-closed work accounting for one public query.\n\n'+imports(budget,'query/budget')+budget+'\n#[cfg(test)]\nmod tests;\n')
qm['query_health']=qm['query_health'].replace('self.runtime.failed.load(Ordering::Acquire)','self.runtime.is_failed()').replace('self.runtime.shutdown.load(Ordering::Acquire)','self.runtime.is_shutdown()')
qm['scan_live_rows']=qm['scan_live_rows'][:qm['scan_live_rows'].index('        if !scan.complete')]+'        budget.accept_live_scan(scan)\n    }\n'
qm['index_progress_for']=qm['index_progress_for'].replace('    fn index_progress_for','    pub(super) fn index_progress_for')
query=cut('/// Authoritative Live query sources:','impl TxIndexQueryEngine {')+'\n'+impl('TxIndexQueryEngine',qm,list(qm))+'\n'+cut('/// One coherent read of index progress','/// Private index-side `BlockSource`:')+'\n'+cut('impl TxIndexQuery for TxIndexQueryEngine {','#[cfg(all(test, feature = "fjall"))]\nmod body_reader_tests')
write('query',query,'//! Snapshot-gated transaction and script queries.\n//! Watermark, revision, health, and chain-transition checks remain one owner.',extra='mod budget;\n\nuse budget::QueryBudget;\n\nconst MAX_SERIALIZED_BLOCK_BYTES: usize = 4_000_000;\n\n',tail='\n#[cfg(test)]\nmod tests;\n')
write('block_source',cut('/// Private index-side `BlockSource`:','/// Progress reads that raced a tip'),'//! Resolve block bodies against captured chain identity, never height alone.',tail='\n#[cfg(test)]\nmod tests;\n')
write('capability',cut('/// Progress reads that raced a tip','impl TxIndexQuery for TxIndexQueryEngine {'),'//! Project worker-owned lifecycle and coherent progress onto RPC capabilities.')
worker=cut('/// Default fork depth','const IDENTITY_CHUNK_BLOCKS:')+'\n'+cut('const REVISION_QUIET_PERIOD:','/// Maximum time the txindex worker waits')+'\n'+cut('struct Worker {','fn index_ahead_capability_label(')+'\n'
a=worker.index('\n}\n',worker.index('impl PendingForward {'))
worker=worker[:a]+'''

    /// Transfers the retained rows without changing their fence or deadline.
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
'''+worker[a:]
worker+=impl('Worker',wm,groups[''])+'\n'+cut('enum CursorCommit','#[derive(Debug, thiserror::Error)]\nenum TxIndexWorkerError')
mods=''.join('mod '+m+';\n' for m in ['error','forward','heartbeat','live','namespace','rollback','scheduling'])+'\n'+''.join('pub(crate) mod '+m+';\n' for m in ['block_source','capability','lifecycle','query','query_adapter','runtime','store','supervisor'])+'\n#[cfg(test)]\npub(crate) mod test_support;\n\n'
doc='\n'.join(s.splitlines()[:18]).replace('[`ScriptIndexQuery`]','[`bitcoin_rs_rpc::context::ScriptIndexQuery`]')+'\n//!\n//! The root owns reconciliation orchestration; forward/rollback/live own its\n//! work phases. Runtime and lifecycle own publication, supervisor/store own\n//! startup, and query/block_source/capability own read-side projections.\n'
write('',worker,doc,extra=mods,tail='\n#[cfg(all(test, feature = "fjall"))]\n#[path = "txindex_worker/tests/body_reader.rs"]\nmod body_reader_tests;\n\n#[cfg(all(test, feature = "fjall"))]\n#[allow(clippy::expect_used, clippy::panic)]\n#[path = "txindex_worker/tests/recovery.rs"]\nmod recovery_tests;\n')
moves={'block_source':'block_source/tests.rs','query':'query/tests.rs','lifecycle':'lifecycle/tests.rs','integration':'supervisor/tests.rs','recovery':'tests/recovery.rs'}
for old,new in moves.items():
    f=node/('txindex_worker_'+old+'_tests.rs'); dest=node/'txindex_worker'/new; dest.parent.mkdir(parents=True,exist_ok=True); dest.write_text(f.read_text()); f.unlink()
body=cut('#[cfg(all(test, feature = "fjall"))]\nmod body_reader_tests','#[cfg(test)]\n#[path = "txindex_worker_block_source_tests.rs"]')
(node/'txindex_worker/tests/body_reader.rs').write_text(textwrap.dedent(body[body.index('{')+1:body.rfind('}')]).strip()+'\n')
for rel,im in {
'lifecycle/tests.rs':'use crate::txindex_worker::query_adapter::TxIndexQueryAdapter;\nuse bitcoin_rs_primitives::{Hash256, Txid};\nuse bitcoin_rs_rpc::context::{TxIndexQuery, TxQueryError};\n',
'supervisor/tests.rs':'use crate::txindex_worker::{query_adapter::TxIndexQueryAdapter, store::open_tx_index_on_worker, test_support::{detached_chain_publisher, test_recovery_reporter}};\nuse bitcoin_rs_primitives::{Hash256, Txid};\nuse bitcoin_rs_rpc::context::{TxIndexQuery, TxQueryError};\n',
'query/tests.rs':'use bitcoin_rs_index::{IndexError, IndexWatermark, ScriptLiveScan, TxIndexScan, TxIndexScanRow};\nuse super::budget::QUERY_SCAN_COUNT_LIMIT;\n',
 'tests/recovery.rs':'use crate::txindex_worker::{store::DEFAULT_BATCH_LIMITS, test_support::{detached_chain_publisher, test_recovery_reporter}};\n',
 'tests/body_reader.rs':'use crate::txindex_worker::{store::DEFAULT_BATCH_LIMITS, test_support::{detached_chain_publisher, test_recovery_reporter}};\n'}.items():
    f=node/'txindex_worker'/rel; t=f.read_text(); assert 'use super::*;' in t; f.write_text(t.replace('use super::*;','use super::*;\n'+im,1))
owners={'TxIndexRuntime':'runtime','TxIndexWorker':'supervisor','TxIndexOpenSpec':'supervisor','TxIndexLifecycle':'lifecycle','Generation':'lifecycle','TxIndexQueryAdapter':'query_adapter','TxIndexCapability':'capability','IndexBlockSource':'block_source','TxIndexQueryEngine':'query','QueryEngineLive':'query','DEFAULT_BATCH_LIMITS':'store','test_recovery_reporter':'test_support','detached_chain_publisher':'test_support'}
for f in node.rglob('*.rs'):
    t=f.read_text(); before=t
    for symbol,owner in owners.items(): t=t.replace('txindex_worker::'+symbol,'txindex_worker::'+owner+'::'+symbol)
    if f==node/'txindex_worker/scheduling.rs': t=t.replace('use super::TxIndexRuntime;','use super::runtime::TxIndexRuntime;')
    if t!=before: f.write_text(t)
f=root/'docs/contracts/indexing.md'; t=f.read_text()
t=t.replace('- `TxIndexRuntime`, `TxIndexQueryEngine`, `Worker` in `crates/node/src/txindex_worker.rs`','''- Reconciliation orchestration: `Worker` in `crates/node/src/txindex_worker.rs`;
  bounded forward work, rollback selection, and live seeding in its
  `forward.rs`, `rollback.rs`, and `live.rs` submodules.
- Shared runtime: `TxIndexRuntime` in `crates/node/src/txindex_worker/runtime.rs`.
- Snapshot-gated reads: `TxIndexQueryEngine` in
  `crates/node/src/txindex_worker/query.rs`; aggregate work accounting in
  `query/budget.rs`.
- Worker startup and backend composition: `txindex_worker/supervisor.rs` and
  `txindex_worker/store.rs`.''')
t=t.replace('`crates/node/src/txindex_worker.rs` mapped by `TxIndexCapability` onto the','`crates/node/src/txindex_worker/lifecycle.rs` mapped by `TxIndexCapability`\n  (`txindex_worker/capability.rs`) onto the')
for old,new in moves.items(): t=t.replace('crates/node/src/txindex_worker_'+old+'_tests.rs','crates/node/src/txindex_worker/'+new)
f.write_text(t)
f=node/'txindex_worker/query/budget/tests.rs'; f.parent.mkdir(parents=True,exist_ok=True); f.write_text((Path(__file__).parent/'budget_tests.rs').read_text())
f=node/'txindex_worker/lifecycle/tests.rs'; f.write_text(f.read_text()+'''
/// IDX-07: failure always stops this runtime; revocation only fences publication.
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
''')
print('Extracted',len(wm),'worker methods and',len(qm),'query methods; retained the existing test bodies.')
