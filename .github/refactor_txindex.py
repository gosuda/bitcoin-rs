from pathlib import Path
import re
p=Path('crates/node/src/txindex_worker.rs'); orig=p.read_text(); lines=orig.splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel,body):
 q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')
def localize_top(body):
 return re.sub(r'(?m)^(fn|struct|enum) ', r'pub(super) \1 ', body)

runtime=sl(134,302).replace('    fn load_engine(', '    pub(super) fn load_engine(')
write('txindex_worker/runtime.rs','//! Worker health, generation fencing, lifecycle publication, and stable query adapter.\n\nuse super::*;\n\n'+runtime)
openmod=sl(304,904)
write('txindex_worker/open.rs','//! Worker-owned backend open, supervision, and lifecycle handoff.\n\nuse super::*;\nuse super::reconcile::{TxIndexWorkerError, Worker};\n\n'+openmod)
write('txindex_worker/undo.rs','//! Undo-record script projection used by ScriptLive reconciliation.\n\nuse super::*;\n\n'+sl(905,958))
recon=localize_top(sl(959,2160))
fields=['runtime','writer','applied_tip','block_tree','body_store','batch_limits','enabled','chain_events','reporter','wake_rx','quiet_period','batch_delay','rollback_rebuild_cutover','utxo','chain_transition']
for field in fields:
 recon=recon.replace(f'    {field}:', f'    pub(super) {field}:',1)
recon=recon.replace('    fn run(self) -> Result<(), TxIndexWorkerError> {','    pub(super) fn run(self) -> Result<(), TxIndexWorkerError> {')
write('txindex_worker/reconcile.rs','//! Durable watermark reconciliation, rollback, rebuild, and forward batching.\n\nuse super::*;\n\n'+recon)
query=sl(2161,2948)+sl(3129,3185)
write('txindex_worker/query.rs','//! Snapshot-gated transaction and script query engine.\n\nuse super::*;\n\n'+query)
write('txindex_worker/block_source.rs','//! Active-chain block source and progress snapshot types.\n\nuse super::*;\n\n'+sl(2949,3024))
write('txindex_worker/capability.rs','//! RPC capability projection over worker lifecycle and query progress.\n\nuse super::*;\n\n'+sl(3026,3127))
write('txindex_worker/body_reader_tests.rs','use super::*;\nuse super::reconcile::*;\n\n'+sl(3189,3350))
root=sl(1,133)+'''\nmod block_source;\nmod capability;\nmod open;\nmod query;\nmod reconcile;\nmod runtime;\nmod undo;\n\npub use runtime::TxIndexRuntime;\npub(crate) use block_source::{IndexBlockSource, IndexProgress};\npub(crate) use capability::TxIndexCapability;\npub(crate) use open::{OpenTxIndex, TxIndexOpenSpec, TxIndexWorker, wait_txindex_open_gate};\n#[cfg(test)]\npub(crate) use open::install_txindex_open_gate;\npub(crate) use query::{QueryEngineLive, TxIndexQueryEngine};\npub(crate) use runtime::{Generation, TxIndexLifecycle, TxIndexQueryAdapter};\npub(crate) use undo::UndoScripts;\n#[cfg(test)]\npub(crate) use undo::{detached_chain_publisher, test_recovery_reporter};\n#[cfg(test)]\nuse open::*;\n#[cfg(test)]\nuse reconcile::*;\n\n#[cfg(all(test, feature = "fjall"))]\nmod body_reader_tests;\n'''+sl(3353,3372)
p.write_text(root.rstrip()+'\n')
