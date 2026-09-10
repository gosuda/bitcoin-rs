from pathlib import Path
import re

p = Path('crates/node/src/state.rs')
lines = p.read_text().splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel,body):
    q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')
def expose_struct(body,name):
    marker=f'struct {name} {{'
    start=body.index(marker)
    end=body.index('\n}',start)+2
    block=body[start:end].replace(marker,f'pub(super) struct {name} {{',1)
    block=re.sub(r'(?m)^    ([A-Za-z_][A-Za-z0-9_]*):',r'    pub(super) \1:',block)
    return body[:start]+block+body[end:]

write('state/events.rs','//! Coherent chain snapshots and nonblocking post-commit hints.\n\nuse super::*;\n\n'+sl(64,196).replace('    fn new(epoch:','    pub(super) fn new(epoch:',1))
epoch=sl(198,290).replace('fn allocate_process_epoch(','pub(super) fn allocate_process_epoch(',1)
write('state/epoch.rs','//! Durable per-process epoch allocation.\n\nuse super::*;\n\n'+epoch)
write('state/errors.rs','//! Typed authoritative chainstate failures.\n\n'+sl(291,477))

storage=sl(479,622)+sl(634,824)
storage=storage.replace('struct NodeStorage {','pub(super) struct NodeStorage {',1)
for old,new in [
('    fn open(\n        config:','    pub(super) fn open(\n        config:'),
('    const fn kind(&self)','    pub(super) const fn kind(&self)'),
('    fn prune_service(\n        &self,','    pub(super) fn prune_service(\n        &self,'),
('    fn block_body_store(&self)','    pub(super) fn block_body_store(&self)'),
('    fn undo_store(&self)','    pub(super) fn undo_store(&self)'),
('    fn journal_writer(\n        &self,','    pub(super) fn journal_writer(\n        &self,'),
('    fn stored_prune_body(\n        &self,','    pub(super) fn stored_prune_body(\n        &self,'),
('    fn stored_prune_undo(\n        &self,','    pub(super) fn stored_prune_undo(\n        &self,'),
('    fn write_test_rows(&self,','    pub(super) fn write_test_rows(&self,'),
('    fn read_test_row(&self,','    pub(super) fn read_test_row(&self,'),
]: storage=storage.replace(old,new,1)
storage=expose_struct(storage,'JournalBootstrap')
storage=storage.replace('struct StoredBlockBodySource {','pub(super) struct StoredBlockBodySource {',1).replace('    fn new(store:','    pub(super) fn new(store:',1)
write('state/storage.rs','//! Chainstate storage capability composition.\n\nuse super::*;\n\n'+storage)

bootstrap=sl(828,1095).replace('const STALE_RESTORE_ERROR_THRESHOLD:','pub(super) const STALE_RESTORE_ERROR_THRESHOLD:',1)
bootstrap=expose_struct(bootstrap,'InitialChainstate')
for name in ['requires_full_revalidation','reset_journal_dir','open_journal_dir','checkpoint_bootstrap','restored_initial','cold_initial_chainstate','prepare_initial_chainstate','replay_checkpoint_journal']:
    bootstrap=bootstrap.replace(f'fn {name}(',f'pub(super) fn {name}(',1)
write('state/bootstrap.rs','//! Checkpoint/journal startup selection and recovery bootstrap.\n\nuse super::*;\n\n'+bootstrap)
write('state/prune.rs','//! Storage-backed manual pruning.\n\nuse super::*;\n\n'+sl(826,826)+'\n'+sl(1097,1255))

tx=sl(1257,1307).replace('fn tx_index_capabilities(','pub(super) fn tx_index_capabilities(',1).replace('fn build_tx_index_open_spec(','pub(super) fn build_tx_index_open_spec(',1)
tx=expose_struct(tx,'TxIndexSpawn')
write('state/txindex.rs','//! Txindex capability selection and deferred worker spawn state.\n\nuse super::*;\n\n'+tx)
write('state/open.rs','//! Node runtime construction.\n\nuse super::*;\n\n'+sl(1372,1845)+'}\n')
write('state/services.rs','//! Checkpoint, index, and prune service lifecycle.\n\nuse super::*;\n\nimpl NodeState {\n'+sl(1846,2040)+'}\n')
write('state/handles.rs','//! Cheap capability-handle accessors.\n\nuse super::*;\n\nimpl NodeState {\n'+sl(2041,2270)+'}\n')
write('state/lifecycle.rs','//! Shutdown and authoritative chainstate convenience entry points.\n\nuse super::*;\n\nimpl NodeState {\n'+sl(2271,2371))
write('state/tests.rs',sl(2375,len(lines)-1))
intro='''//! Shared node runtime state and composition handles.\n//!\n//! This root is intentionally declarative. Storage, restore, pruning, index\n//! startup, event publication, and runtime methods each have one focused owner.\n\nmod bootstrap;\nmod epoch;\nmod errors;\nmod events;\nmod handles;\nmod lifecycle;\nmod open;\nmod prune;\nmod services;\nmod storage;\nmod txindex;\n#[cfg(test)]\nmod tests;\n\npub use errors::{ApplyError, DisconnectError};\npub use events::{ChainEventHint, ChainEventPublisher, ChainSnapshot, HintKind};\npub use prune::NodePruneService;\nuse bootstrap::*;\nuse epoch::allocate_process_epoch;\nuse storage::{JournalBootstrap, NodeStorage, StoredBlockBodySource};\nuse txindex::*;\n\n'''
p.write_text((intro+sl(7,62)+'\n'+sl(623,632)+'\n'+sl(1309,1370)).rstrip()+'\n')
