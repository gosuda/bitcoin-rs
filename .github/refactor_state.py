from pathlib import Path

root = Path('.')
p = root / 'crates/node/src/state.rs'
orig = p.read_text()
lines = orig.splitlines(True)

def sl(a, b):
    return ''.join(lines[a - 1:b])

def write(rel, body):
    q = p.parent / rel
    q.parent.mkdir(parents=True, exist_ok=True)
    q.write_text(body.rstrip() + '\n')

write('state/events.rs', '//! Coherent chain snapshots and nonblocking post-commit hints.\n\nuse super::*;\n\n' + sl(64, 196))

epoch = sl(198, 290).replace('fn allocate_process_epoch(', 'pub(super) fn allocate_process_epoch(')
write('state/epoch.rs', '//! Durable per-process epoch allocation.\n\nuse super::*;\n\n' + epoch)

write('state/errors.rs', '//! Typed authoritative chainstate failures.\n\nuse super::*;\n\n' + sl(291, 477))

storage = sl(479, 622) + sl(634, 824)
storage = storage.replace('struct NodeStorage {', 'pub(super) struct NodeStorage {')
for name in ['open', 'kind', 'prune_service', 'block_body_store', 'undo_store', 'journal_writer', 'stored_prune_body', 'stored_prune_undo', 'write_test_rows', 'read_test_row']:
    storage = storage.replace(f'    fn {name}(', f'    pub(super) fn {name}(')
write('state/storage.rs', '//! Chainstate storage capability composition.\n\nuse super::*;\n\n' + storage)

bootstrap = sl(828, 1095).replace(
    '''struct InitialChainstate {
    utxo: UtxoSet,
    coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    tree: bitcoin_rs_chain::BlockTree,
    applied_tip: Option<TipSnapshot>,
    chain_tx_count: u64,
    resume_source: ResumeSource,
    journal_bootstrap: Option<JournalBootstrap>,
}''',
    '''pub(super) struct InitialChainstate {
    pub(super) utxo: UtxoSet,
    pub(super) coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    pub(super) tree: bitcoin_rs_chain::BlockTree,
    pub(super) applied_tip: Option<TipSnapshot>,
    pub(super) chain_tx_count: u64,
    pub(super) resume_source: ResumeSource,
    pub(super) journal_bootstrap: Option<JournalBootstrap>,
}'''
)
for name in ['requires_full_revalidation', 'reset_journal_dir', 'open_journal_dir', 'checkpoint_bootstrap', 'restored_initial', 'cold_initial_chainstate', 'prepare_initial_chainstate', 'replay_checkpoint_journal']:
    bootstrap = bootstrap.replace(f'fn {name}(', f'pub(super) fn {name}(')
write('state/bootstrap.rs', '//! Checkpoint/journal startup selection and recovery bootstrap.\n\nuse super::*;\n\n' + bootstrap)

write('state/prune.rs', '//! Storage-backed manual pruning.\n\nuse super::*;\n\n' + sl(826, 826) + '\n' + sl(1097, 1255))

tx = sl(1257, 1307)
tx = tx.replace('fn tx_index_capabilities(', 'pub(super) fn tx_index_capabilities(')
tx = tx.replace('fn build_tx_index_open_spec(', 'pub(super) fn build_tx_index_open_spec(')
tx = tx.replace(
    '''struct TxIndexSpawn {
    spec: crate::txindex_worker::TxIndexOpenSpec,
    generation: crate::txindex_worker::Generation,
    block_source: crate::txindex_worker::IndexBlockSource,
    body_source: Arc<dyn BlockBodySource>,
    wake_rx: Receiver<()>,
    recovery_reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
}''',
    '''pub(super) struct TxIndexSpawn {
    pub(super) spec: crate::txindex_worker::TxIndexOpenSpec,
    pub(super) generation: crate::txindex_worker::Generation,
    pub(super) block_source: crate::txindex_worker::IndexBlockSource,
    pub(super) body_source: Arc<dyn BlockBodySource>,
    pub(super) wake_rx: Receiver<()>,
    pub(super) recovery_reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
}'''
)
write('state/txindex.rs', '//! Txindex capability selection and deferred worker spawn state.\n\nuse super::*;\n\n' + tx)

write('state/open.rs', '//! Node runtime construction.\n\nuse super::*;\n\n' + sl(1372, 1845) + '}\n')
write('state/services.rs', '//! Checkpoint, index, and prune service lifecycle.\n\nuse super::*;\n\nimpl NodeState {\n' + sl(1846, 2040) + '}\n')
write('state/handles.rs', '//! Cheap capability-handle accessors.\n\nuse super::*;\n\nimpl NodeState {\n' + sl(2041, 2270) + '}\n')
write('state/lifecycle.rs', '//! Shutdown and authoritative chainstate convenience entry points.\n\nuse super::*;\n\nimpl NodeState {\n' + sl(2271, 2371))

write('state/tests.rs', sl(2375, len(lines) - 1))

intro = '''//! Shared node runtime state and composition handles.\n//!\n//! This root is intentionally declarative. Storage, restore, pruning, index\n//! startup, event publication, and runtime methods each have one focused owner.\n\nmod bootstrap;\nmod epoch;\nmod errors;\nmod events;\nmod handles;\nmod lifecycle;\nmod open;\nmod prune;\nmod services;\nmod storage;\nmod txindex;\n#[cfg(test)]\nmod tests;\n\npub use errors::{ApplyError, DisconnectError};\npub use events::{ChainEventHint, ChainEventPublisher, ChainSnapshot, HintKind};\npub use prune::NodePruneService;\nuse bootstrap::*;\nuse epoch::allocate_process_epoch;\nuse storage::NodeStorage;\nuse txindex::*;\n\n'''
p.write_text((intro + sl(7, 62) + '\n' + sl(623, 632) + '\n' + sl(1309, 1370)).rstrip() + '\n')
