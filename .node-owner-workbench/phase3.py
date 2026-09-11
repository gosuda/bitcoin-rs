"""Index runtime ownership, retaining mainline index reconciliation policy."""
from pathlib import Path
import re
from support import r, assign, dedup_imports, relative_paths, frontmatter, migration


def run():
    groups = assign({}, {
        'lifecycle': 'Generation TxIndexLifecycle TxIndexQueryAdapter',
        'service': 'TxIndexWorker run_worker_with_open fail_worker publish_lifecycle open_and_run',
        'open': 'TXINDEX_OPEN_TIMEOUT TxIndexOpenSpec OpenTxIndex open_tx_index_with_timeout open_tx_index_on_worker TxIndexComposer open_tx_index_store_on_worker TXINDEX_OPEN_GATE install_txindex_open_gate wait_txindex_open_gate',
        'worker': 'Worker PendingForward BlockIdentity ChunkAction CursorCommit ReconcileAction UndoScripts',
        'reconciliation': 'DEFAULT_ROLLBACK_REBUILD_CUTOVER index_ahead_capability_label',
        'catch_up': 'BATCH_BYTE_LIMIT ROCKSDB_BATCH_LIMITS DEFAULT_BATCH_LIMITS REDB_BATCH_LIMITS IDENTITY_CHUNK_BLOCKS POSITION_PREFETCH_BLOCKS PREPARE_CHUNK_BLOCKS PREPARE_CHUNK_BYTES',
        'error': 'TxIndexWorkerError',
        'query': 'QueryEngineLive TxIndexQueryEngine',
        'query_budget': 'QueryBudget QUERY_SCAN_ROW_LIMIT QUERY_SCAN_BYTE_LIMIT QUERY_SCAN_COUNT_LIMIT QUERY_BODY_READ_LIMIT MAX_SERIALIZED_BLOCK_BYTES',
        'body_source': 'IndexBlockSource',
        'progress': 'IndexProgress PROGRESS_READ_ATTEMPTS TxIndexCapability',
    })
    worker_methods = assign({}, {
        'reconciliation': 'reconcile_once reconcile_pass seed_live_from_utxo reset_for_rebuild report_index_ahead reconcile_pending capture_target_watermarks rollback_selection forward_selection watermark_is_on_target_chain rollback_depth_for',
        'catch_up': 'collect_target_chain catch_up_to prepare_and_admit_chunk finish_catch_up load_body',
        'commit': 'persist_chain_cursor rollback_one live_anchor sync_and_commit cursor_for_result commit_pending',
    })
    query_methods = assign({}, {
        'lookup': 'resolve_hash_at_height hash_at_height resolve_block resolve_block_body_bytes verify_block validated_positions resolve_positioned_transaction transaction_from_full_block transaction_for locate_transaction_for outpoint_value_for',
        'script_queries': 'scan_funding_rows scan_spending_rows scan_live_rows collect_funding_outputs funding_outputs_for spender_for spending_input history_snapshot_for unspent_outputs_for',
        'progress': 'index_progress_for',
    })
    source = r.split_owner('txindex_worker', 'index_runtime', groups, {'Worker': worker_methods, 'TxIndexQueryEngine': query_methods})
    root = r.ROOT / 'index_runtime.rs'
    text = root.read_text()
    for name in ['heartbeat', 'namespace', 'query_adapter', 'scheduling']:
        text = re.sub(r'(?m)^mod ' + name + r';$', 'pub(crate) mod ' + name + ';', text)
    root.write_text(text)
    path = r.ROOT / 'lib.rs'
    text = path.read_text().replace('mod txindex_worker;', '/// Index runtime supervision and generation-fenced query access.\npub mod index_runtime;')
    text = text.replace('pub use txindex_worker::TxIndexRuntime;\n', '')
    path.write_text(text)
    r.add_map('TxIndexRuntime', 'index_runtime::TxIndexRuntime')

    source_root = root.read_text()
    edits, declarations = [], []
    for node, raw in r.items(source_root):
        if node.type != 'mod_item' or not r.is_test(raw):
            continue
        name = r.name_of(source_root, node)
        if name == 'fixtures':
            continue
        target_name = name.removesuffix('_tests')
        attr = re.search(r'#\[path\s*=\s*"([^"]+)"\]', raw)
        old = (r.ROOT / attr.group(1)) if attr else r.ROOT / 'index_runtime' / (name + '.rs')
        target = r.ROOT / 'index_runtime/tests' / (target_name + '.rs')
        body = relative_paths(old.read_text(), 'index_runtime::' + name, True)
        imports = r.canonical_imports(source, 'index_runtime', {'heartbeat', 'namespace', 'query_adapter', 'scheduling'})
        links = '\n'.join('use crate::index_runtime::' + group + '::*;' for group in sorted(set(groups.values()) | {'fixtures', 'commit', 'lookup', 'script_queries'}))
        r.write(target, frontmatter(dedup_imports(imports + '\nuse crate::index_runtime::*;\n' + links + '\n' + body)))
        old.unlink()
        attrs = re.findall(r'#\[(?:cfg|allow)[^\n]+', raw)
        declarations.append('\n'.join(attrs) + '\nmod ' + target_name + ';')
        r.add_map('index_runtime::' + name, 'index_runtime::tests::' + target_name)
        start = node.start_byte
        previous = node.prev_named_sibling
        while previous and previous.type in ('attribute_item', 'line_comment', 'block_comment'):
            start = previous.start_byte
            previous = previous.prev_named_sibling
        edits.append((start, node.end_byte))
    data = source_root.encode()
    for start, end in sorted(edits, reverse=True):
        data = data[:start] + data[end:]
    root.write_text(data.decode() + '\n#[cfg(test)]\nmod tests;\n')
    r.write(r.ROOT / 'index_runtime/tests.rs', '//! Index runtime contracts and recovery witnesses.\n\n' + '\n'.join(declarations))
    r.migrate_paths()
    for path in list((r.ROOT / 'index_runtime/tests').glob('*.rs')):
        r.test_partition(path)

    path = r.ROOT / 'storage_backend.rs'
    text = path.read_text().replace('include_str!("txindex_worker.rs")', 'include_str!("index_runtime/open.rs")')
    text = text.replace('"txindex_worker.rs",\n            include_str!("index_runtime/open.rs"),\n            Some("mod body_reader_tests {"),', '"index_runtime/open.rs",\n            include_str!("index_runtime/open.rs"),\n            None,')
    path.write_text(text)
    for path in Path('docs').rglob('*.md'):
        text = path.read_text()
        changed = text.replace('crates/node/src/txindex_worker.rs', 'crates/node/src/index_runtime.rs')
        if changed != text:
            path.write_text(changed)
    migration('''## Index runtime

The private `txindex_worker` module and crate-root `TxIndexRuntime` export are
removed. The public handle is `index_runtime::TxIndexRuntime`. Lifecycle, service
startup, backend open, catch-up, reconciliation execution, durable cursor commits,
bounded queries, body access, and progress reporting have explicit owners.

State composition imports the service, open specification, lifecycle, and query
adapter directly. There is one runtime and authoritative index writer; queries
remain generation-fenced projections. Mainline reconciliation policy continues
to belong to `bitcoin_rs_index::reconcile`; this split does not move it back.

Lifecycle/recovery tests move to `index_runtime/tests`, retaining feature gates.
''')


def after_fix():
    # cargo fix resolves production imports first; these names belong to the
    # existing cfg(test) constructor and must remain test-scoped.
    path = r.ROOT / 'index_runtime/service.rs'
    text = path.read_text()
    names = 'IndexCapabilities', 'PreparedBatchLimits', 'TxIndexWriter'
    if not all(re.search(r'(?m)^use .*\b' + name + r'\b', text) for name in names):
        text = text.replace('use arc_swap::ArcSwap;', '#[cfg(test)]\nuse bitcoin_rs_index::{IndexCapabilities, PreparedBatchLimits, writer::TxIndexWriter};\n\nuse arc_swap::ArcSwap;')
        path.write_text(text)
    path = r.ROOT / 'index_runtime/tests.rs'
    text = path.read_text()
    if 'mod recovery;' in text and '#[allow(clippy::expect_used, clippy::panic)]\nmod recovery;' not in text:
        text = text.replace('mod recovery;', '#[allow(clippy::expect_used, clippy::panic)]\nmod recovery;')
    path.write_text(text)
