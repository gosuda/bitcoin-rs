#!/usr/bin/env python3
"""Apply the query ownership cut to the pinned af5d034 source checkout."""
from pathlib import Path
import re
import shutil
import subprocess
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()

def get(path):
    return (root / path).read_text()

def put(path, text):
    p = root / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)

def edit(path, old, new, count=1):
    text = get(path)
    found = text.count(old)
    if found != count:
        raise RuntimeError(f'{path}: expected {count} matches, found {found}: {old[:100]!r}')
    put(path, text.replace(old, new))

def cut(text, start, end):
    a, b = text.index(start), text.index(end)
    return text[a:b], text[:a] + text[b:]

worker_path = 'crates/node/src/txindex_worker.rs'
worker = get(worker_path)
actual = subprocess.check_output(['git','hash-object',worker_path],cwd=root,text=True).strip()
if actual != '2b77378c96f1fc14a2396cf3d07cda48b17e9940':
    raise RuntimeError(f'Unexpected worker baseline: {actual}')

# Index owns its shared revision/health state; node retains the worker handle.
runtime, worker = cut(worker, '/// Shared wake/revision/health state', '/// Monotonic publication token.')
runtime = runtime.replace('/// Shared wake/revision/health state owned by `NodeState` and referenced by\n/// `Chainstate`, the worker thread, and the query engine.',
'''/// Shared revision, health, and reconciliation phase for an index instance.
///
/// The process owner creates this handle and wakes it after committed chain
/// transitions. Index workers publish health and phase; index queries consume
/// the same state. This handle owns no authoritative chain or coin data.''')
runtime = runtime.replace('self.shutdown.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)', 'self.is_shutdown() || self.is_failed()')
runtime += '''impl TxIndexRuntime {
    pub(crate) fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests;
'''
put('crates/index/src/runtime.rs', '''//! Shared health and revision state for asynchronous derived-index consumers.
//!
//! Wake delivery is advisory. A coalesced or dropped wake never replaces the
//! durable watermark and authoritative-chain checks owned by reconciliation.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use compact_str::CompactString;
use crossbeam_channel::Sender;
use parking_lot::RwLock;
use crate::IndexCapabilities;
use crate::reconcile::{ReconcileLeg, ReconcilePhase};

''' + runtime)

# Extract protocol-independent query values and contracts, not RPC projection.
context_path = 'crates/rpc/src/context.rs'
context = get(context_path)
query_types, context = cut(context, '/// Actual progress reported by the node-owned transaction index.', 'impl TxQueryError {')
_, context = cut(context, 'impl TxQueryError {', '/// Handles owned by the node and observed by the RPC context,')
query_types = query_types.replace('node-owned transaction index', 'transaction index')
query_types = query_types.replace('Lockless read-only adapter', 'Read-only interface')
query_types = query_types.replace('Lockless query adapter for the node-owned generic script index.', 'Read-only interface for the generic script index.')
put('crates/index/src/query/types.rs', '''//! Complete, protocol-independent index answers and typed query failures.

use bitcoin_rs_primitives::{OutPoint, Tx, Txid};
use compact_str::CompactString;
use crate::ScriptHash;

''' + query_types)
context = 'use bitcoin_rs_index::query::{ScriptIndexQuery, TxIndexQuery};\n' + context
put(context_path, context)

# One query implementation, with the existing authoritative read fence intact.
query = get('crates/node/src/txindex_worker/query.rs')
start, end = query.index('use super::{'), query.index('mod block_source;')
query = query[:start] + '''use std::sync::Arc;
use bitcoin_rs_chain::{BlockBodySource, BlockTree, TipSnapshot};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, OutPoint, Tx, Txid, deserialize};
use bitcoin_rs_storage::PrefixScanLimit;
use parking_lot::{Mutex, RwLock};
use crate::{IndexCapabilities, IndexCapability, IndexReader, IndexWatermark, ScriptHash,
    ScriptLiveScan, TxIndexScan, TxIndexScanRow, TxIndexSnapshot};
use crate::runtime::TxIndexRuntime;
use crate::types::{TxPosition, TxPositionValue};

mod types;
pub use types::{ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot,
    SpendingRecord, TxIndexInfo, TxIndexQuery, TxQueryError};

''' + query[end:]
query = query.replace('mod block_source;\n','').replace('pub(crate) use block_source::IndexBlockSource;\n','')
query = query.replace('    block_source: IndexBlockSource,\n','').replace('        block_source: IndexBlockSource,\n','').replace('            block_source,\n','')
query = query.replace('pub(crate) ', 'pub ')
query = query.replace('/// Node-owned, snapshot-gated transaction-index query engine.', '/// Index-owned, snapshot-gated transaction-index query engine.')
query = query.replace('`bitcoin_rs_rpc::context::TxIndexQuery`', '[`TxIndexQuery`]')
query = query.replace('self.runtime.failed.load(Ordering::Acquire)', 'self.runtime.is_failed()')
query = query.replace('self.runtime.shutdown.load(Ordering::Acquire)', 'self.runtime.is_shutdown()')
query = query.replace('    pub utxo:', '    /// Read-only source of authoritative coins for Live queries.\n    pub utxo:')
query = query.replace('    pub chain_transition:', '    /// The same transition mutex used by authoritative coin mutation.\n    pub chain_transition:')
query = query.replace('    pub enabled:', '    /// Configured capability selection; disabled families are unavailable.\n    pub enabled:')
query = query.replace('    pub synced: bool,', '    /// Whether every requested watermark names the captured applied tip.\n    pub synced: bool,')
query = query.replace('    pub processed_height: u32,', '    /// Lowest height completely covered by the requested capabilities.\n    pub processed_height: u32,')
query = query.replace('    pub target_height: u32,', '    /// Applied-tip height from the same coherent progress read.\n    pub target_height: u32,')
constants, worker = cut(worker, '/// Bounded scan limits used by the query engine.', '/// Writer-side batch limits.')
query = query.replace('mod budget;', constants + 'mod budget;')
query += '\n#[cfg(test)]\nmod tests;\n'
put('crates/index/src/query.rs', query)
for child in ['budget.rs','budget/tests.rs','scripts.rs','transactions.rs']:
    text = get('crates/node/src/txindex_worker/query/' + child)
    text = text.replace('bitcoin_rs_index::', 'crate::')
    put('crates/index/src/query/' + child, text)
transactions = get('crates/index/src/query/transactions.rs')
a, b = transactions.index('        if let Some(body_source)'), transactions.index('\n    fn verify_block')
transactions = transactions[:a] + '''        self.body_source
            .as_ref()
            .and_then(|source| source.block_body(height, hash))
            .ok_or_else(|| {
                TxQueryError::Unavailable(
                    format!("block body missing for txindex query at height {height}").into(),
                )
            })
    }
''' + transactions[b:]
put('crates/index/src/query/transactions.rs', transactions)

# Move the full existing engine tests; drop only the obsolete BlockLog fixture.
tests = get('crates/node/src/txindex_worker_query_tests.rs')
tests = tests.replace('bitcoin_rs_index::', 'crate::')
tests = tests.replace('use bitcoin_rs_rpc::context::{BlockRecord, ScriptHistoryRecord};\n', '')
a,b = tests.index('        let records = if config.retain_body'), tests.index('        let body = config.retain_body')
tests = tests[:a] + tests[b:]
a,b = tests.index('        let block_source = IndexBlockSource::new'), tests.index('        let engine = TxIndexQueryEngine::new')
tests = tests[:a] + tests[b:]
tests = tests.replace('            block_source,\n','')
tests += '\nmod source;\n'
put('crates/index/src/query/tests.rs', tests)

# No node forwarding query module or metadata-only body wrapper remains.
worker = worker.replace('mod query;\n', '')
worker = worker.replace('use query::IndexProgress;\npub(crate) use query::{IndexBlockSource, QueryEngineLive, TxIndexQueryEngine};\n','')
worker = worker.replace('    BlockSource, ', '    ')
worker = worker.replace('    ScriptLiveScan, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,\n', '')
worker = worker.replace('    types::{TxPosition, TxPositionValue},\n', '')
worker = worker.replace('use bitcoin_rs_storage::{PrefixScanLimit, block_body::BlockBodyStore};', 'use bitcoin_rs_storage::block_body::BlockBodyStore;')
worker = worker.replace('use crossbeam_channel::{Receiver, Sender};', 'use crossbeam_channel::Receiver;')
worker = worker.replace('atomic::{AtomicBool, AtomicU64, Ordering}', 'atomic::{AtomicBool, Ordering}')
worker = worker.replace('        BlockLog, ', '        ').replace(', record_at_height,', ',')
worker = worker.replace('#[cfg(test)]\n#[path = "txindex_worker_query_tests.rs"]\nmod query_tests;\n\n','')
worker = worker.replace('#[cfg(test)]\n#[path = "txindex_worker_block_source_tests.rs"]\nmod block_source_tests;\n\n','')
idx = worker.index('use arc_swap::ArcSwap;')
worker = worker[:idx] + 'use bitcoin_rs_index::query::{IndexProgress, QueryEngineLive, TxIndexQueryEngine};\nuse bitcoin_rs_index::runtime::TxIndexRuntime;\n\n' + worker[idx:]
worker = worker.replace('//! A snapshot-gated query engine serves `bitcoin_rs_rpc::context::TxIndexQuery`\n//! and the generic [`ScriptIndexQuery`] without raw index mutex paths.',
'''//! Query assembly, readiness, and shared health/revision state are owned by
//! `bitcoin_rs_index::query` and `bitcoin_rs_index::runtime`. Node supplies the
//! applied chain, coins, body source, and process lifecycle.''')
put(worker_path, worker)
shutil.rmtree(root/'crates/node/src/txindex_worker/query')
for old in ['crates/node/src/txindex_worker/query.rs', 'crates/node/src/txindex_worker_query_tests.rs', 'crates/node/src/txindex_worker_block_source_tests.rs']:
    (root/old).unlink()

# Remove the second identical body source from all private startup plumbing.
paths = ['crates/node/src/txindex_worker/lifecycle.rs','crates/node/src/txindex_worker/startup.rs',
         'crates/node/src/txindex_worker_integration_tests.rs','crates/node/src/state/index.rs']
for path in paths:
    text = get(path)
    text = re.sub(r'(?m)^.*\bblock_source\b[^\n]*\n', '', text)
    text = text.replace('use super::IndexBlockSource;\n','')
    text = text.replace('    let blocks = Arc::new(RwLock::new(BlockLog::new()));\n','')
    put(path,text)
path = 'crates/node/src/state/open.rs'
text=get(path)
a,b=text.index('                    let block_source ='),text.index('                    let lifecycle:',text.index('                    let block_source ='))
text=text[:a]+text[b:]
text=text.replace('                            block_source,\n','')
put(path,text)
path='crates/node/src/apply/consensus_rule_tests/behavior_3.rs'
text=get(path)
a=text.index('        crate::txindex_worker::IndexBlockSource::new(')
b=text.index('        Arc::clone(&handles.block_tree)',a)
put(path,text[:a]+text[b:])

# Imports point directly to the owner. No deprecated RPC/node type aliases.
names = ['TxQueryError','TxIndexInfo','TxIndexQuery','ScriptIndexQuery','ScriptIndexRecord',
         'ScriptHistoryRecord','ScriptIndexSnapshot','SpendingRecord']
all_rs = list((root/'crates').rglob('*.rs'))+list((root/'bin').rglob('*.rs'))
for path in all_rs:
    text=path.read_text()
    if path.relative_to(root).as_posix()==worker_path:
        text=text.replace('''use bitcoin_rs_rpc::{
    capabilities::{CapabilityState, CapabilityStatus, TxIndexCapabilitySource, txindex_status},
    context::{
        ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot,
        SpendingRecord, TxIndexInfo, TxIndexQuery, TxQueryError,
    },
};''','''use bitcoin_rs_rpc::capabilities::{CapabilityState, CapabilityStatus, TxIndexCapabilitySource, txindex_status};
use bitcoin_rs_index::query::{ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord,
    ScriptIndexSnapshot, SpendingRecord, TxIndexInfo, TxIndexQuery, TxQueryError};''')
    def relocate(m):
        indent, origin, content=m.group(1),m.group(2),m.group(3)
        items=[x.strip() for x in content.strip('{}').split(',') if x.strip()]
        moved=[x for x in items if x.split(' as ')[0] in names]
        rest=[x for x in items if x not in moved]
        if not moved: return m.group(0)
        stmts=[]
        if rest: stmts.append(f'use {origin}::{{{", ".join(rest)}}};')
        stmts.append(f'use bitcoin_rs_index::query::{{{", ".join(moved)}}};')
        return ('\n'+indent).join(stmts) if not indent else indent+('\n'+indent).join(stmts)
    text=re.sub(r'(?m)^([ \t]*)use ((?:bitcoin_rs_rpc|crate|super)::context)::(\{[^;{}]*\}|\w+);',relocate,text)
    for name in names:
        for prefix in ['bitcoin_rs_rpc::context::', 'crate::context::', 'super::context::']:
            text=text.replace(prefix+name,'bitcoin_rs_index::query::'+name)
    text=text.replace('crate::txindex_worker::TxIndexRuntime','bitcoin_rs_index::runtime::TxIndexRuntime')
    text=text.replace('crate::txindex_worker::TxIndexQueryEngine','bitcoin_rs_index::query::TxIndexQueryEngine')
    text=text.replace('crate::txindex_worker::QueryEngineLive','bitcoin_rs_index::query::QueryEngineLive')
    path.write_text(text)

edit('crates/node/src/lib.rs','\npub use txindex_worker::TxIndexRuntime;\n','\n')
edit('crates/node/benches/sync_pipeline.rs','BlockSync, Network, NodeConfig, TxIndexRuntime, apply::Chainstate, state::NodeState,',
     'BlockSync, Network, NodeConfig, apply::Chainstate, state::NodeState,')
p='crates/node/benches/sync_pipeline.rs'; text=get(p); pos=re.search(r'(?m)^use ', text).start(); put(p,text[:pos]+'use bitcoin_rs_index::runtime::TxIndexRuntime;\n'+text[pos:])

p='crates/rpc/src/error.rs'; text=get(p)
text=text.replace('''        error.into_rpc_error()''','''        match error {
            bitcoin_rs_index::query::TxQueryError::Retry => Self::Internal(
                "transaction index is still catching up; retry later".to_owned(),
            ),
            bitcoin_rs_index::query::TxQueryError::Unavailable(reason) =>
                Self::Internal(format!("transaction index unavailable: {reason}")),
            bitcoin_rs_index::query::TxQueryError::Storage(reason) =>
                Self::Internal(format!("transaction index storage error: {reason}")),
        }''')
put(p,text)
edit('crates/rpc/src/handlers/chain.rs','TxQueryError::into_rpc_error','RpcError::from',count=2)

p='crates/index/Cargo.toml'; text=get(p)
text=text.replace('[dependencies]\n','''[dependencies]
bitcoin-rs-chain.workspace = true
bitcoin-rs-utxo.workspace = true
arc-swap.workspace = true
compact_str.workspace = true
crossbeam-channel.workspace = true
''')
put(p,text)
edit('crates/index/src/lib.rs','/// Derived-index reconciliation phase', '''/// Complete index queries, readiness, and snapshot consistency.
pub mod query;
/// Shared index runtime health, revisions, and reconciliation phases.
pub mod runtime;
/// Derived-index reconciliation phase''')

p='Cargo.toml'; text=get(p); text=text.replace('"0.5.0"','"0.6.0"'); put(p,text)
for p in ['Cargo.lock','fuzz/Cargo.lock']:
    text=get(p)
    text=re.sub(r'(\[\[package\]\]\nname = "bitcoin-rs[^"\n]*"\nversion = )"0\.5\.0"',r'\g<1>"0.6.0"',text)
    package=re.search(r'\[\[package\]\]\nname = "bitcoin-rs-index"\n.*?(?=\n\[\[package\]\]|\Z)',text,re.S)
    if package:
        entry=package.group()
        a,b=entry.index('dependencies = [\n')+len('dependencies = [\n'),entry.index('\n]',entry.index('dependencies = [\n'))
        deps=entry[a:b].splitlines()
        deps=sorted(set(deps+[' "arc-swap",',' "bitcoin-rs-chain",',' "bitcoin-rs-utxo",',' "compact_str",',' "crossbeam-channel",']))
        replacement=entry[:a]+'\n'.join(deps)+entry[b:]
        text=text[:package.start()]+replacement+text[package.end():]
    put(p,text)
edit('docs/policies/source-compatibility.md','(currently `0.5.0`)','(currently `0.6.0`)')
edit('crates/rpc/tests/corpus/core-31.1/20_batch_two_requests.json','/bitcoin-rs:0.5.0/','/bitcoin-rs:0.6.0/')

assets=Path(__file__).resolve().parent/'query-owner-assets'
if assets.is_dir():
    for file in assets.rglob('*'):
        if file.is_file():
            put(file.relative_to(assets).as_posix(),file.read_text())
print('Applied query ownership cut')
