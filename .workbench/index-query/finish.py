from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve()
def edit(path,old,new):
 p=root/path;s=p.read_text();assert old in s, (path,old);p.write_text(s.replace(old,new))
edit('crates/node/src/txindex_worker.rs','use bitcoin_rs_chain::{BlockBodySource, BlockTree, TipSnapshot};','use bitcoin_rs_chain::{BlockTree, TipSnapshot};')
edit('crates/node/src/txindex_worker.rs','    IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark,\n    IndexWatermarks, IndexWriteFence, PreparedBatch, PreparedBatchLimits, ScriptHash,\n    reconcile::{ReconcileLeg, ReconcilePhase},','    IndexCapabilities, IndexError, IndexWatermark,\n    IndexWatermarks, IndexWriteFence, PreparedBatch, PreparedBatchLimits,')
edit('crates/node/src/txindex_worker.rs','use bitcoin_rs_primitives::{Block, BlockHash, Hash256, OutPoint, Tx, Txid, deserialize};','use bitcoin_rs_primitives::Hash256;')
edit('crates/node/src/txindex_worker.rs','use bitcoin_rs_index::query::{ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord,\n    ScriptIndexSnapshot, SpendingRecord, TxIndexInfo, TxIndexQuery, TxQueryError};','use bitcoin_rs_index::query::TxQueryError;')
edit('crates/node/src/txindex_worker_lifecycle_tests.rs','use super::*;','use super::*;\nuse bitcoin_rs_index::query::TxIndexQuery;\nuse bitcoin_rs_primitives::Txid;')
edit('crates/node/src/txindex_worker_recovery_tests.rs','use super::*;','use super::*;\nuse bitcoin_rs_index::reconcile::{ReconcileLeg, ReconcilePhase};')
edit('crates/node/src/txindex_worker_integration_tests.rs','use bitcoin_rs_rpc::context::BlockLog;\n','')
edit('crates/rpc/src/context.rs','use bitcoin_rs_index::ScriptHash;\n','')
edit('crates/rpc/src/context.rs','use compact_str::CompactString;\n','')
edit('crates/index/src/query/tests.rs','use crate::TxIndexSnapshot;','use crate::{IndexError, TxIndexSnapshot};')
edit('crates/node/src/txindex_worker/query_adapter.rs','//! RPC trait adapters over a single captured lifecycle query payload.\n//!\n//! Protocol-facing types remain in node, not in the derived index crate.','//! Stable query handles across process-level open and shutdown transitions.\n//!\n//! Capture one lifecycle payload for the whole call, then use the index-owned\n//! query contract. Readiness, row resolution, and budgets are not duplicated here.')
edit('crates/index/src/query.rs','            block_tree: Arc<RwLock<BlockTree>>,','        block_tree: Arc<RwLock<BlockTree>>,')
edit('crates/index/src/query.rs','/// Implements [`TxIndexQuery`] and [`ScriptIndexQuery`] as the\n/// only public read paths for the transaction index. Every query runs against','/// Implements [`TxIndexQuery`] and [`ScriptIndexQuery`] for callers that need\n/// answers proven against the supplied authoritative chain. Every query runs against')
edit('crates/index/src/query.rs','    /// Builds a query engine over the shared reader and authoritative block source.','    /// Builds a query engine over the shared reader and authoritative block source.\n    ///\n    /// The caller supplies the applied chain, not the best-header tip. Live reads\n    /// require the same transition mutex that protects mutations of `live.utxo`.\n    /// The runtime must be woken after every committed chain transition so its\n    /// revision detects tip ABA. This engine never mutates chainstate or coins.')
edit('crates/index/src/query/tests/source.rs','fn wrong_height_or_hash_at_the_source_cannot_serve_indexed_rows()', 'fn wrong_hash_at_the_source_cannot_serve_indexed_rows()')
p=root/'crates/rpc/src/error.rs'
p.write_text(p.read_text()+'''

#[cfg(test)]
mod tests {
    use super::RpcError;
    use bitcoin_rs_index::query::TxQueryError;

    #[test]
    fn index_failures_keep_their_rpc_code_and_message() {
        for (error, message) in [
            (TxQueryError::Retry, "internal error: transaction index is still catching up; retry later"),
            (TxQueryError::Unavailable("opening".into()), "internal error: transaction index unavailable: opening"),
            (TxQueryError::Storage("read failed".into()), "internal error: transaction index storage error: read failed"),
        ] {
            let rpc = RpcError::from(error);
            assert_eq!(rpc.code(), -32_603);
            assert_eq!(rpc.to_string(), message);
        }
    }
}
''')
p=root/'bin/bitcoin-rs/tests/overhaul_ownership.rs'
p.write_text(p.read_text()+'''

/// IDX-03: query resolution remains usable below RPC and process orchestration.
#[test]
fn index_query_owner_has_no_upward_surface_dependency() {
    let graph = WorkspaceGraph::from_cargo_metadata();
    for target in ["bitcoin-rs-node", "bitcoin-rs-rpc"] {
        let mut pending = vec!["bitcoin-rs-index"];
        let mut visited = std::collections::BTreeSet::new();
        while let Some(name) = pending.pop() {
            assert_ne!(name, target, "index query ownership has an upward dependency");
            if !visited.insert(name) {
                continue;
            }
            if let Some(dependencies) = graph.normal_deps.get(name) {
                pending.extend(dependencies.iter().map(String::as_str));
            }
        }
    }
}
''')
p=root/'docs/contracts/indexing.md';s=p.read_text();a=s.index('Owners:\n');b=s.index('\n## Clauses',a)
s=s[:a]+'''Owners:
- `TxIndexRuntime` in `crates/index/src/runtime.rs` owns the shared health,
  revision, wake notification, and reconciliation-phase state used by workers
  and queries. Node constructs the handle and wakes it after committed changes.
- `TxIndexQueryEngine` in `crates/index/src/query.rs` owns readiness, the shared
  snapshot gate, and public query entrypoints. Its `query/transactions.rs`,
  `query/scripts.rs`, and `query/budget.rs` modules own exact identity resolution,
  script traversal, and aggregate work accounting. `query/types.rs` owns the
  protocol-independent query contracts and typed failures.
- Worker state remains in `crates/node/src/txindex_worker.rs`; reconciliation,
  cursor commits, bounded preparation, and rollback remain in its
  `reconciliation.rs`, `cursor.rs`, `catch_up.rs`, and `rollback.rs` modules.
  Completing that worker extraction is separate from query ownership.
- Node supplies the applied-chain tree/tip, `BlockBodySource`, authoritative
  coins, and their transition mutex. Queries do not mutate these sources. Body
  reads use one height-and-hash provider; RPC `BlockLog` is not a body source or
  a fallback authority.
- Worker supervision and backend opening remain in `txindex_worker/lifecycle.rs`
  and `txindex_worker/startup.rs`; startup owns generation-checked publication.
  The stable node query adapter captures one lifecycle payload per call; it
  does not implement row resolution or readiness.
- `IndexWriter`, `IndexReader`, `IndexCapabilities`, `IndexCapability`,
  `IndexWatermarks`, and `IndexWatermark` remain in `crates/index`.
- Capability status: worker-owned `TxIndexLifecycle` in
  `crates/node/src/txindex_worker.rs` is mapped by `TxIndexCapability` onto the
  RPC wire types in `crates/rpc/src/capabilities.rs`. There is no parallel status
  enum. RPC error-code/message mapping remains in `crates/rpc/src/error.rs`.
''' + s[b:]
s=s.replace('crates/node/src/txindex_worker_query_tests.rs','crates/index/src/query/tests.rs').replace('crates/node/src/txindex_worker_block_source_tests.rs','crates/index/src/query/tests/source.rs').replace('crates/node/src/txindex_worker/query/budget/tests.rs','crates/index/src/query/budget/tests.rs')
s=s.replace('- Enabling either `--txindex` or `--scriptindex` spawns exactly one node-owned\n  `TxIndexRuntime` worker thread.', '- Enabling either `--txindex` or `--scriptindex` spawns exactly one node-supervised\n  worker thread sharing the index-owned `TxIndexRuntime`.')
s += '''\n### Query-owner regression coverage\n\n`crates/index/src/runtime/tests.rs` covers coalesced/lost wake hints, nonblocking\nshutdown, failure diagnostics, and independent phase publication. Query tests\nrun in the index crate without a node or RPC dev-dependency. The source tests\nexercise exact height/hash reads, positioned-read fallback, and missing/corrupt\nbodies through the actual query engine rather than the removed metadata adapter.\n`crates/rpc/src/error.rs` preserves all three query failure mappings;\n`bin/bitcoin-rs/tests/overhaul_ownership.rs` rejects an index-to-node/RPC path.\n'''
p.write_text(s)
p=root/'crates/index/README.md';s=p.read_text();n=s.index('\n## Features');s=s[:n]+'''
`query::TxIndexQueryEngine` owns complete transaction, script-history, and live
queries, including readiness, snapshot fences, exact identity resolution, and
aggregate scan/body budgets. It uses the authoritative applied tip/tree, body
provider, and coin view supplied by the node; it does not own their mutation.
`runtime::TxIndexRuntime` holds the shared health, revision, and phase state.
Query contracts are independent of RPC. The process-level worker, backend-open
supervision, and rollback execution still live in node pending their separate
ownership cut.
''' + s[n:];p.write_text(s)
p=root/'docs/policies/source-compatibility.md';s=p.read_text();n=s.index('\n## 5.');s=s[:n]+'''
### 4.2. Index query ownership in 0.6.0

Index query contracts (`TxIndexQuery`, `ScriptIndexQuery`, `TxIndexInfo`,
`TxQueryError`, `ScriptIndexRecord`, `ScriptHistoryRecord`,
`ScriptIndexSnapshot`, and `SpendingRecord`) move from
`bitcoin_rs_rpc::context` to `bitcoin_rs_index::query`. The former node root
`TxIndexRuntime` export moves to `bitcoin_rs_index::runtime::TxIndexRuntime`.
Update imports directly; the former paths are not retained as aliases.
Convert query failures at the RPC boundary with `RpcError::from` rather than
`TxQueryError::into_rpc_error`. Error codes and messages are unchanged.

This Rust API break advances the shared workspace minor version to 0.6.0.
Index/chainstate encodings, query budgets, configured defaults, and recovery
behavior are not changed by this ownership cut.
''' +s[n:];p.write_text(s)
