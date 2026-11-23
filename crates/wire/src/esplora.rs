#![expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::needless_borrow,
    clippy::significant_drop_in_scrutinee
)]

pub(crate) mod admission;
mod backend;
mod http;
mod model;
mod projection;
mod public;

use crate::context::Context;
use crate::handlers::Handler;
use crate::rest::Response;

use self::projection::Projection;
const MAX_BATCH_BYTES: usize = 16 * 1_024 * 1_024;
pub const DEFAULT_MAX_QUERIES: std::num::NonZeroUsize =
    std::num::NonZeroUsize::MIN.saturating_add(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Surface {
    Public,
    Backend,
}

pub(crate) enum Request<'a> {
    Get(&'a str),
    Post(&'a [u8]),
}

pub(crate) fn respond<R>(
    handler: &Handler,
    surface: Surface,
    path: &str,
    request: Request<'_>,
    send: impl FnOnce(Response) -> R,
) -> R {
    let backend_expensive = surface == Surface::Backend
        && match request {
            Request::Get(_) => admission::is_backend_expensive_get(path),
            Request::Post(_) => admission::is_backend_bulk_post(path),
        };
    let permit = if backend_expensive
        || (matches!(request, Request::Get(_)) && admission::is_expensive(path))
    {
        let Some(permit) = handler.context().esplora_admission.try_acquire() else {
            return send(crate::rest::service_unavailable(
                "expensive Esplora query limit reached",
            ));
        };
        Some(permit)
    } else {
        None
    };
    let response = match request {
        Request::Get(query) => get(handler, surface, path, query),
        Request::Post(body) => {
            if surface == Surface::Backend
                && let Some(response) = backend_post(handler, path, body)
            {
                response
            } else {
                public::post(handler, path, body)
            }
        }
    };
    if !backend_expensive {
        drop(permit);
    }
    send(response)
}

#[must_use]
pub fn route(handler: &Handler, surface: Surface, path: &str, query: &str) -> Response {
    respond(
        handler,
        surface,
        path,
        Request::Get(query),
        core::convert::identity,
    )
}

fn get(handler: &Handler, surface: Surface, path: &str, query: &str) -> Response {
    let ctx = handler.context();
    if needs_tip_fence(path) {
        let projection = Projection::new(&ctx);
        let chain_view = projection.capture_chain_view();
        #[cfg(test)]
        crate::esplora::tests::gate_route_for_tests();
        let response = dispatch_get(handler, &ctx, surface, path, query);
        if response.status == 400 || response.status == 404 {
            return response;
        }
        match projection.ensure_chain_view(&chain_view) {
            Ok(()) => response,
            Err(response) => response,
        }
    } else {
        dispatch_get(handler, &ctx, surface, path, query)
    }
}

fn dispatch_get(
    handler: &Handler,
    ctx: &Context,
    surface: Surface,
    path: &str,
    query: &str,
) -> Response {
    if surface == Surface::Backend {
        if let Some(response) = backend::get(handler, ctx, path, query) {
            return response;
        }
    }
    public::get(ctx, path)
}
#[cfg(test)]
pub(crate) fn route_post(handler: &Handler, surface: Surface, path: &str, body: &[u8]) -> Response {
    respond(
        handler,
        surface,
        path,
        Request::Post(body),
        core::convert::identity,
    )
}

fn backend_post(handler: &Handler, path: &str, body: &[u8]) -> Option<Response> {
    if !needs_tip_fence(path) {
        return backend::post(handler, path, body);
    }
    let ctx = handler.context();
    let projection = Projection::new(&ctx);
    let chain_view = projection.capture_chain_view();
    #[cfg(test)]
    crate::esplora::tests::gate_route_for_tests();
    let response = backend::post(handler, path, body)?;
    if response.status == 400 || response.status == 404 {
        return Some(response);
    }
    match projection.ensure_chain_view(&chain_view) {
        Ok(()) => Some(response),
        Err(unavailable) => Some(unavailable),
    }
}

#[must_use]
pub fn namespace(path: &str) -> Option<(Surface, &str)> {
    strip_dir(path, "/api")
        .map(|rest| (Surface::Public, rest))
        .or_else(|| strip_dir(path, "/esplora").map(|rest| (Surface::Backend, rest)))
}

fn needs_tip_fence(path: &str) -> bool {
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    !matches!(
        parts.as_slice(),
        ["blocks", ..]
            | ["block", ..]
            | ["block-height", ..]
            | ["tx", _, "merkleblock-proof" | "merkle-proof"]
            | ["tx", _]
            | ["tx", _, "hex" | "raw" | "status" | "outspends"]
            | ["tx", _, "outspend", _]
            | ["address-prefix", ..]
            | ["internal", "block", _, "txs"]
            | ["mempool", ..]
            | ["fee-estimates"]
    )
}

fn strip_dir<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        Some("/")
    } else if rest.starts_with('/') {
        Some(rest)
    } else {
        None
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use alloc::sync::Arc;
    mod admission {
        use super::*;
        use crate::context::{ScriptIndexQuery, ScriptIndexSnapshot};

        mod load {
            //! Bounded CPU/projection probe. This synthetic index is not disk/sync evidence.

            use super::super::*;
            use std::sync::Barrier;
            use std::time::Instant;

            struct LoadTxIndex {
                transactions: std::collections::HashMap<Txid, Tx>,
                calls: AtomicUsize,
                block: TransactionBlock,
            }

            impl crate::context::DerivedIndexQuery for LoadTxIndex {
                fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
                    self.calls.fetch_add(1, Ordering::Relaxed);
                    Ok(self.transactions.get(txid).cloned())
                }

                fn transaction_block(
                    &self,
                    txid: &Txid,
                ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
                    Ok(self.transaction(txid)?.map(|tx| (tx, self.block)))
                }

                fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                    Ok(None)
                }

                fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
                    Ok(crate::context::DerivedIndexInfo {
                        synced: true,
                        best_block_height: 0,
                        applied_height: 0,
                        historical_height: 0,
                        verified_height: 0,
                        coverage_height: 0,
                    })
                }
            }

            #[test]
            #[ignore = "bounded load probe; run explicitly with --ignored --nocapture"]
            fn large_script_projection_load() {
                let limit = std::env::var("ESPLORA_LOAD_LIMIT")
                    .expect("set candidate limit")
                    .parse::<std::num::NonZeroUsize>()
                    .expect("positive limit");
                let target = vec![0x51];
                let transactions = (1..=20_000)
                    .map(|value| {
                        transaction(
                            None,
                            TxOut {
                                value: Amount::from_sat(value),
                                script_pubkey: target.clone().into(),
                            },
                        )
                    })
                    .collect::<Vec<_>>();
                let history = transactions
                    .iter()
                    .map(|tx| ScriptHistoryRecord {
                        txid: tx.txid(),
                        height: 0,
                    })
                    .collect();
                let funding = transactions
                    .iter()
                    .map(|tx| ScriptIndexRecord {
                        txid: tx.txid(),
                        height: 0,
                        value: tx.outputs[0].value.to_sat(),
                        vout: 0,
                    })
                    .collect::<Vec<_>>();
                let mut ctx = Context::new().with_esplora_query_limit(limit);
                let mut block = fixture_genesis();
                block.txs = transactions.clone();
                block.header.merkle_root = merkle_root(&block.txs).expect("load transactions");
                ctx.chain
                    .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                        0, &block,
                    ));
                ctx.chain
                    .block_tree
                    .write()
                    .insert_node(None, block.header, NodeStatus::Active)
                    .expect("load block header");
                ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
                    history,
                    funding: funding.clone(),
                    unspent: funding,
                }));
                let tx_index = Arc::new(LoadTxIndex {
                    block: TransactionBlock {
                        height: 0,
                        hash: Hash256::from(block.block_hash()),
                    },
                    transactions: transactions.into_iter().map(|tx| (tx.txid(), tx)).collect(),
                    calls: AtomicUsize::new(0),
                });
                ctx.indexes.esplora_tx_index = Some(tx_index.clone());
                let handler = Arc::new(Handler::new(Arc::new(ctx)));
                let hash = ScriptHash::new(&target)
                    .to_byte_array()
                    .to_lower_hex_string();
                let paths = ["", "/utxo", "/txs", "/txs/summary", "/txs/chain"]
                    .map(|suffix| format!("/scripthash/{hash}{suffix}"));
                // Validate all successful results and warm the same fixture before sampling.
                for path in &paths {
                    assert_eq!(route(&handler, path, "").status, 200);
                }
                let start = Instant::now();
                let barrier = Arc::new(Barrier::new(8));
                let results = std::thread::scope(|scope| {
                    let mut workers = Vec::with_capacity(8);
                    for _ in 0..8 {
                        let paths = &paths;
                        let handler = &handler;
                        let barrier = &barrier;
                        workers.push(scope.spawn(move || {
                            let mut results = Vec::new();
                            for round in 0..20 {
                                barrier.wait();
                                let started = Instant::now();
                                let response = route(handler, &paths[round % paths.len()], "");
                                assert!(matches!(response.status, 200 | 503));
                                results.push((
                                    response.status,
                                    started.elapsed().as_secs_f64() * 1000.0,
                                ));
                            }
                            results
                        }));
                    }
                    workers
                        .into_iter()
                        .flat_map(|worker| worker.join().expect("load worker"))
                        .collect::<Vec<_>>()
                });
                let mut accepted = results
                    .iter()
                    .filter(|(status, _)| *status == 200)
                    .map(|(_, ms)| *ms)
                    .collect::<Vec<_>>();
                let mut rejected = results
                    .iter()
                    .filter(|(status, _)| *status == 503)
                    .map(|(_, ms)| *ms)
                    .collect::<Vec<_>>();
                accepted.sort_by(f64::total_cmp);
                rejected.sort_by(f64::total_cmp);
                assert_ne!(accepted.len(), 0);
                assert_ne!(rejected.len(), 0);
                println!(
                    "limit={} requests=160 accepted={} rejected={} accepted_p50_ms={:.3} accepted_p95_ms={:.3} rejected_p95_ms={:.3} wall_s={:.3} tx_lookups={} body_reads=0 sync_progress=not_attached",
                    limit,
                    accepted.len(),
                    rejected.len(),
                    accepted[accepted.len() / 2],
                    accepted[(accepted.len() - 1) * 95 / 100],
                    rejected[(rejected.len() - 1) * 95 / 100],
                    start.elapsed().as_secs_f64(),
                    tx_index.calls.load(Ordering::Relaxed)
                );
                assert_eq!(
                    route(&handler, &paths[0], "").status,
                    200,
                    "permits recover after successful load"
                );
            }
        }

        struct GatedIndex {
            entered: Sender<()>,
            release: std::sync::Mutex<Receiver<()>>,
            calls: AtomicUsize,
        }

        impl ScriptIndexQuery for GatedIndex {
            fn history_snapshot(&self, _: ScriptHash) -> Result<ScriptIndexSnapshot, TxQueryError> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                self.entered.send(()).expect("signal admitted work");
                self.release
                    .lock()
                    .expect("release gate")
                    .recv_timeout(Duration::from_secs(30))
                    .expect("release admitted work");
                Err(TxQueryError::Unavailable(
                    TxUnavailableCause::ScriptHashLimitExceeded { limit: 25_000 },
                ))
            }

            fn unspent_outputs(
                &self,
                _: ScriptHash,
            ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
                panic!("rejected request reached the index")
            }

            fn spender(
                &self,
                _: OutPoint,
            ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
                panic!("rejected request reached the index")
            }
        }

        #[test]
        fn concurrent_routes_reject_before_index_work_and_release_after_errors() {
            let (entered_send, entered_recv) = channel();
            let (release_send, release_recv) = channel();
            let index = Arc::new(GatedIndex {
                entered: entered_send,
                release: std::sync::Mutex::new(release_recv),
                calls: AtomicUsize::new(0),
            });
            let mut ctx = Context::new()
                .with_esplora_query_limit(std::num::NonZeroUsize::new(2).expect("limit"));
            ctx.indexes.script_index = Some(index.clone());
            let handler = Arc::new(Handler::new(Arc::new(ctx)));
            let hash = "00".repeat(32);
            let mut workers = Vec::new();
            for prefix in ["/api", "/esplora"] {
                let handler = Arc::clone(&handler);
                let path = format!("{prefix}/scripthash/{hash}");
                workers.push(std::thread::spawn(move || dispatch(&handler, &path, "")));
            }
            for _ in 0..2 {
                entered_recv
                    .recv_timeout(Duration::from_secs(30))
                    .expect("concurrent query entered");
            }
            for suffix in [
                "",
                "/utxo",
                "/txs",
                "/txs/chain",
                "/txs/chain/cursor",
                "/txs/summary",
                "/txs/mempool",
            ] {
                let response = route(&handler, &format!("/scripthash/{hash}{suffix}"), "");
                assert_eq!(response.status, 503);
                assert_eq!(response.body, b"expensive Esplora query limit reached");
            }
            assert_eq!(index.calls.load(Ordering::Relaxed), 2);
            assert_eq!(route(&handler, "/blocks/tip/height", "").status, 200);
            for _ in 0..2 {
                release_send.send(()).expect("release");
            }
            for worker in workers {
                assert_eq!(worker.join().expect("request thread").status, 422);
            }
            assert_eq!(route(&handler, "/address/invalid", "").status, 400);
            let first = handler
                .context()
                .esplora_admission
                .try_acquire()
                .expect("recovered first slot");
            let second = handler
                .context()
                .esplora_admission
                .try_acquire()
                .expect("recovered second slot");
            assert!(handler.context().esplora_admission.try_acquire().is_none());
            drop((first, second));
        }
    }
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::time::Duration;

    use bitcoin::hashes::Hash as _;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_chain::chain::{NodeStatus, TipSnapshot, regtest_fixture::merkle_root};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_index::block_log::BlockRecord;
    use bitcoin_rs_index::{ScriptHash, TransactionBlock};
    use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry, MempoolObserver, MutationEnvelope};
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};

    use super::projection::Projection;
    use super::public::{
        CHAIN_PAGE, address_transaction_summary, block_txs, chain_history, fee_rate_sat_per_vbyte,
        full_history, mempool_history, summary,
    };
    use crate::context::{
        Context, ScriptHistoryRecord, ScriptIndexRecord, TxQueryError, TxUnavailableCause,
    };
    use crate::handlers::Handler;
    use crate::rest::Response;
    use crate::test_error::TestError;

    fn route(handler: &Handler, path: &str, query: &str) -> Response {
        dispatch(handler, &api(path), query)
    }

    fn route_post(handler: &Handler, path: &str, body: &[u8]) -> Response {
        dispatch_post(handler, &api(path), body)
    }

    fn backend_route(handler: &Handler, path: &str, query: &str) -> Response {
        dispatch(handler, &esplora(path), query)
    }

    fn backend_route_post(handler: &Handler, path: &str, body: &[u8]) -> Response {
        dispatch_post(handler, &esplora(path), body)
    }

    fn dispatch(handler: &Handler, full: &str, query: &str) -> Response {
        let (surface, path) = super::namespace(full).expect("test path is an Esplora directory");
        super::route(handler, surface, path, query)
    }

    fn dispatch_post(handler: &Handler, full: &str, body: &[u8]) -> Response {
        let (surface, path) = super::namespace(full).expect("test path is an Esplora directory");
        super::route_post(handler, surface, path, body)
    }

    fn api(path: &str) -> String {
        prefixed("/api", path)
    }

    fn esplora(path: &str) -> String {
        prefixed("/esplora", path)
    }

    fn prefixed(prefix: &str, path: &str) -> String {
        match super::namespace(path) {
            Some(_) => path.to_owned(),
            None => format!("{prefix}{path}"),
        }
    }

    use crate::context::BlockBodies;

    fn transaction(input: Option<OutPoint>, output: TxOut) -> Tx {
        Tx {
            version: 2,
            inputs: input
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: vec![output],
            lock_time: LockTime::ZERO,
        }
    }

    fn fixture_genesis() -> Block {
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            },
            txs: vec![transaction(
                Some(OutPoint::null()),
                TxOut {
                    value: Amount::from_sat(5_000_000_000),
                    script_pubkey: vec![0x51].into(),
                },
            )],
        };
        block.header.merkle_root = merkle_root(&block.txs).expect("fixture block has transactions");
        block
    }

    fn extend_tip(
        context: &Context,
        block: &Block,
    ) -> Result<(Arc<TipSnapshot>, Arc<TipSnapshot>, Header), TestError> {
        let mut tree = context.chain.block_tree.write();
        let genesis = tree.insert_node(None, block.header, NodeStatus::Active)?;
        let tip = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("fixture tip missing"))?;
        let child = Header {
            prev_blockhash: block.header.compute_hash(),
            nonce: block.header.nonce.wrapping_add(1),
            ..block.header
        };
        tree.insert_node(Some(genesis), child, NodeStatus::Active)?;
        let extended = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("fixture tip missing"))?;
        Ok((tip, extended, child))
    }

    fn p2sh_true_script() -> Script {
        let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        Script::from_bytes(redeem.to_p2sh().into_bytes())
    }

    fn p2sh_true_spend_script_sig() -> Script {
        Script::from_bytes(vec![0x01, 0x51])
    }

    fn transaction_with_funded_input(ctx: &Context, input_value: u64) -> (Tx, Tx) {
        let spendable = p2sh_true_script();
        let script = [vec![0x00, 0x14], vec![0x11; 20]].concat();
        let funding = transaction(
            None,
            TxOut {
                value: Amount::from_sat(input_value),
                script_pubkey: spendable.clone(),
            },
        );
        let txid = funding.txid();
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(txid, 0),
            TxOut {
                value: Amount::from_sat(input_value),
                script_pubkey: spendable,
            },
            false,
            1,
        ));
        ctx.populate_fixture_coins(&changes)
            .expect("fund test UTXO");
        let mut spend = transaction(
            Some(OutPoint::new(txid, 0)),
            TxOut {
                value: Amount::from_sat(input_value - 1_000),
                script_pubkey: script.into(),
            },
        );
        spend.inputs[0].script_sig = p2sh_true_spend_script_sig();
        (spend, funding)
    }

    struct StaticTxIndex {
        transaction: Tx,
        block: Option<TransactionBlock>,
    }

    impl StaticTxIndex {
        fn new(transaction: Tx) -> Self {
            Self {
                transaction,
                block: None,
            }
        }
    }

    impl crate::context::DerivedIndexQuery for StaticTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            Ok((self.transaction.txid() == *txid).then(|| self.transaction.clone()))
        }

        fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            let (out_txid, out_vout) = (outpoint.txid, outpoint.vout);
            Ok((self.transaction.txid() == out_txid)
                .then(|| {
                    self.transaction
                        .outputs
                        .get(usize::try_from(out_vout).unwrap_or(usize::MAX))
                })
                .flatten()
                .map(|output| output.value.to_sat()))
        }

        fn transaction_block(
            &self,
            txid: &Txid,
        ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
            Ok((self.transaction.txid() == *txid)
                .then_some(self.block)
                .flatten()
                .map(|block| (self.transaction.clone(), block)))
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 0,
                applied_height: 0,
                historical_height: 0,
                verified_height: 0,
                coverage_height: 0,
            })
        }
    }

    struct CountingTxIndex {
        transactions: Vec<Tx>,
        calls: Arc<AtomicUsize>,
        block: Option<bitcoin_rs_index::block_log::BlockRecord>,
    }

    impl crate::context::DerivedIndexQuery for CountingTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .transactions
                .iter()
                .find(|transaction| transaction.txid() == *txid)
                .cloned())
        }

        fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }

        fn transaction_block(
            &self,
            txid: &Txid,
        ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
            Ok(self
                .transaction(txid)?
                .zip(self.block.as_ref())
                .map(|(tx, block)| {
                    (
                        tx,
                        TransactionBlock {
                            height: block.height,
                            hash: Hash256::from(block.hash),
                        },
                    )
                }))
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 0,
                applied_height: 0,
                historical_height: 0,
                verified_height: 0,
                coverage_height: 0,
            })
        }
    }

    struct FixtureTxIndex(Vec<(Tx, TransactionBlock)>);

    impl crate::context::DerivedIndexQuery for FixtureTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            Ok(self
                .0
                .iter()
                .find(|(transaction, _)| transaction.txid() == *txid)
                .map(|(transaction, _)| transaction.clone()))
        }

        fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            let (out_txid, out_vout) = (outpoint.txid, outpoint.vout);
            Ok(self
                .0
                .iter()
                .find(|(transaction, _)| transaction.txid() == out_txid)
                .and_then(|(transaction, _)| {
                    transaction
                        .outputs
                        .get(usize::try_from(out_vout).unwrap_or(usize::MAX))
                })
                .map(|output| output.value.to_sat()))
        }

        fn transaction_block(
            &self,
            txid: &Txid,
        ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
            Ok(self
                .0
                .iter()
                .find(|(transaction, _)| transaction.txid() == *txid)
                .map(|(transaction, block)| (transaction.clone(), *block)))
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            let best = self
                .0
                .iter()
                .map(|(_, block)| block.height)
                .max()
                .unwrap_or(0);
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: best,
                applied_height: best,
                historical_height: best,
                verified_height: best,
                coverage_height: best,
            })
        }
    }

    struct StaticScriptIndex {
        history: Vec<ScriptHistoryRecord>,
        funding: Vec<ScriptIndexRecord>,
        unspent: Vec<ScriptIndexRecord>,
    }

    struct RepublishTipScriptIndex {
        applied_tip: bitcoin_rs_chain::chain::TipReader,
        replacement: Option<Arc<bitcoin_rs_chain::chain::TipSnapshot>>,
        published: AtomicBool,
    }

    impl crate::context::ScriptIndexQuery for RepublishTipScriptIndex {
        fn unspent_outputs(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            Ok(Vec::new())
        }

        fn history_snapshot(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<crate::context::ScriptIndexSnapshot, TxQueryError> {
            if !self.published.swap(true, Ordering::SeqCst)
                && let Some(tip) = self.applied_tip.load_full()
            {
                self.applied_tip.store(Some(
                    self.replacement
                        .clone()
                        .unwrap_or_else(|| Arc::new((*tip).clone())),
                ));
            }
            Ok(crate::context::ScriptIndexSnapshot::default())
        }

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            Ok(None)
        }
    }

    struct AdvanceTipScriptIndex {
        applied_tip: bitcoin_rs_chain::chain::TipReader,
        extended: Arc<bitcoin_rs_chain::chain::TipSnapshot>,
        history: Vec<ScriptHistoryRecord>,
    }

    impl crate::context::ScriptIndexQuery for AdvanceTipScriptIndex {
        fn unspent_outputs(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            Ok(Vec::new())
        }

        fn history_snapshot(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<crate::context::ScriptIndexSnapshot, TxQueryError> {
            self.applied_tip.store(Some(Arc::clone(&self.extended)));
            Ok(crate::context::ScriptIndexSnapshot {
                history: self.history.clone(),
                funding: Vec::new(),
            })
        }

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            Ok(None)
        }
    }

    struct AdvanceTipTxIndex {
        applied_tip: bitcoin_rs_chain::chain::TipReader,
        extended: Arc<bitcoin_rs_chain::chain::TipSnapshot>,
        tx: Tx,
        height: u32,
        hash: Hash256,
    }

    impl crate::context::DerivedIndexQuery for AdvanceTipTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            self.applied_tip.store(Some(Arc::clone(&self.extended)));
            Ok((self.tx.txid() == *txid).then(|| self.tx.clone()))
        }

        fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }

        fn transaction_block(
            &self,
            txid: &Txid,
        ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
            self.applied_tip.store(Some(Arc::clone(&self.extended)));
            Ok((self.tx.txid() == *txid).then(|| {
                (
                    self.tx.clone(),
                    TransactionBlock {
                        height: self.height,
                        hash: self.hash,
                    },
                )
            }))
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 0,
                applied_height: 0,
                historical_height: 0,
                verified_height: 0,
                coverage_height: 0,
            })
        }
    }

    impl crate::context::ScriptIndexQuery for StaticScriptIndex {
        fn unspent_outputs(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            Ok(self.unspent.clone())
        }

        fn history_snapshot(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<crate::context::ScriptIndexSnapshot, TxQueryError> {
            Ok(crate::context::ScriptIndexSnapshot {
                history: self.history.clone(),
                funding: self.funding.clone(),
            })
        }

        fn confirmed_history(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
            Ok(self.history.clone())
        }

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            Ok(None)
        }
    }

    struct MonitoredScriptIndex {
        history: Vec<ScriptHistoryRecord>,
        funding: Vec<ScriptIndexRecord>,
        unspent: Vec<ScriptIndexRecord>,
        unspent_calls: Arc<AtomicUsize>,
        history_calls: Arc<AtomicUsize>,
    }

    impl crate::context::ScriptIndexQuery for MonitoredScriptIndex {
        fn unspent_outputs(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            self.unspent_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.unspent.clone())
        }

        fn history_snapshot(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<crate::context::ScriptIndexSnapshot, TxQueryError> {
            self.history_calls.fetch_add(1, Ordering::Relaxed);
            Ok(crate::context::ScriptIndexSnapshot {
                history: self.history.clone(),
                funding: self.funding.clone(),
            })
        }

        fn confirmed_history(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
            self.history_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.history.clone())
        }

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            Ok(None)
        }
    }

    fn contract_fixture() -> Result<(Handler, Tx, Block, String), TestError> {
        let target = {
            let mut script = Vec::with_capacity(22);
            script.push(0x00);
            script.push(0x14);
            script.extend_from_slice(&[2; 20]);
            script
        };
        let address = bitcoin::Address::from_script(
            bitcoin::Script::from_bytes(&target),
            bitcoin::Network::Regtest,
        )?
        .to_string();
        let mut transaction = transaction(
            None,
            TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: target.into(),
            },
        );
        transaction.inputs.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![1, 1].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            },
            txs: vec![transaction.clone()],
        };
        block.header.merkle_root = merkle_root(&block.txs).expect("fixture block has transactions");
        let record = bitcoin_rs_index::block_log::BlockRecord::from_block(0, &block);
        let txid = transaction.txid();
        let mut context = Context::new();
        context.chain.chain_network = bitcoin_rs_consensus::primitives::Network::Regtest;
        context.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(0, record.hash, consensus_bytes(&block))],
        }));
        context.chain.add_block(record);
        let tip = {
            let mut tree = context.chain.block_tree.write();
            tree.insert_node(None, block.header, NodeStatus::Active)?;
            tree.tip()
                .ok_or_else(|| std::io::Error::other("fixture tip missing"))?
                .as_ref()
                .clone()
        };
        context.chain.applied_tip.store(Some(Arc::new(tip)));
        context.indexes.esplora_tx_index = Some(Arc::new(FixtureTxIndex(vec![(
            transaction.clone(),
            TransactionBlock {
                height: 0,
                hash: Hash256::from(block.block_hash()),
            },
        )])));
        let funding = vec![ScriptIndexRecord {
            txid,
            height: 0,
            value: 5_000_000_000,
            vout: 0,
        }];
        context.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: vec![ScriptHistoryRecord { txid, height: 0 }],
            funding: funding.clone(),
            unspent: funding,
        }));
        Ok((Handler::new(Arc::new(context)), transaction, block, address))
    }

    #[test]
    fn tip_routes_remain_available_without_script_index() {
        let handler = Handler::new(Arc::new(Context::new()));
        assert_eq!(route(&handler, "/blocks/tip/height", "").status, 200);
        assert_eq!(
            route(
                &handler,
                "/scripthash/0000000000000000000000000000000000000000000000000000000000000000/utxo",
                ""
            )
            .status,
            503
        );
    }

    #[test]
    fn fee_estimate_conversion_preserves_the_exact_relay_floor() {
        assert_eq!(
            fee_rate_sat_per_vbyte(crate::convert::sat_to_btc(1_000)).to_bits(),
            1.0_f64.to_bits()
        );
    }

    #[test]
    fn bitcoin_esplora_surface_matches_documented_routes_and_content_types() -> Result<(), TestError>
    {
        let (handler, transaction, block, address) = contract_fixture()?;
        let txid = transaction.txid().to_string();
        let block_hash = block.block_hash().to_string();
        let script_hash = ScriptHash::new(&transaction.outputs[0].script_pubkey)
            .to_byte_array()
            .to_lower_hex_string();
        let routes = [
            (format!("/tx/{txid}"), 200, "application/json"),
            (format!("/tx/{txid}/status"), 200, "application/json"),
            (format!("/tx/{txid}/hex"), 200, "text/plain"),
            (format!("/tx/{txid}/raw"), 200, "application/octet-stream"),
            (format!("/tx/{txid}/merkleblock-proof"), 200, "text/plain"),
            (format!("/tx/{txid}/merkle-proof"), 200, "application/json"),
            (format!("/tx/{txid}/outspend/0"), 200, "application/json"),
            (format!("/tx/{txid}/outspends"), 200, "application/json"),
            (format!("/address/{address}"), 200, "application/json"),
            (format!("/address/{address}/txs"), 200, "application/json"),
            (
                format!("/address/{address}/txs/chain"),
                200,
                "application/json",
            ),
            (
                format!("/address/{address}/txs/chain/{txid}"),
                200,
                "application/json",
            ),
            (
                format!("/address/{address}/txs/mempool"),
                200,
                "application/json",
            ),
            (format!("/address/{address}/utxo"), 200, "application/json"),
            (
                format!("/scripthash/{script_hash}"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/txs"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/txs/chain"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/txs/chain/{txid}"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/txs/mempool"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/utxo"),
                200,
                "application/json",
            ),
            (format!("/block/{block_hash}"), 200, "application/json"),
            (format!("/block/{block_hash}/header"), 200, "text/plain"),
            (
                format!("/block/{block_hash}/status"),
                200,
                "application/json",
            ),
            (format!("/block/{block_hash}/txs"), 200, "application/json"),
            (
                format!("/block/{block_hash}/txs/0"),
                200,
                "application/json",
            ),
            (
                format!("/block/{block_hash}/txids"),
                200,
                "application/json",
            ),
            (format!("/block/{block_hash}/txid/0"), 200, "text/plain"),
            (
                format!("/block/{block_hash}/raw"),
                200,
                "application/octet-stream",
            ),
            ("/block-height/0".to_owned(), 200, "text/plain"),
            ("/blocks".to_owned(), 200, "application/json"),
            ("/blocks/0".to_owned(), 200, "application/json"),
            ("/blocks/tip/height".to_owned(), 200, "text/plain"),
            ("/blocks/tip/hash".to_owned(), 200, "text/plain"),
            ("/mempool".to_owned(), 200, "application/json"),
            ("/mempool/txids".to_owned(), 200, "application/json"),
            ("/mempool/recent".to_owned(), 200, "application/json"),
            ("/fee-estimates".to_owned(), 200, "application/json"),
            ("/address-prefix/bcrt1".to_owned(), 503, "text/plain"),
        ];
        for (path, expected_status, expected_content_type) in routes {
            let response = route(&handler, &path, "");
            assert_eq!(response.status, expected_status, "status for {path}");
            assert_eq!(
                response.content_type, expected_content_type,
                "content type for {path}"
            );
        }

        let (broadcast_transaction, _) =
            transaction_with_funded_input(handler.context().as_ref(), 10_000);
        let raw = consensus_bytes(&broadcast_transaction).to_lower_hex_string();
        let broadcast = route_post(&handler, "/tx", raw.as_bytes());
        assert_eq!(
            broadcast.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&broadcast.body)
        );
        assert_eq!(broadcast.content_type, "text/plain");

        let package = route_post(&handler, "/txs/package", b"[]");
        assert_eq!(package.status, 404);
        Ok(())
    }

    #[test]
    fn bitcoin_esplora_representations_match_the_documented_schemas() -> Result<(), TestError> {
        fn keys(value: &Value) -> std::collections::BTreeSet<&str> {
            value
                .as_object()
                .map(|object| object.iter().map(|(key, _)| key).collect())
                .unwrap_or_default()
        }

        let (handler, transaction, block, address) = contract_fixture()?;
        let txid = transaction.txid().to_string();
        let block_hash = block.block_hash().to_string();
        let transaction_value: Value =
            sonic_rs::from_slice(&route(&handler, &format!("/tx/{txid}"), "").body)?;
        assert_eq!(
            keys(&transaction_value),
            [
                "fee", "locktime", "size", "status", "txid", "version", "vin", "vout", "weight",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            keys(&transaction_value["vin"][0]),
            [
                "is_coinbase",
                "prevout",
                "scriptsig",
                "scriptsig_asm",
                "sequence",
                "txid",
                "vout",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            transaction_value["vin"][0]["txid"],
            json!(Txid::default().to_string())
        );
        assert_eq!(transaction_value["vin"][0]["vout"], json!(u32::MAX));
        assert!(transaction_value["vin"][0]["prevout"].is_null());
        assert_eq!(transaction_value["fee"], json!(0));
        assert_eq!(
            keys(&transaction_value["vout"][0]),
            [
                "scriptpubkey",
                "scriptpubkey_address",
                "scriptpubkey_asm",
                "scriptpubkey_type",
                "value",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            keys(&transaction_value["status"]),
            ["block_hash", "block_height", "block_time", "confirmed"]
                .into_iter()
                .collect()
        );

        let block_value: Value =
            sonic_rs::from_slice(&route(&handler, &format!("/block/{block_hash}"), "").body)?;
        assert_eq!(
            keys(&block_value),
            [
                "bits",
                "difficulty",
                "height",
                "id",
                "mediantime",
                "merkle_root",
                "nonce",
                "previousblockhash",
                "size",
                "timestamp",
                "tx_count",
                "version",
                "weight",
            ]
            .into_iter()
            .collect()
        );
        assert!(block_value["previousblockhash"].is_null());

        let summary: Value =
            sonic_rs::from_slice(&route(&handler, &format!("/address/{address}"), "").body)?;
        assert_eq!(
            keys(&summary),
            ["address", "chain_stats", "mempool_stats"]
                .into_iter()
                .collect()
        );
        let stat_keys = [
            "funded_txo_count",
            "funded_txo_sum",
            "spent_txo_count",
            "spent_txo_sum",
            "tx_count",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys(&summary["chain_stats"]), stat_keys);
        assert_eq!(summary["chain_stats"]["funded_txo_count"], json!(1));
        assert_eq!(summary["chain_stats"]["spent_txo_count"], json!(0));

        let utxos: Value =
            sonic_rs::from_slice(&route(&handler, &format!("/address/{address}/utxo"), "").body)?;
        assert_eq!(utxos[0]["status"]["confirmed"], json!(true));
        assert_eq!(utxos[0]["status"]["block_height"], json!(0));

        let outspend: Value =
            sonic_rs::from_slice(&route(&handler, &format!("/tx/{txid}/outspend/0"), "").body)?;
        assert_eq!(outspend, json!({"spent":false}));

        let mempool: Value = sonic_rs::from_slice(&route(&handler, "/mempool", "").body)?;
        assert_eq!(
            keys(&mempool),
            ["count", "fee_histogram", "total_fee", "vsize"]
                .into_iter()
                .collect()
        );
        Ok(())
    }

    #[test]
    fn bitcoin_esplora_errors_distinguish_bad_missing_and_unavailable() {
        let handler = Handler::new(Arc::new(Context::new()));
        assert_eq!(route(&handler, "/tx/not-a-txid", "").status, 400);
        assert_eq!(route(&handler, "/block/not-a-hash", "").status, 400);
        assert_eq!(
            route(&handler, "/block-height/not-a-height", "").status,
            400
        );
        assert_eq!(
            route(
                &handler,
                "/block/0000000000000000000000000000000000000000000000000000000000000000",
                ""
            )
            .status,
            404
        );
        assert_eq!(
            route(
                &handler,
                "/tx/0000000000000000000000000000000000000000000000000000000000000000",
                ""
            )
            .status,
            503
        );
        assert_eq!(
            route(
                &handler,
                "/block/0000000000000000000000000000000000000000000000000000000000000000/txs/1",
                ""
            )
            .status,
            400
        );
    }

    #[test]
    fn esplora_numeric_path_segments_refuse_leading_plus() -> Result<(), TestError> {
        let (handler, transaction, block, _) = contract_fixture()?;
        let block_hash = block.block_hash().to_string();
        assert_eq!(route(&handler, "/block-height/+1", "").status, 400);
        assert_eq!(route(&handler, "/blocks/+1", "").status, 400);
        assert_eq!(
            route(&handler, &format!("/block/{block_hash}/txs/+25"), "").status,
            400
        );
        assert_eq!(
            route(
                &handler,
                &format!("/tx/{}/outspend/+0", transaction.txid()),
                ""
            )
            .status,
            400
        );
        assert_eq!(
            route(&handler, &format!("/block/{block_hash}/txid/+0"), "").status,
            400
        );
        assert_eq!(route(&handler, "/block-height/0", "").status, 200);
        assert_eq!(route(&handler, "/blocks/0", "").status, 200);
        assert_eq!(
            route(&handler, &format!("/block/{block_hash}/txs/25"), "").status,
            200
        );
        assert_eq!(
            route(
                &handler,
                &format!("/tx/{}/outspend/0", transaction.txid()),
                ""
            )
            .status,
            200
        );
        assert_eq!(
            route(&handler, &format!("/block/{block_hash}/txid/0"), "").status,
            200
        );
        Ok(())
    }

    #[test]
    fn esplora_lives_only_under_the_api_prefix() -> Result<(), TestError> {
        let (handler, _, _, _) = contract_fixture()?;
        let genesis = route(&handler, "/block-height/0", "");
        assert_eq!(genesis.status, 200);
        assert_eq!(
            dispatch(&handler, "/api/block-height/0", "").body,
            genesis.body
        );
        assert!(
            super::namespace("/block-height/0").is_none(),
            "unprefixed electrs paths are not Esplora on this listener"
        );
        assert_eq!(
            dispatch(&handler, "/api/v1/block-height/0", "").status,
            404,
            "/api/v1 is Mempool's API, not an Esplora alias"
        );
        assert!(
            super::namespace("/apitx").is_none(),
            "/apitx is not an Esplora directory"
        );
        assert_eq!(
            dispatch_post(&handler, "/api/tx", b"00").status,
            400,
            "POST /api/tx stays Esplora"
        );
        assert_eq!(
            dispatch_post(&handler, "/api/v1/tx", b"00").status,
            404,
            "POST /api/v1/tx stays in the /api namespace, not JSON-RPC"
        );
        assert!(
            super::namespace("/tx").is_none(),
            "unprefixed POST /tx falls through to JSON-RPC"
        );
        Ok(())
    }

    #[test]
    fn api_is_the_public_electrs_directory() -> Result<(), TestError> {
        let (handler, _, _, _) = contract_fixture()?;
        assert_eq!(
            route(&handler, "/internal/mempool/txs", "").status,
            404,
            "/api/internal is not a wallet-facing route"
        );
        assert_eq!(
            route(&handler, "/block-template", "").status,
            404,
            "/api/block-template is not a wallet-facing route"
        );
        assert!(
            super::namespace("/internal/mempool/txs").is_none(),
            "unprefixed /internal is not served"
        );
        assert_eq!(
            dispatch_post(&handler, "/api/internal/txs", b"[]").status,
            404,
            "POST /api/internal/txs stays in the public directory (404)"
        );
        assert_eq!(
            dispatch_post(&handler, "/api/v1/not-esplora", b"{}").status,
            404,
            "unknown POST under /api must not fall through to JSON-RPC"
        );
        assert!(
            super::namespace("/not-esplora").is_none(),
            "unprefixed unknown POST still falls through to JSON-RPC"
        );
        Ok(())
    }

    #[test]
    fn esplora_is_the_mempool_backend_superset() -> Result<(), TestError> {
        let (handler, _, _, _) = contract_fixture()?;
        assert_eq!(
            backend_route(&handler, "/internal/mempool/txs", "").status,
            200,
            "mempool backend uses ESPLORA_REST_API_URL=…/esplora"
        );
        assert_eq!(
            backend_route(&handler, "/block-template", "").status,
            503,
            "/esplora/block-template stays on the node listener for the backend"
        );
        assert_eq!(
            backend_route(&handler, "/block-height/0", "").status,
            200,
            "/esplora is a superset: public electrs routes still answer"
        );
        assert_eq!(
            dispatch_post(&handler, "/esplora/internal/txs", b"[]").status,
            200,
            "POST /esplora/internal/txs is the mempool-backend bulk path"
        );
        assert_eq!(
            dispatch_post(&handler, "/esplora/not-esplora", b"{}").status,
            404,
            "unknown POST under /esplora must not fall through to JSON-RPC"
        );
        assert!(
            super::namespace("/esplorafoo").is_none(),
            "POST /esplorafoo is not an Esplora path"
        );
        Ok(())
    }

    // WF-02
    #[test]
    fn composed_response_refuses_when_a_fresh_identical_tip_is_published_during_the_read() {
        let block = fixture_genesis();
        for path_suffix in ["", "/txs/chain/not-a-txid"] {
            let mut context = Context::new();
            context
                .chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                    0, &block,
                ));
            let tip = {
                let mut tree = context.chain.block_tree.write();
                tree.insert_node(None, block.header, NodeStatus::Active)
                    .expect("insert applied tip");
                tree.tip().expect("applied tip")
            };
            context.chain.applied_tip.store(Some(tip));
            let reader = context.chain.applied_tip.clone();
            let start = reader.load_full().expect("captured tip");
            context.indexes.script_index = Some(Arc::new(RepublishTipScriptIndex {
                applied_tip: context.chain.applied_tip.clone(),
                replacement: None,
                published: AtomicBool::new(false),
            }));
            let handler = Handler::new(Arc::new(context));

            let response = route(
                &handler,
                &format!("/scripthash/{0}{path_suffix}", "00".repeat(32)),
                "",
            );
            assert_eq!(response.status, 503);
            let end = reader.load_full().expect("tip after the read");
            assert!(
                !Arc::ptr_eq(&end, &start),
                "a fresh identical-content publication must have landed during the read"
            );
            assert_eq!(
                end.hash, start.hash,
                "the new publication returns to the same block"
            );
            assert_eq!(end.height, start.height);
            assert_eq!(
                String::from_utf8_lossy(&response.body),
                "transaction index changed during query; retry"
            );
            let retry = route(
                &handler,
                &format!("/scripthash/{0}{path_suffix}", "00".repeat(32)),
                "",
            );
            assert_eq!(
                retry.status, 200,
                "the retry runs on one stable publication"
            );
            let settled = reader.load_full().expect("tip after the retry");
            assert!(
                Arc::ptr_eq(&settled, &end),
                "the retry must observe the same publication end to end"
            );
        }
    }

    // WF-02
    #[test]
    fn composed_response_refuses_when_the_applied_tip_moves_between_reads() -> Result<(), TestError>
    {
        let block = fixture_genesis();
        let mut context = Context::new();
        context
            .chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                0, &block,
            ));
        let (tip, moved, _) = extend_tip(&context, &block)?;
        assert_ne!(
            tip.hash, moved.hash,
            "the second read must observe a different tip"
        );
        context.chain.applied_tip.store(Some(tip));
        context.indexes.script_index = Some(Arc::new(RepublishTipScriptIndex {
            applied_tip: context.chain.applied_tip.clone(),
            replacement: Some(moved),
            published: AtomicBool::new(false),
        }));
        let handler = Handler::new(Arc::new(context));

        let response = route(&handler, &format!("/scripthash/{}", "00".repeat(32)), "");
        assert_eq!(response.status, 503);
        Ok(())
    }

    // WF-02
    #[test]
    fn chain_only_history_refuses_an_ordinary_extension_during_the_read() -> Result<(), TestError> {
        use bitcoin_rs_consensus::primitives::Header;

        let block = fixture_genesis();
        let txid = block.txs[0].txid();
        let block_hash = block.block_hash().to_string();
        let mut context = Context::new();
        context
            .chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                0, &block,
            ));
        let child = Header {
            prev_blockhash: block.header.compute_hash(),
            nonce: block.header.nonce.wrapping_add(1),
            ..block.header
        };
        context
            .chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                1,
                &Block {
                    header: child,
                    txs: block.txs.clone(),
                },
            ));
        let (tip, extended, _) = extend_tip(&context, &block)?;
        assert_ne!(
            tip.hash, extended.hash,
            "the extending read must observe a different tip"
        );
        assert_eq!(
            extended.height,
            tip.height + 1,
            "the extension adds exactly one block"
        );
        context.chain.applied_tip.store(Some(tip));
        context.indexes.esplora_tx_index = Some(Arc::new(FixtureTxIndex(vec![(
            block.txs[0].clone(),
            TransactionBlock {
                height: 0,
                hash: Hash256::from(block.block_hash()),
            },
        )])));
        context.indexes.script_index = Some(Arc::new(AdvanceTipScriptIndex {
            applied_tip: context.chain.applied_tip.clone(),
            extended,
            history: vec![ScriptHistoryRecord { txid, height: 0 }],
        }));
        let handler = Handler::new(Arc::new(context));

        let response = route(
            &handler,
            &format!("/scripthash/{}/txs/chain", "00".repeat(32)),
            "",
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            String::from_utf8_lossy(&response.body),
            "transaction index changed during query; retry"
        );
        let retry = route(
            &handler,
            &format!("/scripthash/{}/txs/chain", "00".repeat(32)),
            "",
        );
        assert_eq!(retry.status, 200, "the retry uses the settled publication");
        let page: Value = sonic_rs::from_slice(&retry.body)?;
        let Some(page) = page.as_array() else {
            return Err("chain page missing".into());
        };
        assert_eq!(page.len(), 1);
        assert_eq!(page[0]["txid"], json!(txid.to_string()));
        assert_eq!(page[0]["status"]["confirmed"], json!(true));
        assert_eq!(page[0]["status"]["block_height"], json!(0));
        assert_eq!(page[0]["status"]["block_hash"], json!(block_hash));
        Ok(())
    }

    // QRY-03, WF-02
    #[test]
    fn confirmed_transaction_survives_an_ordinary_extension() -> Result<(), TestError> {
        use bitcoin_rs_consensus::primitives::Header;

        let block = fixture_genesis();
        let txid = block.txs[0].txid();
        let block_hash = block.block_hash().to_string();
        let mut context = Context::new();
        context
            .chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                0, &block,
            ));
        let child = Header {
            prev_blockhash: block.header.compute_hash(),
            nonce: block.header.nonce.wrapping_add(1),
            ..block.header
        };
        context
            .chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                1,
                &Block {
                    header: child,
                    txs: block.txs.clone(),
                },
            ));
        let (tip, extended, _) = extend_tip(&context, &block)?;
        assert_ne!(
            tip.hash, extended.hash,
            "the extending read must observe a different tip"
        );
        assert_eq!(
            extended.height,
            tip.height + 1,
            "the extension adds exactly one block"
        );
        let extended_height = extended.height;
        context.chain.applied_tip.store(Some(tip));
        context.indexes.esplora_tx_index = Some(Arc::new(AdvanceTipTxIndex {
            applied_tip: context.chain.applied_tip.clone(),
            extended,
            tx: block.txs[0].clone(),
            height: 0,
            hash: Hash256::from(block.block_hash()),
        }));
        let ctx = Arc::new(context);
        let handler = Handler::new(Arc::clone(&ctx));

        let response = route(&handler, &format!("/tx/{txid}"), "");
        assert_eq!(response.status, 200);
        let value: Value = sonic_rs::from_slice(&response.body)?;
        assert_eq!(value["txid"], json!(txid.to_string()));
        assert_eq!(value["status"]["confirmed"], json!(true));
        assert_eq!(value["status"]["block_height"], json!(0));
        assert_eq!(value["status"]["block_hash"], json!(block_hash));
        assert_eq!(
            ctx.chain
                .applied_tip
                .load_full()
                .as_ref()
                .map(|tip| tip.height),
            Some(extended_height),
            "the index read must have advanced the applied tip"
        );
        Ok(())
    }

    // QRY-01, QRY-02, QRY-03, SYNC-05
    #[test]
    fn transaction_status_keeps_occurrence_identity_across_reorg_and_aba() -> Result<(), TestError>
    {
        struct ReorgTxIndex {
            source: StaticTxIndex,
            applied_tip: bitcoin_rs_chain::chain::TipReader,
            replacement: Arc<bitcoin_rs_chain::chain::TipSnapshot>,
            restored: Option<Arc<bitcoin_rs_chain::chain::TipSnapshot>>,
            transitioned: Arc<AtomicBool>,
        }

        impl crate::context::DerivedIndexQuery for ReorgTxIndex {
            fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
                crate::context::DerivedIndexQuery::transaction(&self.source, txid)
            }

            fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                crate::context::DerivedIndexQuery::outpoint_value(&self.source, outpoint)
            }

            fn transaction_block(
                &self,
                txid: &Txid,
            ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
                let found =
                    crate::context::DerivedIndexQuery::transaction_block(&self.source, txid)?;
                self.applied_tip.store(Some(Arc::clone(&self.replacement)));
                if let Some(restored) = &self.restored {
                    self.applied_tip.store(Some(Arc::clone(restored)));
                }
                self.transitioned.store(true, Ordering::SeqCst);
                Ok(found)
            }

            fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
                crate::context::DerivedIndexQuery::index_info(&self.source)
            }
        }

        let genesis = fixture_genesis();
        let mut original = genesis.clone();
        original.header.prev_blockhash = genesis.block_hash();
        original.header.time += 1;
        original.txs[0].outputs[0].value = Amount::from_sat(4_999_999_999);
        original.header.merkle_root = merkle_root(&original.txs).expect("original transactions");
        let mut replacement = original.clone();
        replacement.header.time += 1;
        replacement.txs[0].outputs[0].value = Amount::from_sat(4_999_999_998);
        replacement.header.merkle_root =
            merkle_root(&replacement.txs).expect("replacement transactions");
        let extension = Block {
            header: Header {
                prev_blockhash: replacement.block_hash(),
                time: replacement.header.time + 1,
                ..replacement.header
            },
            txs: replacement.txs.clone(),
        };
        let txid = original.txs[0].txid();
        assert!(original.txs.iter().any(|tx| tx.txid() == txid));
        assert!(replacement.txs.iter().all(|tx| tx.txid() != txid));
        assert_ne!(original.block_hash(), replacement.block_hash());
        let mut context = Context::new();
        for (height, block) in [
            (0, &genesis),
            (1, &original),
            (1, &replacement),
            (2, &extension),
        ] {
            context
                .chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                    height, block,
                ));
        }
        let (original_tip, replacement_tip) = {
            let mut tree = context.chain.block_tree.write();
            let root = tree.insert_node(None, genesis.header, NodeStatus::Active)?;
            tree.insert_node(Some(root), original.header, NodeStatus::Active)?;
            let original_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("original tip missing"))?;
            let fork = tree.insert_node(Some(root), replacement.header, NodeStatus::Active)?;
            tree.insert_node(Some(fork), extension.header, NodeStatus::Active)?;
            let replacement_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("replacement tip missing"))?;
            (original_tip, replacement_tip)
        };
        assert_eq!(original_tip.hash, Hash256::from(original.block_hash()));
        assert_eq!(replacement_tip.hash, Hash256::from(extension.block_hash()));
        context
            .chain
            .applied_tip
            .store(Some(Arc::clone(&original_tip)));
        assert_eq!(
            context
                .chain
                .block_by_height(1)
                .expect("original block")
                .hash,
            original.block_hash()
        );
        for restore in [false, true] {
            context
                .chain
                .applied_tip
                .store(Some(Arc::clone(&original_tip)));
            let transitioned = Arc::new(AtomicBool::new(false));
            context.indexes.esplora_tx_index = Some(Arc::new(ReorgTxIndex {
                source: StaticTxIndex {
                    transaction: original.txs[0].clone(),
                    block: Some(TransactionBlock {
                        height: 1,
                        hash: Hash256::from(original.block_hash()),
                    }),
                },
                applied_tip: context.chain.applied_tip.clone(),
                replacement: Arc::clone(&replacement_tip),
                restored: restore.then(|| Arc::clone(&original_tip)),
                transitioned: Arc::clone(&transitioned),
            }));
            let response = super::public::get(&context, &format!("/tx/{txid}/status"));
            assert!(transitioned.load(Ordering::SeqCst));
            assert_eq!(
                context
                    .chain
                    .block_by_height(1)
                    .expect("current block")
                    .hash,
                if restore {
                    original.block_hash()
                } else {
                    replacement.block_hash()
                }
            );
            assert_eq!(response.status, 200);
            let status: Value = sonic_rs::from_slice(&response.body)?;
            assert_eq!(status["confirmed"], true);
            assert_eq!(status["block_hash"], original.block_hash().to_string());
            assert_eq!(status["block_height"], 1);
            assert_eq!(status["block_time"], original.header.time);
        }
        Ok(())
    }

    // QRY-01, QRY-02
    #[test]
    fn merkle_proofs_keep_occurrence_identity_across_a_same_height_reorg() -> Result<(), TestError>
    {
        use core::str::FromStr as _;

        use bitcoin::merkle_tree::MerkleBlock;

        use bitcoin_rs_consensus::primitives::encode::double_sha256;

        struct ReorgTxIndex {
            source: StaticTxIndex,
            applied_tip: bitcoin_rs_chain::chain::TipReader,
            replacement: Arc<bitcoin_rs_chain::chain::TipSnapshot>,
            transitioned: Arc<AtomicBool>,
        }

        impl crate::context::DerivedIndexQuery for ReorgTxIndex {
            fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
                crate::context::DerivedIndexQuery::transaction(&self.source, txid)
            }

            fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                crate::context::DerivedIndexQuery::outpoint_value(&self.source, outpoint)
            }

            fn transaction_block(
                &self,
                txid: &Txid,
            ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
                let found =
                    crate::context::DerivedIndexQuery::transaction_block(&self.source, txid)?;
                self.applied_tip.store(Some(Arc::clone(&self.replacement)));
                self.transitioned.store(true, Ordering::SeqCst);
                Ok(found)
            }

            fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
                crate::context::DerivedIndexQuery::index_info(&self.source)
            }
        }

        let genesis = fixture_genesis();
        let mut original = genesis.clone();
        original.header.prev_blockhash = genesis.block_hash();
        original.header.time += 1;
        let occurrence = paying_transaction(
            &[OutPoint::new(original.txs[0].txid(), 0)],
            &[(1, vec![0x51])],
        );
        original.txs.push(occurrence.clone());
        original.header.merkle_root = merkle_root(&original.txs).expect("original transactions");
        let mut replacement = original.clone();
        replacement.header.time += 1;
        replacement.txs[1] = paying_transaction(
            &[OutPoint::new(replacement.txs[0].txid(), 0)],
            &[(2, vec![0x51])],
        );
        replacement.header.merkle_root =
            merkle_root(&replacement.txs).expect("replacement transactions");
        let extension = Block {
            header: Header {
                prev_blockhash: replacement.block_hash(),
                time: replacement.header.time + 1,
                ..replacement.header
            },
            txs: replacement.txs.clone(),
        };
        let txid = occurrence.txid();
        let txid_text = txid.to_string();
        assert!(replacement.txs.iter().all(|tx| tx.txid() != txid));
        assert_ne!(original.block_hash(), replacement.block_hash());

        let genesis_record = BlockRecord::from_block(0, &genesis);
        let original_record = BlockRecord::from_block(1, &original);
        let replacement_record = BlockRecord::from_block(1, &replacement);
        let extension_record = BlockRecord::from_block(2, &extension);
        let mut context = Context::new();
        for record in [
            &genesis_record,
            &original_record,
            &replacement_record,
            &extension_record,
        ] {
            context.chain.add_block(record.clone());
        }
        let (original_tip, replacement_tip) = {
            let mut tree = context.chain.block_tree.write();
            let root = tree.insert_node(None, genesis.header, NodeStatus::Active)?;
            tree.insert_node(Some(root), original.header, NodeStatus::Active)?;
            let original_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("original tip missing"))?;
            let replacement_node =
                tree.insert_node(Some(root), replacement.header, NodeStatus::Active)?;
            tree.insert_node(Some(replacement_node), extension.header, NodeStatus::Active)?;
            let replacement_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("replacement tip missing"))?;
            (original_tip, replacement_tip)
        };
        assert_eq!(original_tip.hash, Hash256::from(original.block_hash()));
        assert_eq!(replacement_tip.hash, Hash256::from(extension.block_hash()));
        context.chain.applied_tip.store(Some(original_tip));
        context.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![
                (0, genesis_record.hash, consensus_bytes(&genesis)),
                (1, original_record.hash, consensus_bytes(&original)),
                (1, replacement_record.hash, consensus_bytes(&replacement)),
                (2, extension_record.hash, consensus_bytes(&extension)),
            ],
        }));
        let transitioned = Arc::new(AtomicBool::new(false));
        context.indexes.esplora_tx_index = Some(Arc::new(ReorgTxIndex {
            source: StaticTxIndex {
                transaction: occurrence.clone(),
                block: Some(TransactionBlock {
                    height: 1,
                    hash: Hash256::from(original.block_hash()),
                }),
            },
            applied_tip: context.chain.applied_tip.clone(),
            replacement: Arc::clone(&replacement_tip),
            transitioned: Arc::clone(&transitioned),
        }));
        assert_eq!(
            context
                .chain
                .block_by_height(1)
                .expect("the fixture branch answers height 1")
                .hash,
            original.block_hash(),
            "the fixture must start on the original branch"
        );
        let handler = Handler::new(Arc::new(context));

        let merkleblock = route(&handler, &format!("/tx/{txid_text}/merkleblock-proof"), "");
        assert!(
            transitioned.load(Ordering::SeqCst),
            "the same-height reorg must land during the occurrence lookup"
        );
        assert_eq!(
            merkleblock.status,
            200,
            "merkleblock-proof body: {}",
            String::from_utf8_lossy(&merkleblock.body)
        );
        let proof_bytes: Vec<u8> =
            bitcoin::hex::FromHex::from_hex(&String::from_utf8_lossy(&merkleblock.body))
                .map_err(|_| "merkleblock proof must be lowercase hex".to_owned())?;
        let merkle_block = bitcoin::consensus::encode::deserialize::<MerkleBlock>(&proof_bytes)
            .map_err(|_| "merkleblock proof must decode".to_owned())?;
        let mut matched = Vec::new();
        let mut indexes = Vec::new();
        merkle_block
            .extract_matches(&mut matched, &mut indexes)
            .map_err(|_| "merkleblock proof must verify".to_owned())?;
        assert_eq!(
            matched.len(),
            1,
            "exactly the requested occurrence must match, got {matched:?}"
        );
        assert_eq!(matched[0].to_string(), txid_text);
        let fixture_block =
            bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&consensus_bytes(&original))
                .map_err(|_| "fixture block must decode with the reference decoder".to_owned())?;
        let expected = MerkleBlock::from_block_with_predicate(&fixture_block, |candidate| {
            candidate.as_byte_array() == txid.as_bytes()
        });
        assert_eq!(
            merkleblock.body,
            bitcoin::consensus::encode::serialize(&expected)
                .to_lower_hex_string()
                .into_bytes(),
            "the served proof must byte-match the reference proof for the captured occurrence block"
        );
        let header_bytes = bitcoin::consensus::encode::serialize(&merkle_block.header);
        let header = bitcoin_rs_consensus::primitives::deserialize::<Header>(&header_bytes)
            .map_err(|_| "proof header must decode natively".to_owned())?;
        assert_eq!(
            header.compute_hash(),
            original.block_hash(),
            "the proof header must name the captured occurrence block, not the reorged branch"
        );
        assert_eq!(
            header.merkle_root, original.header.merkle_root,
            "the proof must commit to the captured block merkle root"
        );

        let merkle = route(&handler, &format!("/tx/{txid_text}/merkle-proof"), "");
        assert_eq!(
            merkle.status,
            200,
            "merkle-proof body: {}",
            String::from_utf8_lossy(&merkle.body)
        );
        let proof: Value = sonic_rs::from_slice(&merkle.body)?;
        assert_eq!(proof["block_height"], json!(original_record.height));
        let Some(position) = proof["pos"].as_u64() else {
            return Err("merkle proof position missing".into());
        };
        let position =
            usize::try_from(position).map_err(|_| "position must fit usize".to_owned())?;
        assert_eq!(
            position,
            original
                .txs
                .iter()
                .position(|tx| tx.txid() == txid)
                .expect("captured occurrence"),
        );
        let Some(branch) = proof["merkle"].as_array() else {
            return Err("merkle branch missing".into());
        };
        let mut node = *txid.as_bytes();
        let mut walk = position;
        for step in branch {
            let Some(text) = step.as_str() else {
                return Err("merkle sibling must be a hex string".into());
            };
            let sibling =
                Txid::from_str(text).map_err(|_| "merkle sibling must parse".to_owned())?;
            let (left, right) = if walk % 2 == 0 {
                (node, *sibling.as_bytes())
            } else {
                (*sibling.as_bytes(), node)
            };
            node = double_sha256(&[left.as_slice(), right.as_slice()].concat()).to_le_bytes();
            walk /= 2;
        }
        assert_eq!(
            Hash256::from_le_bytes(&node),
            original.header.merkle_root,
            "the branch must rebuild the captured block merkle root from the requested txid"
        );
        Ok(())
    }

    // WF-02
    #[test]
    fn mempool_transaction_refuses_when_the_applied_tip_moves_between_reads()
    -> Result<(), TestError> {
        let parent = transaction(
            None,
            TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: vec![0x51].into(),
            },
        );
        let unconfirmed = transaction(
            Some(OutPoint::new(parent.txid(), 0)),
            TxOut {
                value: Amount::from_sat(4_999_999_000),
                script_pubkey: vec![0x52].into(),
            },
        );
        let unconfirmed_txid = unconfirmed.txid().to_string();
        let block = fixture_genesis();
        let mut context = Context::new();
        let (tip, extended, _) = extend_tip(&context, &block)?;
        assert_ne!(
            tip.hash, extended.hash,
            "the second read must observe a different tip"
        );
        assert_eq!(
            extended.height,
            tip.height + 1,
            "the extension adds exactly one block"
        );
        let extended_height = extended.height;
        context.chain.applied_tip.store(Some(tip));
        context.indexes.esplora_tx_index = Some(Arc::new(AdvanceTipTxIndex {
            applied_tip: context.chain.applied_tip.clone(),
            extended,
            tx: parent.clone(),
            height: 0,
            hash: Hash256::from(block.block_hash()),
        }));
        assert!(
            context
                .mempool
                .gateway
                .pool()
                .write()
                .insert_entry(MempoolEntry::new(
                    Arc::new(unconfirmed),
                    100,
                    1_000,
                    0,
                    0,
                    0,
                ))
                .is_ok(),
            "mempool entry accepted"
        );
        let ctx = Arc::new(context);
        let handler = Handler::new(Arc::clone(&ctx));

        let response = route(&handler, &format!("/tx/{unconfirmed_txid}"), "");
        assert_eq!(response.status, 503);
        assert_eq!(
            ctx.chain
                .applied_tip
                .load_full()
                .as_ref()
                .map(|tip| tip.height),
            Some(extended_height),
            "the parent read must have advanced the applied tip"
        );
        Ok(())
    }
    // WF-02
    #[test]
    fn internal_block_txs_refuses_when_a_mempool_parent_meets_a_moved_tip() -> Result<(), TestError>
    {
        let parent = paying_transaction(&[OutPoint::null()], &[(125, vec![0x51])]);
        let mut block = fixture_genesis();
        let child = paying_transaction(&[OutPoint::new(parent.txid(), 0)], &[(100, vec![0x52])]);
        block.txs.push(child);
        let Some(root) = merkle_root(&block.txs) else {
            return Err("fixture block has transactions".into());
        };
        block.header.merkle_root = root;
        let record = bitcoin_rs_index::block_log::BlockRecord::from_block(0, &block);
        let mut context = Context::new();
        context.chain.add_block(record.clone());
        let (tip, extended, _) = extend_tip(&context, &block)?;
        assert_ne!(
            tip.hash, extended.hash,
            "the second read must observe a different tip"
        );
        assert_eq!(
            extended.height,
            tip.height + 1,
            "the extension adds exactly one block"
        );
        let extended_height = extended.height;
        context.chain.applied_tip.store(Some(tip));
        context
            .mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0, 0))?;
        struct AdvancingBodies {
            bodies: Vec<(u32, BlockHash, Vec<u8>)>,
            applied_tip: bitcoin_rs_chain::chain::TipReader,
            extended: Arc<bitcoin_rs_chain::chain::TipSnapshot>,
        }
        impl bitcoin_rs_storage::block_body::BlockBodySource for AdvancingBodies {
            fn block_body(
                &self,
                height: u32,
                hash: BlockHash,
            ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError>
            {
                self.applied_tip.store(Some(Arc::clone(&self.extended)));
                Ok(self
                    .bodies
                    .iter()
                    .find(|(candidate_height, candidate_hash, _)| {
                        *candidate_height == height && *candidate_hash == hash
                    })
                    .map(|(_, _, body)| body.clone()))
            }
        }
        context.chain.block_body_source = Some(Arc::new(AdvancingBodies {
            bodies: vec![(0, record.hash, consensus_bytes(&block))],
            applied_tip: context.chain.applied_tip.clone(),
            extended,
        }));
        context.indexes.esplora_tx_index = None;
        let ctx = Arc::new(context);
        let handler = Handler::new(Arc::clone(&ctx));
        let response = backend_route(
            &handler,
            &format!("/internal/block/{}/txs", record.hash),
            "",
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            ctx.chain
                .applied_tip
                .load_full()
                .as_ref()
                .map(|tip| tip.height),
            Some(extended_height),
            "the block read must have advanced the applied tip"
        );
        Ok(())
    }
    #[test]
    fn malformed_txid_keeps_bad_request_when_the_tip_moves() -> Result<(), TestError> {
        let block = fixture_genesis();
        let context = Context::new();
        context
            .chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                0, &block,
            ));
        let (tip, extended, _) = extend_tip(&context, &block)?;
        context.chain.applied_tip.store(Some(tip));
        let body = sonic_rs::to_vec(&vec!["zz".to_string()])?;
        let ctx = Arc::new(context);
        let handler = Handler::new(Arc::clone(&ctx));
        let extended_height = extended.height;
        let (entered_send, entered_recv) = channel();
        let (release_send, release_recv) = channel();
        let request = std::thread::spawn(move || {
            arm_route_gate(entered_send, release_recv);
            backend_route_post(&handler, "/internal/txs", &body)
        });
        entered_recv
            .recv_timeout(GATE_TIMEOUT)
            .map_err(|_| "request did not capture its view")?;
        ctx.chain.applied_tip.store(Some(extended));
        let _ = release_send.send(());
        let response = request.join().map_err(|_| "route thread failed")?;
        assert_eq!(response.status, 400);
        assert_eq!(
            ctx.chain
                .applied_tip
                .load_full()
                .as_ref()
                .map(|tip| tip.height),
            Some(extended_height)
        );
        Ok(())
    }
    // WF-02
    #[test]
    fn joined_answer_refuses_a_same_height_tip_replacement() -> Result<(), TestError> {
        let block = fixture_genesis();
        let mut context = Context::new();
        context
            .chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                0, &block,
            ));
        let (tip, replacement) = {
            let mut tree = context.chain.block_tree.write();
            tree.insert_node(None, block.header, NodeStatus::Active)?;
            let Some(tip) = tree.tip() else {
                return Err("fixture tip missing".into());
            };
            let mut other = (*tip).clone();
            other.hash = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[9; 32]);
            if other.hash == tip.hash {
                other.hash = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[10; 32]);
            }
            let replacement = std::sync::Arc::new(other);
            (tip, replacement)
        };
        if tip.hash == replacement.hash {
            return Err("fixture must differ in hash".into());
        }
        context.chain.applied_tip.store(Some(tip));
        context.indexes.script_index = Some(Arc::new(RepublishTipScriptIndex {
            applied_tip: context.chain.applied_tip.clone(),
            replacement: Some(replacement),
            published: AtomicBool::new(false),
        }));
        let handler = Handler::new(Arc::new(context));
        let response = route(&handler, &format!("/scripthash/{}", "00".repeat(32)), "");
        assert_eq!(response.status, 503);
        Ok(())
    }

    // WF-02
    #[test]
    fn composed_history_and_mempool_routes_refuse_reorg_and_aba_publications()
    -> Result<(), TestError> {
        for (same_height, aba) in [(false, false), (true, false), (false, true)] {
            let block = fixture_genesis();
            let mut context = Context::new();
            let coinbase = &block.txs[0];
            let coinbase_txid = coinbase.txid();
            let script_hash = ScriptHash::new(&coinbase.outputs[0].script_pubkey)
                .to_byte_array()
                .to_lower_hex_string();
            let spend = paying_transaction(
                &[OutPoint::new(coinbase_txid, 0)],
                &[(4_000_000_000, vec![0x52])],
            );
            let funding_txid = coinbase_txid.to_string();
            let confirmed_funding = ScriptIndexRecord {
                txid: coinbase_txid,
                height: 0,
                value: coinbase.outputs[0].value.to_sat(),
                vout: 0,
            };
            context
                .chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                    0, &block,
                ));
            let (tip, extended, _) = extend_tip(&context, &block)?;
            context.chain.applied_tip.store(Some(Arc::clone(&tip)));
            context.indexes.script_index = Some(Arc::new(MonitoredScriptIndex {
                history: vec![ScriptHistoryRecord {
                    txid: coinbase_txid,
                    height: 0,
                }],
                funding: vec![confirmed_funding],
                unspent: vec![confirmed_funding],
                unspent_calls: Arc::new(AtomicUsize::new(0)),
                history_calls: Arc::new(AtomicUsize::new(0)),
            }));
            context.indexes.esplora_tx_index = Some(Arc::new(StaticTxIndex::new(coinbase.clone())));
            context
                .mempool
                .gateway
                .pool()
                .write()
                .insert_entry(MempoolEntry::new(
                    Arc::new(spend.clone()),
                    100,
                    1_000,
                    0,
                    0,
                    0,
                ))?;
            let spend_txid = spend.txid().to_string();
            let post_body = sonic_rs::to_vec(std::slice::from_ref(&spend_txid))?;
            let cases = [
                (format!("/scripthash/{script_hash}/txs/summary"), false),
                (format!("/scripthash/{script_hash}/txs/chain"), false),
                (format!("/scripthash/{script_hash}/txs/mempool"), false),
                ("/internal/mempool/txs".to_owned(), false),
                ("/internal/mempool/txs".to_owned(), true),
            ];
            let ctx = Arc::new(context);
            for (path, post) in cases {
                let handler = Handler::new(Arc::clone(&ctx));
                let stable = if post {
                    backend_route_post(&handler, &path, &post_body)
                } else if path.starts_with("/internal/") {
                    backend_route(&handler, &path, "")
                } else {
                    route(&handler, &path, "")
                };
                assert_eq!(stable.status, 200, "stable route {path}");
                let stable_body: Value = sonic_rs::from_slice(&stable.body)?;
                let entries = stable_body.as_array().ok_or("route must return a list")?;
                if path.ends_with("/txs/mempool") || path == "/internal/mempool/txs" {
                    assert_eq!(entries.len(), 1, "populated mempool route {path}");
                    let entry = entries.first().ok_or("mempool entry missing")?;
                    assert_eq!(
                        entry["txid"].as_str(),
                        Some(spend_txid.as_str()),
                        "mempool route {path} must return the admitted spend"
                    );
                    assert_eq!(
                        entry["status"]["confirmed"].as_bool(),
                        Some(false),
                        "the spend stays unconfirmed on route {path}"
                    );
                    assert_eq!(
                        entry["vin"][0]["txid"].as_str(),
                        Some(funding_txid.as_str()),
                        "route {path} must name the confirmed funding parent"
                    );
                    assert_eq!(
                        entry["vin"][0]["prevout"]["value"].as_u64(),
                        Some(coinbase.outputs[0].value.to_sat()),
                        "route {path} must resolve the confirmed funding prevout"
                    );
                } else if path.ends_with("/txs/chain") {
                    assert_eq!(
                        entries.first().map(|entry| entry["txid"].as_str()),
                        Some(Some(funding_txid.as_str())),
                        "chain route {path} keeps confirmed-only history"
                    );
                } else {
                    assert_eq!(
                        entries.first().map(|entry| entry["txid"].as_str()),
                        Some(Some(funding_txid.as_str())),
                        "summary route {path} lists the confirmed funding"
                    );
                }
                let (entered_send, entered_recv) = channel();
                let (release_send, release_recv) = channel();
                let request = {
                    let path = path.clone();
                    let post_body = post_body.clone();
                    std::thread::spawn(move || {
                        arm_route_gate(entered_send, release_recv);
                        if post {
                            backend_route_post(&handler, &path, &post_body)
                        } else if path.starts_with("/internal/") {
                            backend_route(&handler, &path, "")
                        } else {
                            route(&handler, &path, "")
                        }
                    })
                };
                let entered = entered_recv.recv_timeout(GATE_TIMEOUT);
                let publication = if same_height {
                    let mut replacement = (*tip).clone();
                    replacement.hash = extended.hash;
                    Arc::new(replacement)
                } else {
                    Arc::new((*extended).clone())
                };
                ctx.chain.applied_tip.store(Some(publication));
                if aba {
                    ctx.chain.applied_tip.store(Some(Arc::new((*tip).clone())));
                }
                let _ = release_send.send(());
                let response = request.join().map_err(|_| "route thread failed")?;
                assert_eq!(
                    response.status, 503,
                    "composed read must refuse a changed publication (same_height={same_height}, aba={aba})"
                );
                entered.map_err(|_| "request did not capture its publication")?;
            }
        }
        Ok(())
    }

    // WF-02
    #[test]
    fn pure_mempool_reads_stay_unfenced_across_ordinary_extension() -> Result<(), TestError> {
        let block = fixture_genesis();
        let context = Context::new();
        context
            .chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                0, &block,
            ));
        let (tip, extended, _) = extend_tip(&context, &block)?;
        assert_ne!(
            tip.hash, extended.hash,
            "the extending read must observe a different tip"
        );
        assert_eq!(
            extended.height,
            tip.height + 1,
            "the extension adds exactly one block"
        );
        context.chain.applied_tip.store(Some(Arc::clone(&tip)));
        let spend = paying_transaction(&[unconfirmed_outpoint(7)], &[(1_000, vec![0x51])]);
        context
            .mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(spend.clone()),
                100,
                1_000,
                0,
                0,
                0,
            ))?;
        let ctx = Arc::new(context);
        let handler = Handler::new(Arc::clone(&ctx));
        let spend_txid = spend.txid().to_string();
        let stable = route(&handler, "/mempool", "");
        assert_eq!(stable.status, 200);
        let stable_body = stable.body.clone();
        let summary: Value = sonic_rs::from_slice(&stable_body)?;
        assert_eq!(
            summary,
            json!({
                "count": 1,
                "vsize": 100,
                "total_fee": 1_000,
                "fee_histogram": [[10.0, 100_u64]],
            })
        );
        let (entered_send, entered_recv) = channel();
        let (release_send, release_recv) = channel();
        let request = std::thread::spawn({
            let ctx = Arc::clone(&ctx);
            move || {
                arm_mempool_summary_gate(entered_send, release_recv);
                let handler = Handler::new(ctx);
                route(&handler, "/mempool", "")
            }
        });
        let entered = entered_recv.recv_timeout(GATE_TIMEOUT);
        ctx.chain.applied_tip.store(Some(Arc::clone(&extended)));
        let _ = release_send.send(());
        let response = request.join().map_err(|_| "route thread failed")?;
        assert_eq!(
            response.status, 200,
            "a pure mempool read must not observe the applied-tip publication"
        );
        assert_eq!(response.body, stable_body);
        entered.map_err(|_| "request never reached summary encoding")?;
        let mut next = Arc::clone(&tip);
        for path in ["/mempool/txids", "/mempool/recent", "/fee-estimates"] {
            let stable = route(&handler, path, "");
            assert_eq!(
                stable.status, 200,
                "unfenced route {path} is 200 before the tip advances"
            );
            let (entered_send, entered_recv) = channel();
            let (release_send, release_recv) = channel();
            let request = std::thread::spawn({
                let ctx = Arc::clone(&ctx);
                move || {
                    arm_mempool_read_gate(entered_send, release_recv);
                    let handler = Handler::new(ctx);
                    route(&handler, path, "")
                }
            });
            let entered = entered_recv.recv_timeout(GATE_TIMEOUT);
            ctx.chain.applied_tip.store(Some(Arc::clone(&next)));
            next = if next.hash == tip.hash {
                Arc::clone(&extended)
            } else {
                Arc::clone(&tip)
            };
            let _ = release_send.send(());
            let response = request.join().map_err(|_| "route thread failed")?;
            assert_eq!(
                response.status, 200,
                "a pure mempool read must not observe the applied-tip publication ({path})"
            );
            assert_eq!(
                response.body, stable.body,
                "unfenced route {path} keeps its body"
            );
            entered.map_err(|_| "request never reached mempool encoding")?;
        }
        let txids: Value = sonic_rs::from_slice(&route(&handler, "/mempool/txids", "").body)?;
        assert_eq!(txids.as_array().map(|ids| ids.len()), Some(1));
        assert_eq!(
            txids
                .as_array()
                .and_then(|ids| ids.first())
                .and_then(|id| id.as_str()),
            Some(spend_txid.as_str())
        );
        Ok(())
    }

    #[test]
    fn block_status_and_block_list_never_straddle_two_applied_branches() -> Result<(), TestError> {
        use bitcoin_rs_chain::chain::{NodeStatus, TipSnapshot};
        use bitcoin_rs_consensus::primitives::Header;

        let header = |prev: BlockHash, nonce: u32, time: u32| Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        };
        let coinbase = transaction(
            Some(OutPoint::null()),
            TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: vec![0x51].into(),
            },
        );
        let block_at = |block_header: Header| Block {
            header: block_header,
            txs: vec![coinbase.clone()],
        };
        let genesis_header = header(BlockHash::default(), 0, 1_000_000);
        let a1 = header(genesis_header.compute_hash(), 1, 1_000_900);
        let b1 = header(genesis_header.compute_hash(), 2, 1_000_901);
        let b2 = header(b1.compute_hash(), 3, 1_001_800);
        let (a1_hash, b1_hash, b2_hash, genesis_hash) = (
            a1.compute_hash(),
            b1.compute_hash(),
            b2.compute_hash(),
            genesis_header.compute_hash(),
        );

        let mut context = Context::new();
        context.chain.chain_network = bitcoin_rs_consensus::primitives::Network::Regtest;
        let (a_tip, b_tip) = {
            let mut tree = context.chain.block_tree.write();
            let genesis_id = tree.insert_node(None, genesis_header, NodeStatus::Active)?;
            let a1_id = tree.insert_node(Some(genesis_id), a1, NodeStatus::Active)?;
            let b1_id = tree.insert_node(Some(genesis_id), b1, NodeStatus::HeaderValid)?;
            let b2_id = tree.insert_node(Some(b1_id), b2, NodeStatus::HeaderValid)?;
            (
                Arc::new(TipSnapshot {
                    tip_id: a1_id,
                    height: 1,
                    chainwork: bitcoin_rs_consensus::header_rules::ChainWork::ZERO,
                    hash: a1_hash.0,
                    chain_tx_count: bitcoin_rs_chain::chain::ChainTxCount::UNKNOWN,
                }),
                Arc::new(TipSnapshot {
                    tip_id: b2_id,
                    height: 2,
                    chainwork: bitcoin_rs_consensus::header_rules::ChainWork::ZERO,
                    hash: b2_hash.0,
                    chain_tx_count: bitcoin_rs_chain::chain::ChainTxCount::UNKNOWN,
                }),
            )
        };
        let mut bodies = Vec::new();
        for (height, block_header) in [(0, genesis_header), (1, a1), (1, b1), (2, b2)] {
            let block = block_at(block_header);
            let record = bitcoin_rs_index::block_log::BlockRecord::from_block(height, &block);
            bodies.push((record.height, record.hash, consensus_bytes(&block)));
            context.chain.add_block(record);
        }
        context.chain.block_body_source = Some(Arc::new(BlockBodies { bodies }));
        context.chain.applied_tip.store(Some(Arc::clone(&a_tip)));

        let ctx = Arc::new(context);
        let handler = Handler::new(Arc::clone(&ctx));
        let stop = Arc::new(AtomicBool::new(false));
        let (cell, swap_a, swap_b, flag) = (
            ctx.chain.applied_tip.clone(),
            a_tip,
            b_tip,
            Arc::clone(&stop),
        );
        let swapper = std::thread::spawn(move || {
            let mut flip = false;
            while !flag.load(Ordering::Relaxed) {
                flip = !flip;
                let tip = if flip { &swap_b } else { &swap_a };
                cell.store(Some(Arc::clone(tip)));
            }
        });
        let mut swapper = SwapperGuard {
            stop: Arc::clone(&stop),
            handle: Some(swapper),
        };

        let status_path = format!("/block/{a1_hash}/status");
        let (a1_text, b1_text) = (a1_hash.to_string(), b1_hash.to_string());
        let (b2_text, genesis_text) = (b2_hash.to_string(), genesis_hash.to_string());
        let mut seen_a = false;
        let mut seen_b = false;
        let mut accepted = 0_usize;
        let mut attempts = 0_usize;
        while !(accepted >= 200 && seen_a && seen_b) {
            attempts += 1;
            assert!(
                attempts < 100_000,
                "a publication was never observed, so coherence proved nothing"
            );
            let status_response = route(&handler, &status_path, "");
            if status_response.status == 503 {
                continue;
            }
            assert_eq!(
                status_response.status,
                200,
                "status body: {}",
                String::from_utf8_lossy(&status_response.body)
            );
            let status: Value = sonic_rs::from_slice(&status_response.body)?;
            match status.get("in_best_chain").and_then(Value::as_bool) {
                Some(true) => {
                    assert!(
                        status.get("next_best").is_none_or(|value| value.is_null()),
                        "a1 is the tip of its branch; a next best straddles branches"
                    );
                    seen_a = true;
                }
                Some(false) => seen_b = true,
                other => panic!("in_best_chain is {other:?}, which no branch explains"),
            }

            let list_response = route(&handler, "/blocks", "");
            if list_response.status == 503 {
                continue;
            }
            assert_eq!(
                list_response.status,
                200,
                "list body: {}",
                String::from_utf8_lossy(&list_response.body)
            );
            let list: Value = sonic_rs::from_slice(&list_response.body)?;
            let ids: Vec<String> = list
                .as_array()
                .expect("block list")
                .iter()
                .map(|entry| {
                    entry
                        .get("id")
                        .and_then(Value::as_str)
                        .expect("id")
                        .to_owned()
                })
                .collect();
            match ids.as_slice() {
                [a, g] if a == &a1_text && g == &genesis_text => {}
                [b2, b1, g] if b2 == &b2_text && b1 == &b1_text && g == &genesis_text => {}
                other => panic!("block list {other:?} straddles two applied branches"),
            }
            accepted += 1;
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Relaxed);
        swapper
            .handle
            .take()
            .expect("swapper handle")
            .join()
            .expect("swapper thread panicked");
        assert!(
            seen_a && seen_b,
            "a publication was never observed, so coherence proved nothing"
        );
        Ok(())
    }

    struct OrphanedPageFixture {
        context: Context,
        orphan_hash: BlockHash,
        transactions: Vec<Tx>,
        first_mined: (u32, BlockHash),
        second_mined: (u32, BlockHash),
    }

    fn orphaned_page_fixture() -> Result<OrphanedPageFixture, TestError> {
        let header = |prev: BlockHash, nonce: u32, time: u32| Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        };
        let coinbase =
            |tag: u8| paying_transaction(&[OutPoint::null()], &[(5_000_000_000, vec![0x51, tag])]);
        let funding = paying_transaction(
            &[OutPoint::null()],
            &[(2_500_000_000, vec![0x51]), (2_500_000_000, vec![0x51])],
        );
        let first = paying_transaction(
            &[OutPoint::new(funding.txid(), 0)],
            &[(2_499_999_000, vec![0x52])],
        );
        let second = paying_transaction(
            &[OutPoint::new(funding.txid(), 1)],
            &[(2_499_998_000, vec![0x53])],
        );
        let block_at = |block_header: Header, txs: Vec<Tx>| {
            let mut block = Block {
                header: block_header,
                txs,
            };
            block.header.merkle_root =
                merkle_root(&block.txs).expect("fixture block has transactions");
            block
        };
        let genesis = block_at(
            header(BlockHash::default(), 0, 1_000_000),
            vec![funding.clone()],
        );
        let genesis_hash = genesis.block_hash();
        let orphan_coinbase = coinbase(1);
        let orphan = block_at(
            header(genesis_hash, 1, 1_000_900),
            vec![orphan_coinbase.clone(), first.clone(), second.clone()],
        );
        let b1 = block_at(header(genesis_hash, 2, 1_000_901), vec![coinbase(2)]);
        let b1_hash = b1.block_hash();
        let b2 = block_at(
            header(b1_hash, 3, 1_001_800),
            vec![coinbase(3), first.clone()],
        );
        let b2_hash = b2.block_hash();
        let b3 = block_at(
            header(b2_hash, 4, 1_002_700),
            vec![coinbase(4), second.clone()],
        );
        let b3_hash = b3.block_hash();
        let orphan_hash = orphan.block_hash();
        assert_ne!(
            orphan_hash, b1_hash,
            "the orphaned block must differ from the applied block at height 1"
        );

        let context = Context::new();
        let tip = {
            let mut tree = context.chain.block_tree.write();
            let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::Active)?;
            tree.insert_node(Some(genesis_id), orphan.header, NodeStatus::Active)?;
            let b1_id = tree.insert_node(Some(genesis_id), b1.header, NodeStatus::Active)?;
            let b2_id = tree.insert_node(Some(b1_id), b2.header, NodeStatus::Active)?;
            let b3_id = tree.insert_node(Some(b2_id), b3.header, NodeStatus::Active)?;
            Arc::new(TipSnapshot {
                tip_id: b3_id,
                height: 3,
                chainwork: bitcoin_rs_consensus::header_rules::ChainWork::ZERO,
                hash: b3_hash.0,
                chain_tx_count: bitcoin_rs_chain::chain::ChainTxCount::UNKNOWN,
            })
        };
        let mut bodies = Vec::new();
        for (height, block) in [(0u32, &genesis), (1, &orphan), (1, &b1), (2, &b2), (3, &b3)] {
            let record = BlockRecord::from_block(height, block);
            bodies.push((record.height, record.hash, consensus_bytes(block)));
            context.chain.add_block(record);
        }
        let mut context = context;
        context.chain.block_body_source = Some(Arc::new(BlockBodies { bodies }));
        context.chain.applied_tip.store(Some(tip));
        assert_eq!(
            context
                .chain
                .active_hash_in_view(&context.chain.applied_view(), 1),
            Some(Hash256::from(b1_hash)),
            "the fixture must resolve height 1 to the applied branch"
        );
        Ok(OrphanedPageFixture {
            context,
            orphan_hash,
            transactions: vec![orphan_coinbase, first, second, funding],
            first_mined: (2, b2_hash),
            second_mined: (3, b3_hash),
        })
    }

    struct PageTxIndex {
        transactions: Vec<Tx>,
        confirmed: Vec<(Txid, TransactionBlock)>,
        republish: Option<(bitcoin_rs_chain::chain::TipReader, Vec<Arc<TipSnapshot>>)>,
        reads: AtomicUsize,
    }

    impl crate::context::DerivedIndexQuery for PageTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            Ok(self
                .transactions
                .iter()
                .find(|transaction| transaction.txid() == *txid)
                .cloned())
        }

        fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            let (out_txid, out_vout) = (outpoint.txid, outpoint.vout);
            Ok(self
                .transactions
                .iter()
                .find(|transaction| transaction.txid() == out_txid)
                .and_then(|transaction| {
                    transaction
                        .outputs
                        .get(usize::try_from(out_vout).unwrap_or(usize::MAX))
                })
                .map(|output| output.value.to_sat()))
        }

        fn transaction_block(
            &self,
            txid: &Txid,
        ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
            let Some(transaction) = self
                .transactions
                .iter()
                .find(|transaction| transaction.txid() == *txid)
            else {
                return Ok(None);
            };
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            if let Some((applied_tip, publications)) = &self.republish
                && let Some(next) = read
                    .checked_sub(1)
                    .and_then(|index| publications.get(index))
            {
                applied_tip.store(Some(Arc::clone(next)));
            }
            Ok(self
                .confirmed
                .iter()
                .find(|(confirmed, _)| confirmed == txid)
                .map(|(_, block)| (transaction.clone(), *block)))
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 3,
                applied_height: 3,
                historical_height: 3,
                verified_height: 3,
                coverage_height: 3,
            })
        }
    }

    fn mined(height: u32, hash: BlockHash) -> TransactionBlock {
        TransactionBlock {
            height,
            hash: Hash256::from(hash),
        }
    }

    // WF-02
    #[test]
    fn block_page_never_mixes_confirmations_from_two_branches() -> Result<(), TestError> {
        for (returns_to_start, backend) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let OrphanedPageFixture {
                mut context,
                orphan_hash,
                transactions,
                second_mined,
                ..
            } = orphaned_page_fixture()?;
            let Some(tip) = context.chain.applied_tip.load_full() else {
                return Err("fixture tip missing".into());
            };
            let mut moved = (*tip).clone();
            moved.hash = Hash256::from_le_bytes(&[9; 32]);
            assert_ne!(
                tip.hash, moved.hash,
                "the page must observe a different tip"
            );
            let mut publications = vec![Arc::new(moved)];
            if returns_to_start {
                publications.push(Arc::new((*tip).clone()));
            }
            let Some(last) = publications.last().cloned() else {
                return Err("fixture publications missing".into());
            };
            let second_txid = transactions[2].txid();
            context.indexes.esplora_tx_index = Some(Arc::new(PageTxIndex {
                transactions,
                confirmed: vec![(second_txid, mined(second_mined.0, second_mined.1))],
                republish: Some((context.chain.applied_tip.clone(), publications)),
                reads: AtomicUsize::new(0),
            }));
            let ctx = Arc::new(context);
            let handler = Handler::new(Arc::clone(&ctx));

            let response = if backend {
                backend_route(&handler, &format!("/internal/block/{orphan_hash}/txs"), "")
            } else {
                route(&handler, &format!("/block/{orphan_hash}/txs"), "")
            };
            let label = format!("returns_to_start={returns_to_start} backend={backend}");
            assert_eq!(
                response.status,
                503,
                "{label} page body: {}",
                String::from_utf8_lossy(&response.body)
            );
            assert_eq!(
                String::from_utf8_lossy(&response.body),
                "transaction index changed during query; retry"
            );
            let Some(end) = ctx.chain.applied_tip.load_full() else {
                return Err("fixture tip missing after the page".into());
            };
            assert!(
                Arc::ptr_eq(&end, &last),
                "{label}: the page must have read confirmations across every tip publication"
            );
            if returns_to_start {
                assert_eq!(end.hash, tip.hash, "the tip must end where it started");
                assert!(
                    !Arc::ptr_eq(&end, &tip),
                    "the returned tip must be a new publication"
                );
            }
        }
        Ok(())
    }

    // WF-02
    #[test]
    fn block_page_keeps_each_confirmation_of_transactions_mined_again_at_other_heights()
    -> Result<(), TestError> {
        let OrphanedPageFixture {
            mut context,
            orphan_hash,
            transactions,
            first_mined,
            second_mined,
        } = orphaned_page_fixture()?;
        let (first_txid, second_txid) = (transactions[1].txid(), transactions[2].txid());
        context.indexes.esplora_tx_index = Some(Arc::new(PageTxIndex {
            transactions,
            confirmed: vec![
                (first_txid, mined(first_mined.0, first_mined.1)),
                (second_txid, mined(second_mined.0, second_mined.1)),
            ],
            republish: None,
            reads: AtomicUsize::new(0),
        }));
        let handler = Handler::new(Arc::new(context));

        for (surface, response) in [
            (
                "public",
                route(&handler, &format!("/block/{orphan_hash}/txs"), ""),
            ),
            (
                "backend",
                backend_route(&handler, &format!("/internal/block/{orphan_hash}/txs"), ""),
            ),
        ] {
            assert_eq!(
                response.status,
                200,
                "{surface} page body: {}",
                String::from_utf8_lossy(&response.body)
            );
            let page: Value = sonic_rs::from_slice(&response.body)?;
            assert_eq!(page[0]["status"]["confirmed"], json!(false), "{surface}");
            assert_eq!(page[1]["status"]["block_height"], json!(first_mined.0));
            assert_eq!(
                page[1]["status"]["block_hash"],
                json!(first_mined.1.to_string())
            );
            assert_eq!(page[2]["status"]["block_height"], json!(second_mined.0));
            assert_eq!(
                page[2]["status"]["block_hash"],
                json!(second_mined.1.to_string())
            );
        }
        Ok(())
    }

    #[test]
    fn internal_mempool_routes_return_live_transactions() {
        let transaction = transaction(
            None,
            TxOut {
                value: Amount::from_sat(125),
                script_pubkey: vec![0x51].into(),
            },
        );
        let txid = transaction.txid();
        let ctx = Arc::new(Context::new());
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(transaction),
                100,
                1_000,
                0,
                0,
                0,
            ))
            .expect("mempool entry accepted");
        let handler = Handler::new(Arc::clone(&ctx));
        let body = sonic_rs::to_vec(&vec![txid.to_string()]).expect("txids serialize");

        let post = backend_route_post(&handler, "/internal/mempool/txs", &body);
        assert_eq!(post.status, 200);
        let paged = backend_route(&handler, "/internal/mempool/txs", "max_txs=1");
        assert_eq!(paged.status, 200);
        let values: Value = sonic_rs::from_slice(&paged.body).expect("mempool response json");
        assert_eq!(values[0]["txid"], json!(txid.to_string()));
    }

    // API-08, API-09, WF-02
    #[test]
    fn backend_templates_share_expensive_admission_through_send() {
        use crate::mining::{
            BlockTemplate, CandidateContext, FakeMiningControl, MiningRule, assemble_candidate,
        };

        let mut context = Context::new().with_esplora_query_limit(std::num::NonZeroUsize::MIN);
        context.chain.chain_network = bitcoin_rs_consensus::primitives::Network::Regtest;
        let candidate = assemble_candidate(
            &CandidateContext {
                previous_block_hash: Hash256::default(),
                height: 1,
                version: 0x2000_0000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                min_time: 1,
                current_time: 1,
                locktime_cutoff: 0,
                staged_parent_mtp: 0,
                network: context.chain.chain_network,
                csv_active: true,
                segwit_active: true,
                max_weight: 4_000_000,
                max_size: 4_000_000,
                max_sigops: 80_000,
            },
            &context.mempool.gateway.pool().read(),
            &[0x51],
        )
        .expect("empty candidate");
        let control = FakeMiningControl::with_template(
            BlockTemplate {
                candidate: Arc::new(candidate),
                rules: vec![MiningRule::new("segwit")],
                version_bits_available: Vec::new(),
                version_bits_required: 0,
                capabilities: Vec::new(),
                mutable: Vec::new(),
                submit_old: None,
                signet: None,
            },
            FakeMiningControl::default().info.into_inner(),
        );
        let ctx = Arc::new(context.with_mining_control(control.clone()));
        let handler = Handler::new(Arc::clone(&ctx));
        let permit = ctx
            .esplora_admission
            .try_acquire()
            .expect("reserve the only slot");
        for path in ["/block-template", "/block-template/"] {
            assert_eq!(backend_route(&handler, path, "").status, 503);
        }
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 0);
        assert_eq!(route(&handler, "/block-template", "").status, 404);
        drop(permit);

        for result in [Ok(()), Err(std::io::ErrorKind::BrokenPipe)] {
            let sent = super::respond(
                &handler,
                super::Surface::Backend,
                "/block-template",
                super::Request::Get(""),
                |response| {
                    assert_eq!(response.status, 200);
                    assert!(ctx.esplora_admission.try_acquire().is_none());
                    result
                },
            );
            assert_eq!(sent, result);
            let released = ctx
                .esplora_admission
                .try_acquire()
                .expect("response write released the slot");
            drop(released);
        }
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 2);
    }

    // API-09, WF-02
    #[test]
    fn backend_bulk_routes_share_expensive_admission() {
        let ctx = Arc::new(Context::new().with_esplora_query_limit(
            std::num::NonZeroUsize::new(1).expect("nonzero admission limit"),
        ));
        let handler = Handler::new(Arc::clone(&ctx));
        let permit = ctx
            .esplora_admission
            .try_acquire()
            .expect("reserve the only slot");
        for path in ["/internal/mempool/txs", "/internal/block/00/txs"] {
            let response = backend_route(&handler, path, "max_txs=0");
            assert_eq!(response.status, 503, "status for {path}");
        }
        let body = sonic_rs::to_vec(&Vec::<String>::new()).expect("empty request");
        for path in [
            "/internal/txs",
            "/internal/mempool/txs",
            "/internal/txs/outspends/by-txid",
            "/internal/txs/outspends/by-outpoint",
        ] {
            let response = backend_route_post(&handler, path, &body);
            assert_eq!(response.status, 503, "status for {path}");
        }
        drop(permit);
        for request in [
            super::Request::Get("max_txs=0"),
            super::Request::Post(&body),
        ] {
            super::respond(
                &handler,
                super::Surface::Backend,
                "/internal/mempool/txs",
                request,
                |response| {
                    assert_eq!(response.status, 200);
                    assert!(ctx.esplora_admission.try_acquire().is_none());
                },
            );
        }
        for path in [
            "/internal/txs",
            "/internal/mempool/txs",
            "/internal/txs/outspends/by-txid",
            "/internal/txs/outspends/by-outpoint",
        ] {
            assert_eq!(
                backend_route_post(&handler, path, &body).status,
                200,
                "status for {path}"
            );
        }
    }

    // API-09, WF-02
    #[test]
    fn mempool_backend_extension_surface_uses_the_same_projections() -> Result<(), TestError> {
        let (handler, transaction, block, address) = contract_fixture()?;
        let txid = transaction.txid().to_string();
        let ids = sonic_rs::to_vec(&vec![txid.clone()])?;
        let outpoints = sonic_rs::to_vec(&vec![format!("{txid}:0")])?;

        for (path, body) in [
            ("/internal/txs", ids.as_slice()),
            ("/internal/mempool/txs", ids.as_slice()),
            ("/internal/txs/outspends/by-txid", ids.as_slice()),
            ("/internal/txs/outspends/by-outpoint", outpoints.as_slice()),
        ] {
            let response = backend_route_post(&handler, path, body);
            assert_eq!(response.status, 200, "status for {path}");
            assert_eq!(response.content_type, "application/json");
        }

        let block_response = backend_route(
            &handler,
            &format!("/internal/block/{}/txs", block.block_hash()),
            "",
        );
        assert_eq!(block_response.status, 200);
        let block_rows: Vec<Value> = sonic_rs::from_slice(&block_response.body)?;
        assert_eq!(block_rows.len(), block.txs.len());
        let summary = route(&handler, &format!("/address/{address}/txs/summary"), "");
        assert_eq!(summary.status, 200);
        Ok(())
    }

    #[test]
    fn package_broadcast_is_not_exposed_without_package_admission() {
        let handler = Handler::new(Arc::new(Context::new()));
        assert_eq!(route_post(&handler, "/txs/package", b"[]").status, 404);
    }

    #[derive(Default)]
    struct BroadcastObserver(parking_lot::Mutex<Vec<MutationEnvelope>>);

    impl MempoolObserver for BroadcastObserver {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            self.0.lock().push(envelope.clone());
        }
    }

    // API-10
    #[test]
    fn broadcast_preserves_esplora_origin_and_idempotence() {
        for path in ["/api/tx", "/esplora/tx"] {
            let observer = Arc::new(BroadcastObserver::default());
            let ctx = Arc::new(Context::new_with_mempool_observer(observer.clone()));
            let (transaction, _) = transaction_with_funded_input(&ctx, 10_000);
            let handler = Handler::new(Arc::clone(&ctx));
            let raw = consensus_bytes(&transaction).to_lower_hex_string();
            let sequence = ctx.mempool.gateway.read().sequence_number();
            for _ in 0..2 {
                let response = dispatch_post(&handler, path, format!("  {raw}\n").as_bytes());
                assert_eq!(response.status, 200, "{path}");
                assert_eq!(response.content_type, "text/plain");
                assert_eq!(response.body, transaction.txid().to_string().as_bytes());
            }
            let events = observer.0.lock();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].origin, AdmissionOrigin::Esplora);
            assert_eq!(ctx.mempool.gateway.read().sequence_number(), sequence + 1);
            assert!(
                ctx.mempool
                    .gateway
                    .read()
                    .contains_txid(&transaction.txid())
            );
        }
    }

    // API-10
    #[test]
    fn broadcast_rejections_are_400_without_mutation() {
        for path in ["/api/tx", "/esplora/tx"] {
            let observer = Arc::new(BroadcastObserver::default());
            let ctx = Arc::new(Context::new_with_mempool_observer(observer.clone()));
            let handler = Handler::new(Arc::clone(&ctx));
            let (mut transaction, _) = transaction_with_funded_input(&ctx, 10_000);
            transaction.inputs[0].previous_output.vout = 1;
            let missing = consensus_bytes(&transaction).to_lower_hex_string();
            transaction.inputs[0].previous_output.vout = 0;
            transaction.inputs.push(transaction.inputs[0].clone());
            let duplicate = consensus_bytes(&transaction).to_lower_hex_string();
            let sequence = ctx.mempool.gateway.read().sequence_number();
            for body in [
                b"\xff".as_slice(),
                b"zz".as_slice(),
                b"00".as_slice(),
                missing.as_bytes(),
                duplicate.as_bytes(),
            ] {
                let response = dispatch_post(&handler, path, body);
                assert_eq!(response.status, 400, "{path}");
                assert_eq!(response.content_type, "text/plain");
            }
            assert!(ctx.mempool.gateway.read().is_empty());
            assert_eq!(ctx.mempool.gateway.read().sequence_number(), sequence);
            assert!(observer.0.lock().is_empty());
        }
    }

    #[test]
    fn broadcast_refuses_hex_beyond_the_standard_size_limit_before_decode() {
        for path in ["/api/tx", "/esplora/tx"] {
            let observer = Arc::new(BroadcastObserver::default());
            let ctx = Arc::new(Context::new_with_mempool_observer(observer.clone()));
            let handler = Handler::new(Arc::clone(&ctx));
            let sequence = ctx.mempool.gateway.read().sequence_number();
            let oversized = "00".repeat(400_001);
            let response = dispatch_post(&handler, path, oversized.as_bytes());
            assert_eq!(response.status, 400, "{path}");
            assert_eq!(response.content_type, "text/plain");
            assert_eq!(
                response.body,
                b"transaction hex exceeds the broadcast size limit"
            );
            assert!(ctx.mempool.gateway.read().is_empty());
            assert_eq!(ctx.mempool.gateway.read().sequence_number(), sequence);
            assert!(observer.0.lock().is_empty());
        }
    }

    #[test]
    fn broadcast_fee_ceiling_is_independent_of_rpc_overrides() {
        use sonic_rs::JsonValueTrait as _;
        for path in ["/api/tx", "/esplora/tx"] {
            let observer = Arc::new(BroadcastObserver::default());
            let ctx = Arc::new(Context::new_with_mempool_observer(observer.clone()));
            let (mut transaction, _) = transaction_with_funded_input(&ctx, 100_000_000);
            transaction.outputs[0].value = Amount::from_sat(1_000_000);
            let handler = Handler::new(Arc::clone(&ctx));
            let raw = consensus_bytes(&transaction).to_lower_hex_string();
            let response = dispatch_post(&handler, path, raw.as_bytes());
            assert_eq!(response.status, 400);
            assert_eq!(response.body, b"invalid params: max-fee-exceeded");
            assert!(ctx.mempool.gateway.read().is_empty());
            assert!(observer.0.lock().is_empty());
            let default_error = handler
                .dispatch("sendrawtransaction", &sonic_rs::json!([raw]))
                .expect_err("RPC still enforces its default maximum");
            assert_eq!(default_error.code(), crate::RpcError::INVALID_PARAMS);
            let accepted = handler
                .dispatch("sendrawtransaction", &sonic_rs::json!([raw, 0]))
                .expect("RPC zero fee cap opts out");
            assert_eq!(
                accepted.as_str(),
                Some(transaction.txid().to_string().as_str())
            );
            let events = observer.0.lock();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].origin, AdmissionOrigin::Rpc);
            drop(events);

            let (mut next, _) = transaction_with_funded_input(&ctx, 200_000_000);
            next.outputs[0].value = Amount::from_sat(1_000_000);
            let next_raw = consensus_bytes(&next).to_lower_hex_string();
            let refused = dispatch_post(&handler, path, next_raw.as_bytes());
            assert_eq!(
                refused.status, 400,
                "RPC override cannot change the HTTP cap"
            );
            assert_eq!(observer.0.lock().len(), 1);
        }
    }

    #[test]
    fn broadcast_fee_ceiling_accepts_equality_and_refuses_one_sat_above() {
        for above in [0, 1] {
            let ctx = Arc::new(Context::new());
            let (mut transaction, _) = transaction_with_funded_input(&ctx, 100_000_000);
            let reference: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&consensus_bytes(&transaction))
                    .expect("independently decode fixture");
            let maximum_fee = u64::try_from(reference.vsize()).expect("vsize fits u64") * 10_000;
            transaction.outputs[0].value = Amount::from_sat(100_000_000 - maximum_fee - above);
            let handler = Handler::new(Arc::clone(&ctx));
            let raw = consensus_bytes(&transaction).to_lower_hex_string();
            let response = route_post(&handler, "/tx", raw.as_bytes());
            assert_eq!(response.status, if above == 0 { 200 } else { 400 });
            assert_eq!(
                ctx.mempool
                    .gateway
                    .read()
                    .contains_txid(&transaction.txid()),
                above == 0
            );
        }
    }

    #[test]
    fn broadcast_transaction_is_immediately_visible_as_unconfirmed() {
        let mut ctx = Context::new();
        let (transaction, funding) = transaction_with_funded_input(&ctx, 10_000);
        ctx.indexes.esplora_tx_index = Some(Arc::new(StaticTxIndex::new(funding)));
        let ctx = Arc::new(ctx);
        let txid = transaction.txid();
        let handler = Handler::new(ctx);
        let raw = consensus_bytes(&transaction).to_lower_hex_string();
        let broadcast = route_post(&handler, "/tx", raw.as_bytes());
        assert_eq!(broadcast.status, 200);
        let response = route(&handler, &format!("/tx/{txid}"), "");
        assert_eq!(response.status, 200);
        let value: Value = sonic_rs::from_slice(&response.body).expect("transaction json");
        assert_eq!(value["status"], json!({"confirmed":false}));
    }

    // API-09
    #[test]
    fn history_cursors_follow_api_09_on_both_esplora_surfaces() -> Result<(), TestError> {
        let (handler, transaction, _, address) = contract_fixture()?;
        let txid = transaction.txid().to_string();
        let script_hash = ScriptHash::new(&transaction.outputs[0].script_pubkey)
            .to_byte_array()
            .to_lower_hex_string();
        let mut unavailable = Context::new();
        unavailable.chain.chain_network = bitcoin_rs_consensus::primitives::Network::Regtest;
        let unavailable = Handler::new(Arc::new(unavailable));
        for prefix in ["/api", "/esplora"] {
            for target in [
                format!("address/{address}"),
                format!("scripthash/{script_hash}"),
            ] {
                let path = format!("{prefix}/{target}/txs/chain");
                let first = dispatch(&handler, &path, "");
                assert_eq!(first.status, 200);
                let first_page: Value = sonic_rs::from_slice(&first.body)?;
                assert_eq!(first_page.as_array().map(|array| array.len()), Some(1));
                for cursor in [
                    "00".repeat(32),
                    "not-a-txid".to_owned(),
                    txid.to_uppercase(),
                    format!("0x{txid}"),
                ] {
                    let cursor_path = format!("{path}/{cursor}");
                    let response = dispatch(&handler, &cursor_path, "");
                    assert_eq!(response.status, 200, "{cursor_path}");
                    assert_eq!(response.body, first.body, "{cursor_path}");
                    assert_eq!(dispatch(&unavailable, &cursor_path, "").status, 503);
                }
                let end = dispatch(&handler, &format!("{path}/{txid}"), "");
                assert_eq!(end.status, 200);
                assert_eq!(sonic_rs::from_slice::<Value>(&end.body)?, json!([]));
                let mempool = dispatch(&handler, &format!("{prefix}/{target}/txs/mempool"), "");
                assert_eq!(mempool.status, 200);
                assert_eq!(sonic_rs::from_slice::<Value>(&mempool.body)?, json!([]));
                assert_eq!(
                    dispatch(&handler, &format!("{path}/{txid}/extra"), "").status,
                    404
                );
            }
        }
        Ok(())
    }

    #[test]
    fn history_mempool_sentinel_keeps_the_fifty_transaction_bound() {
        let target = vec![0x51];
        let mut ctx = Context::new();
        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: Vec::new(),
            funding: Vec::new(),
            unspent: Vec::new(),
        }));
        for value in 1..=60 {
            let tx = Arc::new(transaction(
                None,
                TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: target.clone().into(),
                },
            ));
            ctx.mempool
                .gateway
                .pool()
                .write()
                .insert_entry(MempoolEntry::new(tx, 100, 100, 0, 0, 0))
                .expect("insert mempool fixture");
        }
        let mempool = mempool_history(&ctx, ScriptHash::new(&target));
        assert_eq!(mempool.status, 200);
        let values: Value = sonic_rs::from_slice(&mempool.body).expect("mempool page json");
        assert_eq!(values.as_array().map(|array| array.len()), Some(50));
        assert!(
            values
                .as_array()
                .expect("page")
                .iter()
                .all(|tx| tx["status"]["confirmed"] == false)
        );
        let chain = chain_history(&ctx, ScriptHash::new(&target), Some("not-a-txid"));
        assert_eq!(chain.status, 200);
        assert_eq!(chain.body, b"[]");
    }

    #[test]
    fn history_hydrates_only_the_requested_chain_page() {
        let target = vec![0x51];
        let transactions = (1_u64..=30)
            .map(|value| {
                transaction(
                    None,
                    TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: target.clone().into(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let records = transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| ScriptHistoryRecord {
                txid: transaction.txid(),
                height: u32::try_from(index + 1).expect("fixture height fits u32"),
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        for record in &records {
            ctx.chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
                    record.height,
                    BlockHash::default(),
                ));
        }
        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: records.clone(),
            funding: Vec::new(),
            unspent: Vec::new(),
        }));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions,
            calls: Arc::clone(&calls),
        }));

        let response = chain_history(&ctx, ScriptHash::new(&target), None);
        assert_eq!(response.status, 200);
        let values: Value = sonic_rs::from_slice(&response.body).expect("history response json");
        assert_eq!(values.as_array().map(|array| array.len()), Some(CHAIN_PAGE));
        assert_eq!(calls.load(Ordering::Relaxed), CHAIN_PAGE);

        let cursor = records[5].txid.to_string();
        let second = chain_history(&ctx, ScriptHash::new(&target), Some(&cursor));
        assert_eq!(second.status, 200);
        let second: Value = sonic_rs::from_slice(&second.body).expect("second page json");
        assert_eq!(second.as_array().map(|array| array.len()), Some(5));
        assert_eq!(second[0]["txid"], records[4].txid.to_string());
        assert_eq!(second[4]["txid"], records[0].txid.to_string());
        assert_eq!(calls.load(Ordering::Relaxed), 30);
        let end = chain_history(
            &ctx,
            ScriptHash::new(&target),
            Some(&records[0].txid.to_string()),
        );
        assert_eq!(end.status, 200);
        assert_eq!(end.body, b"[]");
        assert_eq!(calls.load(Ordering::Relaxed), 30);

        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: records
                .into_iter()
                .filter(|row| row.txid.to_string() != cursor)
                .collect(),
            funding: Vec::new(),
            unspent: Vec::new(),
        }));
        let first = chain_history(&ctx, ScriptHash::new(&target), None);
        calls.store(0, Ordering::Relaxed);
        let restarted = chain_history(&ctx, ScriptHash::new(&target), Some(&cursor));
        assert_eq!(restarted.status, 200);
        assert_eq!(restarted.body, first.body);
        assert_eq!(calls.load(Ordering::Relaxed), CHAIN_PAGE);
    }

    #[test]
    fn chain_history_does_not_enumerate_script_live_or_poll_mempool() {
        let target = vec![0x51];
        let script_hash = ScriptHash::new(&target);
        let transactions = (1_u64..=30)
            .map(|value| {
                transaction(
                    None,
                    TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: target.clone().into(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let history_records = transactions
            .iter()
            .enumerate()
            .map(|(index, tx)| ScriptHistoryRecord {
                txid: tx.txid(),
                height: u32::try_from(index + 1).expect("height"),
            })
            .collect::<Vec<_>>();
        let unspent_record = ScriptIndexRecord {
            txid: transactions[0].txid(),
            height: 1,
            value: 1,
            vout: 0,
        };

        let unspent_calls = Arc::new(AtomicUsize::new(0));
        let history_calls = Arc::new(AtomicUsize::new(0));
        let tx_calls = Arc::new(AtomicUsize::new(0));

        let mut ctx = Context::new();
        for record in &history_records {
            ctx.chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
                    record.height,
                    BlockHash::default(),
                ));
        }
        ctx.indexes.script_index = Some(Arc::new(MonitoredScriptIndex {
            history: history_records.clone(),
            funding: vec![unspent_record],
            unspent: vec![unspent_record],
            unspent_calls: Arc::clone(&unspent_calls),
            history_calls: Arc::clone(&history_calls),
        }));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions,
            calls: Arc::clone(&tx_calls),
        }));

        let mempool_tx = Arc::new(transaction(
            None,
            TxOut {
                value: Amount::from_sat(999),
                script_pubkey: target.into(),
            },
        ));
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(mempool_tx, 100, 100, 0, 0, 0))
            .expect("insert mempool entry");

        let chain_resp = chain_history(&ctx, script_hash, None);
        assert_eq!(chain_resp.status, 200);
        let chain_val: Value = sonic_rs::from_slice(&chain_resp.body).expect("chain json");
        assert_eq!(
            chain_val.as_array().map(|array| array.len()),
            Some(CHAIN_PAGE)
        );
        assert_eq!(
            unspent_calls.load(Ordering::Relaxed),
            0,
            "chain history must not enumerate ScriptLive unspent outputs"
        );
        assert_eq!(history_calls.load(Ordering::Relaxed), 1);
        assert_eq!(tx_calls.load(Ordering::Relaxed), CHAIN_PAGE);
        assert!(
            chain_val
                .as_array()
                .expect("page")
                .iter()
                .all(|tx| tx["status"]["confirmed"] == true)
        );

        let cursor = history_records[5].txid.to_string();
        let chain_page2 = chain_history(&ctx, script_hash, Some(&cursor));
        assert_eq!(chain_page2.status, 200);
        assert_eq!(
            unspent_calls.load(Ordering::Relaxed),
            0,
            "chain page 2 must not enumerate ScriptLive"
        );

        let mempool_resp = mempool_history(&ctx, script_hash);
        assert_eq!(mempool_resp.status, 200);
        let mempool_val: Value = sonic_rs::from_slice(&mempool_resp.body).expect("mempool json");
        assert_eq!(mempool_val.as_array().map(|array| array.len()), Some(1));
        assert_eq!(
            history_calls.load(Ordering::Relaxed),
            2,
            "mempool-only query must not invoke confirmed history (still 2 from chain queries)"
        );

        let utxo_resp = Projection::new(&ctx)
            .script_utxos(script_hash)
            .expect("utxos");
        assert_eq!(
            unspent_calls.load(Ordering::Relaxed),
            2,
            "utxo endpoint retains ScriptLive scan"
        );
        assert_eq!(utxo_resp.len(), 2);
    }

    #[test]
    fn chain_history_pagination_traversal_multi_page_and_pruned_blocks() {
        let target = vec![0x51];
        let script_hash = ScriptHash::new(&target);
        let mut transactions = Vec::with_capacity(60);
        let mut history_records = Vec::with_capacity(60);
        for height in 1_u32..=20 {
            for vout_val in 1_u64..=3 {
                let tx = transaction(
                    None,
                    TxOut {
                        value: Amount::from_sat(u64::from(height) * 10 + vout_val),
                        script_pubkey: target.clone().into(),
                    },
                );
                history_records.push(ScriptHistoryRecord {
                    txid: tx.txid(),
                    height,
                });
                transactions.push(tx);
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();

        for height in 12_u32..=20 {
            ctx.chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
                    height,
                    BlockHash::default(),
                ));
        }

        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: history_records.clone(),
            funding: Vec::new(),
            unspent: Vec::new(),
        }));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions,
            calls: Arc::clone(&calls),
        }));

        let page1 = chain_history(&ctx, script_hash, None);
        assert_eq!(
            page1.status, 200,
            "Page 1 must succeed even when unselected past blocks are pruned"
        );
        let page1_vals: Value = sonic_rs::from_slice(&page1.body).expect("page1 json");
        assert_eq!(
            page1_vals.as_array().map(|array| array.len()),
            Some(CHAIN_PAGE)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 25);

        ctx.chain.blocks.write().clear();
        for height in 1_u32..=20 {
            ctx.chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
                    height,
                    BlockHash::default(),
                ));
        }

        let page1_txids: Vec<String> = page1_vals
            .as_array()
            .expect("page1 json array")
            .iter()
            .map(|tx| tx["txid"].as_str().expect("txid str").to_owned())
            .collect();
        let cursor1 = page1_txids.last().expect("page1 last txid").clone();

        let page2 = chain_history(&ctx, script_hash, Some(&cursor1));
        assert_eq!(page2.status, 200);
        let page2_vals: Value = sonic_rs::from_slice(&page2.body).expect("page2 json");
        assert_eq!(
            page2_vals.as_array().map(|array| array.len()),
            Some(CHAIN_PAGE)
        );
        let page2_txids: Vec<String> = page2_vals
            .as_array()
            .expect("page2 json array")
            .iter()
            .map(|tx| tx["txid"].as_str().expect("txid str").to_owned())
            .collect();
        let cursor2 = page2_txids.last().expect("page2 last txid").clone();

        let page3 = chain_history(&ctx, script_hash, Some(&cursor2));
        assert_eq!(page3.status, 200);
        let page3_vals: Value = sonic_rs::from_slice(&page3.body).expect("page3 json");
        assert_eq!(page3_vals.as_array().map(|array| array.len()), Some(10));
        let page3_txids: Vec<String> = page3_vals
            .as_array()
            .expect("page3 json array")
            .iter()
            .map(|tx| tx["txid"].as_str().expect("txid str").to_owned())
            .collect();
        let cursor3 = page3_txids.last().expect("page3 last txid").clone();

        let page4 = chain_history(&ctx, script_hash, Some(&cursor3));
        assert_eq!(page4.status, 200);
        assert_eq!(page4.body, b"[]");

        let mut all_traversed = Vec::new();
        all_traversed.extend(page1_txids);
        all_traversed.extend(page2_txids);
        all_traversed.extend(page3_txids);
        assert_eq!(all_traversed.len(), 60);

        let mut deduped = all_traversed.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            60,
            "stable pagination must contain 0 duplicates"
        );

        for invalid_cursor in [
            "00".repeat(32),
            "not-a-txid".to_owned(),
            cursor1.to_uppercase(),
            format!("0x{cursor1}"),
        ] {
            let restarted = chain_history(&ctx, script_hash, Some(&invalid_cursor));
            assert_eq!(restarted.status, 200, "cursor: {invalid_cursor}");
            assert_eq!(
                restarted.body, page1.body,
                "noncanonical/unknown cursor must restart from page 1"
            );
        }
    }

    #[test]
    fn chain_history_deduplicates_multiple_outputs_in_same_transaction() {
        let target = vec![0x51];
        let script_hash = ScriptHash::new(&target);
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(100),
                    script_pubkey: target.clone().into(),
                },
                TxOut {
                    value: Amount::from_sat(200),
                    script_pubkey: target.clone().into(),
                },
                TxOut {
                    value: Amount::from_sat(300),
                    script_pubkey: target.into(),
                },
            ],
            lock_time: LockTime::ZERO,
        };
        let txid = tx.txid();
        let records = vec![
            ScriptHistoryRecord { txid, height: 10 },
            ScriptHistoryRecord { txid, height: 10 },
            ScriptHistoryRecord { txid, height: 10 },
        ];
        let mut ctx = Context::new();
        ctx.chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
                10,
                BlockHash::default(),
            ));
        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: records,
            funding: Vec::new(),
            unspent: Vec::new(),
        }));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions: vec![tx],
            calls: Arc::new(AtomicUsize::new(0)),
        }));

        let response = chain_history(&ctx, script_hash, None);
        assert_eq!(response.status, 200);
        let val: Value = sonic_rs::from_slice(&response.body).expect("json");
        assert_eq!(val.as_array().map(|array| array.len()), Some(1));
        assert_eq!(val[0]["txid"], txid.to_string());
    }

    #[test]
    fn address_statistics_read_no_transactions_beyond_the_script_index() {
        let target = vec![0x51];
        let script_hash = ScriptHash::new(&target);
        let transactions = (1_u64..=30)
            .map(|value| {
                transaction(
                    None,
                    TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: target.clone().into(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let history = transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| ScriptHistoryRecord {
                txid: transaction.txid(),
                height: u32::try_from(index + 1).expect("fixture height fits u32"),
            })
            .collect::<Vec<_>>();
        let funding = transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| ScriptIndexRecord {
                txid: transaction.txid(),
                height: u32::try_from(index + 1).expect("fixture height fits u32"),
                value: u64::try_from(index + 1).expect("fixture value fits u64"),
                vout: 0,
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        for record in &history {
            ctx.chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
                    record.height,
                    BlockHash::default(),
                ));
        }
        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history,
            funding: funding.clone(),
            unspent: vec![funding[0]],
        }));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions,
            calls: Arc::clone(&calls),
        }));

        let summary = summary(
            &ctx,
            &script_hash.to_byte_array().to_lower_hex_string(),
            None,
        );
        assert_eq!(summary.status, 200);
        let value: Value = sonic_rs::from_slice(&summary.body).expect("summary json");
        assert_eq!(value["chain_stats"]["funded_txo_count"], json!(30));
        assert_eq!(value["chain_stats"]["funded_txo_sum"], json!(465));
        assert_eq!(value["chain_stats"]["spent_txo_count"], json!(29));
        assert_eq!(value["chain_stats"]["spent_txo_sum"], json!(464));

        let per_transaction = address_transaction_summary(&ctx, script_hash);
        assert_eq!(per_transaction.status, 200);
        let rows: Value = sonic_rs::from_slice(&per_transaction.body).expect("summary rows json");
        assert_eq!(rows.as_array().map(|array| array.len()), Some(30));

        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn mempool_spender_of_a_confirmed_target_output_remains_in_activity_and_stats() {
        let target = vec![0x51];
        let confirmed = ScriptIndexRecord {
            txid: Txid(Hash256::from_le_bytes(&[3; 32])),
            height: 42,
            value: 125,
            vout: 0,
        };
        let spending = transaction(
            Some(OutPoint::new(confirmed.txid, confirmed.vout)),
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: vec![0x52].into(),
            },
        );
        let mut ctx = Context::new();
        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: Vec::new(),
            funding: vec![confirmed],
            unspent: vec![confirmed],
        }));
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(spending.clone()),
                100,
                1_000,
                0,
                0,
                0,
            ))
            .expect("mempool entry accepted");

        let script_hash = ScriptHash::new(&target);
        let projection = Projection::new(&ctx);
        let activity = projection
            .script_activity(script_hash)
            .expect("script activity resolves");
        assert_eq!(
            activity
                .mempool
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
            vec![&spending]
        );
        assert!(
            projection
                .script_utxos(script_hash)
                .expect("UTXO overlay resolves")
                .is_empty()
        );
        let stats = activity.mempool_stats(script_hash);
        assert_eq!(stats.spent_txo_count, 1);
        assert_eq!(stats.spent_txo_sum, 125);
    }
    #[test]
    fn script_activity_retries_when_pool_changes_between_views() {
        let target = vec![0x51];
        let confirmed = ScriptIndexRecord {
            txid: Txid(Hash256::from_le_bytes(&[3; 32])),
            height: 42,
            value: 125,
            vout: 0,
        };
        let funder = Arc::new(paying_transaction(
            &[unconfirmed_outpoint(1)],
            &[(200, target.clone())],
        ));
        let spender = paying_transaction(
            &[OutPoint::new(confirmed.txid, confirmed.vout)],
            &[(100, vec![0x52])],
        );
        let funder_txid = funder.txid();
        let spender_txid = spender.txid();
        let mut context = Context::new();
        context.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: Vec::new(),
            funding: vec![confirmed],
            unspent: vec![confirmed],
        }));
        context
            .mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(Arc::clone(&funder), 100, 1_000, 1, 0, 0))
            .expect("seed funder");
        let first_sequence = context.mempool.gateway.pool().read().sequence_number();
        let context = Arc::new(context);
        let handler = Handler::new(Arc::clone(&context));
        let script_hash = ScriptHash::new(&target)
            .to_byte_array()
            .to_lower_hex_string();
        let path = format!("/scripthash/{script_hash}");
        let (entered_send, entered_recv) = channel();
        let (release_send, release_recv) = channel();
        let request = std::thread::spawn(move || {
            arm_mempool_activity_gate(entered_send, release_recv);
            route(&handler, &path, "")
        });

        assert!(
            entered_recv.recv_timeout(GATE_TIMEOUT).is_ok(),
            "request did not capture its first mempool view"
        );
        {
            let mut pool = context.mempool.gateway.pool().write();
            pool.remove_for_block(
                &bitcoin_rs_mempool::TransitionFacts::from_txs(&[funder.as_ref()]),
                42,
                1,
            );
            assert!(!pool.contains_txid(&funder_txid));
            pool.insert_entry(MempoolEntry::new(Arc::new(spender), 100, 1_000, 2, 0, 0))
                .expect("seed spender");
            assert_ne!(pool.sequence_number(), first_sequence);
            assert!(pool.contains_txid(&spender_txid));
        }
        release_send.send(()).expect("release request");

        let response = request.join().expect("route thread");
        assert_eq!(
            response.status,
            503,
            "mempool snapshots changed during projection: {}",
            String::from_utf8_lossy(&response.body)
        );
    }

    #[test]
    fn transaction_projection_uses_internal_lookup_for_prevout_and_fee() -> Result<(), TestError> {
        let parent = transaction(
            None,
            TxOut {
                value: Amount::from_sat(125),
                script_pubkey: vec![0x51].into(),
            },
        );
        let child = transaction(
            Some(OutPoint::new(parent.txid(), 0)),
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: vec![0x52].into(),
            },
        );
        let mut ctx = Context::new();
        ctx.indexes.esplora_tx_index = Some(Arc::new(StaticTxIndex::new(parent)));

        let Ok((rendered, _)) = Projection::new(&ctx).transaction_values([(&child, None)], None)
        else {
            return Err("prevout indexed".into());
        };
        let rendered = &rendered[0];
        assert_eq!(rendered.fee, 25);
        let Some(prevout) = rendered.vin[0].prevout.as_ref() else {
            return Err("rendered prevout".into());
        };
        assert_eq!(prevout.value, 125);
        Ok(())
    }

    #[test]
    fn history_resolves_shared_parents_once_per_page() {
        let parent = paying_transaction(&[OutPoint::null()], &vec![(125, vec![0x52]); 62]);
        let transactions = (0_u32..30)
            .map(|n| {
                paying_transaction(
                    &[
                        OutPoint::new(parent.txid(), n * 2),
                        OutPoint::new(parent.txid(), n * 2 + 1),
                    ],
                    &[(200, vec![0x51])],
                )
            })
            .collect::<Vec<_>>();
        let records = transactions
            .iter()
            .enumerate()
            .map(|(n, tx)| ScriptHistoryRecord {
                txid: tx.txid(),
                height: u32::try_from(n + 1).expect("height"),
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        for record in &records {
            ctx.chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
                    record.height,
                    BlockHash::default(),
                ));
        }
        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: records.clone(),
            funding: vec![],
            unspent: vec![],
        }));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions: transactions
                .iter()
                .cloned()
                .chain([parent.clone()])
                .collect(),
            calls: Arc::clone(&calls),
        }));
        for (cursor, expected) in [
            (None, &transactions[5..]),
            (Some(records[5].txid.to_string()), &transactions[..5]),
        ] {
            calls.store(0, Ordering::Relaxed);
            let response = chain_history(&ctx, ScriptHash::new(&[0x51]), cursor.as_deref());
            assert_eq!(response.status, 200);
            let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("page");
            assert_eq!(calls.load(Ordering::Relaxed), expected.len() + 1);
            assert_eq!(values.len(), expected.len());
            for (value, tx) in values.iter().zip(expected.iter().rev()) {
                assert_eq!(value["txid"], tx.txid().to_string());
                assert_eq!(value["fee"], 50);
                assert_eq!(value["status"]["confirmed"], true);
                for (input, original) in value["vin"]
                    .as_array()
                    .expect("inputs")
                    .iter()
                    .zip(&tx.inputs)
                {
                    assert_eq!(input["txid"], parent.txid().to_string());
                    assert_eq!(input["vout"], { original.previous_output.vout });
                    assert_eq!(input["prevout"]["value"], 125);
                    assert_eq!(input["prevout"]["scriptpubkey"], "52");
                }
            }
        }
        let unconfirmed = paying_transaction(
            &[
                OutPoint::new(parent.txid(), 60),
                OutPoint::new(parent.txid(), 61),
            ],
            &[(200, vec![0x51])],
        );
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(unconfirmed.clone()),
                100,
                1_000,
                1,
                0,
                0,
            ))
            .expect("mixed page");
        calls.store(0, Ordering::Relaxed);
        let mixed = full_history(&ctx, ScriptHash::new(&[0x51]));
        assert_eq!(mixed.status, 200);
        let mixed: Vec<Value> = sonic_rs::from_slice(&mixed.body).expect("mixed page");
        assert_eq!(mixed.len(), CHAIN_PAGE + 1);
        assert_eq!(mixed[0]["txid"], unconfirmed.txid().to_string());
        assert_eq!(mixed[0]["status"]["confirmed"], false);
        assert_eq!(mixed[0]["fee"], 50);
        assert_eq!(calls.load(Ordering::Relaxed), CHAIN_PAGE + 1);
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions,
            calls,
        }));
        assert_eq!(
            chain_history(&ctx, ScriptHash::new(&[0x51]), None).status,
            503
        );
    }

    #[test]
    fn batch_reuses_selected_transactions_and_mempool_parents() -> Result<(), TestError> {
        let parent =
            paying_transaction(&[OutPoint::null()], &[(125, vec![0x51]), (175, vec![0x52])]);
        let child = paying_transaction(
            &[
                OutPoint::new(parent.txid(), 0),
                OutPoint::new(parent.txid(), 1),
            ],
            &[(250, vec![0x53])],
        );
        let ctx = Context::new();
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(parent.clone()),
                100,
                1_000,
                1,
                0,
                0,
            ))?;
        let projection = Projection::new(&ctx);
        let Ok((values, _)) = projection.transaction_values([(&child, None), (&child, None)], None)
        else {
            return Err("mempool prevouts".into());
        };
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].fee, 50);
        let Some(first) = values[0].vin[0].prevout.as_ref() else {
            return Err("vout 0".into());
        };
        assert_eq!(first.value, 125);
        let Some(second) = values[0].vin[1].prevout.as_ref() else {
            return Err("vout 1".into());
        };
        assert_eq!(second.value, 175);
        assert!(!values[0].status.confirmed);
        assert_eq!(
            sonic_rs::to_value(&values[0])?,
            sonic_rs::to_value(&values[1])?
        );
        let ctx = Context::new();
        let Ok((values, _)) =
            Projection::new(&ctx).transaction_values([(&child, None), (&parent, None)], None)
        else {
            return Err("selected parent".into());
        };
        assert_eq!(values[0].fee, 50);
        let Some(first) = values[0].vin[0].prevout.as_ref() else {
            return Err("vout 0".into());
        };
        assert_eq!(first.value, 125);
        let Some(second) = values[0].vin[1].prevout.as_ref() else {
            return Err("vout 1".into());
        };
        assert_eq!(second.value, 175);
        assert_eq!(values[1].txid, parent.txid().to_string());
        let missing = paying_transaction(&[OutPoint::new(parent.txid(), 2)], &[(1, vec![0x51])]);
        let Err(response) =
            Projection::new(&ctx).transaction_values([(&missing, None), (&parent, None)], None)
        else {
            return Err("missing output".into());
        };
        assert_eq!(response.status, 503);
        Ok(())
    }

    #[test]
    fn block_page_reuses_parent_outside_the_selected_page() {
        let mut block = fixture_genesis();
        let parent = block.txs[0].clone();
        let child = paying_transaction(&[OutPoint::new(parent.txid(), 0)], &[(100, vec![0x51])]);
        block.txs.push(child.clone());
        block.header.merkle_root = merkle_root(&block.txs).expect("fixture block has transactions");
        let record = bitcoin_rs_index::block_log::BlockRecord::from_block(0, &block);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        ctx.chain.add_block(record.clone());
        let tip = {
            let mut tree = ctx.chain.block_tree.write();
            tree.insert_node(None, block.header, NodeStatus::Active)
                .expect("tip");
            tree.tip().expect("tip")
        };
        ctx.chain.applied_tip.store(Some(tip));
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(0, record.hash, consensus_bytes(&block))],
        }));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions: block.txs.clone(),
            calls: Arc::clone(&calls),
        }));
        let response = block_txs(&ctx, &record.hash.to_string(), 1);
        assert_eq!(response.status, 200);
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("block page");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["txid"], child.txid().to_string());
        assert_eq!(values[0]["fee"], parent.outputs[0].value.to_sat() - 100);
        assert_eq!(values[0]["status"]["block_hash"], record.hash.to_string());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let mut corrupt = block.clone();
        corrupt.txs[0].outputs[0].value = Amount::from_sat(999);
        corrupt.txs[1].inputs[0].previous_output = OutPoint::new(corrupt.txs[0].txid(), 0);
        assert_eq!(corrupt.block_hash(), block.block_hash());
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(0, record.hash, consensus_bytes(&corrupt))],
        }));
        assert_eq!(block_txs(&ctx, &record.hash.to_string(), 1).status, 500);
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(0, record.hash, consensus_bytes(&block))],
        }));
        let stale_record =
            bitcoin_rs_index::block_log::BlockRecord::synthetic(0, BlockHash::default());
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions: vec![],
            calls,
        }));
        let response = super::public::block_transaction_values(&ctx, &stale_record, &block, 1, 1)
            .expect_err("stale body cannot supply parents");
        assert_eq!(response.status, 503);
        for (error, status) in [
            (
                TxQueryError::Retry(bitcoin_rs_index::RetryReason::TipMoved {
                    expected_revision: 0,
                    current_revision: 1,
                }),
                503,
            ),
            (TxQueryError::Storage("corrupt".into()), 500),
        ] {
            ctx.indexes.esplora_tx_index = Some(Arc::new(FailingParentIndex {
                error: Some(error),
                republish: None,
                published: AtomicBool::new(false),
                parent: parent.clone(),
            }));
            assert_eq!(block_txs(&ctx, &record.hash.to_string(), 1).status, status);
        }
        ctx.indexes.esplora_tx_index = None;
        assert_eq!(block_txs(&ctx, &record.hash.to_string(), 1).status, 503);
        block.header.nonce = block.header.nonce.wrapping_add(1);
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(0, record.hash, consensus_bytes(&block))],
        }));
        assert_eq!(block_txs(&ctx, &record.hash.to_string(), 1).status, 500);
    }

    #[test]
    fn block_transactions_reject_corrupt_witness_commitments() {
        use bitcoin_rs_consensus::primitives::encode::double_sha256;
        let parent = paying_transaction(&[OutPoint::null()], &[(125, vec![0x51])]);
        let mut child =
            paying_transaction(&[OutPoint::new(parent.txid(), 0)], &[(100, vec![0x52])]);
        child.inputs[0].witness = vec![vec![0x42]].into();
        let mut block = fixture_genesis();
        block.txs[0].inputs[0].witness = vec![vec![0; 32]].into();
        let mut leaves = vec![[0; 32], *child.wtxid().as_bytes()];
        let root = bitcoin_rs_consensus::compute_merkle_root(&mut leaves).expect("witness root");
        let commitment = double_sha256(&[root.as_slice(), &[0; 32]].concat());
        block.txs[0].outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: [
                &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
                commitment.to_le_bytes().as_slice(),
            ]
            .concat()
            .into(),
        });
        block.txs.push(child);
        block.header.merkle_root = merkle_root(&block.txs).expect("merkle root");
        let record = bitcoin_rs_index::block_log::BlockRecord::from_block(0, &block);
        let mut ctx = Context::new();
        ctx.chain.chain_network = bitcoin_rs_consensus::primitives::Network::Regtest;
        ctx.chain.add_block(record.clone());
        let tip = {
            let mut tree = ctx.chain.block_tree.write();
            tree.insert_node(None, block.header, NodeStatus::Active)
                .expect("header");
            tree.tip().expect("tip")
        };
        ctx.chain.applied_tip.store(Some(tip));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions: vec![parent],
            calls: Arc::new(AtomicUsize::new(0)),
        }));
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(0, record.hash, consensus_bytes(&block))],
        }));
        let response = block_txs(&ctx, &record.hash.to_string(), 1);
        assert_eq!(response.status, 200);
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("block page");
        assert_eq!(values[0]["vin"][0]["witness"], json!(["42"]));
        for (tx_index, witness) in [(1, vec![vec![0x43]]), (0, vec![vec![1; 32]]), (0, vec![])] {
            let mut corrupt = block.clone();
            corrupt.txs[tx_index].inputs[0].witness = witness.into();
            assert_eq!(corrupt.block_hash(), block.block_hash());
            assert_eq!(corrupt.txids(), block.txids());
            ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
                bodies: vec![(0, record.hash, consensus_bytes(&corrupt))],
            }));
            assert_eq!(block_txs(&ctx, &record.hash.to_string(), 1).status, 500);
        }
    }

    #[test]
    fn block_witness_binding_observes_activation() {
        let mut block = fixture_genesis();
        block.txs[0].outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: [&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed], &[0; 32][..]]
                .concat()
                .into(),
        });
        block.header.merkle_root = merkle_root(&block.txs).expect("merkle root");
        let record = bitcoin_rs_index::block_log::BlockRecord::from_block(0, &block);
        let mut ctx = Context::new();
        ctx.chain.add_block(record.clone());
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, block.header, NodeStatus::Active)
            .expect("header");
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(0, record.hash, consensus_bytes(&block))],
        }));
        for (network, expected) in [
            (bitcoin_rs_consensus::primitives::Network::Mainnet, true),
            (bitcoin_rs_consensus::primitives::Network::Regtest, false),
        ] {
            ctx.chain.chain_network = network;
            let projection = Projection::new(&ctx);
            let loaded = projection
                .required_block_record(&record.hash.to_string())
                .and_then(|record| projection.block_from_record(record));
            assert_eq!(loaded.is_ok(), expected);
        }
    }

    // WF-02
    #[test]
    fn block_parent_reuse_checks_readiness_only_when_needed() -> Result<(), TestError> {
        struct ReadinessIndex {
            parent: Tx,
            checks: Arc<AtomicUsize>,
            synced: bool,
        }
        impl crate::context::DerivedIndexQuery for ReadinessIndex {
            fn transaction(&self, _: &Txid) -> Result<Option<Tx>, TxQueryError> {
                if self.synced {
                    Ok(Some(self.parent.clone()))
                } else {
                    Err(TxQueryError::Retry(
                        bitcoin_rs_index::RetryReason::TipMoved {
                            expected_revision: 0,
                            current_revision: 1,
                        },
                    ))
                }
            }
            fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }
            fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
                self.checks.fetch_add(1, Ordering::Relaxed);
                Ok(crate::context::DerivedIndexInfo {
                    synced: self.synced,
                    best_block_height: 0,
                    applied_height: 0,
                    historical_height: 0,
                    verified_height: 0,
                    coverage_height: 0,
                })
            }
        }
        let parent = paying_transaction(&[OutPoint::null()], &[(125, vec![0x51])]);
        let child = paying_transaction(&[OutPoint::new(parent.txid(), 0)], &[(100, vec![0x52])]);
        let checks = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        ctx.indexes.esplora_tx_index = Some(Arc::new(ReadinessIndex {
            parent: parent.clone(),
            checks: Arc::clone(&checks),
            synced: true,
        }));
        let Ok((values, _)) = Projection::new(&ctx).transaction_values(
            [(&child, None)],
            Some(
                &Projection::new(&ctx)
                    .block_parents(std::slice::from_ref(&child), std::slice::from_ref(&child)),
            ),
        ) else {
            return Err("external parent".into());
        };
        assert_eq!(values[0].fee, 25);
        assert_eq!(
            checks.load(Ordering::Relaxed),
            0,
            "an index-resolved parent needs no readiness read"
        );
        let projection = Projection::new(&ctx);
        let block = [parent.clone(), child.clone()];
        let parents = projection.block_parents(&block, std::slice::from_ref(&child));
        assert_eq!(parents.len(), 1);
        assert!(parents.contains_key(&parent.txid()));
        let Ok((values, _)) =
            projection.transaction_values([(&child, None), (&child, None)], Some(&parents))
        else {
            return Err("in-block parent".into());
        };
        assert_eq!(values[0].fee, 25);
        assert_eq!(values[1].fee, 25);
        assert_eq!(
            checks.load(Ordering::Relaxed),
            1,
            "a block-supplied spent parent confirms readiness once"
        );
        ctx.indexes.esplora_tx_index = Some(Arc::new(ReadinessIndex {
            parent: parent.clone(),
            checks: Arc::clone(&checks),
            synced: false,
        }));
        let Err(error) = Projection::new(&ctx).transaction_values(
            [(&child, None)],
            Some(
                &Projection::new(&ctx)
                    .block_parents(std::slice::from_ref(&parent), std::slice::from_ref(&child)),
            ),
        ) else {
            return Err("index behind tip".into());
        };
        assert_eq!(error.status, 503);
        assert_eq!(
            checks.load(Ordering::Relaxed),
            2,
            "the behind-tip path confirms readiness once more"
        );
        Ok(())
    }

    // API-09, WF-02
    #[test]
    fn backend_mempool_get_bounds_pages_and_prevouts() {
        let parent = paying_transaction(
            &[OutPoint::null()],
            &(0..57)
                .flat_map(|_| [(125, vec![0x51]), (175, vec![0x52])])
                .collect::<Vec<_>>(),
        );
        let txs = (0_u32..57)
            .map(|n| {
                paying_transaction(
                    &[
                        OutPoint::new(parent.txid(), 2 * n),
                        OutPoint::new(parent.txid(), 2 * n + 1),
                    ],
                    &[(250, vec![0x51])],
                )
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions: vec![parent],
            calls: Arc::clone(&calls),
        }));
        for (n, tx) in (0_u64..).zip(&txs) {
            ctx.mempool
                .gateway
                .pool()
                .write()
                .insert_entry(MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, n, 0, 0))
                .expect("fixture entry");
        }
        let handler = Handler::new(Arc::new(ctx));
        let first_cursor = format!("/internal/mempool/txs/{}", txs[24].txid());
        let second_cursor = format!("/internal/mempool/txs/{}", txs[49].txid());
        for (path, query, start, count) in [
            ("/internal/mempool/txs", "", 0, 25),
            ("/internal/mempool/txs", "max_txs=25", 0, 25),
            (first_cursor.as_str(), "", 25, 25),
            (second_cursor.as_str(), "", 50, 7),
            ("/internal/mempool/txs", "max_txs=0", 0, 0),
        ] {
            calls.store(0, Ordering::Relaxed);
            let response = backend_route(&handler, path, query);
            assert_eq!(response.status, 200);
            let rows: Vec<Value> = sonic_rs::from_slice(&response.body).expect("rows");
            assert_eq!(rows.len(), count);
            assert_eq!(
                calls.load(Ordering::Relaxed),
                count.div_ceil(super::backend::MAX_BACKEND_BULK_ITEMS),
                "one index read per distinct prevout txid in each batch for {path} with {count} rows"
            );
            for (row, tx) in rows.iter().zip(txs.iter().skip(start)) {
                assert_eq!(row["txid"], tx.txid().to_string());
                assert_eq!(row["fee"], 50);
                assert_eq!(row["vin"][0]["prevout"]["value"], 125);
                assert_eq!(row["vin"][1]["prevout"]["value"], 175);
                assert_eq!(row["status"]["confirmed"], false);
            }
        }
        let unresolved =
            paying_transaction(&[OutPoint::new(Txid::default(), 0)], &[(1, vec![0x51])]);
        handler
            .context()
            .mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(unresolved),
                100,
                1_000,
                57,
                0,
                0,
            ))
            .expect("unavailable parent fixture");
        assert_eq!(
            backend_route(&handler, second_cursor.as_str(), "").status,
            503
        );
        assert_eq!(
            backend_route(&handler, second_cursor.as_str(), "max_txs=7").status,
            200
        );
        assert_eq!(
            backend_route(&handler, "/internal/mempool/txs", "max_txs=26").status,
            400
        );
    }

    // WF-02
    #[test]
    fn backend_mempool_get_keeps_captured_parents_within_a_page() {
        struct RemovingIndex {
            gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
            captured_parent: Txid,
            external: Tx,
            calls: Arc<AtomicUsize>,
        }
        impl crate::context::DerivedIndexQuery for RemovingIndex {
            fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                self.gateway
                    .pool()
                    .write()
                    .remove_for_reorg(&[self.captured_parent]);
                Ok((*txid == self.external.txid()).then(|| self.external.clone()))
            }
            fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }
            fn transaction_block(
                &self,
                _: &Txid,
            ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
                Ok(None)
            }
            fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
                panic!("captured mempool parents must not require index readiness")
            }
        }
        let parent = paying_transaction(&[OutPoint::null()], &[(300, vec![0x51])]);
        let external = paying_transaction(&[OutPoint::null()], &[(400, vec![0x52])]);
        let trigger =
            paying_transaction(&[OutPoint::new(external.txid(), 0)], &[(350, vec![0x51])]);
        let child = paying_transaction(&[OutPoint::new(parent.txid(), 0)], &[(250, vec![0x51])]);
        let mut txs = vec![parent.clone(), trigger];
        txs.extend((2..24).map(|n| paying_transaction(&[OutPoint::null()], &[(n, vec![0x51])])));
        txs.push(child.clone());
        let mut ctx = Context::new();
        for (n, tx) in (0_u64..).zip(&txs) {
            ctx.mempool
                .gateway
                .pool()
                .write()
                .insert_entry(MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, n, 0, 0))
                .expect("fixture entry");
        }
        let calls = Arc::new(AtomicUsize::new(0));
        ctx.indexes.esplora_tx_index = Some(Arc::new(RemovingIndex {
            gateway: ctx.mempool.gateway.clone(),
            captured_parent: parent.txid(),
            external,
            calls: Arc::clone(&calls),
        }));
        let ctx = Arc::new(ctx);
        let handler = Handler::new(Arc::clone(&ctx));
        let response = backend_route(&handler, "/internal/mempool/txs", "");
        assert_eq!(response.status, 200);
        let rows: Vec<Value> = sonic_rs::from_slice(&response.body).expect("rows");
        assert_eq!(rows.len(), txs.len());
        for (row, tx) in rows.iter().zip(&txs) {
            assert_eq!(row["txid"], tx.txid().to_string());
        }
        assert_eq!(rows[24]["vin"][0]["prevout"]["value"], 300);
        assert_eq!(rows[24]["fee"], 50);
        assert!(!ctx.mempool.gateway.read().contains_txid(&parent.txid()));
        assert!(!ctx.mempool.gateway.read().contains_txid(&child.txid()));
    }

    // API-09, WF-02
    #[test]
    fn backend_transaction_batches_share_duplicate_bodies_and_preserve_rows() {
        let parent =
            paying_transaction(&[OutPoint::null()], &[(150, vec![0x51]), (200, vec![0x52])]);
        let mut first =
            paying_transaction(&[OutPoint::new(parent.txid(), 0)], &[(125, vec![0x51])]);
        first.inputs[0].witness = vec![vec![0x42; 1024]].into();
        let second = paying_transaction(&[OutPoint::new(parent.txid(), 1)], &[(175, vec![0x52])]);
        let missing = Txid::default();
        let mut ids = [first.txid(), missing, second.txid(), first.txid()].repeat(6);
        ids.push(first.txid());
        let body = sonic_rs::to_vec(&ids.iter().map(ToString::to_string).collect::<Vec<_>>())
            .expect("request");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        let mut block = fixture_genesis();
        block.txs = vec![first.clone(), second.clone()];
        block.header.merkle_root = merkle_root(&block.txs).expect("batch transactions");
        ctx.chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                0, &block,
            ));
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, block.header, NodeStatus::Active)
            .expect("batch block header");
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            block: ctx.chain.block_by_height(0),
            transactions: vec![first.clone(), second.clone(), parent],
            calls: Arc::clone(&calls),
        }));
        let ctx = Arc::new(ctx);
        let handler = Handler::new(Arc::clone(&ctx));
        let response = backend_route_post(&handler, "/internal/txs", &body);
        assert_eq!(response.status, 200);
        let rows: Vec<Value> = sonic_rs::from_slice(&response.body).expect("batch");
        let expected = ids.iter().filter(|id| **id != missing).collect::<Vec<_>>();
        assert_eq!(rows.len(), expected.len());
        for (row, id) in rows.iter().zip(&expected) {
            assert_eq!(row["txid"], id.to_string());
            assert_eq!(row["status"]["confirmed"], true);
        }
        assert_eq!(rows[0], rows[2]);
        assert_eq!(rows[0]["vin"][0]["witness"], json!(["42".repeat(1024)]));
        assert_eq!(
            calls.load(Ordering::Relaxed),
            4,
            "three distinct IDs and one shared parent"
        );
        calls.store(0, Ordering::Relaxed);
        let oversized = vec![first.txid().to_string(); 26];
        let oversized = sonic_rs::to_vec(&oversized).expect("oversized request");
        let response = backend_route_post(&handler, "/internal/txs", &oversized);
        assert_eq!(response.status, 400);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        for tx in [first, second] {
            ctx.mempool
                .gateway
                .pool()
                .write()
                .insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 0, 0))
                .expect("pool entry");
        }
        calls.store(0, Ordering::Relaxed);
        let response = backend_route_post(&handler, "/internal/mempool/txs", &body);
        assert_eq!(response.status, 200);
        let mempool: Vec<Value> = sonic_rs::from_slice(&response.body).expect("pool batch");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "one shared confirmed parent"
        );
        assert_eq!(mempool.len(), rows.len());
        for (mut row, expected) in mempool.into_iter().zip(rows) {
            assert_eq!(row["status"]["confirmed"], false);
            row["status"] = expected["status"].clone();
            assert_eq!(row, expected);
        }
    }

    struct FailingParentIndex {
        error: Option<TxQueryError>,
        republish: Option<bitcoin_rs_chain::chain::TipReader>,
        published: AtomicBool,
        parent: Tx,
    }

    impl crate::context::DerivedIndexQuery for FailingParentIndex {
        fn transaction(&self, _: &Txid) -> Result<Option<Tx>, TxQueryError> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            if let Some(reader) = &self.republish
                && !self.published.swap(true, Ordering::SeqCst)
                && let Some(tip) = reader.load_full()
            {
                reader.store(Some(Arc::new((*tip).clone())));
            }
            Ok(Some(self.parent.clone()))
        }
        fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }
        fn transaction_block(
            &self,
            txid: &Txid,
        ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
            Ok(self.transaction(txid)?.map(|tx| {
                (
                    tx,
                    TransactionBlock {
                        height: 0,
                        hash: Hash256::from(fixture_genesis().block_hash()),
                    },
                )
            }))
        }
        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            self.error.clone().map_or(
                Err(TxQueryError::Retry(
                    bitcoin_rs_index::RetryReason::TipMoved {
                        expected_revision: 0,
                        current_revision: 1,
                    },
                )),
                Err,
            )
        }
    }

    #[test]
    fn parent_query_errors_and_republication_never_yield_a_cached_success() {
        let block = fixture_genesis();
        let parent = block.txs[0].clone();
        let child = paying_transaction(&[OutPoint::new(parent.txid(), 0)], &[(100, vec![0x51])]);
        let mut ctx = Context::new();
        ctx.chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::from_block(
                0, &block,
            ));
        let tip = {
            let mut tree = ctx.chain.block_tree.write();
            tree.insert_node(None, block.header, NodeStatus::Active)
                .expect("tip");
            tree.tip().expect("tip")
        };
        ctx.chain.applied_tip.store(Some(tip));
        for (error, status) in [
            (
                Some(TxQueryError::Retry(
                    bitcoin_rs_index::RetryReason::TipMoved {
                        expected_revision: 0,
                        current_revision: 1,
                    },
                )),
                503,
            ),
            (
                Some(TxQueryError::Unavailable(TxUnavailableCause::Other(
                    "pruned".into(),
                ))),
                503,
            ),
            (Some(TxQueryError::Storage("corrupt".into())), 500),
        ] {
            ctx.indexes.esplora_tx_index = Some(Arc::new(FailingParentIndex {
                error,
                republish: Some(ctx.chain.applied_tip.clone()),
                published: AtomicBool::new(false),
                parent: parent.clone(),
            }));
            let response = Projection::new(&ctx)
                .transaction_values([(&child, None), (&child, None)], None)
                .expect_err("must not publish success");
            assert_eq!(response.status, status);
        }
        ctx.indexes.esplora_tx_index = Some(Arc::new(FailingParentIndex {
            error: None,
            republish: Some(ctx.chain.applied_tip.clone()),
            published: AtomicBool::new(false),
            parent: parent.clone(),
        }));
        let child_id = child.txid();
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 0, 0))
            .expect("child");
        let reader = ctx.chain.applied_tip.clone();
        let start = reader.load_full().expect("captured tip");
        let handler = Handler::new(Arc::new(ctx));
        let refused = route(&handler, &format!("/tx/{child_id}"), "");
        assert_eq!(refused.status, 503);
        assert_eq!(
            String::from_utf8_lossy(&refused.body),
            "transaction index changed during query; retry"
        );
        let moved = reader
            .load_full()
            .expect("tip after the refused parent query");
        assert!(
            !Arc::ptr_eq(&moved, &start),
            "the successful parent query must have published a fresh tip"
        );
        assert_eq!(
            moved.hash, start.hash,
            "the fresh publication repeats the same block"
        );
        assert_eq!(moved.height, start.height);
        let response = backend_route_post(
            &handler,
            "/internal/txs",
            &sonic_rs::to_vec(&[parent.txid().to_string()]).expect("request"),
        );
        assert_eq!(
            response.status, 200,
            "the batch runs on one stable publication and recomputes fresh values"
        );
        let settled = reader.load_full().expect("tip after the batch");
        assert!(
            Arc::ptr_eq(&settled, &moved),
            "the batch must observe the unchanged publication end to end"
        );
    }

    #[test]
    fn stale_block_transactions_do_not_inherit_active_chain_status() -> Result<(), TestError> {
        let transaction = transaction(
            Some(OutPoint::null()),
            TxOut {
                value: Amount::from_sat(125),
                script_pubkey: vec![0x51].into(),
            },
        );
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let stale_block = Block {
            header: Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::from(transaction.txid()),
                time: 2_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 2,
            },
            txs: vec![transaction.clone()],
        };
        let stale_record = bitcoin_rs_index::block_log::BlockRecord::from_block(1, &stale_block);
        let mut ctx = Context::new();
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(1, stale_record.hash, consensus_bytes(&stale_block))],
        }));
        ctx.chain.add_block(stale_record.clone());
        {
            let mut tree = ctx.chain.block_tree.write();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            tree.insert_node(
                Some(genesis_id),
                stale_block.header,
                NodeStatus::HeaderValid,
            )?;
            let active = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: 1_500,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 1,
            };
            tree.insert_node(Some(genesis_id), active, NodeStatus::Active)?;
            let tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing active tip"))?;
            ctx.chain.applied_tip.store(Some(Arc::new((*tip).clone())));
        }
        ctx.indexes.esplora_tx_index = Some(Arc::new(StaticTxIndex::new(transaction)));

        let response = block_txs(&ctx, &stale_record.hash.to_string(), 0);
        assert_eq!(
            response.status,
            200,
            "block_txs failed: {}",
            String::from_utf8_lossy(&response.body)
        );
        let rendered: Value = sonic_rs::from_slice(&response.body)?;
        assert_eq!(rendered[0]["status"], json!({"confirmed":false}));
        Ok(())
    }

    thread_local! {
        static MEMPOOL_SUMMARY_GATE: RefCell<Option<(Sender<()>, Receiver<()>)>> =
            const { RefCell::new(None) };
        static MEMPOOL_ACTIVITY_GATE: RefCell<Option<(Sender<()>, Receiver<()>)>> =
            const { RefCell::new(None) };
        static ROUTE_GATE: RefCell<Option<(Sender<()>, Receiver<()>)>> = const { RefCell::new(None) };
        static MEMPOOL_READ_GATE: RefCell<Option<(Sender<()>, Receiver<()>)>> =
            const { RefCell::new(None) };
    }

    const GATE_TIMEOUT: Duration = Duration::from_secs(30);

    fn arm_mempool_summary_gate(entered: Sender<()>, release: Receiver<()>) {
        MEMPOOL_SUMMARY_GATE.with(|slot| *slot.borrow_mut() = Some((entered, release)));
    }

    struct SwapperGuard {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for SwapperGuard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    pub(crate) fn gate_mempool_summary_for_tests() {
        let armed = MEMPOOL_SUMMARY_GATE.with(|slot| slot.borrow_mut().take());
        let Some((entered, release)) = armed else {
            return;
        };
        let _ = entered.send(());
        let _ = release.recv_timeout(GATE_TIMEOUT);
    }
    fn arm_mempool_activity_gate(entered: Sender<()>, release: Receiver<()>) {
        MEMPOOL_ACTIVITY_GATE.with(|slot| *slot.borrow_mut() = Some((entered, release)));
    }

    pub(crate) fn gate_mempool_activity_for_tests() {
        let armed = MEMPOOL_ACTIVITY_GATE.with(|slot| slot.borrow_mut().take());
        let Some((entered, release)) = armed else {
            return;
        };
        let _ = entered.send(());
        let _ = release.recv_timeout(GATE_TIMEOUT);
    }
    fn arm_route_gate(entered: Sender<()>, release: Receiver<()>) {
        ROUTE_GATE.with(|slot| *slot.borrow_mut() = Some((entered, release)));
    }

    pub(crate) fn gate_route_for_tests() {
        let armed = ROUTE_GATE.with(|slot| slot.borrow_mut().take());
        let Some((entered, release)) = armed else {
            return;
        };
        let _ = entered.send(());
        let _ = release.recv_timeout(GATE_TIMEOUT);
    }
    fn arm_mempool_read_gate(entered: Sender<()>, release: Receiver<()>) {
        MEMPOOL_READ_GATE.with(|slot| *slot.borrow_mut() = Some((entered, release)));
    }

    pub(crate) fn gate_pure_mempool_read_for_tests() {
        let armed = MEMPOOL_READ_GATE.with(|slot| slot.borrow_mut().take());
        let Some((entered, release)) = armed else {
            return;
        };
        let _ = entered.send(());
        let _ = release.recv_timeout(GATE_TIMEOUT);
    }

    fn paying_transaction(inputs: &[OutPoint], outputs: &[(u64, Vec<u8>)]) -> Tx {
        Tx {
            version: 2,
            inputs: inputs
                .iter()
                .copied()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: outputs
                .iter()
                .map(|(value, script)| TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: script.clone().into(),
                })
                .collect(),
            lock_time: LockTime::ZERO,
        }
    }

    fn unconfirmed_outpoint(marker: u8) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0)
    }

    #[derive(Clone)]
    struct Seed {
        transaction: Tx,
        vsize: u32,
        fee: u64,
        time: u64,
    }

    impl Seed {
        fn txid(&self) -> Txid {
            self.transaction.txid()
        }

        fn value(&self) -> u64 {
            self.transaction.outputs.iter().fold(0_u64, |sum, output| {
                sum.saturating_add(output.value.to_sat())
            })
        }
    }

    fn seed_mempool(ctx: Context, seeds: &[Seed]) -> Arc<Context> {
        for seed in seeds {
            ctx.mempool
                .gateway
                .pool()
                .write()
                .insert_entry(MempoolEntry::new(
                    Arc::new(seed.transaction.clone()),
                    seed.vsize,
                    seed.fee,
                    seed.time,
                    0,
                    0,
                ))
                .expect("seed entry admitted");
        }
        Arc::new(ctx)
    }

    #[test]
    fn mempool_projection_releases_read_guard_before_encoding() {
        let target = vec![0x51_u8];
        let seeds = [
            Seed {
                transaction: paying_transaction(
                    &[unconfirmed_outpoint(1)],
                    &[(1_000, target.clone())],
                ),
                vsize: 100,
                fee: 1_000,
                time: 1,
            },
            Seed {
                transaction: paying_transaction(
                    &[unconfirmed_outpoint(2)],
                    &[(1_000, target.clone())],
                ),
                vsize: 100,
                fee: 2_000,
                time: 2,
            },
            Seed {
                transaction: paying_transaction(&[unconfirmed_outpoint(3)], &[(1_000, target)]),
                vsize: 200,
                fee: 2_000,
                time: 3,
            },
        ];
        let ctx = seed_mempool(Context::new(), &seeds);
        let serving_ctx = Arc::clone(&ctx);
        let (entered_send, entered_recv) = channel();
        let (release_send, release_recv) = channel();
        let request = std::thread::spawn(move || {
            arm_mempool_summary_gate(entered_send, release_recv);
            let handler = Handler::new(serving_ctx);
            route(&handler, "/mempool", "")
        });

        let reached_encoding = entered_recv.recv_timeout(GATE_TIMEOUT).is_ok();
        let writer_progress = ctx.mempool.gateway.pool().try_write().is_some();
        let _ = release_send.send(());
        let response = request.join().expect("gated request completes");

        assert!(
            reached_encoding,
            "the request thread never reached summary encoding"
        );
        assert!(
            writer_progress,
            "the summary held the pool read guard during JSON encoding"
        );
        assert_eq!(response.status, 200);
        let rendered: Value = sonic_rs::from_slice(&response.body).expect("summary json");
        assert_eq!(
            rendered,
            json!({
                "count": 3,
                "vsize": 400,
                "total_fee": 5_000,
                "fee_histogram": [[20.0, 100_u64], [10.0, 300_u64]],
            })
        );
    }

    struct ParityFixture {
        ctx: Arc<Context>,
        handler: Handler,
        target: Vec<u8>,
        seeds: Vec<Seed>,
        script_hash: String,
    }

    fn parity_fixture() -> ParityFixture {
        const TOP: u64 = 1_700_000_050;
        let target = vec![0x51_u8];
        let unrelated = vec![0x52_u8];
        let funder = paying_transaction(
            &[unconfirmed_outpoint(1)],
            &[
                (1_000, target.clone()),
                (2_000, target.clone()),
                (3_000, unrelated.clone()),
            ],
        );
        let spender =
            paying_transaction(&[OutPoint::new(funder.txid(), 0)], &[(900, target.clone())]);
        let mut seeds = vec![
            Seed {
                transaction: funder,
                vsize: 100,
                fee: 1_000,
                time: TOP,
            },
            Seed {
                transaction: spender,
                vsize: 100,
                fee: 1_000,
                time: TOP,
            },
        ];
        for index in 0..10_u8 {
            let vsize = 100 + u32::from(index) * 10;
            seeds.push(Seed {
                transaction: paying_transaction(
                    &[unconfirmed_outpoint(10 + index)],
                    &[(500, unrelated.clone())],
                ),
                vsize,
                fee: u64::from(vsize) * if index < 4 { 10 } else { 5 },
                time: TOP - u64::from(index / 2),
            });
        }
        let mut ctx = Context::new();
        ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
            history: Vec::new(),
            funding: Vec::new(),
            unspent: Vec::new(),
        }));
        let ctx = seed_mempool(ctx, &seeds);
        let handler = Handler::new(Arc::clone(&ctx));
        let script_hash = ScriptHash::new(&target)
            .to_byte_array()
            .to_lower_hex_string();
        ParityFixture {
            ctx,
            handler,
            target,
            seeds,
            script_hash,
        }
    }

    fn routed_bytes(fixture: &ParityFixture, path: &str) -> Vec<u8> {
        let public = route(&fixture.handler, path, "");
        let backend = backend_route(&fixture.handler, path, "");
        assert_eq!(
            public.status,
            200,
            "{path}: {}",
            String::from_utf8_lossy(&public.body)
        );
        assert_eq!(backend.status, 200, "{path}");
        assert_eq!(public.content_type, "application/json", "{path}");
        assert_eq!(
            public.body, backend.body,
            "{path} differs between /api and /esplora"
        );
        public.body
    }

    fn descending_recent(seeds: &[Seed]) -> Vec<usize> {
        let mut order = (0..seeds.len()).collect::<Vec<_>>();
        order.sort_by(|left, right| {
            let (left, right) = (&seeds[*left], &seeds[*right]);
            right
                .time
                .cmp(&left.time)
                .then_with(|| right.txid().cmp(&left.txid()))
        });
        order
    }

    #[test]
    fn esplora_mempool_summary_recent_and_txids_match_the_seeded_pool() -> Result<(), TestError> {
        let fixture = parity_fixture();
        let mut bins = std::collections::BTreeMap::new();
        for seed in &fixture.seeds {
            let rate = seed.fee.saturating_mul(1_000) / u64::from(seed.vsize);
            *bins.entry(rate).or_insert(0_u64) += u64::from(seed.vsize);
        }
        let summary: Value = sonic_rs::from_slice(&routed_bytes(&fixture, "/mempool"))?;
        assert_eq!(
            summary,
            json!({
                "count": fixture.seeds.len(),
                "vsize": fixture
                    .seeds
                    .iter()
                    .map(|seed| u64::from(seed.vsize))
                    .sum::<u64>(),
                "total_fee": fixture.seeds.iter().map(|seed| seed.fee).sum::<u64>(),
                "fee_histogram": bins
                    .iter()
                    .rev()
                    .map(|(rate, size)| {
                        let rate = u32::try_from(*rate).expect("fixture fee rate fits u32");
                        json!([f64::from(rate) / 1000.0, size])
                    })
                    .collect::<Vec<Value>>(),
            })
        );

        let recent: Vec<Value> = sonic_rs::from_slice(&routed_bytes(&fixture, "/mempool/recent"))?;
        assert_eq!(
            recent,
            descending_recent(&fixture.seeds)
                .iter()
                .take(10)
                .map(|index| {
                    let seed = &fixture.seeds[*index];
                    json!({
                        "txid": seed.txid().to_string(),
                        "fee": seed.fee,
                        "vsize": seed.vsize,
                        "value": seed.value(),
                    })
                })
                .collect::<Vec<Value>>()
        );

        let mut listed: Vec<String> =
            sonic_rs::from_slice(&routed_bytes(&fixture, "/mempool/txids"))?;
        listed.sort();
        let mut expected = fixture
            .seeds
            .iter()
            .map(|seed| seed.txid().to_string())
            .collect::<Vec<String>>();
        expected.sort();
        assert_eq!(listed, expected);
        Ok(())
    }

    #[test]
    fn esplora_script_overlay_and_activity_match_the_seeded_pool() -> Result<(), TestError> {
        let fixture = parity_fixture();
        let unconfirmed = json!({ "confirmed": false });
        let utxos: Value = sonic_rs::from_slice(&routed_bytes(
            &fixture,
            &format!("/scripthash/{}/utxo", fixture.script_hash),
        ))?;
        assert_eq!(
            utxos,
            json!([
                {
                    "txid": fixture.seeds[0].txid().to_string(),
                    "vout": 1,
                    "status": unconfirmed,
                    "value": 2_000,
                },
                {
                    "txid": fixture.seeds[1].txid().to_string(),
                    "vout": 0,
                    "status": unconfirmed,
                    "value": 900,
                },
            ])
        );

        let activity = Projection::new(&fixture.ctx)
            .script_activity(ScriptHash::new(&fixture.target))
            .expect("script activity resolves");
        assert_eq!(
            activity
                .mempool
                .iter()
                .map(|transaction| transaction.txid())
                .collect::<Vec<Txid>>(),
            descending_recent(&fixture.seeds)
                .iter()
                .filter(|index| **index < 2)
                .map(|index| fixture.seeds[*index].txid())
                .collect::<Vec<Txid>>()
        );
        Ok(())
    }

    #[test]
    fn exhausted_block_render_budget_refuses_esplora_block_reads() -> Result<(), TestError> {
        let (handler, tx, block, _address) = contract_fixture()?;
        let block_hash = block.block_hash().to_string();
        let txid = tx.txid().to_string();
        let ctx = handler.context();
        let _first = ctx.try_acquire_block_render().expect("first permit");
        let _second = ctx.try_acquire_block_render().expect("second permit");
        assert!(ctx.try_acquire_block_render().is_none());

        let refused_paths = [
            format!("/block/{block_hash}"),
            format!("/block/{block_hash}/raw"),
            format!("/block/{block_hash}/txs"),
            format!("/block/{block_hash}/txs/0"),
            format!("/block/{block_hash}/txids"),
            format!("/block/{block_hash}/txid/0"),
            "/blocks".to_owned(),
            "/blocks/0".to_owned(),
            format!("/tx/{txid}/merkleblock-proof"),
            format!("/tx/{txid}/merkle-proof"),
        ];
        for path in &refused_paths {
            let response = route(&handler, path, "");
            assert_eq!(response.status, 503, "{path}");
            assert_eq!(
                response.body, b"too many concurrent full-block reads; retry",
                "{path}"
            );
        }

        let internal_path = format!("/internal/block/{block_hash}/txs");
        let backend_response = backend_route(&handler, &internal_path, "");
        assert_eq!(backend_response.status, 503, "{internal_path}");
        assert_eq!(
            backend_response.body, b"too many concurrent full-block reads; retry",
            "{internal_path}"
        );

        let permitted_paths = [
            format!("/block/{block_hash}/header"),
            format!("/block/{block_hash}/status"),
            "/blocks/tip/height".to_owned(),
            "/blocks/tip/hash".to_owned(),
            "/block-height/0".to_owned(),
            format!("/tx/{txid}"),
            format!("/tx/{txid}/status"),
        ];
        for path in &permitted_paths {
            let response = route(&handler, path, "");
            assert_eq!(response.status, 200, "{path}");
        }

        Ok(())
    }
}
