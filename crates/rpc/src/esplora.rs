//! Esplora HTTP projections over confirmed indexes and the live mempool.
#![expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::needless_borrow,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::significant_drop_in_scrutinee
)]

mod backend;
mod http;
mod model;
mod projection;
mod public;

use crate::context::Context;
use crate::handlers::Handler;
use crate::rest::Response;

use self::projection::Projection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Surface {
    Public,
    Backend,
}

/// `path` is the rest after `/api` or `/esplora`. The listener demux owns
/// prefix matching; this function only dispatches inside a directory.
#[must_use]
pub fn route(handler: &Handler, surface: Surface, path: &str, query: &str) -> Response {
    let ctx = handler.context();
    let projection = Projection::new(&ctx);
    let chain_view = projection.capture_chain_view();
    let response = dispatch_get(handler, &ctx, surface, path, query);
    match projection.ensure_chain_view(chain_view.as_ref()) {
        Ok(()) => response,
        Err(response) => response,
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

/// `path` is the rest after `/api` or `/esplora`. Unknown paths 404.
#[must_use]
pub(crate) fn route_post(handler: &Handler, surface: Surface, path: &str, body: &[u8]) -> Response {
    if surface == Surface::Backend {
        let ctx = handler.context();
        let projection = Projection::new(&ctx);
        let chain_view = projection.capture_chain_view();
        if let Some(response) = backend::post(handler, path, body) {
            return match projection.ensure_chain_view(chain_view.as_ref()) {
                Ok(()) => response,
                Err(response) => response,
            };
        }
    }
    public::post(handler, path, body)
}

/// `/api/v1` is not an alias: that prefix is Mempool's own API on the
/// explorer port, so `/api/v1/block-height/{h}` is `/v1/block-height/{h}`
/// here and 404s.
#[must_use]
pub fn namespace(path: &str) -> Option<(Surface, &str)> {
    strip_dir(path, "/api")
        .map(|rest| (Surface::Public, rest))
        .or_else(|| strip_dir(path, "/esplora").map(|rest| (Surface::Backend, rest)))
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
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::time::Duration;

    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_chain::{NodeStatus, regtest_fixture::merkle_root};
    use bitcoin_rs_index::ScriptHash;
    use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry, MempoolObserver, MutationEnvelope};
    use bitcoin_rs_primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};

    use super::projection::Projection;
    use super::public::{
        CHAIN_PAGE, address_transaction_summary, block_txs, fee_rate_sat_per_vbyte, history,
        outspend, summary,
    };
    use crate::context::{
        Context, ScriptHistoryRecord, ScriptIndexRecord, TxQueryError, TxUnavailableCause,
    };
    use crate::handlers::Handler;
    use crate::rest::Response;

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

    fn transaction_with_funded_input(ctx: &Context, input_value: u64) -> (Tx, Tx) {
        let spendable = vec![0x51];
        let script = [vec![0x00, 0x14], vec![0x11; 20]].concat();
        let funding = transaction(
            None,
            TxOut {
                value: Amount::from_sat(input_value),
                script_pubkey: spendable.clone().into(),
            },
        );
        let txid = funding.txid();
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(txid, 0),
            TxOut {
                value: Amount::from_sat(input_value),
                script_pubkey: spendable.into(),
            },
            false,
            1,
        ));
        bitcoin_rs_utxo::contract::commit_block_changes(
            &ctx.chain.utxo.fixture_set(),
            &changes,
            &Hash256::from_le_bytes(&[0xaa; 32]),
        )
        .expect("fund test UTXO");
        (
            transaction(
                Some(OutPoint::new(txid, 0)),
                TxOut {
                    value: Amount::from_sat(input_value - 1_000),
                    script_pubkey: script.into(),
                },
            ),
            funding,
        )
    }

    struct StaticTxIndex {
        transaction: Tx,
        height: Option<u32>,
    }

    impl StaticTxIndex {
        fn new(transaction: Tx) -> Self {
            Self {
                transaction,
                height: None,
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

        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            Ok((self.transaction.txid() == *txid)
                .then_some(self.height)
                .flatten())
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }
    }

    struct CountingTxIndex {
        transactions: Vec<Tx>,
        calls: Arc<AtomicUsize>,
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

        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            Ok(self
                .transactions
                .iter()
                .any(|tx| tx.txid() == *txid)
                .then_some(0))
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }
    }

    struct FixtureTxIndex(Vec<(Tx, u32)>);

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

        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            Ok(self
                .0
                .iter()
                .find(|(transaction, _)| transaction.txid() == *txid)
                .map(|(_, height)| *height))
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: self.0.iter().map(|(_, height)| *height).max().unwrap_or(0),
            })
        }
    }

    struct StaticScriptIndex {
        history: Vec<ScriptHistoryRecord>,
        funding: Vec<ScriptIndexRecord>,
        unspent: Vec<ScriptIndexRecord>,
    }

    struct CountingScriptIndex {
        history_calls: Arc<AtomicUsize>,
        unspent_calls: Arc<AtomicUsize>,
        spender_calls: Arc<AtomicUsize>,
    }

    impl crate::context::ScriptIndexQuery for CountingScriptIndex {
        fn unspent_outputs(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            self.unspent_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        }

        fn history_snapshot(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<crate::context::ScriptIndexSnapshot, TxQueryError> {
            self.history_calls.fetch_add(1, Ordering::Relaxed);
            Ok(crate::context::ScriptIndexSnapshot::default())
        }

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            self.spender_calls.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
    }

    struct RepublishTipScriptIndex {
        applied_tip: bitcoin_rs_chain::TipReader,
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
            if let Some(tip) = self.applied_tip.load_full() {
                self.applied_tip.store(Some(Arc::new((*tip).clone())));
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

    fn contract_fixture() -> Result<(Handler, Tx, Block, String), Box<dyn std::error::Error>> {
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
        context.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
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
        context.indexes.esplora_tx_index =
            Some(Arc::new(FixtureTxIndex(vec![(transaction.clone(), 0)])));
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
    #[expect(clippy::too_many_lines)]
    fn bitcoin_esplora_surface_matches_documented_routes_and_content_types()
    -> Result<(), Box<dyn std::error::Error>> {
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
    #[expect(clippy::too_many_lines)]
    fn bitcoin_esplora_representations_match_the_documented_schemas()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn esplora_lives_only_under_the_api_prefix() -> Result<(), Box<dyn std::error::Error>> {
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
    fn api_is_the_public_electrs_directory() -> Result<(), Box<dyn std::error::Error>> {
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
    fn esplora_is_the_mempool_backend_superset() -> Result<(), Box<dyn std::error::Error>> {
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

    #[test]
    fn composed_response_retries_when_the_applied_tip_identity_changes() {
        let block = fixture_genesis();
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
        context.indexes.script_index = Some(Arc::new(RepublishTipScriptIndex {
            applied_tip: context.chain.applied_tip.clone(),
        }));
        let handler = Handler::new(Arc::new(context));

        for suffix in ["", "/txs/chain/not-a-txid"] {
            let response = route(
                &handler,
                &format!("/scripthash/{0}{suffix}", "00".repeat(32)),
                "",
            );
            assert_eq!(response.status, 503);
        }
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn block_status_and_block_list_never_straddle_two_applied_branches()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
        use bitcoin_rs_primitives::Header;

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
        context.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
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
                    chainwork: bitcoin_rs_chain::ChainWork::ZERO,
                    hash: a1_hash.0,
                    chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
                }),
                Arc::new(TipSnapshot {
                    tip_id: b2_id,
                    height: 2,
                    chainwork: bitcoin_rs_chain::ChainWork::ZERO,
                    hash: b2_hash.0,
                    chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
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

    #[test]
    fn mempool_backend_extension_surface_uses_the_same_projections()
    -> Result<(), Box<dyn std::error::Error>> {
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

    /// API-10: both directories identify Esplora at the existing publication
    /// boundary; successful retries publish no second acceptance.
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

    /// The HTTP rejection dialect and lack of publication are observable
    /// contracts, including malformed input and a missing UTXO.
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
            for (body, reason) in [
                (b"\xff".as_slice(), "transaction body must be UTF-8 hex"),
                (
                    b"zz".as_slice(),
                    "TX decode failed. Make sure the tx has at least one input.",
                ),
                (
                    b"00".as_slice(),
                    "TX decode failed. Make sure the tx has at least one input.",
                ),
                (missing.as_bytes(), "bad-txns-inputs-missingorspent"),
                (duplicate.as_bytes(), "consensus-verification-failed"),
            ] {
                let response = dispatch_post(&handler, path, body);
                assert_eq!(response.status, 400, "{path}");
                assert_eq!(response.content_type, "text/plain");
                assert_eq!(response.body, reason.as_bytes());
            }
            assert!(ctx.mempool.gateway.read().is_empty());
            assert_eq!(ctx.mempool.gateway.read().sequence_number(), sequence);
            assert!(observer.0.lock().is_empty());
        }
    }

    /// The 0.1 BTC/kvB HTTP cap is fixed. RPC's zero override still opts
    /// out only for that RPC call, and the observer receives its RPC origin.
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

    /// Independent rust-bitcoin decoding supplies the wire vsize; this
    /// fixture has no sigops, so that is also its policy vsize.
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

    #[test]
    fn history_cursors_follow_api_09_on_both_esplora_surfaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let (handler, transaction, _, address) = contract_fixture()?;
        let txid = transaction.txid().to_string();
        let script_hash = ScriptHash::new(&transaction.outputs[0].script_pubkey)
            .to_byte_array()
            .to_lower_hex_string();
        let mut unavailable = Context::new();
        unavailable.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
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
        let mempool = history(&ctx, ScriptHash::new(&target), Some(""), false);
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
        let chain = history(&ctx, ScriptHash::new(&target), Some("not-a-txid"), false);
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
            transactions,
            calls: Arc::clone(&calls),
        }));

        let response = history(&ctx, ScriptHash::new(&target), None, false);
        assert_eq!(response.status, 200);
        let values: Value = sonic_rs::from_slice(&response.body).expect("history response json");
        assert_eq!(values.as_array().map(|array| array.len()), Some(CHAIN_PAGE));
        assert_eq!(calls.load(Ordering::Relaxed), CHAIN_PAGE);

        let cursor = records[5].txid.to_string();
        let second = history(&ctx, ScriptHash::new(&target), Some(&cursor), false);
        assert_eq!(second.status, 200);
        let second: Value = sonic_rs::from_slice(&second.body).expect("second page json");
        assert_eq!(second.as_array().map(|array| array.len()), Some(5));
        assert_eq!(second[0]["txid"], records[4].txid.to_string());
        assert_eq!(second[4]["txid"], records[0].txid.to_string());
        assert_eq!(calls.load(Ordering::Relaxed), 30);
        let end = history(
            &ctx,
            ScriptHash::new(&target),
            Some(&records[0].txid.to_string()),
            false,
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
        let first = history(&ctx, ScriptHash::new(&target), None, false);
        calls.store(0, Ordering::Relaxed);
        let restarted = history(&ctx, ScriptHash::new(&target), Some(&cursor), false);
        assert_eq!(restarted.status, 200);
        assert_eq!(restarted.body, first.body);
        assert_eq!(calls.load(Ordering::Relaxed), CHAIN_PAGE);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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

        let chain_resp = history(&ctx, script_hash, None, false);
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
        let chain_page2 = history(&ctx, script_hash, Some(&cursor), false);
        assert_eq!(chain_page2.status, 200);
        assert_eq!(
            unspent_calls.load(Ordering::Relaxed),
            0,
            "chain page 2 must not enumerate ScriptLive"
        );

        let mempool_resp = history(&ctx, script_hash, Some(""), false);
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
    #[allow(clippy::too_many_lines)]
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
            transactions,
            calls: Arc::clone(&calls),
        }));

        let page1 = history(&ctx, script_hash, None, false);
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

        let page2 = history(&ctx, script_hash, Some(&cursor1), false);
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

        let page3 = history(&ctx, script_hash, Some(&cursor2), false);
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

        let page4 = history(&ctx, script_hash, Some(&cursor3), false);
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
            let restarted = history(&ctx, script_hash, Some(&invalid_cursor), false);
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
            transactions: vec![tx],
            calls: Arc::new(AtomicUsize::new(0)),
        }));

        let response = history(&ctx, script_hash, None, false);
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
            pool.remove_for_block(&[funder.as_ref()], &[funder_txid], 42, 1);
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
    fn utxo_and_outspend_use_their_dedicated_index_queries() {
        let history_calls = Arc::new(AtomicUsize::new(0));
        let unspent_calls = Arc::new(AtomicUsize::new(0));
        let spender_calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        ctx.indexes.script_index = Some(Arc::new(CountingScriptIndex {
            history_calls: Arc::clone(&history_calls),
            unspent_calls: Arc::clone(&unspent_calls),
            spender_calls: Arc::clone(&spender_calls),
        }));
        let projection = Projection::new(&ctx);
        let script_hash = ScriptHash::from_script_bytes(&[]);

        assert!(
            projection
                .script_utxos(script_hash)
                .expect("UTXO query")
                .is_empty()
        );
        assert!(
            !outspend(&projection, OutPoint::null())
                .expect("outspend query")
                .spent
        );
        assert_eq!(unspent_calls.load(Ordering::Relaxed), 1);
        assert_eq!(spender_calls.load(Ordering::Relaxed), 1);
        assert_eq!(history_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn transaction_projection_uses_internal_lookup_for_prevout_and_fee() {
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

        let rendered = Projection::new(&ctx)
            .transaction_values([(&child, None)], None)
            .expect("prevout indexed");
        let rendered = &rendered[0];
        assert_eq!(rendered.fee, 25);
        assert_eq!(
            rendered.vin[0]
                .prevout
                .as_ref()
                .expect("rendered prevout")
                .value,
            125
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "first, later, mixed and missing pages share one history fixture"
    )]
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
            let response = history(&ctx, ScriptHash::new(&[0x51]), cursor.as_deref(), false);
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
        let mixed = history(&ctx, ScriptHash::new(&[0x51]), None, true);
        assert_eq!(mixed.status, 200);
        let mixed: Vec<Value> = sonic_rs::from_slice(&mixed.body).expect("mixed page");
        assert_eq!(mixed.len(), CHAIN_PAGE + 1);
        assert_eq!(mixed[0]["txid"], unconfirmed.txid().to_string());
        assert_eq!(mixed[0]["status"]["confirmed"], false);
        assert_eq!(mixed[0]["fee"], 50);
        assert_eq!(calls.load(Ordering::Relaxed), CHAIN_PAGE + 1);
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            transactions,
            calls,
        }));
        assert_eq!(
            history(&ctx, ScriptHash::new(&[0x51]), None, false).status,
            503
        );
    }

    #[test]
    fn batch_reuses_selected_transactions_and_mempool_parents() {
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
            ))
            .expect("parent");
        let projection = Projection::new(&ctx);
        let values = projection
            .transaction_values([(&child, None), (&child, None)], None)
            .expect("mempool prevouts");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].fee, 50);
        assert_eq!(
            values[0].vin[0].prevout.as_ref().expect("vout 0").value,
            125
        );
        assert_eq!(
            values[0].vin[1].prevout.as_ref().expect("vout 1").value,
            175
        );
        assert!(!values[0].status.confirmed);
        assert_eq!(
            sonic_rs::to_value(&values[0]).expect("first"),
            sonic_rs::to_value(&values[1]).expect("duplicate")
        );
        let ctx = Context::new();
        let values = Projection::new(&ctx)
            .transaction_values([(&child, None), (&parent, None)], None)
            .expect("selected parent");
        assert_eq!(values[0].fee, 50);
        assert_eq!(
            values[0].vin[0].prevout.as_ref().expect("vout 0").value,
            125
        );
        assert_eq!(
            values[0].vin[1].prevout.as_ref().expect("vout 1").value,
            175
        );
        assert_eq!(values[1].txid, parent.txid().to_string());
        let missing = paying_transaction(&[OutPoint::new(parent.txid(), 2)], &[(1, vec![0x51])]);
        let response = Projection::new(&ctx)
            .transaction_values([(&missing, None), (&parent, None)], None)
            .expect_err("missing output");
        assert_eq!(response.status, 503);
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
            transactions: vec![],
            calls,
        }));
        let response = super::public::block_transaction_values(&ctx, &stale_record, &block, 1, 1)
            .expect_err("stale body cannot supply parents");
        assert_eq!(response.status, 503);
        for (error, status) in [
            (TxQueryError::Retry, 503),
            (TxQueryError::Storage("corrupt".into()), 500),
        ] {
            ctx.indexes.esplora_tx_index = Some(Arc::new(FailingParentIndex {
                error: Some(error),
                republish: None,
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
        use bitcoin_rs_primitives::encode::double_sha256;
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
        ctx.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
        ctx.chain.add_block(record.clone());
        let tip = {
            let mut tree = ctx.chain.block_tree.write();
            tree.insert_node(None, block.header, NodeStatus::Active)
                .expect("header");
            tree.tip().expect("tip")
        };
        ctx.chain.applied_tip.store(Some(tip));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
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
            (bitcoin_rs_primitives::Network::Mainnet, true),
            (bitcoin_rs_primitives::Network::Regtest, false),
        ] {
            ctx.chain.chain_network = network;
            assert_eq!(
                Projection::new(&ctx)
                    .required_block(&record.hash.to_string())
                    .is_ok(),
                expected
            );
        }
    }

    #[test]
    fn block_parent_reuse_checks_readiness_only_when_needed() {
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
                    Err(TxQueryError::Retry)
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
        let values = Projection::new(&ctx)
            .transaction_values(
                [(&child, None)],
                Some(super::projection::ParentSource::Block(
                    std::slice::from_ref(&child),
                )),
            )
            .expect("external parent");
        assert_eq!(values[0].fee, 25);
        assert_eq!(checks.load(Ordering::Relaxed), 0);
        let values = Projection::new(&ctx)
            .transaction_values(
                [(&child, None), (&child, None)],
                Some(super::projection::ParentSource::Block(
                    std::slice::from_ref(&parent),
                )),
            )
            .expect("in-block parent");
        assert_eq!(values[0].fee, 25);
        assert_eq!(values[1].fee, 25);
        assert_eq!(checks.load(Ordering::Relaxed), 1);
        ctx.indexes.esplora_tx_index = Some(Arc::new(ReadinessIndex {
            parent: parent.clone(),
            checks: Arc::clone(&checks),
            synced: false,
        }));
        let error = Projection::new(&ctx)
            .transaction_values(
                [(&child, None)],
                Some(super::projection::ParentSource::Block(
                    std::slice::from_ref(&parent),
                )),
            )
            .expect_err("index behind tip");
        assert_eq!(error.status, 503);
    }

    #[test]
    fn backend_mempool_get_bounds_prevouts_without_limiting_rows() {
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
        let cursor = format!("/internal/mempool/txs/{}", txs[24].txid());
        for (path, query, start, count, reads) in [
            ("/internal/mempool/txs", "", 0, 57, 3),
            ("/internal/mempool/txs", "max_txs=26", 0, 26, 2),
            (cursor.as_str(), "", 25, 32, 2),
            (cursor.as_str(), "max_txs=25", 25, 25, 1),
            ("/internal/mempool/txs", "max_txs=0", 0, 0, 0),
        ] {
            calls.store(0, Ordering::Relaxed);
            let response = backend_route(&handler, path, query);
            assert_eq!(response.status, 200);
            let rows: Vec<Value> = sonic_rs::from_slice(&response.body).expect("rows");
            assert_eq!(rows.len(), count);
            for (row, tx) in rows.iter().zip(txs.iter().skip(start)) {
                assert_eq!(row["txid"], tx.txid().to_string());
                assert_eq!(row["fee"], 50);
                assert_eq!(row["vin"][0]["prevout"]["value"], 125);
                assert_eq!(row["vin"][1]["prevout"]["value"], 175);
                assert_eq!(row["status"]["confirmed"], false);
            }
            assert_eq!(calls.load(Ordering::Relaxed), reads);
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
            backend_route(&handler, "/internal/mempool/txs", "").status,
            503
        );
        assert_eq!(
            backend_route(&handler, "/internal/mempool/txs", "max_txs=57").status,
            200
        );
    }

    #[test]
    fn backend_mempool_get_keeps_captured_parents_across_batches() {
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
            fn transaction_height(&self, _: &Txid) -> Result<Option<u32>, TxQueryError> {
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
        txs.extend((2..26).map(|n| paying_transaction(&[OutPoint::null()], &[(n, vec![0x51])])));
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
        assert_eq!(rows[26]["vin"][0]["prevout"]["value"], 300);
        assert_eq!(rows[26]["fee"], 50);
        assert!(!ctx.mempool.gateway.read().contains_txid(&parent.txid()));
        assert!(!ctx.mempool.gateway.read().contains_txid(&child.txid()));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn backend_transaction_batches_share_duplicate_bodies_and_preserve_rows() {
        let mut first = paying_transaction(&[OutPoint::null()], &[(125, vec![0x51])]);
        first.inputs[0].witness = vec![vec![0x42; 1024]].into();
        let second = paying_transaction(&[OutPoint::null()], &[(175, vec![0x52])]);
        let missing = Txid::default();
        let ids = [first.txid(), missing, second.txid(), first.txid()].repeat(30);
        let body = sonic_rs::to_vec(&ids.iter().map(ToString::to_string).collect::<Vec<_>>())
            .expect("request");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        ctx.chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
                0,
                BlockHash::default(),
            ));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            transactions: vec![first.clone(), second.clone()],
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
        assert!(
            calls.load(Ordering::Relaxed) < ids.len() / 2,
            "duplicate IDs must share body resolution within bounded batches"
        );
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
        assert_eq!(mempool.len(), rows.len());
        for (mut row, expected) in mempool.into_iter().zip(rows) {
            assert_eq!(row["status"]["confirmed"], false);
            row["status"] = expected["status"].clone();
            assert_eq!(row, expected);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    struct FailingParentIndex {
        error: Option<TxQueryError>,
        republish: Option<bitcoin_rs_chain::TipReader>,
        parent: Tx,
    }

    impl crate::context::DerivedIndexQuery for FailingParentIndex {
        fn transaction(&self, _: &Txid) -> Result<Option<Tx>, TxQueryError> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            if let Some(reader) = &self.republish {
                if let Some(tip) = reader.load_full() {
                    reader.store(Some(Arc::new((*tip).clone())));
                }
            }
            Ok(Some(self.parent.clone()))
        }
        fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }
        fn transaction_height(&self, _: &Txid) -> Result<Option<u32>, TxQueryError> {
            Ok(Some(0))
        }
        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            self.error.clone().map_or(Err(TxQueryError::Retry), Err)
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
            (Some(TxQueryError::Retry), 503),
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
            parent: parent.clone(),
        }));
        let child_id = child.txid();
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 0, 0))
            .expect("child");
        let handler = Handler::new(Arc::new(ctx));
        assert_eq!(route(&handler, &format!("/tx/{child_id}"), "").status, 503);
        let response = backend_route_post(
            &handler,
            "/internal/txs",
            &sonic_rs::to_vec(&[parent.txid().to_string()]).expect("request"),
        );
        assert_eq!(response.status, 503);
    }

    #[test]
    fn stale_block_transactions_do_not_inherit_active_chain_status()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn esplora_mempool_summary_recent_and_txids_match_the_seeded_pool()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn esplora_script_overlay_and_activity_match_the_seeded_pool()
    -> Result<(), Box<dyn std::error::Error>> {
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
}
