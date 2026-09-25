//! Esplora HTTP projections over confirmed indexes and the live mempool.
#![allow(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::significant_drop_in_scrutinee,
    clippy::unnecessary_semicolon
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

/// Which Esplora directory a request landed in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Surface {
    /// Wallet and explorer electrs tree at `/api`. No mempool-backend helpers.
    Public,
    /// Electrs plus mempool-backend `/internal` and `/block-template` at `/esplora`.
    Backend,
}

/// Routes a read-only Esplora request already classified onto a surface.
///
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
    public::get(handler, ctx, path, query)
}

/// Routes Esplora raw-transaction broadcast and mempool-backend POSTs.
///
/// `path` is the rest after `/api` or `/esplora`. Unknown paths 404.
/// The listener demux never calls this outside those directories.
#[must_use]
pub(crate) fn route_post(handler: &Handler, surface: Surface, path: &str, body: &[u8]) -> Response {
    if surface == Surface::Backend {
        if let Some(response) = backend::post(handler, path, body) {
            return response;
        }
    }
    public::post(handler, path, body)
}

/// See `docs/contracts/wallet-facing.md` WF-02.
///
/// `/api` is the public electrs directory. `/esplora` is the mempool-backend
/// electrs tree (public routes plus `/internal` and `/block-template`).
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
#[allow(clippy::expect_used)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::cell::RefCell;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::time::Duration;

    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_index::ScriptHash;
    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::encode::double_sha256;
    use bitcoin_rs_primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use serde_json::{Value, json};

    use super::projection::Projection;
    use super::public::{
        CHAIN_PAGE, address_transaction_summary, block_txs, fee_rate_sat_per_vbyte, history,
        outspend, summary,
    };
    use crate::context::{Context, ScriptHistoryRecord, ScriptIndexRecord, TxQueryError};
    use crate::handlers::Handler;
    use crate::rest::Response;

    /// Canonical public Esplora lives at `/api`. Tests that omit the prefix
    /// are naming that surface, not a second listener root.
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

    struct SingleBlockSource {
        height: u32,
        hash: BlockHash,
        body: Vec<u8>,
    }

    impl bitcoin_rs_chain::BlockBodySource for SingleBlockSource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            (height == self.height && hash == self.hash).then(|| self.body.clone())
        }
    }

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

    /// Core's null outpoint: zero txid, `u32::MAX` vout.
    fn null_outpoint() -> OutPoint {
        OutPoint::new(Txid::default(), u32::MAX)
    }

    /// Folds txids into the block merkle root the consensus encoder builds,
    /// so fixture blocks carry self-consistent identity.
    fn fixture_merkle_root(txids: &[Txid]) -> Hash256 {
        if let [single] = txids {
            return single.0;
        }
        let next = txids
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&pair[0]);
                let mut bytes = [0_u8; 64];
                bytes[..32].copy_from_slice(pair[0].as_bytes());
                bytes[32..].copy_from_slice(right.as_bytes());
                Txid(double_sha256(&bytes))
            })
            .collect::<Vec<_>>();
        fixture_merkle_root(&next)
    }

    /// A native one-transaction block standing in for the network genesis the
    /// fixtures previously pulled from the rust-bitcoin crate.
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
                Some(null_outpoint()),
                TxOut {
                    value: Amount::from_sat(5_000_000_000),
                    script_pubkey: vec![0x51].into(),
                },
            )],
        };
        block.header.merkle_root = fixture_merkle_root(&block.txids());
        block
    }

    fn transaction_with_funded_input(ctx: &Context) -> Tx {
        // OP_TRUE: an anyone-can-spend funding script, so the broadcast
        // fixture's empty scriptSig satisfies script verification. The output
        // stays P2WPKH: standardness only allows known output templates.
        let spendable = vec![0x51];
        let script = [vec![0x00, 0x14], vec![0x11; 20]].concat();
        let funding = transaction(
            None,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: spendable.clone().into(),
            },
        );
        let txid = ctx.chain.add_transaction(funding);
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(txid, 0),
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: spendable.into(),
            },
            false,
            1,
        ));
        ctx.chain
            .utxo
            .commit_block(&changes, &Hash256::from_le_bytes(&[0xaa; 32]))
            .expect("fund test UTXO");
        transaction(
            Some(OutPoint::new(txid, 0)),
            TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: script.into(),
            },
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
        applied_tip: Arc<arc_swap::ArcSwapOption<bitcoin_rs_chain::TipSnapshot>>,
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

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            Ok(None)
        }
    }

    fn contract_fixture() -> Result<(Handler, Tx, Block, String), Box<dyn std::error::Error>> {
        // p2wpkh scriptPubKey for key hash [2; 20]; the address string rides
        // the sanctioned rust-bitcoin Address seam.
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
            previous_output: null_outpoint(),
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
        block.header.merkle_root = fixture_merkle_root(&block.txids());
        let record = bitcoin_rs_index::block_log::BlockRecord::from_block(0, &block);
        let txid = transaction.txid();
        let mut context = Context::new();
        context.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
        context.chain.block_body_source = Some(Arc::new(SingleBlockSource {
            height: 0,
            hash: record.hash,
            body: consensus_bytes(&block),
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
        context.chain.set_applied_tip(tip);
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
            fee_rate_sat_per_vbyte(0.000_01).to_bits(),
            1.0_f64.to_bits()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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

        let broadcast_transaction = transaction_with_funded_input(handler.context().as_ref());
        let raw = consensus_bytes(&broadcast_transaction).to_lower_hex_string();
        let broadcast = route_post(&handler, "/tx", raw.as_bytes());
        assert_eq!(
            broadcast.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&broadcast.body)
        );
        assert_eq!(broadcast.content_type, "text/plain");

        // Package relay is conditional in API.md (Bitcoin Core 28+). This node
        // has no atomic package-admission capability, so it must not advertise
        // sequential sendrawtransaction calls as that endpoint.
        let package = route_post(&handler, "/txs/package", b"[]");
        assert_eq!(package.status, 404);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn bitcoin_esplora_representations_match_the_documented_schemas()
    -> Result<(), Box<dyn std::error::Error>> {
        fn keys(value: &Value) -> std::collections::BTreeSet<&str> {
            value
                .as_object()
                .map(|object| object.keys().map(String::as_str).collect())
                .unwrap_or_default()
        }

        let (handler, transaction, block, address) = contract_fixture()?;
        let txid = transaction.txid().to_string();
        let block_hash = block.block_hash().to_string();
        let transaction_value: Value =
            serde_json::from_slice(&route(&handler, &format!("/tx/{txid}"), "").body)?;
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
            serde_json::from_slice(&route(&handler, &format!("/block/{block_hash}"), "").body)?;
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
            serde_json::from_slice(&route(&handler, &format!("/address/{address}"), "").body)?;
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
            serde_json::from_slice(&route(&handler, &format!("/address/{address}/utxo"), "").body)?;
        assert_eq!(utxos[0]["status"]["confirmed"], json!(true));
        assert_eq!(utxos[0]["status"]["block_height"], json!(0));

        let outspend: Value =
            serde_json::from_slice(&route(&handler, &format!("/tx/{txid}/outspend/0"), "").body)?;
        assert_eq!(outspend, json!({"spent":false}));

        let mempool: Value = serde_json::from_slice(&route(&handler, "/mempool", "").body)?;
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
            applied_tip: Arc::clone(&context.chain.applied_tip),
        }));
        let handler = Handler::new(Arc::new(context));

        let response = route(
            &handler,
            "/scripthash/0000000000000000000000000000000000000000000000000000000000000000",
            "",
        );
        assert_eq!(response.status, 503);
    }

    /// Membership, the next-best lookup, and the block list's start and every
    /// height lookup describe one captured applied publication, so a reorg
    /// landing mid-response cannot mix two branches.
    ///
    /// The genesis has two competing children: `a1` is one applied tip; `b2`
    /// leads a longer branch. Under `a1` the list is `[a1, genesis]` and `a1`
    /// is in the best chain with no next best; under `b2` it is
    /// `[b2, b1, genesis]` and `a1` is off it. Any other combination straddles
    /// two publications.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn block_status_and_block_list_never_straddle_two_applied_branches()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::AtomicBool;

        use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
        use bitcoin_rs_primitives::Header;

        /// Serves every fixture block's body by identity, so the block list
        /// can project each record.
        struct BranchBodies {
            bodies: Vec<(u32, BlockHash, Vec<u8>)>,
        }
        impl bitcoin_rs_chain::BlockBodySource for BranchBodies {
            fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
                self.bodies
                    .iter()
                    .find(|(h, k, _)| *h == height && *k == hash)
                    .map(|(_, _, body)| body.clone())
            }
        }

        let header = |prev: BlockHash, nonce: u32, time: u32| Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        };
        let coinbase = transaction(
            Some(null_outpoint()),
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
        context.chain.block_body_source = Some(Arc::new(BranchBodies { bodies }));
        context.chain.applied_tip.store(Some(Arc::clone(&a_tip)));

        let ctx = Arc::new(context);
        let handler = Handler::new(Arc::clone(&ctx));
        let stop = Arc::new(AtomicBool::new(false));
        let (cell, swap_a, swap_b, flag) = (
            Arc::clone(&ctx.chain.applied_tip),
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

        let status_path = format!("/block/{a1_hash}/status");
        let (a1_text, b1_text) = (a1_hash.to_string(), b1_hash.to_string());
        let (b2_text, genesis_text) = (b2_hash.to_string(), genesis_hash.to_string());
        let mut seen_a = false;
        let mut seen_b = false;
        let mut accepted = 0_usize;
        let mut attempts = 0_usize;
        // Sampling runs until both branches have answered, not for a fixed
        // count: the swapper's first store publishes the b2 tip, but thread
        // startup is the scheduler's call, so a fixed budget can expire before
        // the b2 branch is ever published.
        while !(accepted >= 200 && seen_a && seen_b) {
            attempts += 1;
            assert!(
                attempts < 100_000,
                "a publication was never observed, so coherence proved nothing"
            );
            let status_response = route(&handler, &status_path, "");
            // A tip change inside the projection's own validation window is
            // that guard's documented retry, not a torn response.
            if status_response.status == 503 {
                continue;
            }
            assert_eq!(
                status_response.status,
                200,
                "status body: {}",
                String::from_utf8_lossy(&status_response.body)
            );
            let status: Value = serde_json::from_slice(&status_response.body)?;
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
            let list: Value = serde_json::from_slice(&list_response.body)?;
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
        swapper.join().expect("swapper thread panicked");
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
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(Arc::new(transaction), 100, 1_000, 0, 0))
            .expect("mempool entry accepted");
        let handler = Handler::new(Arc::clone(&ctx));
        let body = serde_json::to_vec(&vec![txid.to_string()]).expect("txids serialize");

        let post = backend_route_post(&handler, "/internal/mempool/txs", &body);
        assert_eq!(post.status, 200);
        let paged = backend_route(&handler, "/internal/mempool/txs", "max_txs=1");
        assert_eq!(paged.status, 200);
        let values: Value = serde_json::from_slice(&paged.body).expect("mempool response json");
        assert_eq!(values[0]["txid"], json!(txid.to_string()));
    }

    #[test]
    fn mempool_backend_extension_surface_uses_the_same_projections()
    -> Result<(), Box<dyn std::error::Error>> {
        let (handler, transaction, block, address) = contract_fixture()?;
        let txid = transaction.txid().to_string();
        let ids = serde_json::to_vec(&vec![txid.clone()])?;
        let outpoints = serde_json::to_vec(&vec![format!("{txid}:0")])?;

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

    #[test]
    fn broadcast_transaction_is_immediately_visible_as_unconfirmed() {
        let ctx = Arc::new(Context::new());
        let transaction = transaction_with_funded_input(&ctx);
        let txid = transaction.txid();
        let handler = Handler::new(ctx);
        let raw = consensus_bytes(&transaction).to_lower_hex_string();
        let broadcast = route_post(&handler, "/tx", raw.as_bytes());
        assert_eq!(broadcast.status, 200);
        let response = route(&handler, &format!("/tx/{txid}"), "");
        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body).expect("transaction json");
        assert_eq!(value["status"], json!({"confirmed":false}));
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
            history: records,
            funding: Vec::new(),
            unspent: Vec::new(),
        }));
        ctx.indexes.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            transactions,
            calls: Arc::clone(&calls),
        }));

        let response = history(&ctx, ScriptHash::new(&target), None, false);
        assert_eq!(response.status, 200);
        let values: Value = serde_json::from_slice(&response.body).expect("history response json");
        assert_eq!(values.as_array().map(Vec::len), Some(CHAIN_PAGE));
        assert_eq!(calls.load(Ordering::Relaxed), CHAIN_PAGE);
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
        let value: Value = serde_json::from_slice(&summary.body).expect("summary json");
        assert_eq!(value["chain_stats"]["funded_txo_count"], json!(30));
        assert_eq!(value["chain_stats"]["funded_txo_sum"], json!(465));
        assert_eq!(value["chain_stats"]["spent_txo_count"], json!(29));
        assert_eq!(value["chain_stats"]["spent_txo_sum"], json!(464));

        let per_transaction = address_transaction_summary(&ctx, script_hash);
        assert_eq!(per_transaction.status, 200);
        let rows: Value = serde_json::from_slice(&per_transaction.body).expect("summary rows json");
        assert_eq!(rows.as_array().map(Vec::len), Some(30));

        // Both endpoints answer from index rows alone. Reading one transaction
        // per history entry escapes the script index's per-query budget, so a
        // long-history address turns one request into unbounded storage I/O.
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
            .pool()
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(spending.clone()),
                100,
                1_000,
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
            !outspend(&projection, null_outpoint())
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
            .transaction_value(&child, None)
            .expect("prevout indexed");
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
    fn stale_block_transactions_do_not_inherit_active_chain_status()
    -> Result<(), Box<dyn std::error::Error>> {
        // Null-prevout coinbase shape: a zero-input tx cannot be consensus
        // encoded into a decodable body (the 0x00 vin count reads as the
        // segwit marker, matching Core), so required_block would reject it.
        let transaction = transaction(
            Some(null_outpoint()),
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
                merkle_root: Hash256::default(),
                time: 2_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 2,
            },
            txs: vec![transaction.clone()],
        };
        let stale_record = bitcoin_rs_index::block_log::BlockRecord::from_block(1, &stale_block);
        let mut ctx = Context::new();
        ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
            height: 1,
            hash: stale_record.hash,
            body: consensus_bytes(&stale_block),
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
            // BlockTree::insert_node now publishes the best-work header on
            // insert and only reorgs on strictly greater chainwork. The stale
            // block had equal work and was inserted first, so it became the
            // active tip. Give the active chain a lower target so it wins.
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
            ctx.chain.set_applied_tip((*tip).clone());
        }
        ctx.indexes.esplora_tx_index = Some(Arc::new(StaticTxIndex::new(transaction)));

        let response = block_txs(&ctx, &stale_record.hash.to_string(), 0);
        assert_eq!(
            response.status,
            200,
            "block_txs failed: {}",
            String::from_utf8_lossy(&response.body)
        );
        let rendered: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(rendered[0]["status"], json!({"confirmed":false}));
        Ok(())
    }

    thread_local! {
        /// The one-shot halves that let a test observe the Esplora summary
        /// reaching its fee-binning loop. Installed per thread, so only the
        /// thread that arms it is ever gated.
        static BINNING_GATE: RefCell<Option<(Sender<()>, Receiver<()>)>> =
            const { RefCell::new(None) };
    }

    /// How long the gated thread waits for release before continuing anyway, so
    /// a failed assertion cannot hang the suite.
    const GATE_TIMEOUT: Duration = Duration::from_secs(30);

    /// Records the halves [`gate_mempool_binning_for_tests`] uses to announce
    /// the binning loop and wait to leave it. Call on the serving thread.
    fn arm_binning_gate(entered: Sender<()>, release: Receiver<()>) {
        BINNING_GATE.with(|slot| *slot.borrow_mut() = Some((entered, release)));
    }

    /// Test-only observation of the histogram-binning call site: announce that
    /// this thread is inside the loop, then wait to be let out of it. With no
    /// gate armed on this thread it returns immediately, so every other request
    /// in the suite is untouched.
    pub(crate) fn gate_mempool_binning_for_tests() {
        let armed = BINNING_GATE.with(|slot| slot.borrow_mut().take());
        let Some((entered, release)) = armed else {
            return;
        };
        let _ = entered.send(());
        let _ = release.recv_timeout(GATE_TIMEOUT);
    }

    /// A v2 transaction with one input per `inputs` and the given
    /// `(value, scriptPubKey)` outputs, in order.
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

    /// A funding outpoint that no other fixture transaction spends.
    fn unconfirmed_outpoint(marker: u8) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0)
    }

    /// One planned mempool entry: the transaction plus the policy facts the
    /// mempool routes report for it.
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

        /// The route's output total for this entry: saturated sum of its
        /// output values.
        fn value(&self) -> u64 {
            self.transaction.outputs.iter().fold(0_u64, |sum, output| {
                sum.saturating_add(output.value.to_sat())
            })
        }
    }

    /// `ctx` with every `seed` admitted, in order.
    fn seed_mempool(ctx: Context, seeds: &[Seed]) -> Arc<Context> {
        for seed in seeds {
            ctx.mempool
                .pool()
                .write()
                .insert_entry(MempoolEntry::new(
                    Arc::new(seed.transaction.clone()),
                    seed.vsize,
                    seed.fee,
                    seed.time,
                    0,
                ))
                .expect("seed entry admitted");
        }
        Arc::new(ctx)
    }

    /// The summary must not hold the pool read guard while it bins fee rates: a
    /// writer waiting behind that guard is the reported live failure. The gate
    /// hands control back to this thread from inside the binning loop, which the
    /// old code ran with the guard held, so the write attempt below fails at the
    /// base and succeeds once the capture is released first.
    #[test]
    fn mempool_projection_releases_read_guard_before_binning() {
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
            arm_binning_gate(entered_send, release_recv);
            let handler = Handler::new(serving_ctx);
            route(&handler, "/mempool", "")
        });

        let reached_binning = entered_recv.recv_timeout(GATE_TIMEOUT).is_ok();
        let writer_progress = ctx.mempool.pool().try_write().is_some();
        let _ = release_send.send(());
        let response = request.join().expect("gated request completes");

        assert!(
            reached_binning,
            "the request thread never reached the fee-binning loop"
        );
        assert!(
            writer_progress,
            "the summary held the mempool read guard while it binned fee rates"
        );
        assert_eq!(response.status, 200);
        // Releasing the guard early must cost nothing: two entries share
        // 10 sat/vB, so their vsizes merge into one bin and the rates stay
        // descending.
        let rendered: Value = serde_json::from_slice(&response.body).expect("summary json");
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

    /// One seeded pool shared by the projection parity tests: a funder with two
    /// target outputs and one unrelated output, the spender of its first target
    /// output, and eight fillers.
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
        // The overlay must drop the funder's spent output, keep its other
        // target output, and append the spender's own.
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
        // Two fillers share the top acceptance time, so the recent list has to
        // break a `(time, txid)` tie; twelve entries are two wider than the ten
        // the route emits, so the oldest pair drops out. The first four fillers
        // join the funder and spender in the 10 sat/vB bin, so six entries merge
        // into one histogram bucket.
        for index in 0..8_u8 {
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

    /// The bytes `path` returns on both Esplora prefixes, asserting the two
    /// surfaces agree and answer as JSON.
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

    /// Indices of `seeds` in the order the recent list emits them: descending
    /// `(time, txid)`.
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

    /// Every mempool projection the two Esplora prefixes share, on one seeded
    /// pool: identical bytes, and the same counts, bins, tie order, and listed
    /// ids the routes emitted before the capture was split out of the guard.
    #[test]
    fn esplora_mempool_summary_recent_and_txids_match_the_seeded_pool()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = parity_fixture();
        let mut bins = std::collections::BTreeMap::new();
        for seed in &fixture.seeds {
            let rate = seed.fee.saturating_mul(1_000) / u64::from(seed.vsize);
            *bins.entry(rate).or_insert(0_u64) += u64::from(seed.vsize);
        }
        let summary: Value = serde_json::from_slice(&routed_bytes(&fixture, "/mempool"))?;
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

        let recent: Vec<Value> =
            serde_json::from_slice(&routed_bytes(&fixture, "/mempool/recent"))?;
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
            serde_json::from_slice(&routed_bytes(&fixture, "/mempool/txids"))?;
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

    /// The script UTXO overlay and the script activity that one funder plus its
    /// spender produce, on the same seeded pool: the spent output is gone, the
    /// pool's own order is kept, and both prefixes answer with the same bytes.
    #[test]
    fn esplora_script_overlay_and_activity_match_the_seeded_pool()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = parity_fixture();
        let unconfirmed = json!({ "confirmed": false });
        let utxos: Value = serde_json::from_slice(&routed_bytes(
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

        // The history route needs a transaction index this fixture does not
        // carry, so the projection that feeds it is the observable: the funder
        // and the spender, each selected once, in descending `(time, txid)`.
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
