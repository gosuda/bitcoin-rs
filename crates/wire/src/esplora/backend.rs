use alloc::sync::Arc;
use core::ops::Range;
use core::str::FromStr as _;
use std::io;

use bitcoin_rs_consensus::primitives::{OutPoint, Txid};
use bitcoin_rs_mempool::MempoolEntry;

use super::http::dispatch_error;
use super::model::{Outspend, TransactionValue};
use super::projection::{Projection, TxSource};
use super::public::{outspend, outspends_for_transaction, visit_block_transactions};
use crate::context::Context;
use crate::handlers::Handler;
use crate::handlers::mining::required_gbt_rules;
use crate::rest::Response;
use crate::rest::{bad_request, internal_error, json_ok, service_unavailable, text_response};
use sonic_rs::json as sonic_json;

pub(super) const MAX_BACKEND_BULK_ITEMS: usize = 25;
const MAX_BACKEND_BULK_BYTES: usize = 16 * 1_024 * 1_024;

struct BoundedJsonArray {
    body: Vec<u8>,
}

impl BoundedJsonArray {
    fn new() -> Self {
        Self { body: vec![b'['] }
    }

    fn reserve_row_bytes(&mut self, additional: usize) -> bool {
        let required = self.body.len().saturating_add(additional).saturating_add(1);
        if required > MAX_BACKEND_BULK_BYTES {
            return false;
        }
        if required > self.body.capacity() {
            let capacity = self
                .body
                .capacity()
                .saturating_mul(2)
                .clamp(required, MAX_BACKEND_BULK_BYTES);
            self.body.reserve_exact(capacity - self.body.len());
        }
        true
    }

    fn push<T: serde::Serialize>(&mut self, value: &T) -> Result<Range<usize>, Response> {
        let rollback = self.body.len();
        if rollback > 1 {
            if !self.reserve_row_bytes(1) {
                return Err(bulk_response_limit());
            }
            self.body.push(b',');
        }
        let start = self.body.len();
        if let Err(error) = value.serialize(&mut sonic_rs::Serializer::with_formatter(
            sonic_rs::writer::BufferedWriter::new(&mut *self),
            ChunkedStrings,
        )) {
            self.body.truncate(rollback);
            return if error.io_error_kind() == Some(io::ErrorKind::FileTooLarge) {
                Err(bulk_response_limit())
            } else {
                Err(internal_error("failed to serialize response"))
            };
        }
        Ok(start..self.body.len())
    }

    fn repeat(&mut self, row: Range<usize>) -> Result<(), Response> {
        if !self.reserve_row_bytes(1 + row.len()) {
            return Err(bulk_response_limit());
        }
        self.body.push(b',');
        self.body.extend_from_within(row);
        Ok(())
    }

    fn finish(mut self) -> Response {
        self.body.push(b']');
        text_response("application/json", self.body)
    }
}

#[derive(Clone, Copy)]
struct ChunkedStrings;

impl sonic_rs::format::Formatter for ChunkedStrings {
    fn write_string_fast<W: sonic_rs::writer::WriteExt + ?Sized>(
        &mut self,
        writer: &mut W,
        mut value: &str,
        need_quote: bool,
    ) -> io::Result<()> {
        const CHUNK: usize = 4096;
        let mut formatter = sonic_rs::format::CompactFormatter;
        if value.len() <= CHUNK {
            return formatter.write_string_fast(writer, value, need_quote);
        }
        if need_quote {
            writer.write_all(b"\"")?;
        }
        while !value.is_empty() {
            let (chunk, rest) = value.split_at(value.floor_char_boundary(CHUNK));
            formatter.write_string_fast(writer, chunk, false)?;
            value = rest;
        }
        if need_quote {
            writer.write_all(b"\"")?;
        }
        Ok(())
    }
}

impl io::Write for BoundedJsonArray {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.reserve_row_bytes(bytes.len()) {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.body.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bulk_response_limit() -> Response {
    service_unavailable(
        "backend bulk response exceeds 16 MiB; split the batch or page block transactions with /esplora/block/{hash}/txs/{start_index}",
    )
}

pub(super) fn get(handler: &Handler, ctx: &Context, path: &str, query: &str) -> Option<Response> {
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    Some(match parts.as_slice() {
        ["internal", "mempool", "txs"] => internal_mempool_txs(ctx, None, query),
        ["internal", "mempool", "txs", last] => internal_mempool_txs(ctx, Some(last), query),
        ["internal", "block", hash, "txs"] => internal_block_txs(ctx, hash),
        ["block-template"] => block_template(handler),
        _ => return None,
    })
}

pub(super) fn post(handler: &Handler, path: &str, body: &[u8]) -> Option<Response> {
    let ctx = handler.context();
    match path {
        "/internal/txs" => Some(internal_transactions_scoped(
            ctx.as_ref(),
            body,
            TransactionScope::All,
            MAX_BACKEND_BULK_BYTES,
        )),
        "/internal/mempool/txs" => Some(internal_transactions_scoped(
            ctx.as_ref(),
            body,
            TransactionScope::MempoolOnly,
            MAX_BACKEND_BULK_BYTES,
        )),
        "/internal/txs/outspends/by-txid" => Some(internal_outspends_by_txid(ctx.as_ref(), body)),
        "/internal/txs/outspends/by-outpoint" => {
            Some(internal_outspends_by_outpoint(ctx.as_ref(), body))
        }
        _ => None,
    }
}

fn internal_block_txs(ctx: &Context, hash: &str) -> Response {
    let projection = Projection::new(ctx);
    let view = projection.capture_chain_view();
    let record = match projection.required_block_record(hash) {
        Ok(record) => record,
        Err(response) => return response,
    };
    let Some(_render) = ctx.try_acquire_block_render() else {
        return service_unavailable("too many concurrent full-block reads; retry");
    };
    let (record, block) = match projection.block_from_record(record) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut output = BoundedJsonArray::new();
    let source = match visit_block_transactions(
        ctx,
        &record,
        &block,
        0..block.txs.len(),
        &view,
        MAX_BACKEND_BULK_BYTES,
        |value| output.push(&value).map(|_| ()),
    ) {
        Ok(source) => source,
        Err(response) => return response,
    };
    let response = output.finish();
    if matches!(source, TxSource::Joined) {
        match projection.ensure_chain_view(&view) {
            Ok(()) => response,
            Err(unavailable) => unavailable,
        }
    } else {
        response
    }
}

fn internal_mempool_txs(ctx: &Context, last: Option<&str>, query: &str) -> Response {
    let max_txs = match mempool_page_limit(query) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    if max_txs == 0 {
        return json_ok(Vec::<TransactionValue>::new());
    }
    let last = last.and_then(|text| {
        let txid = Txid::from_str(text).ok()?;
        (txid.to_string() == text).then_some(txid)
    });
    let transactions = {
        let pool = ctx.mempool.gateway.read();
        let after = last
            .and_then(|txid| pool.entry_by_txid(&txid))
            .map(|entry| (entry.time, entry.txid));
        let mut ordered = select_mempool_page(pool.iter_entries(), after, max_txs)
            .into_iter()
            .map(|entry| (entry.time, entry.txid, Arc::clone(&entry.tx)))
            .collect::<Vec<_>>();
        drop(pool);
        ordered.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
        });
        ordered
    };
    let projection = Projection::new(ctx);
    let mut output = BoundedJsonArray::new();
    match projection.visit_transaction_values(
        transactions.iter().map(|(_, _, tx)| (tx.as_ref(), None)),
        None,
        MAX_BACKEND_BULK_BYTES,
        |value| output.push(&value).map(|_| ()),
    ) {
        Ok(_) => output.finish(),
        Err(response) => response,
    }
}

fn mempool_page_limit(query: &str) -> Result<usize, Response> {
    let requested = query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == "max_txs").then_some(value)
    });
    let Some(requested) = requested else {
        return Ok(MAX_BACKEND_BULK_ITEMS);
    };
    let Ok(requested) = requested.parse::<usize>() else {
        return Err(bad_request(
            "max_txs must be an unsigned integer no greater than 25",
        ));
    };
    if requested > MAX_BACKEND_BULK_ITEMS {
        return Err(bad_request(
            "max_txs must be an unsigned integer no greater than 25",
        ));
    }
    Ok(requested)
}

fn select_mempool_page<'a>(
    entries: impl Iterator<Item = &'a MempoolEntry>,
    after: Option<(u64, Txid)>,
    max_txs: usize,
) -> Vec<&'a MempoolEntry> {
    let mut selected = Vec::new();
    if max_txs == 0 {
        return selected;
    }
    let mut cutoff = None;
    for entry in entries {
        let key = (entry.time, entry.txid);
        if after.is_some_and(|after| key <= after) || cutoff.is_some_and(|cutoff| key >= cutoff) {
            continue;
        }
        selected.push(entry);
        if selected.len() / 2 >= max_txs {
            let (_, excluded, _) =
                selected.select_nth_unstable_by_key(max_txs, |entry| (entry.time, entry.txid));
            cutoff = Some((excluded.time, excluded.txid));
            selected.truncate(max_txs);
        }
    }
    if max_txs < selected.len() {
        selected.select_nth_unstable_by_key(max_txs, |entry| (entry.time, entry.txid));
        selected.truncate(max_txs);
    }
    selected
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionScope {
    All,
    MempoolOnly,
}

fn internal_transactions_scoped(
    ctx: &Context,
    body: &[u8],
    scope: TransactionScope,
    source_limit: usize,
) -> Response {
    let text_ids = match bulk_strings(
        body,
        "transaction request body must be a JSON array of txids",
    ) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let ids = match text_ids
        .into_iter()
        .map(|id| Txid::from_str(&id).map_err(|_| bad_request("txid must be 64 hex characters")))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let projection = Projection::new(ctx);
    let mut transactions = std::collections::HashMap::new();
    let mut source_bytes = 0usize;
    for id in &ids {
        if transactions.contains_key(id) {
            continue;
        }
        let transaction = if scope == TransactionScope::MempoolOnly {
            ctx.mempool
                .gateway
                .read()
                .transaction_by_txid(id)
                .map(|transaction| ((*transaction).clone(), None, TxSource::Joined))
        } else {
            match projection.transaction(id) {
                Ok(transaction) => transaction,
                Err(response) => return response,
            }
        };
        if let Some((transaction, _, _)) = transaction.as_ref() {
            source_bytes = source_bytes.saturating_add(transaction.total_size());
            if source_bytes > source_limit {
                return service_unavailable(
                    "backend bulk transaction sources exceed 16 MiB limit; split the request",
                );
            }
        }
        transactions.insert(*id, transaction);
    }
    let parents: std::collections::HashMap<_, _> = transactions
        .iter()
        .filter_map(|(id, transaction)| {
            transaction
                .as_ref()
                .map(|(transaction, _, _)| (*id, transaction))
        })
        .collect();
    let prevouts = match projection.resolve_prevouts(
        parents.values().copied(),
        &parents,
        MAX_BACKEND_BULK_BYTES,
    ) {
        Ok(prevouts) => prevouts,
        Err(response) => return response,
    };
    let mut output = BoundedJsonArray::new();
    let mut rendered = std::collections::HashMap::<Txid, Range<usize>>::new();
    for id in ids {
        if let Some(row) = rendered.get(&id) {
            if let Err(response) = output.repeat(row.clone()) {
                return response;
            }
            continue;
        }
        let Some(Some((transaction, status, _))) = transactions.get(&id) else {
            continue;
        };
        let value = match projection.transaction_value(transaction, id, *status, &prevouts) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let row = match output.push(&value) {
            Ok(row) => row,
            Err(response) => return response,
        };
        rendered.insert(id, row);
    }
    output.finish()
}

fn bulk_strings(body: &[u8], invalid: &'static str) -> Result<Vec<String>, Response> {
    sonic_rs::from_slice::<BulkStrings>(body)
        .map(|values| values.0)
        .map_err(|_| bad_request(invalid))
}

struct BulkStrings(Vec<String>);

impl<'de> serde::Deserialize<'de> for BulkStrings {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_seq(Self(Vec::new()))
    }
}

impl<'de> serde::de::Visitor<'de> for BulkStrings {
    type Value = Self;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "an array of at most {MAX_BACKEND_BULK_ITEMS} strings"
        )
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(mut self, mut seq: A) -> Result<Self, A::Error> {
        while self.0.len() < MAX_BACKEND_BULK_ITEMS {
            let Some(value) = seq.next_element()? else {
                break;
            };
            self.0.push(value);
        }
        Ok(self)
    }
}

fn internal_outspends_by_txid(ctx: &Context, body: &[u8]) -> Response {
    let text_ids = match bulk_strings(body, "outspend request body must be a JSON array of txids") {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let projection = Projection::new(ctx);
    let mut output = BoundedJsonArray::new();
    let mut rendered = std::collections::HashMap::<Txid, Range<usize>>::new();
    for text_id in text_ids {
        let Ok(id) = Txid::from_str(&text_id) else {
            if let Err(response) = output.push(&Vec::<Outspend>::new()) {
                return response;
            }
            continue;
        };
        if let Some(row) = rendered.get(&id) {
            if let Err(response) = output.repeat(row.clone()) {
                return response;
            }
            continue;
        }
        let transaction = match projection.transaction(&id) {
            Ok(transaction) => transaction,
            Err(response) => return response,
        };
        let outspends = match transaction {
            Some((transaction, _, _)) => {
                match outspends_for_transaction(&projection, &transaction) {
                    Ok(outspends) => outspends,
                    Err(response) => return response,
                }
            }
            None => Vec::new(),
        };
        let row = match output.push(&outspends) {
            Ok(row) => row,
            Err(response) => return response,
        };
        rendered.insert(id, row);
    }
    output.finish()
}

fn internal_outspends_by_outpoint(ctx: &Context, body: &[u8]) -> Response {
    let outpoints = match bulk_strings(
        body,
        "outspend request body must be a JSON array of outpoints",
    ) {
        Ok(outpoints) => outpoints,
        Err(response) => return response,
    };
    let projection = Projection::new(ctx);
    let mut output = BoundedJsonArray::new();
    let mut rendered = std::collections::HashMap::<String, Range<usize>>::new();
    for outpoint in outpoints {
        if let Some(row) = rendered.get(&outpoint) {
            if let Err(response) = output.repeat(row.clone()) {
                return response;
            }
            continue;
        }
        let value = match internal_outspend(&projection, &outpoint) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let row = match output.push(&value) {
            Ok(row) => row,
            Err(response) => return response,
        };
        rendered.insert(outpoint, row);
    }
    output.finish()
}

fn internal_outspend(
    projection: &Projection<'_>,
    text_outpoint: &str,
) -> Result<Outspend, Response> {
    let Some((text_txid, text_vout)) = text_outpoint.split_once(':') else {
        return Ok(Outspend::unspent());
    };
    let Ok(txid) = Txid::from_str(text_txid) else {
        return Ok(Outspend::unspent());
    };
    let Ok(vout) = text_vout.parse::<u32>() else {
        return Ok(Outspend::unspent());
    };
    let Some((transaction, _, _)) = projection.transaction(&txid)? else {
        return Ok(Outspend::unspent());
    };
    let Some(_) = transaction
        .outputs
        .get(usize::try_from(vout).unwrap_or(usize::MAX))
    else {
        return Ok(Outspend::unspent());
    };
    outspend(projection, OutPoint::new(txid, vout))
}

fn block_template(handler: &Handler) -> Response {
    let rules = required_gbt_rules(handler.context().chain.chain_network);
    let request = sonic_json!([{"rules": rules}]);
    handler
        .dispatch("getblocktemplate", &request)
        .map_or_else(dispatch_error, json_ok)
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod pagination_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_mempool::MempoolEntry;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

    use super::{
        BoundedJsonArray, MAX_BACKEND_BULK_BYTES, MAX_BACKEND_BULK_ITEMS, bulk_strings,
        internal_mempool_txs, select_mempool_page,
    };
    use crate::context::Context;

    fn fixture(times: &[u64]) -> (Context, Vec<(u64, Txid)>) {
        let ctx = Context::new();
        let mut expected = Vec::new();
        for (index, &time) in times.iter().enumerate() {
            let tx = Tx {
                version: 2,
                inputs: Vec::new(),
                outputs: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
                lock_time: LockTime::from_consensus(
                    u32::try_from(index).expect("small fixture index"),
                ),
            };
            let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, time, 0, 0);
            expected.push((time, entry.txid));
            ctx.mempool
                .gateway
                .pool()
                .write()
                .insert_entry(entry)
                .expect("insert independent fixture entry");
        }
        expected.sort_unstable();
        (ctx, expected)
    }

    fn page(ctx: &Context, cursor: Option<&str>, query: &str) -> Vec<Txid> {
        let response = internal_mempool_txs(ctx, cursor, query);
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let values: Value = sonic_rs::from_slice(&response.body).expect("response JSON");
        values
            .as_array()
            .expect("transaction array")
            .iter()
            .map(|value| {
                value["txid"]
                    .as_str()
                    .expect("text txid")
                    .parse()
                    .expect("valid txid")
            })
            .collect()
    }

    fn status(ctx: &Context, query: &str) -> u16 {
        internal_mempool_txs(ctx, None, query).status
    }

    #[test]
    fn bounded_pages_match_full_sort_for_every_cursor() {
        for times in [
            Vec::new(),
            vec![0],
            vec![u64::MAX],
            vec![7; 18],
            vec![8, 0, u64::MAX, 8, 1, 8, 1, 0, 9, 8, 1, 0, 9, 4, 4, 8, 2, 9],
        ] {
            let (ctx, expected) = fixture(&times);
            let cursors = std::iter::once(None)
                .chain(expected.iter().map(|(_, txid)| Some(txid.to_string())));
            for (start, cursor) in cursors.enumerate() {
                for limit in [0, 1, 2, 3, 8, 17, 18, 19, MAX_BACKEND_BULK_ITEMS] {
                    let want: Vec<_> = expected
                        .iter()
                        .skip(start)
                        .take(limit)
                        .map(|(_, txid)| *txid)
                        .collect();
                    assert_eq!(
                        page(&ctx, cursor.as_deref(), &format!("max_txs={limit}")),
                        want,
                        "cursor {cursor:?}, limit {limit}"
                    );
                }
            }
        }
    }

    #[test]
    fn noncanonical_and_missing_cursors_keep_restart_behavior() {
        let (ctx, expected) = fixture(&[4, 1, 4, 2, 4, 3]);
        let lower = expected[2].1.to_string();
        let upper = lower.to_ascii_uppercase();
        assert_ne!(lower, upper, "fixture must exercise alphabetic hex");
        let unknown = Txid(Hash256::from_le_bytes(&[0xff; 32]));
        assert!(expected.iter().all(|(_, txid)| *txid != unknown));
        let want: Vec<_> = expected.iter().take(3).map(|(_, txid)| *txid).collect();
        for cursor in [
            String::new(),
            "00".to_owned(),
            "g".repeat(64),
            "é".repeat(32),
            format!(" {lower}"),
            format!("0x{lower}"),
            upper,
            unknown.to_string(),
        ] {
            assert_eq!(page(&ctx, Some(&cursor), "max_txs=3"), want);
        }
    }

    // API-09, WF-02
    #[test]
    fn mempool_limits_default_to_one_page_and_reject_invalid_values() {
        let (ctx, expected) = fixture(&[2, 0, 1, 2]);
        let all: Vec<_> = expected.iter().map(|(_, txid)| *txid).collect();
        for query in ["", "other=1"] {
            assert_eq!(page(&ctx, None, query), all);
        }
        for query in [
            "max_txs=invalid",
            "max_txs=-1",
            "max_txs=184467440737095516160",
            "max_txs=26",
            "max_txs=invalid&max_txs=2",
        ] {
            assert_eq!(status(&ctx, query), 400, "query {query}");
        }
        assert_eq!(page(&ctx, None, "max_txs=1&max_txs=2"), all[..1]);
        assert_eq!(page(&ctx, None, "max_txs=0&max_txs=2"), []);
    }

    // API-09, WF-02
    #[test]
    fn bulk_request_count_includes_duplicate_entries() {
        let at_limit = vec!["duplicate"; MAX_BACKEND_BULK_ITEMS];
        let body = sonic_rs::to_vec(&at_limit).expect("request JSON");
        assert_eq!(
            bulk_strings(&body, "invalid").expect("bounded request"),
            at_limit
        );
        let over_limit = vec!["duplicate"; MAX_BACKEND_BULK_ITEMS + 1];
        let body = sonic_rs::to_vec(&over_limit).expect("request JSON");
        let response = bulk_strings(&body, "invalid").expect_err("oversized request");
        assert_eq!(response.status, 400);
        for invalid in [b"[null]".as_slice(), b"[] trailing", b"[1,"] {
            assert_eq!(
                bulk_strings(invalid, "invalid")
                    .expect_err("invalid request")
                    .status,
                400
            );
        }
    }

    // API-09, WF-02
    #[test]
    fn transaction_batch_charges_only_distinct_source_bytes() {
        let (ctx, ids) = fixture(&[1, 2]);
        for (request, status) in [([ids[0].1, ids[0].1], 200), ([ids[0].1, ids[1].1], 503)] {
            let body = sonic_rs::to_vec(&request.map(|id| id.to_string())).expect("request JSON");
            let response = super::internal_transactions_scoped(
                &ctx,
                &body,
                super::TransactionScope::MempoolOnly,
                20,
            );
            assert_eq!(response.status, status);
        }
    }

    // API-09, WF-02
    #[test]
    fn bounded_json_reuses_rows_and_refuses_oversized_output() {
        let mut output = BoundedJsonArray::new();
        let row = output.push(&"safe").expect("bounded row");
        output.repeat(row).expect("bounded duplicate");
        assert_eq!(output.finish().body, br#"["safe","safe"]"#);

        let mut output = BoundedJsonArray::new();
        let text = format!("{}🦀\n\"{}", "x".repeat(4095), "y".repeat(4096));
        output.push(&text).expect("bounded string");
        let decoded: Vec<String> = sonic_rs::from_slice(&output.finish().body).expect("valid JSON");
        assert_eq!(decoded, [text]);
        let mut output = BoundedJsonArray::new();
        let oversized = "x".repeat(MAX_BACKEND_BULK_BYTES);
        let response = output.push(&oversized).expect_err("oversized response");
        assert_eq!(response.status, 503);
    }

    #[test]
    fn unselected_transactions_are_not_projected() {
        let (ctx, expected) = fixture(&[2, 3]);
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xaa; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::from_consensus(99),
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 0, 0);
        let cursor = entry.txid.to_string();
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(entry)
            .expect("insert unresolved-prevout fixture");
        assert_eq!(internal_mempool_txs(&ctx, None, "max_txs=1").status, 503);
        assert_eq!(page(&ctx, Some(&cursor), "max_txs=1"), vec![expected[0].1]);
        assert_eq!(page(&ctx, None, "max_txs=0"), []);
    }

    #[test]
    fn batched_selection_matches_full_sort_across_flush_boundaries() {
        let entries: Vec<_> = (0_u32..257)
            .map(|index| {
                let tx = Tx {
                    lock_time: LockTime::from_consensus(index),
                    ..Tx::default()
                };
                MempoolEntry::new(Arc::new(tx), 100, 1_000, u64::from(index % 7), 0, 0)
            })
            .collect();
        let mut ordered: Vec<_> = entries.iter().collect();
        ordered.sort_unstable_by_key(|entry| (entry.time, entry.txid));
        for reverse in [false, true] {
            let mut traversal = ordered.clone();
            if reverse {
                traversal.reverse();
            }
            for after in [None, Some((ordered[128].time, ordered[128].txid))] {
                for limit in [0, 1, 2, 3, 25, 127, 128, 129, 256, 257, usize::MAX] {
                    let mut actual = select_mempool_page(traversal.iter().copied(), after, limit);
                    actual.sort_unstable_by_key(|entry| (entry.time, entry.txid));
                    let actual: Vec<_> = actual.iter().map(|entry| entry.txid).collect();
                    let expected: Vec<_> = ordered
                        .iter()
                        .filter(|entry| after.is_none_or(|key| (entry.time, entry.txid) > key))
                        .take(limit)
                        .map(|entry| entry.txid)
                        .collect();
                    assert_eq!(actual, expected, "reverse={reverse}, limit={limit}");
                }
            }
        }
    }

    #[test]
    fn selection_borrows_payloads_and_only_the_final_page_is_cloned() {
        let entries: Vec<_> = (0_u32..129)
            .map(|index| {
                MempoolEntry::new(
                    Arc::new(Tx {
                        lock_time: LockTime::from_consensus(index),
                        ..Tx::default()
                    }),
                    100,
                    1_000,
                    u64::from(129 - index),
                    0,
                    0,
                )
            })
            .collect();
        let selected = select_mempool_page(
            entries.iter().inspect(|_| {
                assert!(
                    entries
                        .iter()
                        .all(|entry| Arc::strong_count(&entry.tx) == 1)
                );
            }),
            None,
            3,
        );
        assert_eq!(selected.len(), 3);
        assert!(
            entries
                .iter()
                .all(|entry| Arc::strong_count(&entry.tx) == 1)
        );
        let captured: Vec<_> = selected.iter().map(|entry| Arc::clone(&entry.tx)).collect();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| Arc::strong_count(&entry.tx) == 2)
                .count(),
            3
        );
        drop(captured);
        assert!(
            entries
                .iter()
                .all(|entry| Arc::strong_count(&entry.tx) == 1)
        );
    }

    #[test]
    fn zero_selection_does_not_poll_the_pool_iterator() {
        let entries = std::iter::from_fn(|| -> Option<&MempoolEntry> {
            panic!("zero-sized pages must not traverse entries")
        });
        assert!(select_mempool_page(entries, None, 0).is_empty());
    }
}
