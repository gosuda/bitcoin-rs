//! Issue #78 Core-parity vertical gate: the real authenticated loopback
//! server over a real regtest node, replaying the checked-in Core 31.1
//! corpus under structural comparison.
//!
//! This gate never starts Bitcoin Core, never compares raw JSON text, never
//! substitutes a fake context, and never changes production behavior. The
//! eight probe-derived fixtures (cases 01, 04, 05, 06, 07, 17, 18, 20) carry
//! exact provenance — pinned Core 31.1.0, the exact binary SHA-256, regtest,
//! tip identity — and exactly one relation each: `exact`, or `known_gap`
//! with one concrete gap identifier pinning both sides of the divergence.

mod support;

use std::collections::BTreeSet;

use bitcoin_rs_rpc::manifest::MANIFEST;
use serde_json::Value;

use support::compare::{self, LiveChain};
use support::fixture::{
    self, BodyCheck, BodyForm, Fixture, HttpTuple, PINNED_NETWORK, Relation, RequestAuth,
};
use support::harness::{NodeHarness, ServerHarness};
use support::http::{Connection, HttpError, RawRequest, RawResponse};
use support::limits::{MAX_CORPUS_BYTES, SEED_CHAIN_BLOCKS};
use support::manifest_check::is_shipped_rpc_method;

/// The probe ordinals this vertical slice covers.
const EXPECTED_ORDINALS: [&str; 8] = ["01", "04", "05", "06", "07", "17", "18", "20"];

/// Stands up the real replay surface: strict corpus load, a real regtest
/// node with the deterministic seed chain, and the authenticated server.
fn stand_up() -> Result<(NodeHarness, ServerHarness), support::Failure> {
    fixture::load_corpus()?;
    let node = NodeHarness::open()?;
    let chain = node.seed(SEED_CHAIN_BLOCKS)?;
    if chain.tip_height != SEED_CHAIN_BLOCKS {
        return Err(support::fail(
            "seed chain did not reach the requested height",
        ));
    }
    let server = ServerHarness::start(&node)?;
    Ok((node, server))
}

/// Converts a decoded response into the fixture-side tuple shape, keeping
/// empty, text, and JSON bodies distinct.
fn as_tuple(response: RawResponse) -> HttpTuple {
    let body = if response.body.is_empty() {
        BodyForm::Empty
    } else if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
        BodyForm::Json { value }
    } else {
        BodyForm::Text {
            text: String::from_utf8_lossy(&response.body).into_owned(),
        }
    };
    HttpTuple {
        status: response.status,
        headers: response.headers,
        body_len: Some(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
        body,
    }
}

/// Decodes every result the fixture demands as typed corepc v31
/// `getblockchaininfo`; a payload that does not fit the versioned wire
/// struct fails the gate here, at the decode boundary.
fn assert_typed_chaininfo(
    fixture: &Fixture,
    response: &RawResponse,
) -> Result<(), support::Failure> {
    match &fixture.checks.body {
        BodyCheck::Single { envelope } => {
            let value: Value = serde_json::from_slice(&response.body)?;
            if envelope.result.typed_chaininfo {
                decode_result_as_chaininfo(&value)?;
            }
        }
        BodyCheck::Batch { elements } => {
            let value: Value = serde_json::from_slice(&response.body)?;
            let rows = value
                .as_array()
                .ok_or_else(|| support::fail("batch replay must answer an array"))?;
            for (element, envelope) in rows.iter().zip(elements) {
                if envelope.result.typed_chaininfo {
                    decode_result_as_chaininfo(element)?;
                }
            }
        }
        BodyCheck::Empty | BodyCheck::Text => {}
    }
    Ok(())
}
/// Re-serializes one envelope's result and decodes it into the typed corepc
/// v31 struct, then proves the network identity inside the typed value.
fn decode_result_as_chaininfo(envelope: &Value) -> Result<(), support::Failure> {
    let result = envelope
        .get("result")
        .ok_or_else(|| support::fail("typed chaininfo envelope carries no result"))?;
    let typed = compare::typed_getblockchain_info(serde_json::to_string(result)?.as_bytes())?;
    if typed.chain != PINNED_NETWORK {
        return Err(support::fail(format!(
            "typed chaininfo decoded for chain {:?}, not {PINNED_NETWORK}",
            typed.chain
        )));
    }
    Ok(())
}

/// The vertical gate: a real regtest chain, the real authenticated loopback
/// server, and every corpus fixture replayed under structural comparison.
#[test]
fn differential_loopback_authenticated_chain() -> Result<(), Box<dyn std::error::Error>> {
    let corpus = fixture::load_corpus()?;
    let (node, server) = stand_up()?;
    let live: LiveChain = node.live_chain()?;

    // Authenticated getblockchaininfo must answer HTTP 200 and decode as the
    // typed corepc v31 wire struct, before any fixture comparison runs.
    let authenticated = server.replay(
        RequestAuth::Valid,
        r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#,
        None,
    )?;
    if authenticated.status != 200 {
        return Err(support::fail(format!(
            "authenticated getblockchaininfo answered HTTP {}",
            authenticated.status
        ))
        .into());
    }
    let envelope: Value = serde_json::from_slice(&authenticated.body)?;
    decode_result_as_chaininfo(&envelope)?;

    // Replay every fixture under its declared relation.
    for fixture in corpus.values() {
        let response = server.replay(
            fixture.request.auth,
            &fixture.request.body,
            fixture.request.fragment_at,
        )?;
        compare::compare(fixture, &as_tuple(response.clone()), &live)?;
        assert_typed_chaininfo(fixture, &response)?;
    }

    // Wrong credentials must be rejected outright by the live server, while
    // the 401 response tuple itself stays a recorded production gap (the
    // known-gap fixtures above pin both sides of it).
    let rejected = server.replay(
        RequestAuth::Invalid,
        r#"{"jsonrpc":"2.0","id":18,"method":"getblockchaininfo","params":[]}"#,
        None,
    )?;
    if rejected.status != 401 {
        return Err(support::fail(format!(
            "wrong credentials answered HTTP {}, not 401",
            rejected.status
        ))
        .into());
    }

    // Classification discipline: every fixture carries exactly one relation
    // and each known gap names one concrete identifier. Every probe in this
    // vertical slice is a known gap by construction: the probe evidence
    // recorded Core response bodies but not the transport headers of the
    // JSON probes, and the live error wording genuinely diverges from
    // Core's — so no row can honestly claim the `exact` relation yet. A
    // future capture that records Core's full header tuple and equal
    // messages may reclassify rows as `exact`; the comparator already
    // enforces full equality on that relation.
    let mut gaps = Vec::new();
    for fixture in corpus.values() {
        match fixture.relation {
            Relation::Exact => {}
            Relation::KnownGap => gaps.push(
                fixture
                    .gap
                    .clone()
                    .ok_or_else(|| support::fail("known gap without an identifier"))?,
            ),
        }
    }
    if gaps.is_empty() {
        return Err(support::fail(format!(
            "corpus must contain known gaps pinning both sides (found {} gaps)",
            gaps.len()
        ))
        .into());
    }
    Ok(())
}

/// One keep-alive connection accepts two fully framed requests — the first
/// answered with 204 and an empty body, the second written in two TCP
/// fragments and answered with 200 — with framing decoded from the 204 status
/// or a declared `Content-Length`, never from end of stream.
#[test]
fn keepalive_two_framed_responses_without_eof() -> Result<(), Box<dyn std::error::Error>> {
    let (_node, server) = stand_up()?;

    let mut connection = Connection::connect(server.address())?;
    let notification = RawRequest {
        path: "/",
        authorization: Some(ServerHarness::basic_token()),
        body: r#"{"jsonrpc":"2.0","method":"getblockchaininfo"}"#.to_owned(),
        keep_alive: true,
    };
    let first = connection.round_trip(&notification)?;
    if first.status != 204 {
        return Err(support::fail(format!(
            "notification must answer HTTP 204, got {}",
            first.status
        ))
        .into());
    }
    if !first.body.is_empty() {
        return Err(support::fail("notification must carry an empty body").into());
    }

    let chaininfo = RawRequest {
        path: "/",
        authorization: Some(ServerHarness::basic_token()),
        body: r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#.to_owned(),
        keep_alive: true,
    };
    let bytes = chaininfo.bytes();
    connection.send_request_fragmented(&bytes, Some(40))?;
    let second = connection.read_response()?;
    if second.status != 200 {
        return Err(support::fail(format!(
            "fragmented request must answer HTTP 200, got {}",
            second.status
        ))
        .into());
    }
    let envelope: Value = serde_json::from_slice(&second.body)?;
    decode_result_as_chaininfo(&envelope)?;
    Ok(())
}

/// Replays one authenticated request from a worker thread while the caller
/// holds the node's chain-transition barrier, and returns the complete framed
/// response.
///
/// PRE: `server` wires the node's real transition barrier into its context,
///   and no other lock is held by the caller.
/// POST: the response was received before the barrier was released, or the
///   call failed with the bound it hit.
/// INVARIANT: the barrier is released on every outcome before the worker is
///   joined, so a blocked handler cannot deadlock the gate.
fn replay_during_chain_transition(
    server: &ServerHarness,
    body: &str,
) -> Result<RawResponse, Box<dyn std::error::Error>> {
    use std::net::SocketAddr;
    use std::sync::mpsc;
    use std::time::Duration;

    /// A status read that waits on the barrier stays blocked for the whole
    /// window; this bounds the wait, it does not assert a latency.
    const DEADLOCK_WATCHDOG: Duration = Duration::from_secs(30);

    /// One bounded exchange on a fresh connection, off the main thread.
    fn request(
        address: SocketAddr,
        authorization: String,
        body: String,
    ) -> Result<RawResponse, HttpError> {
        let mut connection = Connection::connect(address)?;
        let request = RawRequest {
            path: "/",
            authorization: Some(authorization),
            body,
            keep_alive: true,
        };
        let bytes = request.bytes();
        connection.send_request_fragmented(&bytes, None)?;
        connection.read_response()
    }

    let barrier = server.chain_transition();
    let guard = barrier.lock();
    let (sender, receiver) = mpsc::channel();
    let address = server.address();
    let authorization = ServerHarness::basic_token();
    let owned_body = body.to_owned();
    let worker = std::thread::spawn(move || {
        let _ignored = sender.send(request(address, authorization, owned_body));
    });
    let outcome = receiver.recv_timeout(DEADLOCK_WATCHDOG);
    drop(guard);
    if worker.join().is_err() {
        return Err(support::fail("the request worker panicked").into());
    }
    match outcome {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) => Err(support::fail(error).into()),
        Err(_) => Err(support::fail(
            "no complete response arrived while the chain-transition barrier was held",
        )
        .into()),
    }
}

/// Reads the applied tip's published transaction count from the node state,
/// never from an RPC answer, so the status response has an independent
/// expectation to meet.
fn seeded_chain_tx_count(node: &NodeHarness) -> Result<u64, Box<dyn std::error::Error>> {
    let applied = node
        .state
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| support::fail("the seeded node has no applied tip"))?;
    Ok(applied
        .chain_tx_count
        .get()
        .ok_or_else(|| support::fail("the applied tip publishes no transaction count"))?)
}

/// Decodes one JSON-RPC envelope answered while the barrier was held: HTTP
/// 200, the matching id, and no error member.
fn decoded_success(
    response: &RawResponse,
    method: &str,
    id: i64,
) -> Result<Value, Box<dyn std::error::Error>> {
    if response.status != 200 {
        return Err(support::fail(format!(
            "{method} answered HTTP {} while the barrier was held",
            response.status
        ))
        .into());
    }
    let envelope: Value = serde_json::from_slice(&response.body)?;
    if envelope.get("id").and_then(Value::as_i64) != Some(id) {
        return Err(support::fail(format!("{method} answered a different id: {envelope}")).into());
    }
    if !matches!(envelope.get("error"), None | Some(Value::Null)) {
        return Err(support::fail(format!("{method} returned an error: {envelope}")).into());
    }
    envelope
        .get("result")
        .cloned()
        .ok_or_else(|| support::fail(format!("{method} answered no result")).into())
}

/// The live bug (issue #1132): an explorer's status read waited on the
/// whole-chain transition, so requests hung while a block was applying.
/// `getblockchaininfo` must answer from the last complete applied publication
/// with the barrier held.
#[test]
fn getblockchaininfo_returns_during_chain_transition() -> Result<(), Box<dyn std::error::Error>> {
    let (node, server) = stand_up()?;
    let live = node.live_chain()?;

    let response = replay_during_chain_transition(
        &server,
        r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#,
    )?;
    let result = decoded_success(&response, "getblockchaininfo", 1)?;
    let reported = result
        .get("bestblockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| support::fail("getblockchaininfo answered no bestblockhash"))?;
    if reported != live.best_block_hash {
        return Err(support::fail(format!(
            "getblockchaininfo reported {reported}, not the applied tip {}",
            live.best_block_hash
        ))
        .into());
    }
    Ok(())
}

/// `getchaintxstats` must answer from the same published pair with the barrier
/// held, reporting the applied tip's count rather than waiting for the
/// transition to finish.
#[test]
fn getchaintxstats_returns_during_chain_transition() -> Result<(), Box<dyn std::error::Error>> {
    let (node, server) = stand_up()?;
    let seeded_count = seeded_chain_tx_count(&node)?;

    let response = replay_during_chain_transition(
        &server,
        r#"{"jsonrpc":"2.0","id":2,"method":"getchaintxstats","params":[0]}"#,
    )?;
    let result = decoded_success(&response, "getchaintxstats", 2)?;
    let reported = result
        .get("txcount")
        .and_then(Value::as_u64)
        .ok_or_else(|| support::fail("getchaintxstats answered no txcount"))?;
    if reported != seeded_count {
        return Err(support::fail(format!(
            "getchaintxstats reported {reported}, not the published count {seeded_count}"
        ))
        .into());
    }
    // A zero-block window keeps its documented shape: no window fields.
    if result.get("window_tx_count").is_some() || result.get("window_interval").is_some() {
        return Err(support::fail(format!(
            "a zero-block window must omit its fields: {result}"
        ))
        .into());
    }
    Ok(())
}

/// Corpus custody: the checked-in directory obeys every ceiling, every
/// fixture pins the audited Core provenance, the probe ordinals are covered
/// exactly once, and every replayed method is accounted for in the const
/// `MANIFEST`.
#[test]
fn corpus_bounds_and_provenance_hold() -> Result<(), Box<dyn std::error::Error>> {
    let corpus = fixture::load_corpus()?;

    let dir = fixture::corpus_dir();
    let mut total_bytes = 0_u64;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let size = entry.metadata()?.len();
        total_bytes += size;
        if size > support::limits::MAX_FIXTURE_BYTES {
            return Err(support::fail(format!(
                "{} is {size} bytes, above the per-fixture ceiling",
                entry.path().display()
            ))
            .into());
        }
    }
    if total_bytes > MAX_CORPUS_BYTES {
        return Err(support::fail(format!(
            "corpus totals {total_bytes} bytes, above the ceiling of {MAX_CORPUS_BYTES}"
        ))
        .into());
    }
    if corpus.len() != EXPECTED_ORDINALS.len() {
        return Err(support::fail(format!(
            "corpus holds {} fixtures, expected {}",
            corpus.len(),
            EXPECTED_ORDINALS.len()
        ))
        .into());
    }

    let mut ordinals = BTreeSet::new();
    for fixture in corpus.values() {
        ordinals.insert(fixture.case_ordinal.clone());
        match (&fixture.relation, &fixture.current, &fixture.gap) {
            (Relation::Exact, None, None) => {}
            (Relation::KnownGap, Some(_), Some(gap)) if !gap.trim().is_empty() => {}
            _ => {
                return Err(support::fail(format!(
                    "fixture {} violates the relation discipline",
                    fixture.id
                ))
                .into());
            }
        }
        for method in &fixture.request.methods {
            let shipped = is_shipped_rpc_method(method, MANIFEST);
            if shipped != fixture.request.expect_methods_in_manifest {
                return Err(support::fail(format!(
                    "fixture {} method {method:?}: shipped={shipped} but the fixture expects \
                     manifest membership to be {}",
                    fixture.id, fixture.request.expect_methods_in_manifest
                ))
                .into());
            }
        }
    }
    let expected: BTreeSet<String> = EXPECTED_ORDINALS.iter().map(|o| (*o).to_string()).collect();
    if ordinals != expected {
        return Err(support::fail(format!(
            "corpus ordinals {ordinals:?} do not cover the probe cases {EXPECTED_ORDINALS:?}"
        ))
        .into());
    }
    Ok(())
}
