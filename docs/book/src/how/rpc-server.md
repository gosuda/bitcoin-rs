# RPC server internals

One hand-written HTTP/1.1 listener serves JSON-RPC, REST, and Esplora on the same socket. There is no HTTP framework: `crates/rpc/src/server.rs` parses the request line and headers byte by byte, applies Core-shaped authentication and framing rules, and hands the body to a single dispatcher. The registry in `crates/rpc/src/registry.rs` is the only table that decides whether a method exists, how it executes, and what it claims about Core compatibility. This chapter follows one request from the accept loop to the handler, then the shutdown drain, then the boundaries to REST, Esplora, and ZMQ.

The user-facing behavior of these surfaces is documented in [RPC](../use/rpc.md), [REST and Esplora](../use/rest-esplora.md), and [ZeroMQ notifications](../use/zmq.md). This chapter is about the machinery behind them.

## From socket to handler

A connection thread runs `serve_connection` (`crates/rpc/src/server.rs`), which loops over requests on one socket:

```text
accept (mio poll, nonblocking listener)
  -> prepare_http_socket (TCP_NODELAY)          server.rs
  -> ActiveConnections::admit (budget, per IP)  server.rs
  -> spawn "rpc-connection" thread, 2 MiB stack server.rs
  -> serve_connection loop                      server.rs
       read_request_head    (10 s budget)       server.rs
       classify             (route + surface)   server.rs
       surface.allows       (listener split)    server.rs
       authenticate_json_rpc_head (JSON-RPC)    server.rs
       read_request_body    (60 s budget)       server.rs
       dispatch_http_request                    server.rs
```

Framing limits are constants at the top of `server.rs`: a 16 KiB head budget with at most 100 headers, a 16 MiB body cap, a 10 second head timeout, and a 60 second body timeout. The deadlines ride on `RequestDeadlineStream`, a wrapper that adjusts the socket read timeout between the head and body phases, so an idle keep-alive gap never consumes the next request's budget. `POST` without `Content-Length` is a framing error, `Transfer-Encoding` is refused outright, and two conflicting `Content-Length` values abort the request. A partial request line is answered with `400 invalid request: malformed http request` when the 10 second budget expires; the trace below shows the measured 10.1 seconds.

Route classification is exact string matching (`classify`, `server.rs`): `/rest/` prefixes route to REST, `/api` and `/esplora` prefixes route to the two Esplora surfaces (`crates/rpc/src/esplora.rs:87`), and a bare `POST /` is JSON-RPC. Everything else, including every non-POST method on `/`, is 404.

## Listener surfaces and the connection budget

`RpcSurface` splits one binary into up to two listeners (`server.rs`). `Shared`, the default, serves everything. With `--public-bind`, the main `--rpc-bind` listener becomes `Management` and answers JSON-RPC only; the public listener becomes `Public`, serves REST and Esplora, and answers any JSON-RPC POST with 404. The split is decided in `bind_rpc_with_pool` (`crates/node/src/lifecycle.rs`) and each listener thread names its surface in the startup log (`rpc listener bound addr ... surface Shared`, verified in the trace below).

The accept loop keeps a connection budget in `ActiveConnections` (`server.rs`). A new connection is refused with `503 busy` when the total reaches `rpc_max_connections` (default 128, `crates/node/src/config.rs`), and one quarter of the budget is reserved for sources other than the busiest IP (`RESERVED_POOL_DIVISOR = 4`; `per_source_limit`). Refusals increment the `rpc.connections.rejected_total` gauge labeled by surface, and admitted connections raise `rpc.connections.active`, both visible on the metrics endpoint.

## Authentication

JSON-RPC requires HTTP Basic credentials. The cookie file written at `$DATA/.cookie` (or `--rpc-cookie`) holds one line `__cookie__:<64 hex chars>` generated from `OsRng` with mode 0600 (`crates/node/src/config.rs`); explicit `--rpc-user`/`--rpc-password` replaces it. A non-loopback bind without explicit credentials is refused at startup (`RpcNonLoopbackNeedsAuth`, `crates/node/src/config.rs`).

Validation compares both the username and a SHA-256 digest of the password with a branchless `constant_time_eq` (`crates/rpc/src/auth.rs:45-79`), so neither half leaks through timing. Three specifics an operator must know:

- Only the JSON-RPC route checks the header (`authenticate_json_rpc_head`, `server.rs`). REST, Esplora GET and POST, and CORS preflight are unauthenticated on every listener, as in Core; clause [API-08](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-08-bounded-public-exposure) owns that exposure rule.
- A request with credentials that fail pays a 250 ms delay before the 401 (`WRONG_CREDENTIALS_DELAY`); a request with no header fails immediately. The 401 carries `WWW-Authenticate: Basic realm="jsonrpc"` and `Connection: close` (`write_unauthorized`), and the server then drains the declared body up to 64 KiB within a 1 second budget before closing, so a pipelined request behind a refused one is never interpreted (`reject_unauthenticated_json_rpc`, `drain_request`).
- Bitcoin Core's salted `rpcauth=` line is not implemented; the compatibility surface is `rpcuser`, `rpcpassword`, and `rpccookiefile` in `bitcoin.conf` format ([RPC chapter, Authenticate](../use/rpc.md)).

One framing quirk follows from the parser: keep-alive requires the client to send `Connection: keep-alive` explicitly (`read_headers`, `server.rs`). An HTTP/1.1 client that omits the header gets one response with `Connection: close`. The keep-alive trace below shows both requests answered on one socket once the header is present.

## Envelope validation, batches, and the 16 MiB body

`handle_json` (`server.rs`) checks UTF-8, rejects JSON nesting deeper than 512 by a byte scan before parsing (`check_json_depth`), and parses with `sonic-rs`. Envelope rules live in `handle_single_json`: `method` must be a present string, `params` must be array, object, or null, and a non-null `jsonrpc` field must be `"1.0"` or `"2.0"`; the absent or null field selects the legacy dialect. A refused envelope answers `-32600` and never dispatches; clause [API-02](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-02-json-rpc-mechanics-and-the-wallet-free-surface) owns the rule set and Core's exact messages.

Batches are arrays processed in order (`handle_decoded_json`, `server.rs`). The limit is 1,000 members; larger batches are refused before any member runs. An empty batch answers `200 []`, a batch of only JSON-RPC 2.0 notifications answers `204` with no body, and a v2 notification member whose envelope is refused is dropped from the response, both matching Core's `IsNotification` gate. Parameter binding for named params is declared per method in the registry (`arg_names`, `registry.rs`) and resolved by `bind_named_params` (`crates/rpc/src/handlers.rs:161`).

## Execution classes

The registry tags each dispatchable row with an `Execution` class (`crates/rpc/src/registry.rs`), and that tag decides what the call may hold:

| Class | Dispatch | Guarantees |
|---|---|---|
| `Immediate` | plain function | no quota, no latch; `getblockcount`, `sendrawtransaction` |
| `Blocking` | cancellable + one blocking slot | `verifychain`, `gettxoutsetinfo`, `dumptxoutset`, `compressrawtransaction`, the three `waitfor*` calls |
| `Interruptible` | cancellable, no slot | `gettxoutproof`, `decoderawtransaction` keep the request latch without a blocking slot |
| `Scan` | cancellable, slot only for `action=start` | `scantxoutset`; `status` and `abort` never hold a slot |
| `LongPoll` | slot only for template+`longpollid` | `getblocktemplate` proposals and plain templates stay immediate |

The blocking budget is a counter, not a queue: `configure_blocking_admission` sets it to the per-source connection limit minus one (`crates/rpc/src/handlers.rs:50-52`), which is 95 slots at the default 128 connections. `reserve_blocking_request` (`handlers.rs:54`) refuses with `RPC blocking request limit reached` when the counter is exhausted, and the guard releases the slot on drop. Tests pin the two boundary behaviors: an exhausted budget still serves an `Interruptible` decode, and the refusal of a `scantxoutset` start keeps the connection alive because the connection carries no slot (`crates/rpc/src/server/tests.rs`).

Every cancellable dispatch receives `stop.reader()` from `Handler::dispatch` (`handlers.rs:107`), so `Handler::stop` (`handlers.rs:69`) unlatches parked `waitfor*` calls through `ActiveTipWait::wake_waiters`. The keep-alive consequences are visible on the wire: a classified blocking request sets `close` on the response (`registry::blocking_request`, `registry.rs`), so `gettxoutsetinfo` closes the connection after answering, while `decoderawtransaction` leaves it open. Wait-for-tip specifics, including the bounded-wait refusal, are owned by [API-34](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-34-active-tip-waits).

## The registry owns method status

`REGISTRY` (`crates/rpc/src/registry.rs`) is the single inventory for JSON-RPC, REST, and ZMQ rows; clause [API-01](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-01-single-manifest-owner) states the ownership rules. Each row binds a name, a feature gate, a status (`Supported`, `Deviation`, `Implemented (unverified)`, `Extension`, `Disabled`, `Unimplemented`), a `since` version, and per-method notes that carry the owning source path. Dispatch is the same table: `Handler::dispatch` finds the row, and a `None` handler answers `-32601 method not found` (`handlers.rs:82-89`). The manifest and the generated reference are projections of the same rows, and `crates/rpc/tests/manifest_coverage.rs` enforces set equality with live dispatch in both directions.

The `Supported` status is gated by `reference.differential_harness` in `crates/rpc/core-compat.toml`, which pins the released Core 31.1 artifacts the differential lane runs against. With the flag off, no row may claim `Supported`. `Implemented (unverified)` means the method ships and nothing more. The reference file is [docs/rpc-reference.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/rpc-reference.md); do not edit it by hand.

## Error codes and HTTP status

`RpcError` (`crates/rpc/src/error.rs:4`) maps to JSON-RPC codes in `code()` (`error.rs:61-91`): parse `-32700`, invalid request `-32600`, method not found `-32601`, invalid params `-32602`, internal `-32603`, then Core's application codes `-1`, `-3`, `-5`, `-8`, `-9`, `-10`, `-22`, `-25`, `-26`. HTTP status depends on the dialect (`error_status_for_code`, `server.rs`): the legacy dialect answers `-32600` with 400, `-32601` with 404, and everything else with 500; the v2 dialect answers dispatch errors with 200 and reserves 400 for envelope refusals. Tests pin each row of that table (`server/tests.rs`).

## Connection tracking and the shutdown drain

The accept loop tracks every live connection in `ConnectionTracker` (`server.rs`): a map from connection id to a cloned socket plus the connection thread handles. Shutdown is a latch, and three cancel hooks fire off it (`serve_accept_loop`): the handler stops (`Handler::stop`), the mio waker wakes the accept loop, and the tracker calls `shutdown(Read)` on every tracked socket (`wake_readers`). A reader parked on an idle keep-alive socket gets EOF and exits; a reader parked inside a cancellable handler gets the request latch. The loop then joins with a bounded drain: `drain_connections` waits at most `CONNECTION_DRAIN_DEADLINE` (5 seconds) for the exit counter, warns with exact counts if it is not satisfied,

```text
rpc connections exceeded the drain deadline drained=N pending=M
```

and joins whatever finished. The warning exists for handler threads that ignore both wakes; in the trace below an idle keep-alive connection drained immediately and the deadline was never reached. Idle-accept behavior, including prompt cancellation with a connected idle socket, is pinned by `serve_accept_loop_cancels_promptly_on_idle_socket` (`server/tests.rs`).

## Worked trace

A regtest node with default connection limits and `--rest=true` (cookie auth, `$DATA` data directory, `--rpc-bind 127.0.0.1:0` so the port is whatever the kernel assigns). Startup logs the real address and surface:

```text
{"message":"rpc listener bound","addr":"127.0.0.1:44895","surface":"Shared"}
```

One call per execution class, bodies trimmed, real replies:

```console
$ curl -sS -u "$COOKIE" -H 'content-type: application/json' \
    -d '{"method":"getblockcount","params":[],"id":1}' http://127.0.0.1:44895/
{"error":null,"id":1,"result":101}

$ curl -sS -u "$COOKIE" -H 'content-type: application/json' \
    -d '{"method":"gettxoutsetinfo","params":["none"],"id":3}' http://127.0.0.1:44895/
{"error":null,"id":3,"result":{"bestblock":"03b05555...70ac5","bogosize":7575,
"disk_size":12381,"height":101,"total_amount":5050.0,"transactions":101,"txouts":101}}

$ curl -sS -u "$COOKIE" -H 'content-type: application/json' \
    -d '{"method":"decoderawtransaction","params":["0200...0690"],"id":9}' http://127.0.0.1:44895/
{"error":null,"id":9,"result":{"hash":"101e9eb0...e6b8","locktime":0,"size":170,
"txid":"2b037755...0690","version":2,"vin":[{"coinbase":"5100",...}],"vout":[{"n...

$ curl -sS -u "$COOKIE" -H 'content-type: application/json' \
    -d '{"method":"getblocktemplate","params":[{"rules":["segwit"]}],"id":5}' http://127.0.0.1:44895/
{"error":null,"id":5,"result":{"bits":"207fffff","capabilities":["proposal","longpoll"],
"coinbaseaux":{"flags":""},"coinbasevalue":5000000000,...}}

$ curl -sS -u "$COOKIE" -H 'content-type: application/json' \
    -d '{"method":"scantxoutset","params":["status"],"id":6}' http://127.0.0.1:44895/
{"error":null,"id":6,"result":null}
```

The missing credential path, also from that run:

```console
$ curl -sS -i -d '{"method":"getblockcount","params":[],"id":1}' http://127.0.0.1:44895/ | head -2
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="jsonrpc"
```

Keep-alive and head timeout, measured with a raw socket client that sent `Connection: keep-alive` explicitly: two `getblockcount` requests answered on one socket, the second reply carrying `Connection: keep-alive`; a separate socket that sent only `POST / HT` got `HTTP/1.1 400 Bad Request` after 10.1 seconds, the 10 second head budget. Per-call latencies were not recorded in this trace; the endpoint's own histogram reported 15 JSON-RPC requests with a median of 125 microseconds under the route label `rpc_http_request_seconds{surface="shared",route="json_rpc"}`.

Shutdown with that idle keep-alive connection still open: the client stopped after its second reply and held the socket. On SIGTERM the drain closed it in the same second as the listener exit, and the connection thread joined cleanly:

```text
20:22:48.521789 INFO rpc listener exited cleanly
20:22:48.522371 INFO p2p listener exited cleanly
20:22:48.529182 INFO published clean chainstate checkpoint generation=1
20:22:48.533138 INFO bitcoin-rs node exited cleanly
```

The client's socket returned EOF at 20:22:48. No `rpc connections exceeded the drain deadline` line appeared; that warning has not been exercised live and is known from `drain_connections` (`server.rs`).

## REST, Esplora, and ZMQ boundaries

REST and Esplora run in the same connection thread after classification; they share the handler's `Context`, the block-render permits, and the connection budget, but each has its own admission rule.

REST (`crates/rpc/src/rest.rs`) is Core's read surface: 12 routes in `REGISTRATIONS` (`rest.rs:30`), `--rest` gates them (`route`, `rest.rs:48`), and the only POST is `/rest/getutxos.{bin,hex}` with a 2,048 byte body and 15 outpoints (`rest.rs:24-25`). An oversized POST body is refused at head-read time by the server (`RequestReadError::RestBodyTooLarge`, `server.rs`) with `getutxos request body exceeds 2048 bytes`. Full-block routes hold one of the two global block-render permits (`MAX_CONCURRENT_BLOCK_RENDERS`, `crates/rpc/src/context.rs`) and answer `503 too many concurrent full-block REST requests` when both are out; block bodies above the 4,000,000 byte response cap answer 500 (`rest.rs:28`, `bounded_block_body`, `rest.rs:224`). Status-code rules and the coherent-view rule are owned by [API-03](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-03-rest-dialect) and [docs/rest-interface.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/rest-interface.md).

Esplora has two surfaces behind one router (`crates/rpc/src/esplora.rs`): `/api` is the public dialect, `/esplora` the backend superset. Address and scripthash reads are the expensive class (`is_expensive`, `crates/rpc/src/esplora/admission.rs:54`); they take a node-wide permit before any chain-view capture (`route`, `esplora.rs:32-43`), with `--esplora-max-queries` as the cap and a default of 2 (`DEFAULT_MAX_QUERIES`, `esplora.rs:22`; observed as `esplora_max_queries: 2` in the trace node's boot config). An exhausted quota answers `503 expensive Esplora query limit reached` and increments `rpc.esplora.expensive.rejected_total`; the permit's lifetime is the `rpc.esplora.expensive.active` gauge and `rpc.esplora.expensive.execution_seconds` histogram (`admission.rs:22-51`). Only the public surface sends CORS headers, restricted to `GET, POST, OPTIONS` and `Content-Type` (`render_response_head` in `server.rs`); clause [API-09](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-09-esplora-dialects) owns the dialect split.

ZMQ is a publisher attached to mempool and chain events, not a request route. Endpoints are TOML-only; each PUB socket gets `SNDHWM` (default 1,000, `crates/rpc/src/zmq.rs:25`) and `LINGER 0` (`zmq.rs:319-330`). Every publish is `send_multipart(..., DONTWAIT)` (`zmq.rs:386`): a full endpoint queue drops that notification and logs it at debug,

```text
dropping ZMQ notification endpoint=... topic=rawtx error=...
```

and nothing upstream waits or retries; clause [API-04](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-04-zmq-notification-contract) owns the frame format. The mempool side of publication is the `MempoolSequenceObserver` gateway leg (`zmq.rs:493-540`), so a committed admission is also one `hashtx`, one `rawtx`, and one `sequence` event when those topics are configured. `getzmqnotifications` answers `[]` on a node with no endpoints (verified in the trace run).

## Failure modes

Exact refusal text, all from the read path or verified in the trace:

- `400 invalid request: malformed http request` for a head-phase i/o error such as the 10 second budget; `400 malformed http request` for body-phase framing errors (`handle_read_error`, `server.rs`).
- `401 Unauthorized` with `WWW-Authenticate: Basic realm="jsonrpc"` for JSON-RPC without valid credentials; REST and Esplora on the same socket are never 401.
- `404 not found` for any non-POST to `/`, unknown REST path, disabled REST, or a JSON-RPC POST on a `Public` listener; JSON-RPC POST on a `Management` listener is also 404 (`server.rs`).
- `503 busy` body on a refused connection from the accept loop (`server.rs`); `503 too many concurrent full-block REST requests` and `503 expensive Esplora query limit reached` from the render and Esplora permits.
- `-1 RPC blocking request limit reached` when the blocking budget is exhausted, with legacy HTTP 500 (`handlers.rs:54-60`, `server.rs`).
- Head framing refusals carry their own messages: `too many headers`, `unsupported transfer-encoding`, `conflicting content-length`, `missing content-length` for POST, `invalid content-length`, and `body too large` above 16 MiB (`server.rs`).

## Where it is proven

Behavior clauses: [API-01](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-01-single-manifest-owner) manifest ownership, [API-02](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-02-json-rpc-mechanics-and-the-wallet-free-surface) envelope and dialect rules, [API-03](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-03-rest-dialect) REST, [API-04](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-04-zmq-notification-contract) ZMQ, [API-08](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-08-bounded-public-exposure) public exposure, [API-09](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-09-esplora-dialects) Esplora dialects, [API-34](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-34-active-tip-waits) tip waits and blocking admission, [API-35](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-35-bounded-public-descriptor-utxo-scans) bounded scans. Execution-class membership is pinned by `scan_start_and_gbt_long_poll_are_blocking`, `tip_waits_are_blocking_requests`, and `transaction_inspection_keeps_the_latch_without_blocking_admission` in `crates/rpc/src/registry.rs`. The framing, batch, dialect, and auth rules cited above are test functions in `crates/rpc/src/server/tests.rs`, including `slow_drip_request_line_headers_and_body_expire`, `unauthorized_drain_consumes_exactly_the_declared_body`, `an_all_notification_batch_answers_204`, and `connection_admission_reserves_slots_for_other_peers`.

Not exercised here: the 503-connection budget refusal and the drain-deadline warning are known from source only; the differential lane (`differential_harness`) is off, so no `Supported` claim exists anywhere.
