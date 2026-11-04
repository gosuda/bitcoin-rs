# Logs, metrics, and stalls

Logs are JSON lines on stderr. Metrics are a separate opt-in HTTP listener. The stall watchdog is a script outside the node that reads the log. Commands below write `$DATA` for the data directory you pass to `--data-dir`.

## Log format

Each line is one JSON object with a timestamp, a level, a message, and a target. Example startup lines, trimmed to the message field:

```json
{"level":"INFO","fields":{"message":"rpc listener bound","addr":"127.0.0.1:41701","surface":"Shared"},"target":"bitcoin_rs_node::lifecycle"}
```

Every line has the same shape: `timestamp`, `level`, `fields`, and `target`. The interesting text is usually `fields.message`; structured fields sit beside it. The line `opened storage backend with effective cache capacities` carries `backend`, `chainstate_dir`, and the cache byte counts. The line `bitcoin-rs node booting` carries the fully resolved `NodeConfig` in `config`.

`debug` output includes backend detail, for example an `Opening LSM-tree at ...` line with target `lsm_tree::tree`.

Two recurring lines are worth knowing. `sync progress` appears every 60 seconds and reports applied and header heights separately. `bitcoin-rs node booting` prints the fully resolved `NodeConfig`, which is the check described in [Configuration](configuration.md).

Logs go to stderr, not stdout. Redirecting only stdout leaves you with an empty file.

## Metrics

The metrics listener is off by default. Turn it on with `--metrics-bind`:

```sh
$ ./target/release/bitcoin-rs --network regtest --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --metrics-bind 127.0.0.1:19100
```

The listener serves Prometheus text on any request path. It has no separate bound-address log line; the resolved config dump shows `metrics_bind` as you configured it, so choose a fixed port. Scrape it with any HTTP client:

```sh
$ curl -s http://127.0.0.1:19100/
# HELP storage_writes_total storage write batches applied, by backend and durability
# TYPE storage_writes_total counter
storage_writes_total{backend="fjall",durability="durable"} 1
storage_writes_total{backend="fjall",durability="default"} 2

# HELP node_event_loop_sync_ticks block sync ticks
# TYPE node_event_loop_sync_ticks counter
node_event_loop_sync_ticks 2

# TYPE node_durable_head_commits counter
node_durable_head_commits 1
```

The response is `text/plain; version=0.0.4; charset=utf-8`. Metric names in the output use underscores, so the source name `node.sync.stall_seconds` is scraped as `node_sync_stall_seconds`. Histograms and summaries include quantiles; labels are closed enumerations such as backend, durability, surface, route, and capability state.

Enabling metrics also starts a readiness sampler that publishes the txindex capability state once per second. The scrape endpoint has no authentication and no path policy; bind it to loopback or a trusted network.

## Which layer gets the signal

[`docs/observability.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md) owns the boundary:

`metrics::` carries a small, stable set of operator signals: rates, totals, backlog gauges, and latency distributions. Names and semantics are an API. No per-event payload, block hash, txid, peer identity, or other high-cardinality value becomes a label ([`OBS-01`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md)).

`tracing::` carries diagnostics. Field names and levels may change without notice ([`OBS-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md)).

USDT probes carry detailed per-event payloads such as block hashes, txids, and message bytes ([`OBS-03`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md)). The probe ABI is owned by [tracing](https://github.com/gosuda/bitcoin-rs/blob/main/docs/tracing.md).

Measured hot-path histograms are the fixed exempt set of `OBS-04`, not added ad hoc ([`OBS-04`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md)). New instrumentation follows the decision table in [`OBS-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md), and renamed or removed metrics follow the migration table in [`OBS-06`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md).

## Capture a stalled node

The watchdog runs outside the node and watches a dedicated INFO log for `sync progress` against a monotonic deadline. After one missed deadline it collects evidence with GDB, detaches, and exits.

```sh
$ python3 scripts/watch_runtime_stall.py --pid 12345 \
  --log /path/to/this-node.log --output /path/to/private/evidence --timeout 180
```

The default 180 seconds allows three 60-second intervals. The tool needs Linux, Python 3.11 or newer, GDB, the matching executable, and debug symbols. It dry-attaches once to verify permission, then attaches again for the capture, so GDB pauses the target twice. It bounds GDB to 30 seconds plus five seconds for termination, 32 frames per thread, 16 MiB of output, and a 1 MiB log tail.

The capture writes `result.json`, `threads.txt`, `kernel-waits.txt`, and `telemetry-tail.log` into a fresh mode-0700 directory. A missed cadence is not a deadlock verdict: inspect the thread stacks for blocked call sites, then reconcile lock order with the source. Kernel wait channels are not userspace mutex-owner records, and a complete dump still may not name the owner of a `parking_lot` mutex.

This chapter does not run the watchdog; it needs a live stalled process and GDB permission. The procedure and its limits are owned by [runtime stall capture](https://github.com/gosuda/bitcoin-rs/blob/main/docs/operations/runtime-stall.md).

> **Warning** Debugger captures and log tails can reveal addresses, peers, and application state. Write them to a private directory and keep them out of shared artifact stores.

## Next

Use the public surfaces: [RPC](../use/rpc.md).
