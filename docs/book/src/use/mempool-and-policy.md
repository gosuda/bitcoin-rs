# Mempool policy

The node's mempool policy is compiled in and has no operator tuning flags. The only mempool options are persistence: `--persist-mempool` and the two snapshot limits.

## What the node enforces

`getmempoolinfo` projects the enforced snapshot:

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":30,"method":"getmempoolinfo","params":[]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result'
{
  "bytes": 0,
  "fullrbf": true,
  "incrementalrelayfee": 0.00001,
  "limitclustercount": 64,
  "limitclustersize": 101000,
  "loaded": true,
  "maxdatacarriersize": 83,
  "maxmempool": 300000000,
  "mempoolminfee": 0.00001,
  "minrelaytxfee": 0.00001,
  "optimal": true,
  "permitbaremultisig": true,
  "size": 0,
  "total_fee": 0.0,
  "unbroadcastcount": 0,
  "usage": 0
}
```

Those values come from `MempoolLimits::default()` and the enforced standardness policy:

| Limit | Value |
| --- | --- |
| Total pool capacity | 300,000,000 bytes of estimated usage. |
| Minimum relay fee | 1,000 sat/kvB, charged on modified fees with integer truncation. |
| Incremental relay fee | 1,000 sat/kvB. |
| Cluster count | 64 transactions per connected component. |
| Cluster size | 101,000 vbytes, equal to 404,000 sigop-adjusted weight units. |
| Replacement work bound | At most 100 direct-conflict clusters. |
| Expiry | Entries strictly older than 336 hours expire after committed admission and during reorg trim. |
| Data carrier | At most 83 bytes. |
| Bare multisig | Permitted. |
| Full RBF | Always on; signaling does not decide admission. |
| Ordering | Exact graph ordering, reported as `optimal: true`. |

Sigops are bounded per transaction at 16,000 BIP141 cost. Policy weight is `max(wire_weight, sigops * 20)`, and policy vsize is that weight divided by four, rounded up. TRUC rules apply to versions 1 through 3: a root is at most 10,000 adjusted vbytes, a child at most 1,000, and at most one unconfirmed ancestor and one descendant are allowed. Ephemeral dust allows one dust output only when both base and modified fees are zero, and a child must spend all of it.

Packages are scoped. `submitpackage` accepts a singleton or one parent and one child, with Core individual-first partial acceptance. Wider packages, replacement inside a package, and capacity eviction are refused. `testmempoolaccept` previews without mutating membership, the estimator, or relay state.

## Where this differs from Core

These differences are deliberate:

- Full RBF is unconditional. BIP125 metadata is still reported when present, but it does not gate replacement.
- There are no separate 25-ancestor, 25-descendant, or ancestor-size admission limits. The cluster count and cluster size bounds replace them.
- Capacity accounting uses dynamic memory usage in bytes, not virtual size. Refusal is atomic; Core's speculative insert-and-trim side effects are not reproduced.
- Graph linearization is exact-optimal and does not emulate Core's bounded work-budget search or transient tie decisions.
- The rolling minimum fee follows Core's eviction and trim bumps and post-block decay, measured against the same usage.
- Package submission is narrower than Core's, as described above.
- The node has no wallet, so wallet RPC and wallet-funded replacement do not exist.

Replacement errors include `insufficient fee`, `replacement-failed`, `too many potential replacements`, `TRUC-violation`, and `too-large-cluster`. TRUC fee and count failures append ` (including sibling eviction)`. These strings and the boundaries are owned by [docs/policies/mempool-policy.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/mempool-policy.md) and the [mempool policy contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md). Process tests compare named cases against the pinned Core settings; they do not claim default or performance equivalence.

## Persistence

`--persist-mempool` defaults to `true`. The TOML key is `persist_mempool`; the environment name is `BITCOIN_RS_PERSIST_MEMPOOL`.

The snapshot lives at `<data-dir>/mempool-snapshot.dat`. The node writes it only during a clean shutdown, and only when teardown has recorded no error. It also saves fee-estimator history in the same data directory at shutdown.

At startup the node restores the snapshot within two bounds:

- `--mempool-snapshot-max-mb` caps the file at 64 MiB by default.
- `--mempool-snapshot-restore-timeout-secs` caps restore time, defaulting to `max(60, max_mb)` seconds, which is 64 with the default size.

Restored entries are revalidated against the chain before admission. If the snapshot is larger than the budget, the node saves complete transaction families that fit and logs `mempool snapshot capacity reached; saving complete families within the budget`. A snapshot that fails to decode is moved to a `mempool-snapshot-rejected-*` directory and the node starts with an empty pool. A fresh node logs:

```
INFO bitcoin_rs_node::state::open: no mempool snapshot; starting with an empty pool status="missing"
```

> **Warning**: This snapshot is not a durable transaction store. A crash or `kill -9` skips the save, and a node that starts empty does not rebroadcast transactions it no longer holds. Submit important transactions through a path that can retry.

The `savemempool` RPC is unimplemented; persistence is a startup and shutdown behavior. The snapshot format is native and is not Core's `mempool.dat`.

## Inspect and test

`getrawmempool` lists txids or verbose entries. `getmempoolentry` returns one entry, and `getmempoolancestors` and `getmempooldescendants` read the cluster in both directions. `getmempoolinfo` reports `loaded`, `usage`, and the current `mempoolminfee`.

Preview a transaction before broadcast:

```
$ curl -s --user book:bookpass --data-binary "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"testmempoolaccept\",\"params\":[[\"$hex\"]]}" -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result[0]'
{
  "allowed": false,
  "reject-reason": "script-verify-flag-failed",
  "txid": "62ec9f19431503e7dca3db0ca892a9dafbd43e06d8b75f244b1306cf2c73241a",
  "wtxid": "62ec9f19431503e7dca3db0ca892a9dafbd43e06d8b75f244b1306cf2c73241a"
}
```

Rejected preview rows omit fee and size. Accepted rows carry the modified effective feerate and wtxid. Unfinished package rows carry only txid, wtxid, and an optional `package-error`. A transaction above the standard weight parses normally and previews as one rejected row with `reject-reason` and `reject-details` both `tx-size`; the request itself answers 200 (`testmempoolaccept_reports_core_tx_size_on_the_oversize_row`).

The operator-facing differences are mapped in [docs/policies/mempool-policy.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/mempool-policy.md). Admission, publication order, and preview purity are owned by the mempool contracts starting at [POL-02](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md). Mutation publication order is owned by [docs/contracts/mempool-mutations.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-mutations.md).

Next: [Configuration keys](../reference/config-keys.md) lists the persistence keys in TOML and environment form.
