# Optional compact-filter interoperability

Run this opt-in evidence lane on Linux (including WSL), with Python 3.10 or newer,
from the repository root.
It uses only public RPC and P2P interfaces; it does not import node internals.
Kyoto's `bip157` crate is unmodified and pinned to commit
`0169dc3514c8238147302535a1123d5c37468de6`. The small application driver supplies
a regtest genesis checkpoint, one loopback peer and a watched OP_2 script through
its public API. Its dependency graph is isolated from normal node builds.

Install the repository-pinned Bitcoin Core 31.1 using the existing
`scripts/install-bitcoind.sh` installer, then:

```sh
cargo build -p bitcoin-rs --features fjall
cargo build --locked --manifest-path tools/compact-filter-interop/Cargo.toml
python3 tools/compact-filter-interop/run.py \
  --bitcoind /path/to/bitcoin-core-31.1/bin/bitcoind \
  --bitcoin-rs target/debug/bitcoin-rs \
  --client tools/compact-filter-interop/target/debug/compact-filter-interop \
  --evidence /tmp/compact-filter-evidence
```

Use absolute binary paths if invoking the runner from another directory. The
runner creates disposable data directories, binds listeners to loopback, disables
peer discovery, and terminates its processes on completion or failure. Keep the
evidence directory: JSONL consumer events, process logs, wire-response digests
and `result.json` are the reproducible record. A smaller `--blocks 110` smoke run
does not exercise the 1,000/2,000 request boundaries or checkpoint intervals.

The default fixture contains 2,105 generated blocks plus a block with an external
prevout spend, a same-block child spend, duplicate scripts, an empty output and
OP_RETURN. The runner checks:

- Filter bytes and header commitments against Core for every active height,
  including genesis, after delayed activation, forced process death and reorg.
- Actual version service flags and no index directory when disabled; preservation
  of `NODE_NETWORK_LIMITED` and explicit rejection of pruning plus filters.
- Exact Core P2P response payloads for valid ranges/checkpoints, request limits,
  unsupported types, unknown stops and inverted ranges.
  Connection outcomes are recorded separately: Core 31.1 disconnects invalid
  requests without discouragement; bitcoin-rs deliberately ignores them and
  answers the subsequent ping. Payload equality alone does not establish
  connection-policy parity.
- Unmodified Kyoto syncing filters, matching the watched script and fetching its
  block against both implementations; a connected client following a reorg and
  a fresh client resynchronizing afterward.

Kyoto uses `version`/`verack`, `getheaders`, `getcfheaders`, `getcfilters` and
witness block `getdata`, and receives block announcements to follow new tips.
The separate wire probe also exercises `getcfcheckpt`, which this consumer does
not require. Serving this client does not add an SPV wallet to bitcoin-rs.

`result.json` measures local fixture import with the feature off/on, elapsed time
through index catch-up, delayed backfill startup, forced restart, reorg and
physical index bytes. These tiny regtest measurements are not a mainnet IBD
benchmark: hardware, build profile, OS cache, logging and fixture composition
affect them. Keep run-specific measurements with the PR or evidence artifact,
not as a permanent performance guarantee. Mainnet overhead remains unqualified.

The ordinary index suite also uses the unmodified Core v31.1 fixture at
`crates/index/tests/data/blockfilters-core-31.1.json`, from
<https://github.com/bitcoin/bitcoin/blob/v31.1/src/test/data/blockfilters.json>
(SHA256 `d9049756f744e561b882a8eff507582fb7cd74ed9cf5542bdac58257449ee2a2`).
It covers witness, genesis, duplicates, empty scripts and spent prevouts, and is
distributed under Bitcoin Core's MIT license. Run it with
`cargo test -p bitcoin-rs-index basic_filters_match_pinned_core_vectors`.

Enable serving with `--blockfilterindex` (boolean; default false). Only basic
filters on the active chain are supported. Catch-up/reconciliation refuses
queries instead of returning partial data; missing undo or a pruned prefix makes
only filters unavailable, preserving their rows while sibling indexes and validation continue. Restore
the required history and restart. Stale-block filters and `scanblocks` are not
implemented. See [the indexing contract](../../docs/contracts/indexing.md).
