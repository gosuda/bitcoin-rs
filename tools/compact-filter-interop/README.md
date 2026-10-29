# Optional compact-filter interoperability

Run this opt-in evidence lane on Linux (including WSL), with Python 3.10 or newer,
from the repository root.
It uses only public RPC and P2P interfaces; it does not import node internals.
Kyoto's `bip157` crate is unmodified and pinned to commit
`0169dc3514c8238147302535a1123d5c37468de6`. Its dependency graph is isolated
from normal node builds.

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
does not exercise the 1,000/2,000 request boundaries.

`result.json` records fixture import time, elapsed time through index catch-up,
delayed backfill startup, forced restart, reorg and physical index bytes. These
tiny regtest measurements are not a mainnet benchmark; mainnet overhead remains
unqualified.

The pinned Core v31.1 fixture lives at
`crates/index/tests/data/blockfilters-core-31.1.json`. Run it with
`cargo test -p bitcoin-rs-index basic_filters_match_pinned_core_vectors`.

Enable serving with `--blockfilterindex` (boolean; default false). Only basic
filters on the active chain are supported. Catch-up/reconciliation refuses
queries instead of returning partial data; restore the required history and
restart. Stale-block filters and `scanblocks` are not implemented.
See [the indexing contract](../../docs/contracts/indexing.md).
