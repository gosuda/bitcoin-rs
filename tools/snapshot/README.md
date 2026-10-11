# Bitcoin Core snapshot inspection and verification

`bitcoin-rs-snapshot` reads existing Bitcoin Core `dumptxoutset` portable v2
files without starting a node. It shares the production reader and UTXO
commitment implementation in `bitcoin-rs-utxo::core_snapshot`.

```sh
cargo run --locked -p bitcoin-rs-snapshot -- --help
cargo run --locked -p bitcoin-rs-snapshot -- inspect /snapshots/utxo-965000.dat
cargo run --locked -p bitcoin-rs-snapshot -- verify --network mainnet /snapshots/utxo-965000.dat
```

The separate executable is an optional tool: the normal node does not depend
on it. It needs no RPC endpoint, P2P peers, mempool, or mutable node data
directory. Input paths must name regular files, which are opened read-only.
It does not download, export, rewrite, or repair snapshots.

## What each command establishes

`inspect` reads only the header: format/version, network magic, base block
hash, declared coin count, and the filesystem's observed file size. A matching
compiled anchor is reported as `known_anchor`, but the contents are **not
verified**. Even a complete header followed by a truncated body can be
inspected. The Core header does not carry an authenticated height, UTXO
commitment, or cumulative transaction count.

`verify` requires an explicit expected network, decodes the entire file,
checks the declared and actual live output counts, and computes
`hash_serialized_3` over the existing decoded UTXO representation. The base
block hash selects a compiled network anchor. The computed commitment must
match that anchor; raw file SHA-256 is not the UTXO commitment. Reported base
height and cumulative transaction count come from the anchor, not the file.
Malformed data, unsupported format/network/base, duplicate/invalid outpoints,
bad amounts/heights, truncation, trailing bytes, resource-limit violations,
and commitment mismatches fail with a nonzero exit status.

A successful result means **pinned-state consistency**. This offline command
does not validate historical blocks from genesis to the snapshot base or
activate a node chainstate. The node's historical validation remains necessary
for that separate claim. Bitcoin-rs native v4 checkpoint files are not Core
portable files and are rejected by these commands.

## Script-friendly output

Both commands accept `--json`. Reports distinguish `validation: metadata_only`
from `validation: pinned_state_verified`, always report
`historical_validation_performed: false`, and include full verification data
only after success. Diagnostics go to stderr; failed operations emit no
success report on stdout.

| Exit status | Meaning |
| --- | --- |
| 0 | Requested inspection or pinned-state verification succeeded |
| 2 | Invalid command-line usage |
| 3 | Input open/type/metadata error, or report output error |
| 4 | Snapshot could not be parsed or verified, including a read failure |

Header inspection succeeding with status 0 does not imply status 0 from
`verify` for the same file.

## Supported compiled bases and provenance

Network parameters remain the single owner in
[`crates/primitives/src/network.rs`](../../crates/primitives/src/network.rs).
Mainnet bases are 840,000, 880,000, 910,000, 935,000, and 965,000. The first
four match [Bitcoin Core v31.1](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/kernel/chainparams.cpp),
and 965,000 comes from
[v32.0rc1](https://github.com/bitcoin/bitcoin/blob/d0231bb01d83178224bf7b198ba04f78cc2c89ef/src/kernel/chainparams.cpp).
The CLI also accepts testnet3, testnet4, signet, and regtest as explicit network
identities; verification succeeds only for a base that network actually pins.
Testnet4 has a 90,000 base, regtest has 110 and 200, and testnet3/signet have no
compiled bases. Listing a pin does not establish that a matching portable
snapshot is hosted or has been successfully verified here.

The process tests use the unmodified Core-produced regtest-200 artifact in
[`crates/utxo/tests/fixtures/core-v2`](../../crates/utxo/tests/fixtures/core-v2).
Its provenance and generator live beside the shared fixture. The expected
block hash is `385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9`,
with commitment
`17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a`,
200 live outputs, and 201 cumulative transactions. Small-fixture tests do
not establish mainnet artifact interoperability or resource use.

## Resource use and measurement

Inspection reads a fixed-size header. Full verification **materializes the
UTXO state in memory**. The shared decoder stages existing coin records until
their commitment matches the compiled anchor, then moves their payloads into
the UTXO set. It is not a constant-memory streaming verifier and does not need
a second on-disk chainstate. Reserve disk space for the source file and enough
RAM for decoded coins, scripts, the staging list, hash tables, and temporary
per-transaction sorting.

The shared reader's defaults bound encoded input to 32 GiB, live outputs to
250,000,000, aggregate decoded scripts to 32 GiB, and outputs per transaction
group to 1,000,000. These finite budgets are not an RSS quota and may exceed
available RAM on a particular host. `--max-file-bytes` and `--max-coins` pass
explicit overrides to that same reader; use smaller budgets when appropriate.
No allocation follows an unchecked file-provided count.

Measure the built executable separately from compilation. For example, on
Linux with GNU time:

```sh
cargo build --locked -p bitcoin-rs-snapshot
/usr/bin/time -v target/debug/bitcoin-rs-snapshot verify \
  --network regtest crates/utxo/tests/fixtures/core-v2/core200.dat
```

Record source SHA, binary/feature identity, input SHA-256 and file size, host,
elapsed time, and maximum resident set size with any reported result. GNU
time reports maximum RSS in KiB on Linux. The CLI's elapsed seconds cover
its read/verification work; filesystem bytes, decoded-state estimates, and
process RSS are different measurements. Mainnet time/RSS measurements are
not implied by the regtest result.
