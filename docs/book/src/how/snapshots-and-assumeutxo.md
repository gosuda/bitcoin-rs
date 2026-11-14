# Snapshots and assumeutxo

Assumeutxo lets a node start from a UTXO snapshot instead of scanning every block. The node activates immediately on a snapshot whose bytes match a commitment compiled into the binary, serves the chain from it, and revalidates history in the background from genesis. Trust comes from the compiled commitment, never from the file: a snapshot whose base is not pinned is refused even if every byte decodes cleanly.

This chapter covers the Bitcoin Core-format reader, the activation flow, the two chainstate roles, and the offline import path. The normative rules live in [`ARCH-07b`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md). Checkpoint publication and the restore order are covered in [Checkpoints and recovery](checkpoints-and-recovery.md).

## Reading a Core-format snapshot

`crates/storage/src/utxo/core_snapshot.rs` reads Bitcoin Core's `dumptxoutset` output (magic `utxo\xff`, version 2, 51-byte header). The entry points:

- `read_metadata` reads only the fixed header: version, network magic, base block hash, coin count. It reports facts and claims nothing.
- `read_and_verify` decodes all records and checks the commitment.
- `read_verified` additionally recomputes CoinStats from the decoded coins and returns a `VerifiedCoreSnapshot`, the type the activation path requires.

`authenticate` (`core_snapshot.rs:255`) runs these checks, in order:

1. File size stays under `max_file_bytes` (32 GiB default, `SnapshotLimits`).
2. Magic is `utxo\xff` and version is 2; otherwise `InvalidMagic` or `UnsupportedVersion { version }`.
3. Network magic matches the node's network.
4. The base block hash must match a compiled anchor: `network.assume_utxo_for_hash(...)` returns `None` for anything else and the read fails with `snapshot base {base_hash} is not pinned for {network}`.
5. Per-record structural checks: canonical CompactSize encoding, Core VARINT field bounds, no empty transaction groups, groups in Core byte order, unique increasing vouts per txid (`DuplicateOutpoint { vout }`), coin height at or below the base height, compressed amounts in range, scripts at most 10,000 bytes, and uncompressed P2PK scripts must carry valid curve points.
6. Aggregate budget checks: at most 250,000,000 coins, at most 1,000,000 coins per txid, aggregate script bytes and total bytes within limits (`LimitExceeded { resource, actual, limit }`).
7. No trailing bytes.
8. The Core `hash_serialized` commitment, computed over the staged record stream, must equal the pinned anchor's `hash_serialized`; otherwise `CommitmentMismatch { expected, actual }`.

Step 8 is the load-bearing check: steps 1 through 7 bound resource use and reject structural garbage, but only the commitment binds the bytes to the pinned UTXO set. The pins live in `AssumeUtxoData` entries in `crates/consensus/src/primitives/network.rs`: mainnet ships heights 840,000 through 965,000; regtest ships height 110 and height 200 (block `385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9`, commitment `17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a`, 201 chain transactions). Testnet3 and Signet ship no pins, so snapshot loading is unavailable there.

## Activation

The RPC path is `loadtxoutset` (`crates/serving/src/handlers/chain.rs`), which routes through `crates/node/src/snapshot.rs:473`: `read_verified`, then `AssumeUtxoManager::activate_verified_snapshot` (`crates/execution/src/assumeutxo.rs:561`). The sequence:

1. The manager refuses unless disk status is `Uninitialized` (`require_unactivated`) and no full-revalidation marker exists (`AssumeUtxoError::AlreadyActive`, `FullRevalidationRequired`).
2. `install_snapshot` (`crates/execution/src/lib.rs:590`) takes admission and the chain-transition lock and checks the tip is settled: the durable head and the applied tip must name the same `(hash, height, tx count)`. A mismatch fails closed and returns `SnapshotTipNotSettled`; this is the "validating head refusal" in reverse, refusing activation while a head transition is unsettled.
3. The snapshot base must carry more accumulated chainwork than the current tip (`ActivationBehindTip`).
4. The installed coins are scanned; the scan must reproduce the pinned `hash_serialized`, or activation fails before anything is published. The snapshot-base checkpoint is then published (see below).
5. The durable head commits a row carrying `AssumeUtxoDiskStatus::Validating` and attestation `AssumeValid`, which makes the checkpoint live. The manager creates the `Historical` counterpart chainstate at genesis and the node continues.

The node now serves the chain from the snapshot while the historical chainstate revalidates from genesis. The RPC `getchainstates` projects this lifecycle: it reports the active and historical chainstates, their roles, heights, and validation progress as one coherent view (`crates/serving/src/registry.rs`, `API-33`). When history reaches the base height, the reconstructed `hash_serialized` and cumulative tx count must match the pinned metadata; the manager then marks the disk status `Finalized`, attests the durable head `Full`, and the active role decays from `AssumedActive` to `Ordinary` (`assumeutxo.rs:802-850`). On any historical failure the node marks itself `Failed` and refuses subsequent startups rather than serving an unverified base: `trusted_anchor` maps `Failed` to `SnapshotAnchorError::PreviouslyFailed` (`crates/execution/src/assumeutxo_snapshot.rs`).

## The snapshot-base checkpoint

Activation publishes a checkpoint at the snapshot base before the durable head commits the base. The checkpoint holds the engine coin image, the header tree up to the base, and the coin statistics scanned from the installed coins. Activation refuses before publishing if that scan does not reproduce the pinned `hash_serialized`. The checkpoint `CURRENT` file is written last, so a crash before it leaves no checkpoint the head names.

At boot the node resumes from that checkpoint. A base without its checkpoint refuses to open. The retired `assumeutxo/` coin and header archive is not written, read, or copied; datadirs that still hold it convert with `bitcoin-rs-storage-convert` (`4 -> 5`), which verifies the archive before publishing the checkpoint.

Readers of the checkpoint open files with `O_NOFOLLOW` on Unix and require a regular file.


## What "attest" means

The durable head row carries one `ScriptAttestation` byte (`crates/storage/src/durable_head.rs:14`): `Unattested` (0), `AssumeValid` (1), or `Full` (2). It records how far script validation of the certified chain has actually gone. Snapshot activation commits `AssumeValid`: the coins are bound to the pinned commitment, but the scripts that spent into them have not run. Full attestation lands only after real validation: either the historical chainstate finishes and matches the pin, or a cold replay of the committed gap over a restored chain completes (`crates/execution/src/durable.rs:679`).

The byte matters at startup. `require_full_script_attestation` (`crates/execution/src/recovery.rs:97`) loads it when the operator asks for full validation:

- attestation is `Full`: continue normally.
- attestation is below `Full` and the head names a still-`Validating` assumeutxo state: refuse with `full validation cannot revalidate an assumeutxo datadir that is still validating its historical suffix; restart with --validation-mode assume-valid or resync`. Rebuilding scripts under an unsettled snapshot would race the background validation; pinned by `crates/execution/src/durable/tests/revalidation.rs:629`.
- attestation is below `Full` otherwise: write the full-revalidation marker and cold-rebuild the chain with full validation (see [Checkpoints and recovery](checkpoints-and-recovery.md)).

Under assume-valid mode the node keeps running and only logs `the stored assume-valid chain is not fully script-validated; blocks the fast path skipped stay unverified`.

## Background chainstate roles

`ChainstateRole` (`crates/execution/src/assumeutxo.rs:57`) is `Ordinary`, `AssumedActive { base_height, base_hash }`, or `Historical { base_height, base_hash }`. Per `ARCH-07b`, exactly one chainstate is the active authority at all times: it alone drives mempool admission, mining templates, RPC and ZMQ chain effects, indexer updates, and pruning. The `Historical` chainstate validates with the same consensus connect path, holds its own coins and undo stores, and writes no live tip. Its validated body locators are archived as it advances, so a later restart resumes history from the archive plus a suffix instead of re-reading bodies.

Historical progress checkpoints reuse the checkpoint format in a separate namespace, `assumeutxo-historical-checkpoints` (see the recovery contract's `RCV` clauses and [`HISTORICAL_CHECKPOINT_ROOT`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/storage/src/checkpoint.rs)). By default the manager publishes one every 1024 historical blocks (`DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL`, `crates/execution/src/assumeutxo.rs:94`), records the accepted generation, height, and hash in the durable head, and retains earlier generations until the head accepts the replacement. Startup then restores the historical checkpoint before replaying only its certified suffix, so a datadir mid-validation resumes instead of starting history from genesis again. A reorg on the assumed-active chain cannot disconnect blocks at or below the snapshot base: the historical validation owns that prefix, and the refusal is `ApplyError::DisconnectBelowSnapshotBase`.

## Offline import

`--corpus`, `--manifest`, and `--state` (`bin/bitcoin-rs/src/config.rs`) must be given together; any one alone is a config error. This is `run_offline_import` (`crates/node/src/offline_import.rs:396`): replay a pinned archive of blocks offline, validate it fully, and certify the resulting state.

Preconditions (`validate_offline_import_config_and_manifest`): assume-valid height must be 0, auxiliary indexes (txindex, blockfilterindex, script index) must be off, and no stale persisted index may remain. The manifest must be one of two schemas, `core-framed-archive-manifest-v1` or `bitcoin-rs-corpus-manifest` v1, with the node's network name and magic, contiguous heights from `start_height` to `stop_height`, and the archive's SHA-256 and byte count.

The import then walks the archive record by record: each 80-byte header must hash to the manifest's entry hash, each framed record must sit inside consensus payload bounds, the whole archive must be consumed exactly, and the running SHA-256 must match the manifest. Blocks connect in batches of 128 under full validation. If the node already sits inside the manifest range, the resume check requires the applied tip to match that height's entry hash and the datadir to carry full-validation provenance; otherwise it refuses.

Certification (`verify_and_certify`, `offline_import.rs:969`) runs after the last block: the tip must equal the manifest stop entry, the stop block's body must be present, `verify_recent_blocks` with `CheckLevel::CheckUndoAndCommitments` must pass, and a stable-view scan recomputes txouts, total amount, MuHash, and `hash_serialized_3`. The result is a `CertifiedState` JSON written to `--state`, with `bodies_available` and `disconnect_ready` both true, plus a production checkpoint and a full-validation provenance row in the datadir. The import certifies the chainstate; it never activates a snapshot.

The pinned corpus this flow expects is a release-custody artifact owned by the reference-set campaign (`docs/contracts/reference-set.md`, `REF-*` clauses) and is not present on this machine. This chapter describes the flow from source and from `crates/node/src/offline_import.rs`; the end-to-end run was not exercised here.

## Worked traces

Two runs, both on regtest with the binary at HEAD (`$DATA` is the throwaway data directory):

Dump a snapshot at height 200. `dumptxoutset` writes Core v2 framing and reports the commitment:

```json
{"result":{"base_hash":"2de233db507cff01ad4032dec758cf4a70822b71a414fb342dfb98215a721773",
 "base_height":200,"coins_written":200,"nchaintx":201,
 "txoutset_hash":"1a507b2352f9e78004c43670146b7daaa070c3c5364bf57058a586c50bc3d10d"}}
```

Loading it fails because the freshly mined base is not a compiled pin:

```json
{"error":{"code":-22,"message":"invalid Core snapshot: snapshot base
 2de233db...721773 is not pinned for Regtest"}}
```

That refusal is the pin check doing its job: regtest pins describe one deterministic chain (heights 110 and 200), not whatever a local miner produced. The dump side is unrestricted: `dumptxoutset` writes whatever the applied tip holds, to an fsynced temporary sibling that is renamed into place without replacement; a destination under the `assumeutxo/` namespace is refused so an export can never overwrite recovery state. The successful full read of a genuine Core-produced regtest-200 snapshot, including the commitment and a 200-coin CoinStats reconstruction, is covered by `crates/storage/src/utxo/core_snapshot/tests.rs::genuine_core_dump_matches_compiled_anchor_and_full_state` (fixture `crates/storage/tests/fixtures/core-v2/core200.dat`, 14,439 bytes). That test ran at HEAD for this chapter.

## Failure modes

| Condition | Refusal | Error text |
| --- | --- | --- |
| Base not a compiled pin | load | `snapshot base {hash} is not pinned for {network}` |
| Commitment differs from pin | load | `snapshot commitment {actual} does not match pinned {expected}` |
| Wrong network magic | load | `snapshot network magic {actual:02x?} does not match {expected:02x?}` |
| Duplicate vout in a txid | load | `snapshot repeats output index {vout}` |
| Coin or script budgets exceeded | load | `snapshot {resource} budget exceeded: {actual} > {limit}` |
| Trailing bytes after last coin | load | `snapshot has trailing bytes` |
| Snapshot already active, or marker present | activation | `AssumeUtxoError::AlreadyActive`, `FullRevalidationRequired` |
| Durable head and applied tip disagree | activation, fail closed | `snapshot activation requires matching tip ...` |
| Base at or below current chainwork | activation | `snapshot base does not have more accumulated work than the applied tip` |
| Full validation requested while historical suffix unfinished | startup | `full validation cannot revalidate an assumeutxo datadir that is still validating its historical suffix ...` |
| Historical validation failed previously | startup | snapshot status `Failed` refuses the anchor |

## Where the invariants are proven

- `ARCH-07b` owns the roles and the single-active-authority invariant; the pin, commitment, and attestation rules above implement it.
- Snapshot reader: `crates/storage/src/utxo/core_snapshot/tests.rs`, including `forged_collision_families_never_enter_the_utxo_hash_table` (a collision family staged in the stream cannot enter the UTXO hash table), `all_limits_are_enforced_including_aggregate_scripts_and_header_bytes`, and `structure_and_record_semantics_fail_closed`.
- Activation and attestation: `crates/execution/src/assumeutxo/tests.rs` (unsettled-tip refusal pinned at line 740) and `crates/execution/src/durable/tests/revalidation.rs:629`.
- Contract and proof counts live in [`docs/contracts/evidence-index.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/evidence-index.md).

Differences from Bitcoin Core worth knowing: Core 31.1 accepts a snapshot whose per-txid coin groups contain repeated txids in ways this reader rejects as `TransactionOrder`, and Core derives the chain tip from the stream while bitcoin-rs derives it from the pinned anchor; recorded side by side in `docs/contracts/architecture.md` (API-33 evidence). Core also lets the background validation window reassign freely, while bitcoin-rs refuses disconnects below the snapshot base outright.
