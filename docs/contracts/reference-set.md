# Reference set contract

A readable projection of the `[reference]` record in
`docs/api/core-compat.toml` and its typed validation in
`bin/bitcoin-rs/tests/support/reference_set.rs`. `ReferenceSet` is the parsed
identity record used by the test and formal gates. It is not a separate
registry and not a new public type.

This page is a readable projection only. On conflict,
`docs/api/core-compat.toml` governs the reference values and
`bin/bitcoin-rs/tests/support/reference_set.rs` governs their typed validation.
A version label alone is never custody.

## Clauses

### `REF-01`: Manifest values and parser validation govern

- The `[reference]` record in `docs/api/core-compat.toml` is the
  machine-readable authority for reference identity values.
- `bin/bitcoin-rs/tests/support/reference_set.rs` is the typed parser that
  enforces required identities, complete source commits, digest formats,
  corpus presence, product versus kernel-tree separation, and audited
  fingerprints of each complete source-and-artifact identity tuple. The RPC
  corpus gate compiles this same test support module to validate its capture
  provenance.
- `docs/contracts/reference-set.md` is a readable projection. It does not
  override the manifest values or parser validation on conflict.
- A version label alone is never custody. A reference must carry source and
  binary identities.

### `REF-02`: Core 31.1 product reference

The released Bitcoin Core 31.1 reference is the pinned product oracle,
recorded under `[reference.release]` in the manifest:

- `core_version = "31.1"` — a released `MAJOR.MINOR` product version
- `git_tag = "v31.1"`
- `source_commit = "9be056a8a72b624dae9623b2f7bded92c2a21c91"`
- `archive = "bitcoin-31.1-x86_64-linux-gnu.tar.gz"` with `archive_sha256`
  `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`
- `bitcoind_sha256`
  `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`
- `version_output = "Bitcoin Core daemon version v31.1.0 bitcoind"`

This is the behavioral reference. No compatibility claim may be made against a
version string or a source snapshot alone.

The checked-in RPC captures retain their own `core_source_commit`,
`core_binary_sha256`, version, regtest inputs, and allowed differences.
`crates/rpc/tests/support/fixture.rs` compares that provenance to the selected
release through the shared parser. Changing the reference leaves an old
capture stale and fails its gate; it does not relabel the recorded response.
The process harness separately hashes the actual executable before launch.
The parser also fingerprints the complete release tuple using NUL-separated
UTF-8 fields under the `bitcoin-rs/reference-release/v1` domain. Consequently,
a different but well-formed source commit or artifact digest is a custody
mismatch, not a valid new reference.

### `REF-03`: Core 31.99.0 kernel tree evidence

The kernel oracle is a development tree identity, not a released product,
carried by the scalar keys of `[reference]` itself:

- `core_version = "31.99.0"`
- `kernel_crate = "bitcoinkernel"` at `kernel_crate_version = "0.2.1"`
- `kernel_sys_crate = "libbitcoinkernel-sys"` at
  `kernel_sys_crate_version = "0.3.0"`
- `kernel_vendor_commit = "4b51ffdddfa82b84a03a1fa76bbfa72a4f0b6ccf"`
- `kernel_source_commit = "fb0e8612d6f74071af77b3f27d915da69e0a726b"`
- `kernel_sys_crate_sha256 = "2906bc31f02dff7af9611fe9129c9eae021bd359f9d8e79824026fe1aaf28ab1"`
- `differential_harness = false`

The published crate's `.cargo_vcs_info.json` identifies the vendor revision.
Its [subtree import](https://github.com/sedited/rust-bitcoinkernel/commit/691b006f271c6d19565266541d7397eaf0c64944)
records the Bitcoin Core revision in `git-subtree-split`. The reference gate
checks the package digest against `Cargo.lock`; source and package identities
are additionally covered by one NUL-separated, domain-separated
`bitcoin-rs/reference-kernel/v1` fingerprint and must be reviewed together on
an oracle upgrade. Build options remain owned by
that pinned crate's `build.rs`, including its static `RelWithDebInfo` kernel
build with wallet, daemon, tests, and IPC disabled.

This identity is used only for differential evidence. It is not a policy pin,
it is not a stable release, and it must never be read as the `REF-02` product
reference.

### `REF-04`: Corpus identities

The product corpora are defined in
[`campaign-corpora.md`](campaign-corpora.md) and recorded as
`[[reference.corpora]]` rows pinned by `id`, `stop_height`, and `stop_hash`:

- `C150`: mainnet blocks `0 .. 150,000`; stop hash
  `0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b`;
  `muhash` `383a0b41ac28ddf6ac91723b41527fa64c0b54451cee5f2c4b3823ef92117116`.
  The C150 oracle is the first certified Core 31.1 `gettxoutsetinfo`
  response at height 150,000.
- `Cmodern`: mainnet blocks `0 .. 709,635`; stop hash
  `00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f`.
  The Cmodern oracle is the first certified Core 31.1 `gettxoutsetinfo`
  response at height 709,635. A cell may not close on a guessed or recalled
  UTXO total.

`manifest_sha256` is optional until the archive exists. C150 carries its
exported digest; Cmodern has no exported digest yet. `corpus_custody()` in
`bin/bitcoin-rs/tests/support/reference_set.rs` reports such a corpus as
`Blocked { missing: "manifest_sha256" }` rather than inventing a digest.

Each corpus archive uses the Core-framed format with a manifest digest
produced at export time. A length-prefixed diagnostic file is not a product
corpus.

### `REF-06`: Formal tool identity

- `name = "apalache-mc"` at `version = "0.62.2"`
- `archive_sha256`
  `7cfadf6e8c04c63f05ac907ec9541c66297005c8cb5efb1731f6a838dfc3fad2`
- `jar_sha256`
  `079b6c2320252469dcf79afec6886b8255d3dd1b34a9484433c88986752efaa8`
- Observed Java runtime: `26.0.2.1`

This is an evidence tool pin. No checker run is claimed by this page.

### `REF-07`: Pinned mainnet stop and custody rule

- The default unpruned full-tip storage evidence in T39 uses a pinned mainnet
  stop. The stop is `(height, block_hash)` recorded by the run. No stop may be
  floating or unpinned. The 1 TB budget applies only to that pinned default
  lane.
- Missing identities, malformed commits or digests, unbound custody tuples,
  and confused product identities are rejected with a typed `ReferenceError`
  from
  `bin/bitcoin-rs/tests/support/reference_set.rs`. The fixture gate rejects
  stale capture provenance, and the process harness rejects missing binaries
  or executable hashes that differ from the selected reference.
- The 31.1 product reference and the 31.99.0 kernel tree are distinct. No
  test may claim product parity against the kernel tree identity.
- Known deviations are explicit. No status in the manifest upgrades to
  `supported` while `differential_harness = false`.
  - `REF-07a`: reply values are compared after successful transport; any
    difference is behavioral evidence and is not transport success.
  - `REF-07b`: startup reports and reaps an early child exit, including a
    successful exit before readiness.
  - `REF-07c`: readiness and each reference request are deadline-bounded;
    expiration reports the deadline and reaps startup children.
  - `REF-07d`: malformed HTTP, JSON, or P2P envelopes are transport/protocol
    errors, not behavioral comparisons.

## Proven by

- `docs/api/core-compat.toml`: the machine-readable reference identity values.
- `bin/bitcoin-rs/tests/support/reference_set.rs`: typed parsing and custody
  validation for those values.
- `bin/bitcoin-rs/tests/overhaul_reference_set.rs`: rejects label-only,
  malformed, and well-formed-but-unbound identities, checks kernel package
  custody, and pins `corpus_custody()` honesty.
- `crates/rpc/tests/support/fixture.rs`: rejects missing or stale capture
  provenance against the same selected release.

- `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: ordinary binary startup,
  signed RPC admission/confirmation/query, missing/substituted reference,
  deliberate reply difference, early exit, malformed response, and total
  request-deadline controls (REF-07a–d).
- `bin/bitcoin-rs/tests/overhaul_process_p2p.rs`: the same signed transaction
  enters each real binary through its loopback P2P listener, is observed in
  its public mempool, and is confirmed by identical Core-mined block bytes.
  RPC compares tip, transaction, and spent-output state; the candidate's
  explorer HTTP status is checked against that public chain evidence. This
  is not a claim to execute an independent Esplora server.
- `bin/bitcoin-rs/tests/support/process_peer.rs`: independent rust-bitcoin v1
  framing, one deadline per handshake/transaction barrier, bounded frames,
  message count and transcript, and socket custody. Fault cases cover
  malformed/truncated frames, wrong network/checksum, oversized lengths,
  fragmented responses, and cleanup after a connected-peer timeout.
- `target/process-harness/run-*/`: `launch.json` records both loopback binds,
  binary digest and arguments; `transcript.jsonl` records RPC/explorer calls;
  `p2p.jsonl` records ordered wire attempts, completed sends and receives.
  Both transcripts use the same process-relative `at_micros` clock. The
  existing required PR test profile runs these scenarios without an opt-in
  flag and preserves this directory as a CI artifact, including on failure.

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
`ReferenceSet`, oracle, product reference.
