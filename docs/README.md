# Documentation

## Entry points

| Need | Owner |
| --- | --- |
| Build, configure, and run a node | [Getting started](getting-started.md) |
| Find a normative clause and its tests | [Contract index](contracts/README.md) |
| Understand project vocabulary | [Concepts](../CONCEPTS.md) |
| Inspect gate and evidence status | [Constraint register](../CONSTRAINTS.md) |
| Change the repository | [Agent guidelines](../AGENTS.md) and [contributing](../CONTRIBUTING.md) |
| Operate recovery or REST | [Recovery summary](chainstate-recovery.md) and [REST guide](rest-interface.md) |

The contract index owns the clause/proof map; this page does not maintain a
second inventory. Contracts take precedence over local source comments,
detailed policies, and informative guides, in that order. A disagreement
between code and contract is drift to investigate, not permission to silently
change either side.

## Detailed policies and generated inputs

[Source compatibility](policies/source-compatibility.md) owns toolchain,
dependency, TLS, and versioning policy. [Database migration](policies/db-migration.md)
owns format changes. Detailed admission and peer matrices live in
[mempool policy](policies/mempool-policy.md) and
[P2P compatibility](policies/p2p-compatibility.md).

Treat [core-compat.toml](api/core-compat.toml),
[core-rpc-schema.json](api/core-rpc-schema.json), and the
[hot-path ledger](benchmarks/hot-path-ledger.toml) as machine-consumed inputs.
[RPC reference](rpc-reference.md) is generated from
`crates/rpc/src/manifest.rs`; do not edit it by hand.

## Evidence and implementation status

[Benchmarks](benchmarks/) retain methods, measurements, and decisions.
[Solutions](solutions/) are historical context, not current implementation
promises. The [hot-path contract](contracts/hot-path-attribution.md) owns ledger
interpretation. `UNMEASURED`, `planned`, and `BLOCKED` are not successful results.

[Formal models](models/) and their configurations remain subject to the
[constraint register](../CONSTRAINTS.md). A compiled build is not proof of a
target design, and this index does not duplicate gate verdicts.

The default binary is kernel-free; library defaults are governed separately by
[validation-default.md](contracts/validation-default.md). The optional
`kernel` lane is not a claim that native-default promotion has passed.
BIP324 remains target work: there is no usable `bip324` Cargo feature in this
checkout.
