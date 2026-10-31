# Contracts
`docs/contracts/` is normative; fix code drift in the same change; cite clauses, never duplicate contract text. Terms: [CONCEPTS.md](../../CONCEPTS.md).
## Precedence
`docs/contracts/` > source comments > `docs/policies/` > informative docs.
## Index
<!-- contract-index:start -->
- [architecture.md](architecture.md): `ARCH-01`–`ARCH-07`, `ARCH-07a`, `ARCH-07b`, `ARCH-08`–`ARCH-09`.
- [campaign-corpora.md](campaign-corpora.md): `CORP-00`–`CORP-06`.
- [chain-events.md](chain-events.md): `EVT-01`–`EVT-06`.
- [chainstate-journal-v1.md](chainstate-journal-v1.md): `JW-BOOT-1`, `JW-REC-1`, `JW-ORDER-1`, `JW-DUR-1`, `JW-ROT-1`, `JW-RET-1`, `JW-LIFE-1`, `JW-MARK-1`–`JW-MARK-2`, `JW-FAIL-1`.
- [consensus-difficulty.md](consensus-difficulty.md): `DAA-01`.
- [core-differential.md](core-differential.md): `CORE-01`–`CORE-06`.
- [dependency-range.md](dependency-range.md): `DEP-01`–`DEP-03`.
- [ecosystem-compatibility.md](ecosystem-compatibility.md): `ECO-01`–`ECO-09`.
- [embedding.md](embedding.md): `EMB-01`–`EMB-10`.
- [external-api.md](external-api.md): `API-01`–`API-35`.
- [feature-matrix.md](feature-matrix.md): `FEAT-01`–`FEAT-02`.
- [formal-verification.md](formal-verification.md): no clause IDs.
- [hot-path-attribution.md](hot-path-attribution.md): `HPA-01`–`HPA-13`.
- [indexing.md](indexing.md): `IDX-01`–`IDX-12`.
- [mempool-mutations.md](mempool-mutations.md): `MPL-01`–`MPL-04`.
- [mempool-policy.md](mempool-policy.md): `POL-01`–`POL-07`.
- [muhash-rpc.md](muhash-rpc.md): `MRPC-01`–`MRPC-03`.
- [p2p-wire.md](p2p-wire.md): `P2P-01`–`P2P-11`.
- [pool.md](pool.md): `POOL-01`–`POOL-09`.
- [qa-corpus.md](qa-corpus.md): `QAC-01`–`QAC-05`.
- [recovery.md](recovery.md): `RCV-01`–`RCV-15`.
- [reference-set.md](reference-set.md): `REF-01`–`REF-04`, `REF-06`–`REF-07`.
- [storage-footprint.md](storage-footprint.md): `FP-01`–`FP-04`.
- [synchronization.md](synchronization.md): `CONV-1`, `SYNC-01`–`SYNC-07`.
- [test-evidence.md](test-evidence.md): no clause IDs.
- [validation-default.md](validation-default.md): `VAL-01`–`VAL-03`.
- [wallet-facing.md](wallet-facing.md): `WF-01`–`WF-03`.
<!-- contract-index:end -->
Tests map to contracts, not tasks; see [test-evidence.md](test-evidence.md).

The [documentation ownership policy](../policies/documentation.md) assigns comments, defaults, operator guidance, and verification evidence to their owners. [Test evidence](test-evidence.md) retains the independent proof families; source and Cargo listings own executable case discovery.
