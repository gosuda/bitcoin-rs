# Contracts
`docs/contracts/` is normative; fix code drift in the same change; cite clauses, never duplicate contract text. Terms: [CONCEPTS.md](../../CONCEPTS.md).
## Precedence
`docs/contracts/` > source comments > `docs/policies/` > informative docs.
## Index
<!-- contract-index:start -->
- [architecture.md](architecture.md): `ARCH-01`–`ARCH-07`, `ARCH-07a`, `ARCH-07b`, `ARCH-08`–`ARCH-09`.
- [atomic-ownership.md](atomic-ownership.md): `BLK-01`–`BLK-08`, `SCR-01`–`SCR-06`, `WIN-01`–`WIN-08`, `CMT-01`–`CMT-09`, `REO-01`–`REO-06`, `PRJ-01`–`PRJ-13`, `QRY-01`–`QRY-08`, `SNP-01`–`SNP-11`, `BUD-01`–`BUD-07`, `MPS-01`–`MPS-04`, `MOD-01`–`MOD-05`.
- [chain-events.md](chain-events.md): `EVT-01`–`EVT-06`.
- [core-differential.md](core-differential.md): `CORE-01`–`CORE-07`.
- [dependency-range.md](dependency-range.md): `DEP-01`–`DEP-03`, `FEAT-01`–`FEAT-02`.
- [ecosystem-compatibility.md](ecosystem-compatibility.md): `ECO-01`–`ECO-09`.
- [embedding.md](embedding.md): `EMB-01`–`EMB-10`.
- [external-api.md](external-api.md): `API-01`–`API-37`.
- [formal-verification.md](formal-verification.md): no clause IDs.
- [indexing.md](indexing.md): `IDX-01`–`IDX-12`.
- [mempool-mutations.md](mempool-mutations.md): `MPL-01`–`MPL-04`.
- [mempool-policy.md](mempool-policy.md): `POL-01`–`POL-07`.
- [p2p-wire.md](p2p-wire.md): `P2P-01`–`P2P-11`.
- [pool.md](pool.md): `POOL-01`–`POOL-09`.
- [qa-corpus.md](qa-corpus.md): `QAC-01`–`QAC-05`.
- [recovery.md](recovery.md): `RCV-01`–`RCV-15`.
- [reference-set.md](reference-set.md): `REF-01`–`REF-04`, `REF-06`–`REF-07`.
- [storage-footprint.md](storage-footprint.md): `FP-01`–`FP-04`.
- [synchronization.md](synchronization.md): `CONV-1`, `SYNC-01`–`SYNC-07`.
- [test-evidence.md](test-evidence.md): no clause IDs.
- [validation-default.md](validation-default.md): `VAL-01`–`VAL-03`, `DAA-01`.
- [wallet-facing.md](wallet-facing.md): `WF-01`–`WF-03`.
<!-- contract-index:end -->
Tests map to contracts, not tasks; see [test-evidence.md](test-evidence.md).

The [documentation ownership policy](../policies/documentation.md) assigns comments, defaults, operator guidance, and verification evidence to their owners. [Test evidence](test-evidence.md) retains the independent proof families; source and Cargo listings own executable case discovery.
