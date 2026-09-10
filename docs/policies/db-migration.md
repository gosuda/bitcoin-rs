# Current Datadir Format Policy

`bitcoin-rs` supports exactly one persistent datadir format for authoritative chainstate bytes. It does not migrate, translate, or silently recover incompatible state from an older release. Fresh replay is the migration policy: a schema change increments `CURRENT_SCHEMA` and requires an explicit operator resync into a separately named directory.

## CURRENT_SCHEMA scope

`CURRENT_SCHEMA` covers only authoritative chainstate bytes: the durable head, the coin set it commits, body and undo extents and references, and their identity metadata. Owner-local state does not belong to this marker. Fee estimator state, peer discovery state, and index-only layouts carry their own versions (see the owner-local section below).

Every node datadir contains a small `CURRENT_SCHEMA` epoch record. Its current schema epoch is `0`. It is the sole authority for authoritative persistent-format compatibility. The node writes and syncs the marker before any authoritative store opens. Its file contents are synced everywhere; the containing directory is synced on platforms that expose a reliable directory-sync primitive.

Startup follows this contract:

| Datadir state | Startup action |
| --- | --- |
| Empty directory | Create and sync the current `CURRENT_SCHEMA` epoch, then initialize the current schema |
| `CURRENT_SCHEMA` matches the current epoch | Continue startup |
| Non-empty directory without `CURRENT_SCHEMA`, while epoch `0` is current | Treat the datadir as baseline epoch `0`, publish the marker, then continue startup |
| Non-empty directory without `CURRENT_SCHEMA`, while a later epoch is current | Treat the datadir as implicit epoch `0` and refuse open with `incompatible_schema` |
| Marker is malformed or has another epoch | Refuse open with `incompatible_schema` before opening persistent state |
| Current marker with no durable head | Start cold; this is normal before the first committed head |
| Durable head references missing or corrupt authoritative bytes | Refuse open with `incompatible_schema`; committed-range corruption is diagnosed, never silently accepted |

The node never deletes user data automatically. Schema incompatibility fails the open with `incompatible_schema`. The operator then follows the resync procedure below into a separately named directory. Network/backend datadir ownership and multi-process locking are separate configuration and lifecycle concerns; they are not encoded in `CURRENT_SCHEMA`. A future breaking change increments the single epoch and provides no conversion path. The initial unmarked format is the epoch `0` baseline: adopting it while epoch `0` is current does not require a migration or legacy reader. Once the epoch advances, an unmarked non-empty datadir is refused as implicit epoch `0`. Datadir ownership and process locking are tracked in [issue #242](https://github.com/gosuda/bitcoin-rs/issues/242).

The durable head is the only authoritative commit point. A writer appends body and undo frames, syncs those files and any required directories, then commits coins, head, and metadata in one atomic named-family batch and completes durability before publication. Until durability resolves, storage shows only the prior or the wholly proposed root, never a mix. A crash can leave append or temp residue. Recovery ignores orphan append tails: file length and discovered valid frames never promote a head. An unresolved batch resolves to the prior or the wholly proposed root.

## Owner-local versions and degrade behavior

Estimator, discovery, and index formats evolve outside `CURRENT_SCHEMA`. Each carries its own version:

- Fee estimator state carries an estimator-owned version. A corrupt, missing, or unknown version degrades to insufficient-data status. The node starts. It never fabricates a rate or a default confidence.
- Peer discovery state carries a discovery-owned version. A corrupt, missing, or unknown version degrades to seeded or empty discovery with a typed reseed or rebuild status. The node starts.
- Index-only layout changes increment `INDEX_FORMAT_VERSION` only. An unknown index version makes the affected capability report unavailable or rebuilding through the existing status vocabulary. The capability rebuilds from retained canonical data.

In every case:

- Authoritative startup never fails because of an owner-local version.
- Owner-local evolution keeps `CURRENT_SCHEMA` unchanged.
- No translator, converter, or legacy reader exists for any owner-local format.
- A rejected owner-local file stays in place until an explicit authorized rebuild. The node never silently deletes it.
- No backup or rotation framework exists. Recovery is reseed, rebuild, or re-admission from canonical data.

## Operator resync procedure

A `CURRENT_SCHEMA` change has no in-place path. The operator resyncs into a separately named directory:

1. Stop the node on the old datadir. Keep the old datadir untouched.
2. Create a separately named datadir for the new schema epoch.
3. Start the new binary against that datadir and replay the chain from the network, or from an explicit archive or reindex input.
4. Verify identity before use: the pinned stop identity (height and block hash), the durable head hash, and recorded body and undo digests must match the replay record.
5. The replay path fsyncs body, undo, and metadata bytes and their directories before the durable head commits.
6. Switch the manifest to the new store atomically. The switch touches the new store only.

The node performs the identity and digest verification, the fsync, and the atomic manifest switch. It never opens the old datadir with incompatible code.

## Existing datadirs are untouched

- Fresh replay writes only new or disposable data. The node never deletes, rewrites, or upgrades an existing operator datadir.
- An incompatible datadir fails the open with `incompatible_schema`. It is never opened, converted, or repaired in place.
- Existing operator databases and files stay exactly as the old binary left them.

## Current persisted formats

The marker covers the authoritative surfaces:

- KV chainstate uses the chainstate owner's current durable layout and has no historical translation layer.
- Flat block files use the current `BRSB` record format.
- Undo records use only the current undo codec.
- Block-body index rows must decode to 16-byte flat-file positions. That validation is lazy (per read, not a boot-time column-family scan): a non-decoding row is `IncompatibleData`, never a missing body.
- Owner-local state (fee estimator, peer discovery, index capabilities) persists under its own version fields (see the owner-local section).

Current readers still validate magic values, versions, filenames, lengths, hashes, checksums, ancestry, tips, and semantic invariants. Those checks detect corruption in the current format. They are not compatibility or migration machinery.

## Schema changes

A change is breaking when a current binary cannot parse or safely interpret bytes written by another version. This includes column-family names or discriminants, key/value layouts, block-file records, undo records, and every authoritative surface that `CURRENT_SCHEMA` covers.

`CURRENT_SCHEMA` covers only authoritative chainstate bytes. Estimator-only, discovery-only, and index-only format evolution keep `CURRENT_SCHEMA` unchanged: estimator state carries its own estimator-owned version, discovery state carries its own discovery-owned version, and index-only layouts increment only `INDEX_FORMAT_VERSION`. A corrupt, missing, or unknown owner-local version never fails authoritative startup. The estimator degrades to insufficient-data. Discovery degrades to seeded or empty with reseed or rebuild. An affected index capability reports unavailable or rebuilding through the existing status vocabulary and rebuilds from retained canonical data. No legacy reader, converter, or translator exists. A rejected owner-local file stays in place until an explicit authorized rebuild and is never silently deleted. No backup or rotation framework is introduced. Explicit fresh replay for authoritative chainstate is unchanged.

For every breaking change:

1. Increment the datadir schema epoch.
2. Keep one current writer and one current reader.
3. Do not add an in-place converter, legacy reader, compatibility adapter, or automatic fallback for existing state. `Cold` is only the result of no committed durable head, including an unpublished first write.
4. Keep current-format integrity and corruption tests.
5. Document that operators must follow the resync procedure above into a separately named directory.

The `Cold` path is for a datadir with the current marker and no committed durable head. It is also the recovery result for a store containing only unpublished residue. It is not a compatibility mode for an old schema or for a head that references invalid state.

## Schema history

| Epoch | Change | Status |
| --- | --- | --- |
| `0` | Initial baseline format. An unmarked non-empty datadir adopts it while it is current. | current |
| `1` | T14 moves authoritative chainstate bytes to the chainstate owner's durable store. The checkpoint commit point is replaced by the durable head. Open refuses with `incompatible_schema`; explicit operator resync is required. | planned |
