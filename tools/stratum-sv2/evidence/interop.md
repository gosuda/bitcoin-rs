# Native provider interoperability record

Functional regtest run on 2026-10-16, 09:40:21–09:42:42 UTC. This is not a
performance comparison. The exact provider binary and image, device image,
source base and changed production-file digests are in [identity.txt](identity.txt).
The builder resolved Rust 1.99.1, release profile and the standalone lockfile.
External pool/device pins are unchanged in Compose and `device/Dockerfile`.

## Observed behavior

- The final provider restored the existing Fjall volume at height 107. The
  pool completed Noise and TDP version-2 setup. Both distinct worker identities
  opened channels, received jobs, found shares and received `SubmitSharesSuccess`.
- Canonical native submission accepted 27 solutions, advancing height 107→134.
  Pool restart disconnected/reconnected TDP, after which both devices resumed
  shares and accepted blocks. No internal RPC client was used.
- Provider SIGINT at 09:41:24 exited with status 0 and published checkpoint
  generation 2. Restart restored height 122 with zero replayed records and
  mining continued. Final SIGINT published generation 3 and exited with status 0.
- During the provider restart, Docker reassigned the pool IP. The pinned SRI
  devices continued retrying their cached old address. Restarting the devices
  resolved it; this upstream limitation remains documented in the example.
- The pinned CPU devices required a kill after the stop timeout (status 137).
  Pool and provider exited with status 0. The test project was removed without
  deleting its data volume.

Adapter test coverage is listed in the [example README](../README.md). The
Compose run uses coinbase-only blocks; it does not independently demonstrate
those mempool cases over a live SRI connection. Translator interoperability
was not exercised.

## Commands and captured outputs

From the repository root, the run built the provider and the unchanged pinned
device, then tagged them for an isolated project:

```sh
docker compose -f tools/stratum-sv2/compose.yaml build template-provider device-direct-1
docker tag stratum-sv2-example-template-provider bitcoin-rs-1619-native-template-provider
docker tag stratum-sv2-example-device-direct-1 bitcoin-rs-1619-native-device-direct-1
docker tag stratum-sv2-example-device-direct-1 bitcoin-rs-1619-native-device-direct-2
docker compose -p bitcoin-rs-1619-native -f tools/stratum-sv2/compose.yaml up -d --no-build template-provider pool device-direct-1 device-direct-2
docker compose -p bitcoin-rs-1619-native -f tools/stratum-sv2/compose.yaml restart pool
docker compose -p bitcoin-rs-1619-native -f tools/stratum-sv2/compose.yaml stop --timeout 30 template-provider
docker compose -p bitcoin-rs-1619-native -f tools/stratum-sv2/compose.yaml start template-provider
docker compose -p bitcoin-rs-1619-native -f tools/stratum-sv2/compose.yaml restart --timeout 2 device-direct-1 device-direct-2
```

Full `docker logs` outputs for the final-image container lifetimes are retained
as [provider.txt](provider.txt), [pool.txt](pool.txt),
[device-direct-1.txt](device-direct-1.txt) and
[device-direct-2.txt](device-direct-2.txt). ANSI color codes and trailing whitespace
were removed; message contents and timestamps were retained. Source file
digests use checkout bytes, including line endings. The provider source was
unchanged by subsequent test and documentation edits.

## Evidence still required

The issue's matched RPC/native benchmark has not run. Mutation-to-candidate,
first-announcement latency, allocation counts and comparative CPU/peak-RSS
percentiles remain unmeasured. The retained per-job diagnostic timings and
single `/proc/1/status` snapshot cannot establish a speedup. Fresh versus reused
HTTP connections, identical candidate contents and repeated alternating runs
must be controlled before reporting performance gains.
