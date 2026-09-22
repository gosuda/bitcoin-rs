# BIP300/301 enforcer on Betanet

This stack runs the bitcoin-rs node (`Network::Betanet`) together with the
unmodified [LayerTwo-Labs/bip300301_enforcer](https://github.com/LayerTwo-Labs/bip300301_enforcer)
binary, wired for betanet's eCash fork. The enforcer consumes the node's RPC
and `pubsequence` ZMQ stream and enforces the BIP300/301 rules the node does
not know about.

## Run

From the repository root:

```sh
cd tools/bip300301-enforcer
cp .env.example .env
docker compose up -d --build
```

The node and enforcer data directories are network-namespaced:
`../../data/bitcoin-rs/betanet` and `../../data/enforcer/betanet` (relative to
this directory). Published ports default to the betanet ports — RPC on
`127.0.0.1:8532`, P2P on `8533`, enforcer gRPC on `127.0.0.1:50051`, enforcer
RPC on `127.0.0.1:8122`.

The enforcer's mempool mode (`--enable-mempool`) requires the node to run with
`txindex=1`; the stack defaults `BITCOIN_RS_TXINDEX=true` for that reason.

## Fork boundary

Betanet shares mainnet history up to height **967,680** (exclusive). The fork
height lands exactly on a 2016-block retarget boundary (2016 × 480), so no
ordinary retarget ever disagrees with the fork rule. On the two sides of the
boundary:

- **Host-owned rules (bitcoin-rs node).** The node validates betanet
  consensus directly:
  - at height 967,680 the expected difficulty is the fixed fork target
    `0x19044b7e` (difficulty-1e9 reset) instead of the computed retarget;
  - `OP_NOP8` (`0xb7`) on a script that is exactly 4 bytes with `0xb7` as the
    first byte pushes `0xdc` and succeeds (the eCash enabler quirk);
  - transactions in the repurposed-txid set skip input-script verification.
- **Enforcer-owned rules (bip300301_enforcer).** Everything BIP300 (drivechain
  bundle proposal/accept/activation, withdrawals) and BIP301 (blind merged
  mining) — the node applies none of these; it only supplies chain data. The
  enforcer's `--network-preset` and the node's `BITCOIN_RS_NETWORK` must name
  the same network or the two sides will disagree at the fork.

## Enforcer pin and refresh

`Dockerfile.enforcer` clones the upstream enforcer repo and checks out
`ENFORCER_REVISION`. The compose default pins
`0e27251ef351a522c72ab9ef079f75e06075390f`, which has the `betanet` preset
(added upstream in `10f4cfb3`), postdates the removal of the `drynet` preset
(`b0467d60`), and includes mempool support.

To refresh the pin, set a new commit SHA in `.env` and rebuild only the
enforcer:

```sh
ENFORCER_REVISION=<new-commit-sha>
docker compose up -d --build enforcer
```

Always pin a full commit SHA — `master` builds are not reproducible.

## Drynet removal

The stack previously defaulted to `drynet4`. Upstream removed the drynet
preset from the enforcer (`b0467d60`), so `BITCOIN_RS_NETWORK=drynet4` is no
longer a usable value for this stack; the default and every volume/healthcheck
in `docker-compose.yaml` now target `betanet`. Existing drynet4 data
directories (`../../data/bitcoin-rs/drynet4`, `../../data/enforcer/drynet4`)
are left untouched but unused by this stack.

## Smoke checklist

Run from this directory with the stack up.

1. **Tips agree.** The node tip and the enforcer chain tip are the same block
   height/hash:

   ```sh
   # node (defaults from .env.example; adjust if you changed them)
   curl -s --user bitcoin-rs:password \
     --data '{"jsonrpc":"1.0","id":"c","method":"getblockchaininfo","params":[]}' \
     http://127.0.0.1:8532/
   curl -s -X POST -H 'Content-Type: application/json' -d '{}' \
     http://127.0.0.1:50051/cusf.mainchain.v1.ValidatorService/GetChainInfo
   ```

   Compare `blocks` in the first response with the chain height in the second.

2. **`pubsequence` carries C/D/A/R events.** The stream is reachable only
   inside the compose network (`tcp://node:29000`), so observe it through a
   throwaway subscriber on the compose network:

   ```sh
   docker run --rm --network bitcoin-rs_default python:3-bookworm sh -c \
     'pip install --quiet pyzmq && python -c "
import zmq
s = zmq.Context().socket(zmq.SUB)
s.connect(\"tcp://node:29000\")
s.setsockopt_string(zmq.SUBSCRIBE, \"\")
while True:
    topic, body = s.recv_multipart()[:2]
    label = chr(body[32]) if len(body) == 41 else \"?\"
    print(topic.decode(), label, body.hex())
"'
   ```

   The body frame is a reversed txid (32 bytes) + one label byte + a
   little-endian u64 sequence counter (41 bytes total). You should see `C`
   (block connected) / `D` (block disconnected) and `A` (mempool add) /
   `R` (mempool remove) labels as traffic arrives; a transaction mined into a
   block emits `C` only, no `R`.

3. **Enforcer restart keeps state.** The enforcer persists to
   `../../data/enforcer/betanet`, so a restart resumes rather than resyncs:

   ```sh
   docker compose restart enforcer
   docker compose logs --tail 50 enforcer
   ```

   After it comes back healthy, repeat check 1: the tip is unchanged (no
   rollback) and the logs show resumption from the existing data dir, not a
   cold rebuild.
