# Evaluate bitcoin-rs locally

Use regtest to explore startup and public reads without a mainnet migration or
real wallet keys. This walkthrough is source-reviewed, not a recorded successful
node run. Record actual results before describing it as a verified quickstart.

The source reference for these commands is
[`f599c9d`](https://github.com/gosuda/bitcoin-rs/commit/f599c9d5906f999e35fed86ab6cd1f247d051a3a).
[Getting started](getting-started.md) owns setup guidance; the
[embedding](contracts/embedding.md), [wallet-facing](contracts/wallet-facing.md),
and [validation-default](contracts/validation-default.md) contracts own behavior.

## Prepare the environment

Use Bash on a supported Unix-like environment, Git, curl with `--fail-with-body`
support, and the repository's stable Rust toolchain. The reviewed workspace
requires Rust 1.95.0 or newer; see
[source compatibility](policies/source-compatibility.md) and
[build prerequisites](../CONTRIBUTING.md#prerequisites).

The command below deliberately selects the minimal native binary lane: `fjall`
only, without the default `zmq` extension or the optional kernel. Kernel-free
does not mean every transitive dependency is Rust-only. Library defaults differ.

Use a fresh directory. Do not reuse an operator datadir, import private keys,
or expose the RPC port to a public or shared-network listener. Review any
inherited `BITCOIN_RS_*` environment settings before starting; this example
assumes no authentication or notification overrides.

## Terminal 1: build, then start

```sh
git clone https://github.com/gosuda/bitcoin-rs.git
cd bitcoin-rs
git checkout --detach f599c9d5906f999e35fed86ab6cd1f247d051a3a
cargo build --locked --profile quickstart -p bitcoin-rs \
  --no-default-features --features fjall
```

Stop if a command fails; do not continue with an old binary. Record `git rev-parse
HEAD`, `rustc --version`, `cargo --version`, the OS/architecture, and the build
command. The detached checkout makes the source identity explicit. Re-review
and rerun the walkthrough before changing the pin.

Create a unique evaluation directory and start in the foreground:

```sh
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-rs-eval.XXXXXX")" &&
  printf 'Evaluation directory: %s\n' "$RUN_DIR" &&
  ./target/quickstart/bitcoin-rs \
    --network regtest \
    --scriptindex=full \
    --data-dir "$RUN_DIR/state" \
    --rpc-bind 127.0.0.1:18443
```

Save the printed directory path and leave this terminal running. Only the HTTP
listener is explicitly bound here; this is not a network-isolation test.
The quickstart profile is for exploration, not performance evidence.

## Terminal 2: query the node

For this disposable loopback-only demonstration, use the documented default RPC
credentials. They are not suitable for an exposed listener.

```sh
curl --fail-with-body --silent --show-error \
  --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"local-evaluation","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:18443/
```

Inspect the actual JSON response. Require a null `error`, a populated `result`,
and the regtest chain identity. HTTP 200 alone does not mean the JSON-RPC call
succeeded. Record the observed block count rather than inserting an expected
value into the transcript.

Read the public Esplora tip without JSON-RPC credentials:

```sh
curl --fail-with-body --silent --show-error \
  http://127.0.0.1:18443/api/blocks/tip/height
```

Compare the returned height with the applied block count in the chain response.
A successful tip read does not prove a script-index scan or a funded-wallet
workflow. Index-backed routes have separate readiness conditions owned by the
[indexing contract](contracts/indexing.md).

## Shut down and reopen

Press Ctrl-C in Terminal 1. Inspect the shutdown output and record the process's
exit status immediately with `printf 'Node exit status: %s\n' "$?"`.
A stopped process alone does not prove a clean checkpoint.

In the same terminal, reuse the exact directory, network, and feature-built
binary:

```sh
./target/quickstart/bitcoin-rs \
  --network regtest \
  --scriptindex=full \
  --data-dir "$RUN_DIR/state" \
  --rpc-bind 127.0.0.1:18443
```

Repeat both reads, then shut down cleanly again. If the shell was closed, restore
`RUN_DIR` to the saved directory path before restarting. Do not generate a new
directory or delete state to conceal a reopen failure. Preserve failed-run data
for diagnosis; any cleanup must be an explicit action on this disposable run.

## Diagnose a failed step

| Observation | Next check |
| --- | --- |
| Build fails | Record toolchain, platform, feature selection, and the first relevant error; do not report startup as tested. |
| Listener cannot bind | Check whether port 18443 is already in use. Choose another loopback port and update both curl URLs. |
| HTTP authentication fails | Check inherited configuration and the authentication guidance in Getting started. Never paste credentials into an issue. |
| HTTP succeeds but JSON-RPC contains an error | Record the redacted error and request method; this is a failed query, not a pass. |
| An index-backed request is unavailable | Inspect the declared capability/readiness state; unavailable is not empty history. |
| Reopen fails | Preserve the directory and failure output. Do not reset it implicitly. |

## Record a useful result

Report the revision, platform, toolchain, features, exact task, expected result,
actual result, and redacted output through the repository's issue tracker.
State which of build, startup, JSON-RPC read, public tip read, shutdown, and
same-directory reopen succeeded, failed, or were not attempted. Keep acceptance
transcripts in the PR or CI artifacts, not as invented successful output here.

Never publish seeds, private keys, RPC credentials, cookies, or sensitive logs.
Do not put suspected vulnerability details in a public setup report; ask for a
private reporting route without disclosing the exploit.

This evaluation does not test full mainnet synchronization, consensus parity,
funded history, signing, broadcast, reorg recovery, performance, or production
readiness. Existing deeper test entry points are documented by the owning
contracts; they still need their own recorded execution evidence.
