# Shutdown and upgrades

Stop the node with `SIGTERM`, `SIGINT`, or the RPC `stop` method. A clean stop drains open RPC connections, publishes a checkpoint, saves fee-estimator history, writes a mempool snapshot, and exits with status 0. `$DATA` below stands for the data directory you pass to `--data-dir`.

## What a signal does

The signal thread listens for `SIGTERM` and `SIGINT` and triggers the node's shutdown latch. Teardown then, in order:

1. drains the derived index workers,
2. requests chainstate and P2P shutdown,
3. stops each RPC listener. Every listener first wakes readers blocked on idle connections, then waits up to 5 seconds for open connection threads to finish. Connections that outlive the deadline are reported with `rpc connections exceeded the drain deadline`, and the listener thread then joins.
4. joins the event loop and remaining workers,
5. publishes a clean chainstate checkpoint if the shutdown was clean,
6. saves fee-estimator history,
7. writes the mempool snapshot with a 10-second budget.

The clean path ends with:

```
{"message":"published clean chainstate checkpoint","generation":1}
{"message":"saved fee-estimator history","path":"$DATA/fee-estimator-history.dat","bytes":57965}
{"message":"prepared mempool snapshot","transactions":0,"bytes":84,"elapsed_ms":"0"}
{"message":"bitcoin-rs node exited cleanly"}
```

If any teardown step reports an error, the node skips the mempool snapshot and exits nonzero. The checkpoint publication runs only for a clean shutdown; the log says `clean checkpoint publication skipped: the node did not shut down cleanly` otherwise.

The signal handling source is [`crates/node/src/signal.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/signal.rs), and the teardown sequence is in [`crates/node/src/lifecycle.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/lifecycle.rs).

## The stop RPC

The `stop` method requests the same shutdown over RPC. It trips the node's graceful-shutdown latch, the same chainstate latch SIGTERM and SIGINT trip, and answers this node's own status string:

```
{"id":1,"jsonrpc":"2.0","result":"bitcoin-rs stopping"}
```

The latch fires before the reply is written, so delivery is best effort. The detached connection thread normally writes the reply as teardown lets it finish, and the process then exits 0 through the clean path above. A guaranteed pre-teardown write is not part of the API. The string deliberately differs from Bitcoin Core's `Bitcoin Core stopping`. `stop` takes no effect-bearing arguments: Core's hidden numeric wait argument is refused with the local parameter-shape error.

## One node per data directory

The node takes an exclusive lock on the data directory before opening storage. A second process on the same directory exits immediately:

```sh
$ ./target/release/bitcoin-rs --network regtest --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false
Error: Cannot obtain a lock on directory $DATA. bitcoin-rs is probably already running.
```

The exit status is 1. The lock is a POSIX record lock on `.lock` plus an in-process registry keyed by the directory's device and inode, so two paths to the same directory collide as well. The lock lives as long as the last handle that can still write the directory.

> **Warning** Do not delete `.lock` to start a second node. It holds no state you can recover; the lock is advisory on the file descriptor, and the running process still owns the directory. Find and stop the running node.

## After an abrupt stop

`SIGKILL`, a power loss, or a crash records no mempool snapshot and publishes no clean checkpoint. The next start replays the durable head and reports the committed gap. Chainstate survives because the durable head was committed before the kill; the pool starts empty unless an older snapshot exists.

The mempool consequences are narrower than "everything is lost". Locally submitted transactions that are re-admitted across a restart keep their pending-broadcast status, and restored transactions are rechecked against the recovered chainstate. Abrupt termination still does not preserve the pool itself. See [Getting started, mempool persistence](https://github.com/gosuda/bitcoin-rs/blob/main/docs/getting-started.md).

## Upgrade steps

Stop the node cleanly, keep a copy of the data directory, and read the format marker before you swap binaries.

```sh
$ cat $DATA/CURRENT_SCHEMA
2
```

If the new binary uses the same schema epoch, start it on the same directory. The chainstate opens, the checkpoint restores, and sync resumes.

If the new binary uses a different epoch, it refuses the old directory with `incompatible_schema`. Create a new directory, sync or import into it, verify the stop identity, and switch to it. The old directory stays untouched. The [datadir format policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md) owns the resync procedure, and [`RCV-09`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns the refusal rule.

An upgrade never deletes or converts operator data in place. There is no in-place migration flag, no legacy reader, and no automatic repair. `process-epoch` and `.process-epoch.lock` belong to the data directory as well; a corrupt epoch file refuses startup rather than reusing a number.

## Downgrade

A binary that predates the current schema refuses a newer directory the same way. Keep the older binary and the copy of the older directory if you may need to go back. Downgrading a directory in place is not supported.

## Next

Watch the node you started: [Logs, metrics, and stalls](observability.md).
