# Native LDK L1 adapter

Experimental LDK consumer pinning `lightning = 0.2.7` and
`lightning-block-sync = 0.2.0` with its own `Cargo.lock` and independent Cargo
workspace. LDK stays out of the authoritative workspace dependency graph and
default CI.

Run the consumer on an application-owned blocking OS thread, outside executor
tasks and node locks. The adapter constructor takes an explicit fallback fee
rate in sat/kw. Chain polling uses the public Node polling seam; see
[EVT-06](../../docs/contracts/chain-events.md#evt-06-public-settled-polling-and-positional-replay).

## Verification

With the repository's Rust toolchain and a C compiler for secp256k1:

```sh
cargo test --locked --manifest-path tools/ldk/Cargo.toml
cargo clippy --locked --manifest-path tools/ldk/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path tools/ldk/Cargo.toml --check
cargo test --locked -p bitcoin-rs-mempool --lib
cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --lib chain_feed::tests
```

The public consumer test starts a temporary fjall regtest Node, reads genesis
through real LDK traits, checks byte conversions and fee fallback, exercises
admission errors and settled polling, then shuts down and reopens.
