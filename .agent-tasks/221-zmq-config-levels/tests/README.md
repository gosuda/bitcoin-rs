# Verification evidence

Verified on 2026-08-30 from WSL because the Windows build is blocked by the
repository's existing Unix-only `signal_hook::iterator` import.

- `cargo check -p bitcoin-rs-node`: passed with the default Linux feature set.
- `cargo clippy -p bitcoin-rs-node --no-default-features --features fjall,zmq --tests -- -D warnings`: passed.
- `cargo test -p bitcoin-rs-node --no-default-features --features fjall,zmq`: passed:
  515 unit tests and all node integration/doc-test targets, with no failures.
- `cargo check -p bitcoin-rs-node --all-features` on Windows was attempted but
  is not a valid gate in this environment: existing MDBX bindings fail to
  generate and `libclang` is unavailable.
