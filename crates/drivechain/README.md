# bitcoin-rs-drivechain

Owns the optional native Drivechain consensus-extension protocol: deployed
BIP300 coinbase messages and treasury scripts, BIP301 BMM request parsing, and
the stateless M7/M8 block relationship checks.

This crate does not choose a network, activate itself, or own node composition.
`bitcoin-rs-node` depends on it only through the `drivechain` feature and makes
the runtime activation decision from the resolved network profile.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md)
for project vocabulary.
