# Introduction

bitcoin-rs is a Bitcoin full node written in Rust, together with the crates that build it. It validates blocks and transactions, syncs headers and bodies from peers, keeps a durable chainstate, and serves JSON-RPC, REST, Esplora, and ZeroMQ surfaces.

The default binary is kernel-free: script verification runs in a native Rust interpreter, not in Bitcoin Core's `libbitcoinkernel`. A separate `kernel` build lane exists as an oracle and as a selectable engine, but it is not the default validation path. The node has no wallet and holds no private keys.

## Who this book is for

Operators run a node and need the flags, files, and failure messages that matter. Start with [Install](run/install.md) and read the Run a node part in order.

Embedders build on the crates instead of the binary. The Embed the crates part covers the node lifecycle and the crate boundaries; the contracts remain the normative source for library behavior.

Contributors change the node. Build and test, contracts and evidence, and source organization describe the checks a change has to pass.

Readers checking a claim should use [What works today](status.md) and the Trust and evidence part. Those pages separate what is implemented and tested in this tree from what an unmodified external consumer has exercised.

## How to read it

The Run a node part follows one path: install, first start on regtest, configuration, the data directory, storage, sync and recovery, shutdown and upgrades, and observability. Each chapter opens with the action or the answer, and most finish with the next chapter you need.

Use the node covers the public surfaces. How it works explains the mechanisms behind them. Reference holds the flag list, the configuration keys, and the glossary.

## What it is not

bitcoin-rs is not Bitcoin Core. It tracks Core 31.1 as a reference where a contract says so, and it records the exact external runs that exist. A surface without a recorded external run is described as implemented in this tree, not as compatible.

The book does not own any rule. Contracts under `docs/contracts/`, policies under `docs/policies/`, and the generated RPC reference keep their authority. Where a rule matters, this book cites its clause id and links the owner.

A performance claim is a result only with a recorded end-state measurement and complete evidence identities. A lane that never ran, or is blocked on a missing identity, is not a result.

## Commands and outputs

Every command shown here was run against a build of the source commit this book documents, on Linux x86-64. Outputs are trimmed to the lines that matter. Commands that cannot run in a plain checkout, such as a live Bitcoin Core interop lane, are described from their contract and marked as such.
