# Install

Build the default binary with `cargo build --locked --release -p bitcoin-rs`. The result is `target/release/bitcoin-rs`.

```sh
$ cargo build --locked --release -p bitcoin-rs
```

This chapter shows the commands but no build transcript. The transcripts in later chapters come from a binary built from the same source commit.

## What the build needs

The workspace uses the `stable` channel; the MSRV is Rust 1.99.0. The policy is [source compatibility](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/source-compatibility.md).

The default build compiles bundled ZeroMQ and RocksDB from source. Install a C compiler, a C++17 compiler (`g++`), `clang`, `libclang-dev`, `cmake`, and `ar`; on Debian or Ubuntu that is `build-essential clang libclang-dev cmake`. You do not need system ZeroMQ headers, `pkg-config`, or `libsodium`.

A C and C++ compiler stays required even with the `zmq` feature off, because secp256k1, mimalloc, and RocksDB are vendored and compiled. The optional kernel lane also needs Boost (`libboost-dev`):

```sh
$ sudo apt-get install -y libboost-dev
```

## Build lanes

Choose the lane for its purpose. The default binary is kernel-free.

| Lane | Command | What it contains |
| --- | --- | --- |
| Default | `cargo build --locked --release -p bitcoin-rs` | Mandatory RocksDB storage, bundled ZeroMQ, native validation |
| Minimal native | `cargo build --locked --release -p bitcoin-rs --no-default-features` | Mandatory RocksDB storage, ZeroMQ off |
| Kernel | `CARGO_TARGET_DIR=target/oracle cargo build --locked --release -p bitcoin-rs --features kernel` | Optional `bitcoinkernel` validation and oracle lane |

The default feature set in `bin/bitcoin-rs/Cargo.toml` is `zmq`. RocksDB is the mandatory default storage engine, always compiled into the binary; `fjall` and `redb` are removed from runtime.

Keep the kernel lane in its own `CARGO_TARGET_DIR` when you need to prove that a kernel-free binary contains no kernel support; building with `--features kernel` in the shared target directory would leave kernel-linked artifacts beside the default build.

For a faster compile during development, the workspace defines a `quickstart` profile. It inherits the release profile with link-time optimization off and 16 codegen units:

```sh
$ cargo build --locked -p bitcoin-rs --profile quickstart
```

The binary lands at `target/quickstart/bitcoin-rs`. Keep performance work on the release profile; the two profiles do not produce equivalent measurements.

## Check the binary

`--version` prints one line and exits 0:

```sh
$ ./target/release/bitcoin-rs --version
bitcoin-rs daemon version 0.15.0
```

The flag runs before any config or data-directory work, so it is safe on a machine with no datadir. The string is this node's own name and workspace version, not Bitcoin Core's version and not Core's license paragraph.

```sh
$ ./target/release/bitcoin-rs --help
Run a bitcoin-rs node
```

The usage line that follows names the program as it was invoked (argv[0]). The rest of the output is the full flag list.

Help output is the authoritative flag list for the binary in front of you. The [command-line reference](../reference/cli.md) mirrors it for this book's commit.

## Docker

The shipped image is not the default kernel-free build. Its Dockerfile builds with `--no-default-features --features kernel` and selects `kernel` at the config-file layer, so a bare `docker run` uses the kernel engine. Setting `BITCOIN_RS_VALIDATION_ENGINE=native` or mounting your own config file over the image's default still overrides it.

> **Warning** The image keeps RPC on loopback. To serve RPC outside the container you must set an explicit bind and operator credentials; Basic authentication is unencrypted without a TLS-terminating proxy.

The image details are owned by [Getting started](https://github.com/gosuda/bitcoin-rs/blob/main/docs/getting-started.md) and the [Dockerfile](https://github.com/gosuda/bitcoin-rs/blob/main/Dockerfile).

## Next

Start a regtest node: [First start](first-start.md).
