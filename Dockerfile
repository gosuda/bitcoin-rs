# syntax=docker/dockerfile:1.7

FROM rust:1.95-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        cmake \
        libboost-dev \
        libclang-dev \
        libzmq3-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .

# Build the production verifier with the default fjall storage backend, while
# leaving the other storage engines out of the runtime image. `kernel` is a
# capability ("bitcoinkernel support is compiled in"); the shipped image then
# selects it in its default config file below.
RUN cargo build --locked --release -p bitcoin-rs \
    --no-default-features --features fjall,kernel

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libgcc-s1 \
        libstdc++6 \
        libzmq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 bitcoin-rs \
    && useradd --uid 10001 --gid bitcoin-rs --no-create-home bitcoin-rs \
    && install -d -o bitcoin-rs -g bitcoin-rs /data

COPY --from=builder /workspace/target/release/bitcoin-rs /usr/local/bin/bitcoin-rs

# The image's engine selection lives at the config-file layer, below
# environment and CLI in the documented precedence
# (defaults -> file -> environment -> CLI): bare `docker run` keeps the
# historical kernel behavior, while `BITCOIN_RS_VALIDATION_ENGINE=native`
# or a config file mounted over this one still override it without touching
# CMD. A CLI override (`--validation-engine`) replaces CMD wholesale under
# docker semantics — `docker run IMAGE args` runs `bitcoin-rs args` — so
# going that route means repeating the whole argument list
# (`--config --data-dir --rpc-bind --p2p-listen` included).
RUN install -d -o bitcoin-rs -g bitcoin-rs /etc/bitcoin-rs \
    && printf 'validation_engine = "kernel"\n' > /etc/bitcoin-rs/default.toml \
    && chown bitcoin-rs:bitcoin-rs /etc/bitcoin-rs/default.toml

USER bitcoin-rs
VOLUME ["/data"]
EXPOSE 8332 8333

ENTRYPOINT ["bitcoin-rs"]
CMD ["--config", "/etc/bitcoin-rs/default.toml", "--data-dir", "/data", "--rpc-bind", "0.0.0.0:8332", "--p2p-listen", "0.0.0.0:8333"]
