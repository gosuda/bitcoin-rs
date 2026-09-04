# syntax=docker/dockerfile:1.7

FROM rust:1.95-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libzmq3-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .

# Build the production verifier with the default fjall storage backend, while
# leaving the other storage engines and the optional kernel oracle out of the
# runtime image.
RUN cargo build --locked --release -p bitcoin-rs \
    --no-default-features --features fjall

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

USER bitcoin-rs
VOLUME ["/data"]
EXPOSE 8332 8333

ENTRYPOINT ["bitcoin-rs"]
CMD ["--data-dir", "/data", "--rpc-bind", "0.0.0.0:8332", "--p2p-listen", "0.0.0.0:8333"]
