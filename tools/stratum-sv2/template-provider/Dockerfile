# syntax=docker/dockerfile:1.7
# Build with repository root as context: the adapter embeds path dependencies.
FROM rust:1.99-bookworm AS build
WORKDIR /build
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/cargo-target \
    CARGO_TARGET_DIR=/cargo-target cargo build --release --locked --manifest-path tools/stratum-sv2/template-provider/Cargo.toml \
    && cp /cargo-target/release/bitcoin-rs-sv2-template-provider /template-provider

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 && rm -rf /var/lib/apt/lists/*
COPY --from=build /template-provider /usr/local/bin/template-provider
EXPOSE 8442
ENTRYPOINT ["template-provider"]
