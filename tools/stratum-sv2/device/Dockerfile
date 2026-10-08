# Builds the SRI reference SV2 CPU mining device (integration-tests
# mining_device binary) from the pinned sv2-apps revision.
#
# sv2-apps has no root Cargo.toml; integration-tests/ is its own cargo
# workspace, so the build runs there.
#
# syntax=docker/dockerfile:1.7

# Pinned SRI revision: tag and the commit it must resolve to (verified at
# build time; the build fails loudly on a mismatch).
ARG SRI_REF=v0.8.0
ARG SRI_COMMIT=7f49074357e54da4f5b13acfcc29dc3cbb9e541f

FROM rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder
ARG SRI_REF
ARG SRI_COMMIT

# Same builder package set the upstream sv2-apps docker/Dockerfile uses for
# this dependency tree (capnp tooling), plus git for the pinned clone.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        capnproto \
        libcapnp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${SRI_REF}" https://github.com/stratum-mining/sv2-apps . \
    && echo "sv2-apps ${SRI_REF} = $(git rev-parse HEAD)" \
    && test "$(git rev-parse HEAD)" = "${SRI_COMMIT}"

WORKDIR /src/integration-tests
RUN cargo build --locked --release --bin mining_device

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
COPY --from=builder /src/integration-tests/target/release/mining_device /usr/local/bin/mining_device
ENTRYPOINT ["/usr/local/bin/mining_device"]
