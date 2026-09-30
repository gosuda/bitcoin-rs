# Bridge binary for the examples/stratum-sv2 compose stack.
FROM rust:1-slim AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/bitcoin-rs-sv2-template-provider /usr/local/bin/template-provider
EXPOSE 8442
ENTRYPOINT ["template-provider"]
