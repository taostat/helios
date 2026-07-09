# Multi-stage build for the Helios light client (taostats fork).
# Produces a minimal image serving the `helios` binary.
FROM rust:1.96-bookworm AS builder
WORKDIR /helios
COPY . .
RUN cargo build --release --bin helios

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /helios/target/release/helios /usr/local/bin/helios
ENTRYPOINT ["helios"]
