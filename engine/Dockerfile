# Build the engine offline against the committed sqlx cache.
FROM rust:1.82-slim AS builder
RUN apt-get update \
  && apt-get install -y --no-install-recommends protobuf-compiler \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ENV SQLX_OFFLINE=true
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY proto/ proto/
COPY migrations/ migrations/
COPY .sqlx/ .sqlx/
RUN cargo build --release --bin embargo-engine

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/embargo-engine /usr/local/bin/
# gRPC (mTLS), admin HTTP/JSON (console), metrics/health
EXPOSE 50051 8080 9090
ENTRYPOINT ["embargo-engine"]
