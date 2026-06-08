FROM rust:1.82-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# The build references ../engine/proto, so copy both into the context root.
COPY engine/proto /engine/proto
COPY sandbox /build
RUN cargo build --release

FROM debian:bookworm-slim
# Node toolchain so the sandbox can run `npm ci` for the install under test.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/embargo-sandbox /usr/local/bin/
ENTRYPOINT ["embargo-sandbox"]
