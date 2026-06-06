FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig protobuf-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY proto/ proto/
RUN cargo build --release --bin embargo-engine

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/target/release/embargo-engine /usr/local/bin/
EXPOSE 50051 9090
ENTRYPOINT ["embargo-engine"]
