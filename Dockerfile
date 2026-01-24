# ---- build
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --workspace

# ---- runtime
FROM alpine:3.20
RUN adduser -D app && mkdir -p /app/data/receipts && chown -R app:app /app
USER app
WORKDIR /app
# copy bins
COPY --from=build /app/target/release/zkack-verifier /usr/local/bin/
COPY --from=build /app/target/release/zkack-signer   /usr/local/bin/
COPY --from=build /app/target/release/zkack-watcher  /usr/local/bin/
ENV ZKACK_PORT=8787
ENV ZKACK_DB_DIR=/app/data/receipts
EXPOSE 8787
ENTRYPOINT ["zkack-verifier"]
