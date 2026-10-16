# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM rust:1.80-slim AS builder

WORKDIR /usr/src/sentinel

# Install build dependencies for C-amalgamation SQLite and MSVC-compatible toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy real source code and build
COPY src ./src
# Touch main.rs to force rebuild of the binary
RUN touch src/main.rs && cargo build --release

# Strip debug symbols to reduce binary size (< 15MB)
RUN strip target/release/sentinel-backend

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root sentinel user
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -s /bin/sh -m sentinel

# Prepare persistent data directory
RUN mkdir -p /app/data && chown -R sentinel:sentinel /app

COPY --from=builder --chown=sentinel:sentinel /usr/src/sentinel/target/release/sentinel-backend /app/sentinel-backend

USER sentinel:sentinel

ENV HOST=0.0.0.0
ENV PORT=8080
ENV DATABASE_PATH=/app/data/sentinel.db
ENV RUST_LOG=sentinel_backend=info,tower_http=info

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/health || exit 1

VOLUME ["/app/data"]

ENTRYPOINT ["/app/sentinel-backend"]
