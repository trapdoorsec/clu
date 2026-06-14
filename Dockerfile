# Multi-stage build for CLU malware scanner
# Stage 0: Build frontend SPA
# Stage 1: Build Rust binaries
# Stage 2: Runtime environment

# ── Stage 0: Frontend ──────────────────────────────────────────────
FROM node:22-slim AS frontend

WORKDIR /ui
COPY ui/package.json ui/yarn.lock ./
RUN yarn install --frozen-lockfile --production=false
COPY ui/ ./
RUN yarn build

# ── Stage 1: Rust ──────────────────────────────────────────────────
FROM rust:1.83-slim-bookworm AS builder
RUN rustup default nightly

WORKDIR /build

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY *.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash cluuser && \
    chown -R cluuser:cluuser /home/cluuser

USER cluuser
WORKDIR /home/cluuser

RUN python3 -m venv /home/cluuser/venv && \
    /home/cluuser/venv/bin/pip install --no-cache-dir guarddog

ENV PATH="/home/cluuser/venv/bin:${PATH}"

COPY --from=builder --chown=cluuser:cluuser /build/target/release/clu /usr/local/bin/clu
COPY --from=builder --chown=cluuser:cluuser /build/target/release/clu-api /usr/local/bin/clu-api

# Copy frontend SPA assets into the directory clu-api serves
COPY --from=frontend --chown=cluuser:cluuser /ui/dist /home/cluuser/ui/dist

RUN mkdir -p /home/cluuser/config /home/cluuser/data

CMD ["clu", "--help"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD clu --version || exit 1

LABEL maintainer="akses0"
LABEL description="CLU - Containerized malware scanner for Python packages"
LABEL version="0.1-alpha"
LABEL security.isolation="non-root-user"