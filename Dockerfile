# Multi-stage build for CLU malware scanner
# Stage 1: Build Rust binary
FROM rust:1.83-slim-bookworm AS builder
RUN rustup default nightly

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY *.toml Cargo.lock ./
COPY src ./src

# Build release binary
RUN cargo build --release

# Stage 2: Runtime environment
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -fsSL https://ollama.ai/install.sh | sh

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash cluuser && \
    mkdir -p /home/cluuser/.ollama && \
    chown -R cluuser:cluuser /home/cluuser

# Switch to non-root user
USER cluuser
WORKDIR /home/cluuser

# Install GuardDog in user's Python environment
RUN python3 -m venv /home/cluuser/venv && \
    /home/cluuser/venv/bin/pip install --no-cache-dir guarddog

# Add venv to PATH
ENV PATH="/home/cluuser/venv/bin:${PATH}"

# Copy binary from builder
COPY --from=builder --chown=cluuser:cluuser /build/target/release/clu /usr/local/bin/clu

# Create directories for config and data
RUN mkdir -p /home/cluuser/config /home/cluuser/data

# Set working directory
WORKDIR /home/cluuser/config

# Expose Ollama port (for model management)
EXPOSE 11434

# Default command shows help
CMD ["clu", "--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD clu --version || exit 1

# Labels
LABEL maintainer="akses0"
LABEL description="CLU - Containerized malware scanner for Python packages"
LABEL version="0.1-alpha"
LABEL security.isolation="non-root-user"
