# ============================================
# Stage 1: Build the Rust application
# ============================================
FROM rust:1.83-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && echo 'fn main() { println!("Dummy"); }' > src/main.rs

# Build dependencies only (this layer gets cached)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual application
RUN touch src/main.rs && cargo build --release

# ============================================
# Stage 2: Create minimal runtime image
# ============================================
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -r -s /bin/false qlock

# Copy the compiled binary
COPY --from=builder /app/target/release/qlock-api /usr/local/bin/qlock-api

# Set ownership
RUN chown qlock:qlock /usr/local/bin/qlock-api

# Switch to non-root user
USER qlock

# Expose the API port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/api/auth/me || exit 1

# Run the application
CMD ["qlock-api"]
