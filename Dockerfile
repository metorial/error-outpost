# Build stage
FROM rust:1.75-slim as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install CA certificates for HTTPS requests
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binary from builder
COPY --from=builder /app/target/release/error-outpost /app/error-outpost

# Expose the default port
EXPOSE 9000

# Set default environment variables (can be overridden at runtime)
ENV PORT=9000

# Run the binary
CMD ["/app/error-outpost"]
