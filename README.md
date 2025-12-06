# Error Outpost (Sentry Proxy)

A Sentry proxy with PII scrubbing and tenant enrichment for on-premise deployments.

## Motivation

Metorial is a system meant to be deployed on-premises, but we still want to leverage Sentry for error tracking. However, sending raw error data directly to Sentry can expose sensitive information and is simply not acceptable for many organizations. This proxy addresses these concerns by:
- Scrubbing Personally Identifiable Information (PII) from error events
- Enriching events with tenant and cluster metadata
- Limiting which Sentry features are used to reduce data exposure

## Features

- **PII Scrubbing**: Automatically scrubs sensitive data including:
  - Email addresses
  - Phone numbers
  - Social Security Numbers (SSN)
  - Credit card numbers
  - IP addresses (IPv4 & IPv6)
  - JWT tokens
  - API keys
  - UUIDs
  - Sensitive headers (Authorization, Cookie, etc.)
  - Sensitive field names (password, api_key, etc.)
- **Tenant Enrichment**: Adds tenant and cluster information to all events
- **Envelope Support**: Full support for Sentry's envelope protocol

## Configuration

Set the following environment variables:

- `TENANT_ID` (required): Unique identifier for the tenant
- `CLUSTER_ID` (required): Unique identifier for the cluster
- `PORT` (optional, default: 9000): Port to listen on

## Usage

### Local Development

```bash
export TENANT_ID=my-tenant
export CLUSTER_ID=my-cluster
export PORT=9000
cargo run
```

### Docker

```bash
# Build the image
docker build -t ghcr.io/metorial/error-outpost .

# Run the container
docker run -p 9000:9000 \
  -e TENANT_ID=my-tenant \
  -e CLUSTER_ID=my-cluster \
  ghcr.io/metorial/error-outpost
```

## Security

This proxy is designed for on-premise deployments and includes:
- Automatic PII scrubbing before forwarding to central relay
- Removal of authentication headers and cookies
- Redaction of sensitive environment variables
- Scrubbing of stack trace variables

## Architecture

```
[Sentry SDK] -> [Error Outpost] -> [Central Relay] -> [Sentry.io]
                     |
                     +-> PII Scrubbing
                     +-> Tenant Enrichment
                     +-> Metadata Tagging
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) file for details.
