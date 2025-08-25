# JNLP Token Injection Worker

A Cloudflare Worker written in Rust that intercepts JNLP (Java Network Launch Protocol) files and injects security tokens for authentication and authorization.

## Overview

This worker acts as a proxy that:

1. Intercepts requests for JNLP files
2. Extracts client IP and Cloudflare authorization cookies
3. Generates HMAC-based security tokens
4. Modifies JNLP content by injecting tokens into `http_ticket` parameters
5. Returns the modified JNLP file to the client

## Features

- **IP-based Token Generation**: Creates HMAC tokens using client IP and timestamp
- **Cookie Authentication**: Extracts and processes `CF_Authorization` cookies
- **JNLP Content Modification**: Dynamically modifies `http_ticket` parameters
- **Debug Logging**: Configurable debug output for troubleshooting
- **Error Handling**: Robust error handling with fallback mechanisms

## Architecture

```
Client Request → Cloudflare Worker → Origin Server
                      ↓
              Token Injection &
              Content Modification
                      ↓
              Modified JNLP Response → Client
```

## Configuration

### Environment Variables

Set these in your `wrangler.toml` or Cloudflare dashboard:

- `DEBUG`: Enable debug logging (`"true"` or `"false"`)
- `HMAC_SECRET`: Secret key for HMAC token generation (stored as Cloudflare secret)

### Secrets

Configure the following secret in Cloudflare:

```bash
wrangler secret put HMAC_SECRET
```

## Development

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)
- [worker-build](https://crates.io/crates/worker-build)

### Setup

1. Clone the repository
2. Install dependencies:

   ```bash
   cargo install worker-build
   ```

3. Configure your `wrangler.toml` with your account details

### Local Development

```bash
# Start local development server
wrangler dev

# Build for production
wrangler build
```

### Testing

```bash
# Run tests
cargo test

# Test with sample JNLP file
./test.sh
```

## Deployment

```bash
# Deploy to Cloudflare Workers
wrangler deploy

# Set production secrets
wrangler secret put HMAC_SECRET
```

## How It Works

### Token Generation

The worker generates HMAC-SHA256 tokens using:

- Client IP address (from `CF-Connecting-IP` or `X-Forwarded-For` headers)
- Current timestamp
- Configurable HMAC secret

Token format: `{timestamp}-{base64_encoded_hmac}`

### JNLP Modification

The worker searches for `http_ticket` parameters in JNLP files using regex:

```regex
(<param\s+name="http_ticket"\s+value=")([^"]+)(")
```

And modifies them to:

```
{original_value}++{hmac_token}++{cf_authorization}
```

### Request Flow

1. **IP Extraction**: Gets client IP from Cloudflare headers
2. **Cookie Parsing**: Extracts `CF_Authorization` from request cookies
3. **Origin Request**: Forwards request to origin server
4. **Content Analysis**: Checks if response is a JNLP file
5. **Token Generation**: Creates HMAC token with IP and timestamp
6. **Content Modification**: Injects tokens into `http_ticket` parameters
7. **Response**: Returns modified JNLP content

## Dependencies

- `worker`: Cloudflare Workers runtime
- `hmac` & `sha2`: HMAC-SHA256 token generation
- `base64`: Token encoding
- `regex`: JNLP content parsing
- `urlencoding`: Cookie value decoding
- `js-sys`: JavaScript Date API access

## Security Considerations

- HMAC secrets should be rotated regularly
- Debug mode should be disabled in production
- Client IP validation may be needed for high-security environments
- Consider implementing token expiration validation

## Troubleshooting

### Enable Debug Logging

Set `DEBUG="true"` in your environment variables to see detailed logs:

- Client IP addresses
- Cookie values
- HMAC tokens
- Modified content

### Common Issues

- **Missing CF_Authorization**: Ensure Cloudflare Access is properly configured
- **Invalid HMAC Secret**: Verify the secret is set correctly in Cloudflare
- **JNLP Not Detected**: Check that files contain both `<jnlp` and `http_ticket`
