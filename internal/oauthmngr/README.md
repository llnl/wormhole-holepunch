# OAuth Manager Implementation

This package implements the OAuth2 session management strategies for Wormhole Holepunch as specified in `docs/oauth-manager.md`.

## Overview

The oauthmngr package provides a flexible interface (`Validator`) for handling OAuth2 authentication flows with oauth2-proxy. It supports three strategies:

1. **none**: No OAuth2 support (default)
2. **oauth2-proxy-reverse**: Reverse proxy with wildcard redirects
3. **oauth2-proxy-middleware**: Single redirect with middleware (complex multi-step flow)

## Architecture

### Core Interface

The `Validator` interface defines the contract for all OAuth implementations:

- `ExpandSources()`: Adds required OAuth routes to the registry
- `EstablishPreAuthentication()`: Returns pre-auth logic for route-specific handling
- `PrepareAuthRedirect()`: Creates OAuth initiation redirect with nonce generation
- `EstablishPostAuthentication()`: Returns post-auth callback logic for the OAuth redirect endpoint
- `ValidateCookies()`: Validates session cookies and extracts access tokens

### Strategies

#### 1. None Strategy (`none.go`)

A no-op implementation that returns errors for any OAuth operations. Used when OAuth is not configured.

**Usage:**
```bash
--oauth-strategy=none
```

#### 2. Reverse Proxy Strategy (`op-reverse.go`)

Supports oauth2-proxy configured with `reverse_proxy=true`. The proxy establishes session cookies directly on each subdomain through wildcard redirects.

**Features:**
- Simple flow: Holepunch routes `/-/wormhole/oauth2/*` to oauth2-proxy
- OAuth2-proxy handles entire flow and sets cookies per subdomain
- No nonce generation or session management needed

**Configuration:**
```bash
--oauth-strategy=oauth2-proxy-reverse
--oauth2-proxy-upstream=http://oauth2-proxy.namespace.svc.cluster.local:4180
--oauth-cookie-name=_oauth2_proxy
```

**Flow:**
1. User accesses `foo.example.com/app` without auth
2. Redirect to `foo.example.com/-/wormhole/oauth2/start?rd=foo.example.com/app`
3. OAuth2-proxy handles OAuth flow
4. OAuth2-proxy sets cookie on `foo.example.com` and redirects to `/app`

#### 3. Middleware Strategy (`op-middleware.go`)

Handles single OAuth2 redirect with multi-step flow through an auth domain. Required for identity providers that don't support wildcard redirects.

**Features:**
- Multi-step flow through auth domain
- Cryptographically secure nonces (128-bit entropy)
- Nonce binding to client IP and subdomain
- Single-use nonce enforcement with 5-minute TTL
- Subdomain-scoped cookie issuance (12-hour default)
- Comprehensive security logging

**Configuration:**
```bash
--oauth-strategy=oauth2-proxy-middleware
--oauth2-proxy-upstream=http://oauth2-proxy.namespace.svc.cluster.local:4180
--oauth-auth-domain=auth.example.com
--oauth-cookie-name=_wormhole_session
--oauth-cookie-max-age=43200  # 12 hours
--oauth-nonce-ttl=300          # 5 minutes
--oauth-validate-tokens=false
```

**Flow:**
1. User accesses `foo.example.com/app` without auth
2. Generate nonce bound to client IP + subdomain, store with target URL
3. Redirect to `auth.example.com/-/wormhole/oauth2/start?rd=auth.example.com/-/wormhole/oauthmngr?nonce=<nonce>`
4. OAuth2-proxy performs standard OAuth flow
5. OAuth2-proxy sets cookie on `auth.example.com`, redirects to `auth.example.com/-/wormhole/oauthmngr?nonce=<nonce>`
6. At auth domain callback: capture oauth2-proxy cookie, store with nonce, redirect to `foo.example.com/-/wormhole/oauthmngr?nonce=<nonce>`
7. At subdomain callback: retrieve session data, validate nonce binding, issue subdomain cookie, redirect to `foo.example.com/app`

## Security Features

### Nonce Security (`nonce.go`)

The middleware strategy implements robust nonce security:

- **Cryptographic randomness**: 128-bit (16 bytes) entropy using `crypto/rand`
- **Request binding**: Nonces are bound to:
  - Client IP address (from `X-Forwarded-For` or `X-Real-IP`)
  - Target subdomain
- **Single-use enforcement**: Nonces are marked as used after first retrieval
- **Time-bound**: 5-minute TTL (configurable)
- **Comprehensive logging**: All validation failures logged with context

### Session Management

- Sessions stored in KV store (NATS JetStream)
- Automatic cleanup of expired nonces and sessions
- One-time retrieval with immediate deletion for session data
- Subdomain-scoped cookies with configurable max age

## Files

- `manager.go`: Core interface definition and factory function
- `none.go`: No-op implementation
- `op-reverse.go`: Reverse proxy strategy
- `op-middleware.go`: Middleware strategy
- `nonce.go`: Nonce generation and validation utilities
- `helpers.go`: URLString construction helpers

## CLI Flags

All flags are in `internal/args/oauth.go`:

| Flag | Env Variable | Default | Description |
|------|-------------|---------|-------------|
| `--oauth-strategy` | `OAUTH_STRATEGY` | `none` | Strategy: none, oauth2-proxy-reverse, oauth2-proxy-middleware |
| `--oauth2-proxy-upstream` | `OAUTH2_PROXY_UPSTREAM` | - | Upstream URL for oauth2-proxy service |
| `--oauth-source-url` | `OAUTH_SOURCE_URL` | - | Source URL for OAuth flow (middleware) |
| `--oauth-auth-domain` | `OAUTH_AUTH_DOMAIN` | - | Auth domain for middleware strategy |
| `--oauth-cookie-max-age` | `OAUTH_COOKIE_MAX_AGE` | `43200` | Cookie max age in seconds (12 hours) |
| `--oauth-cookie-name` | `OAUTH_COOKIE_NAME` | `_wormhole_session` | Session cookie name |
| `--oauth-nonce-ttl` | `OAUTH_NONCE_TTL` | `300` | Nonce TTL in seconds (5 minutes) |
| `--oauth-validate-tokens` | `OAUTH_VALIDATE_TOKENS` | `false` | Validate oauth2-proxy tokens |

## Integration

### Initialization

```go
import "github.com/llnl/wormhole-holepunch/internal/oauthmngr"

validator, err := oauthmngr.InitializeValidator(
    kvStore,  // streams.KVStore
    logger,   // logs.Logger
    oauthArgs // args.OauthManagement
)
if err != nil {
    // Handle error
}
```

### Usage in Route Registry

The validator integrates with the route registry:

1. Call `ExpandSources()` before snapshot generation to inject OAuth routes
2. Use `EstablishPreAuthentication()` to get per-route pre-auth logic
3. Call `PrepareAuthRedirect()` when user needs authentication
4. Call `ValidateCookies()` to validate existing sessions

## Testing Considerations

When testing:

1. Use `none` strategy for tests that don't need OAuth
2. Mock the `KVStore` for middleware strategy tests
3. Verify nonce binding validation with different client IPs
4. Test nonce expiration and single-use enforcement
5. Verify cookie domain scoping

## Future Enhancements

- Rate limiting for nonce validation failures
- Automated blocking of suspicious IP addresses
- Token validation against oauth2-proxy (when `--oauth-validate-tokens=true`)
- Metrics and observability hooks
- Support for additional OAuth providers
