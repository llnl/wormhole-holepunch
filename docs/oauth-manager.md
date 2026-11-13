# OAuth Session Management

Wormhole supports user-configured routes across multiple sub-domains. OAuth
sessions must remain scoped to the host where they are used, while
[oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) owns the OAuth
flow and access/refresh-token lifecycle.

## Goals

* Keep authentication decisions in Holepunch Auth and OAuth callbacks outside
  its request path.
* Define unauthenticated OAuth endpoints explicitly in Envoy configuration.
* Issue host-only application session cookies and validate them through
  oauth2-proxy.

## Strategies

**Reverse proxy:** With oauth2-proxy's `reverse_proxy` mode and an identity
provider that supports wildcard redirects, each application host can complete
OAuth directly. oauth2-proxy issues the host-scoped session cookie; no
hand-off callback or ledger is needed.

**Middleware:** For providers that require one redirect URI, use a shared auth
host and hand the oauth2-proxy session back to the requesting application host
through a short-lived, one-time flow.

### Middleware Flow

1. On an unauthenticated request, Holepunch Auth creates a random nonce and
   browser secret. The ledger records the intended host and destination,
   client IP, and only the hash of the secret. The redirect response sets a
   short-lived, nonce-specific, host-only browser cookie on the application host.
2. The browser completes the standard OAuth flow through oauth2-proxy on the
   shared auth host. oauth2-proxy sets its session cookie there and redirects to
   the auth-host hand-off callback.
3. The callback captures that session cookie in the ledger and redirects the
   browser to the requesting application's callback.
4. The application callback presents the nonce-specific browser cookie. The
   ledger verifies its hash, client IP, and host, then consumes the flow and
   returns the session and destination. Missing or incorrect browser proof rejects
   and consumes the flow.
5. The callback issues a host-only application session cookie (12-hour default)
   and redirects to the original destination. It expires the temporary browser
   cookie after redemption or a definitive rejection; transient ledger/network
   failures preserve it for retry until its TTL.

Envoy forwards the callback, with authentication disabled, to the oauthmngr
ledger service, which serves both steps. It never reaches an application
upstream or Holepunch Auth.

## Components and Routing

| Component            | Responsibility                                                         |
|----------------------|------------------------------------------------------------------------|
| Envoy                | Routes OAuth endpoints without ext_authz; binds client IP to callbacks |
| Holepunch Auth       | Validates application sessions and mints the flow (middleware)         |
| oauth2-proxy         | Performs OAuth and owns the session lifecycle                          |
| Holepunch oauthmngr  | Serves the callback: captures, redeems, and issues the session cookie  |
| Shared NATS KV store | Holds single-use flows shared by Holepunch Auth and oauthmngr replicas |

The shared path constants live in [`internal/ctls/paths`](../internal/ctls/paths/paths.go),
including the reserved prefix, OAuth endpoints, and admin API paths.

The OAuth strategy adds these routes, each with ext_authz disabled, alongside the
application routes. The middleware strategy uses oauth2-proxy's standard
`/oauth2` prefix on its dedicated auth host and the reserved callback path on
every host; the reverse strategy uses the reserved `/oauth2` path on each
application host:

| Prefix                  | Strategy   | Hosts                      | Forwarded to                     |
|-------------------------|------------|----------------------------|----------------------------------|
| `/oauth2`               | Middleware | Auth host                  | oauth2-proxy                     |
| `/-/wormhole/oauthmngr` | Middleware | Auth and application hosts | oauthmngr (`--oauth-ledger-url`) |
| `/-/wormhole/oauth2`    | Reverse    | Application hosts          | oauth2-proxy                     |

On the callback route Envoy overwrites `x-wormhole-client-ip`,
`x-wormhole-host`, and `x-wormhole-scheme` before forwarding (see
[Security Requirements](#security-requirements)). The original `Host` header is
preserved on all OAuth routes.

OAuth expansion does not add a catch-all route for `/-/wormhole/*`; reserving
the entire prefix is outside oauthmngr's responsibilities.

### Route Reporting

`GET /api/v1/state/ctls` returns a map keyed by route ID. Each entry includes a
`kind` field distinguishing application routes (`upstream`) from generated
OAuth routes (`oauth2-proxy` or `oauth-callback`). Existing fields
and the map structure are unchanged. This is report metadata only; clients
cannot set route kinds through registry JSON.

The admin command expands its local registry using the same OAuth strategy as
auth and xDS. Configure all three with matching `--oauth-*` flags (including
`--oauth-ledger-url` for the middleware strategy) or their
environment-variable equivalents so the report includes the same generated
routes. The default `none` strategy adds no routes. Admin's token authenticator remains
OAuth-disabled; expansion is used only for its registry and reporting.

The report is the admin service's locally reconstructed configuration, not
confirmation of the configuration applied by Envoy.

## Security Requirements

* Use cryptographically random nonces with at least 128 bits of entropy and
  a short TTL (five minutes by default).
* Bind each flow to its target host and a separate 256-bit browser
  secret. Store only the secret's hash; compare it in constant time. This
  prevents another browser behind the same NAT from redeeming a copied callback
  URL. The nonce-specific cookie must be host-only,
  `HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS, scoped to the callback path, and
  expire with the nonce. Mark redirects carrying flow state
  `Cache-Control: no-store`.
  Client-IP binding is opt-in via `HOLEPUNCH_OAUTH_ENABLE_CLIENT_IP_CHECK=true`.
* Consume each flow at most once. A binding failure rejects and consumes it.
* Do not place session cookies or browser secrets in URLs or logs; mark
  redirects and callback responses carrying flow state `Cache-Control: no-store`.
* Derive the client IP consistently from Envoy's trusted downstream address
  configuration. On the callback route Envoy sets `x-wormhole-client-ip` (the
  downstream address ext_authz also sees) and the route's `x-wormhole-host` and
  `x-wormhole-scheme`, overwriting any client-supplied values. The oauthmngr
  service trusts these headers, so it must only be reachable from Envoy (e.g.,
  a NetworkPolicy).

## Deployment Requirements

For the middleware strategy, run `holepunch oauthmngr` and set
`HOLEPUNCH_OAUTH_LEDGER_URL` (or `--oauth-ledger-url`) to the URL Envoy uses to
reach it (e.g., `http://holepunch-oauthmngr:8083`). Like the oauth2-proxy
internal URL, it becomes the destination of the generated callback routes and
is reached over plain HTTP; rely on the cluster network or a service mesh for
transport encryption. Holepunch Auth, xDS, and admin require the same value so
their expanded routes agree.

Configure oauth2-proxy with:

* `proxy_prefix = "/oauth2"` (oauth2-proxy's standard path; no extra
  `/-/wormhole` prefix is needed on the dedicated auth host).
* Set `redirect_url` to the shared auth-host callback and include the auth host
  in `whitelist_domains` for `rd` redirects.
* Enable `pass_access_token` and `set_xauthrequest` so Holepunch can validate
  sessions through oauth2-proxy without handling provider tokens itself.
* Match `session_store_type` (`cookie` or `redis`) with Holepunch's
  configuration.

Each application host gets its own host-only session cookie and therefore
completes the hand-off separately. Use `SameSite=Lax` so the final top-level
redirect works after login at the identity provider. The `/-/wormhole/`
prefix is reserved and must be rejected in user routes.

OAuth flow state must be stored in a shared, atomic store so capture and
redemption remain single-use across all oauthmngr replicas. In this deployment,
the oauthmngr service serves the callback from the shared NATS KV store;
per-process state or state carried only in URLs is insufficient.
