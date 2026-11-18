# OAuth Session Management

Holepunch supports routes on multiple application hosts, including hosts operated
by mutually untrusted users. Sessions must be isolated by host. Holepunch Auth
makes access decisions; [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
performs OAuth and manages the underlying session and tokens.

## Strategies

* **`none`** (default): OAuth session handling is disabled.
* **`oauth2-proxy-reverse`**: Each application host completes OAuth directly
  and receives an oauth2-proxy session cookie. This requires an identity
  provider that supports wildcard redirects.
* **`oauth2-proxy-middleware`**: A shared auth host handles OAuth, then a
  short-lived, browser-bound handoff creates a host-only session for the
  requesting application. This accommodates providers requiring a single
  redirect URI.

## Middleware Flow

1. Holepunch Auth creates a one-time flow bound to the application host and a
   browser secret, then redirects the browser to oauth2-proxy on the auth host.
   The secret is held in a short-lived, host-only application cookie.
2. After OAuth, the auth-host callback issues a separate proof cookie and
   serves a page that authorizes its challenge through the application
   callback. The application cookie proves continuity with the browser that
   started the flow.
3. The auth callback verifies its proof, captures the oauth2-proxy session in
   the shared ledger, and returns a one-time code to the page. The page sends
   the code in a credentialed request to the application callback, not in a
   navigation URL.
4. The ledger verifies the code, browser secret, and application host, consumes
   the flow, and issues a host-bound session handle. The application callback
   sets the handle in a host-only cookie and returns the destination for the
   page to navigate to.
5. On subsequent requests, Holepunch Auth resolves the handle for that host
   and validates the underlying session through oauth2-proxy. The application
   does not receive the oauth2-proxy session cookie.

The ledger stores hashes of browser secrets and session handles. It rejects a
handle on another host and attempts to revoke it; if deletion fails, the
handle remains usable on its original host until expiry. A binding mismatch
detected by the ledger attempts to burn the flow. Failures after consumption
may require a new sign-in.

## Routing and Trust

Envoy routes OAuth endpoints without external authorization. The middleware
strategy routes `/oauth2` on the auth host to oauth2-proxy and
`/-/wormhole/oauthmngr` on auth and application hosts to the oauthmngr service.
The reverse strategy routes `/-/wormhole/oauth2` on application hosts to
oauth2-proxy. The `/-/wormhole/` prefix is reserved; OAuth route expansion
does not itself add a catch-all to enforce that reservation.

For middleware callbacks, Envoy overwrites the forwarded host and scheme
headers with values from the matched route. **The oauthmngr service must be
reachable only through trusted Envoy instances** (for example, using a
NetworkPolicy). Protect internal connections with the cluster network or a
service mesh.

The handoff requires distinct, same-site HTTPS auth and application origins,
and a browser with JavaScript and Fetch Metadata support. The target callback
accepts credentialed requests only from the configured auth origin. Proof
cookies are host-only, secure, HTTP-only, and `SameSite=Lax`; flows are not
bound to client IPs. The redemption code is not placed in a navigation URL,
where application-host scripts could see it.

Before forwarding authenticated application requests, Holepunch strips
oauth2-proxy session cookies and their chunks; middleware also strips its
application session and flow cookies. OAuth endpoints retain the cookies they
need. Routes that bypass authentication do not receive this cleanup.

## Deployment

For middleware:

* Run `holepunch oauthmngr` and configure `--oauth-ledger-url` as the URL Envoy
  uses to reach it. Configure Holepunch Auth, xDS, admin, and oauthmngr
  consistently with the same OAuth settings.
* Configure oauth2-proxy with its standard `/oauth2` prefix, the shared auth
  host's redirect URL, and the auth host in `whitelist_domains`. Enable
  `pass_access_token` and `set_xauthrequest`. Match its session store type
  (`cookie` or `redis`) with Holepunch's configuration.
* Keep the oauth2-proxy cookie on the auth host: do not configure a shared
  parent `cookie_domains`. A `__Host-` cookie name enforces host-only scope.
* Use shared NATS KV storage for flows and host sessions. NATS 2.11 or later
  is required for per-message TTLs. Flow and session lifetimes default to five
  minutes and twelve hours respectively; the shared bucket's TTL is the
  longer of the two. The ledger also rejects expired records before eviction.
  Size the shared bucket for both flows and sessions; when full, new sign-ins
  fail until entries expire. Redis, if used, is oauth2-proxy's session store,
  not the ledger.

The admin route report reflects its locally expanded configuration, not
confirmation of the configuration applied by Envoy. See
[Local Development Deployment](local-deployment.md) for a runnable example.
