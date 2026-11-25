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
   the code in a credentialed request to the application callback.
4. The ledger verifies the code, browser secret, and application host, consumes
   the flow, and issues a host-bound session handle. The application callback
   sets the handle in a host-only cookie and returns the destination for the
   page to navigate to.
5. On subsequent requests, Holepunch Auth resolves the handle for that host
   and validates the underlying session through oauth2-proxy. The application
   does not receive the oauth2-proxy session cookie.

## Routing and Trust

Envoy routes OAuth endpoints without external authorization. The middleware
strategy routes `/oauth2` on the auth host to oauth2-proxy and
`/-/wormhole/oauthmngr` on auth and application hosts to the oauthmngr service.
The reverse strategy routes `/-/wormhole/oauth2` on application hosts to
oauth2-proxy. The `/-/wormhole/` prefix is reserved with support from the 
route registration service.

For middleware callbacks, Envoy overwrites the forwarded host and scheme
headers with values from the matched route. **The oauthmngr service must be
reachable only through trusted Envoy instances** (for example, using a
NetworkPolicy). Protect internal connections with the cluster network or a
service mesh.

The handoff requires distinct, same-site HTTPS auth and application origins,
and a browser with JavaScript and Fetch Metadata support. The target callback
accepts credentialed requests only from the configured auth origin. Proof
cookies are host-only, secure, HTTP-only, and `SameSite=Lax`. Redemption codes
are not placed in a navigation URL, where application-host scripts could see it.

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
  parent `cookie_domains`. Configure oauth2-proxy's `cookie_name` to match
  `--oauth-proxy-cookie-name`, which defaults to `_oauth2_proxy`. A cookie
  without the `__Host-` prefix can be shadowed or injected by a sibling host
  on the shared registrable domain (cookie tossing), even when it is host-only.
  Restrict control of sibling hosts or use a `__Host-` name if supported by
  the oauth2-proxy deployment. Deployments using the previous default
  `__Host-_oauth2_proxy` should explicitly configure that name in Holepunch
  and oauth2-proxy to retain it.
* Outside development Holepunch's session cookie must keep a `__Host-` name;
  this is the default and is required at startup. The prefix prevents sibling
  hosts from shadowing or injecting that cookie.

The admin route report reflects its locally expanded configuration, not
confirmation of the configuration applied by Envoy. See
[Local Development Deployment](local-deployment.md) for a runnable example.
