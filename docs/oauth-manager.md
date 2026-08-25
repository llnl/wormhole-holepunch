# OAuth Sessions Management

The structure of Wormhole necessitates a higher degree of flexibility when it comes to
the utilization of OAuth2 for handling user authentication. This is fundamentally due to
the fact that users are allowed to configure routes on an arbitrary number of sub-domains
(as well as the potential for multiple wildcard domains being managed at the same time).

In addition, we want to rely upon the [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
service for the core authentication and sessions management capabilities
it has a proven track record of offering. This means Holepunch should never directly
manage the access/refresh tokens lifecycle and, where possible, defer to the oauth2-proxy
service to generate the initial cookies.

This presents an interesting challenge as we still want to restrict any session
cookies to a single sub-domain and work across a broad range of identity providers
with widely different implementation/policy requirements. This leaves us with two mutually
exclusive strategies, selected at deployment time, that Holepunch can reasonably facilitate.

## 1: Reverse Proxy with Wildcard Redirects

In this scenario there is a single oauth2-proxy deployment (configured with the
`reverse_proxy = true` setting) that exists behind our Envoy instance. Holepunch
ensures routes (prefixed with `/-/wormhole/oauth2`) are correctly routed to this
instance with all necessary headers in place. This approach allows the oauth2-proxy
to establish a session cookie for each individual sub-domain.

Please note, though this is the easiest to support, the majority of providers
we are targeting unfortunately do not appear to support wildcard redirects. As such,
even though this will be offered, it will likely remain a relatively niche configuration.

## 2: Single Redirect with Middleware

An oauth2-proxy instance is established but it acts as the singular
redirect target for the oauth2 flow. However, this instance exists behind Envoy
and relies upon custom logic within Holepunch to exert additional controls over
the final redirect (e.g., `rd=???`) that the oauth2-proxy supports. This allows
Holepunch Auth to set the cookie scoped to a singular sub-domain.

The flow requires an intermediate step through the auth domain to capture the oauth2-proxy
session cookie, as cookies can only be read by the domain they're scoped to. This is achieved
through a series of redirects that preserve both the authentication state and the user's
intended destination.

1. Holepunch establishes a custom state (`nonce`) that is used to link back to the original
   redirect requirements. The nonce is written to the key/value store along with the
   user's intended destination (e.g., `foo.example.com/app`). The OAuth flow begins with
   a redirect to `auth.example.com/oauth2/start?rd=auth.example.com/-/wormhole/oauthmngr?nonce=<nonce>`.
2. A standard oauth2 flow proceeds, ending back at `auth.example.com/oauth2/callback`.
   Oauth2-proxy establishes its session cookie (scoped to `auth.example.com`) and follows
   the `rd` parameter to redirect to `auth.example.com/-/wormhole/oauthmngr?nonce=<nonce>`.
3. The request to `auth.example.com/-/wormhole/oauthmngr` naturally includes the oauth2-proxy
   session cookie in the request headers (since the browser is making a same-domain request).
   Holepunch captures this cookie from the request, optionally validates it, and stores it
   in the key/value store linked to the nonce. The user is then redirected to
   `foo.example.com/-/wormhole/oauthmngr?nonce=<nonce>`.
4. At `foo.example.com/-/wormhole/oauthmngr`, Holepunch retrieves the stored session cookie
   using the nonce (removing it from the store as this is a one-time operation), validates
   the authentication state, and determines if the redirect can proceed.
5. Finally (if all checks have passed) redirect the user back to `foo.example.com/app`
   with a new cookie scoped to the `foo.example.com` domain. This subdomain cookie is issued
   by Holepunch and limited via configuration to a default 12 hours. Future requests will leverage
   this cookie and avoid repeating this flow for the `foo.example` subdomain.

## Nonce Generation and Security

The middleware strategy relies on cryptographically secure nonces to link the multi-step
authentication flow while preventing replay and forgery attacks.

### Requirements

* **Cryptographically Random**: Nonces must be generated using a cryptographically secure
  random number generator with sufficient entropy (minimum 128-bit) to prevent brute-force
  attacks within the 5-minute TTL window.
* **Request Binding**: Each nonce must be bound to the originating client IP address and
  target subdomain. During callback validation, these characteristics must match the
  original request to prevent nonce theft and replay attacks.
* **Single Use**: Nonces are consumed upon first use and must not be reusable.
* **Logging**: All nonce validation failures should be logged for security monitoring.
  Rate limiting and automated blocking will be addressed in future enhancements.

## Key Interface

At the core of realizing either option there will be a central package and interface found
in `internal/oauthmngr` designed to support a fairly dynamic set of requirements:

```go
type Validator interface {
    ExpandSources(
      rawSources []registry.RawSource,
    ) []registry.RawSource
    EstablishPreAuthentication(
      source registry.RawSource,
    ) func(requests.RequestDetails) (bool, *errs.StatusError)
    PrepareAuthRedirect(
      proposedRedirect string,
      details requests.RequestDetails,
    ) (string, *errs.StatusError)
    EstablishPostAuthentication(
      source registry.RawSource,
    ) func(ctx context.Context, details requests.RequestDetails) *errs.StatusError
    ValidateCookies(
        ctx context.Context,
        details requests.RequestDetails,
        cookies []*http.Cookie,
    ) (Result, *errs.StatusError)
}
```

* **ExpandSources**: Offers an opportunity to expand the route registry provided
  configurations to include additional routes required to support the configured Oauth2 flow.
* **EstablishPreAuthentication**: Returns a function that will be called prior to any request being
  authenticated by the Holepunch Auth service. It will align session management requirements
  (e.g., redirects) and potentially allow auth to be skipped in cases where it is deferred
  to the upstream oauth2-proxy service.
* **PrepareAuthRedirect**: Creates the redirect URL to initiate the OAuth flow for an
  unauthenticated request. Takes the proposed redirect destination and request details,
  generates a nonce bound to the request characteristics, stores the nonce with the
  target destination, and returns the properly constructed redirect URL that will start
  the OAuth flow. This ensures nonces are created and injected when required.
* **EstablishPostAuthentication**: Returns a function, run the same way as `EstablishPreAuthentication`,
  that processes the `/-/wormhole/oauthmngr` callback. It validates nonces, stores session
  state, and relies solely on the returned `StatusError`: use `errs.NewRedirectErr` with
  `errs.WithSetCookie` to redirect and set cookies, otherwise report failure.
* **ValidateCookies**: Primary authentication function to be invoked in cases where the
  traditional Wormhole Access Token is not provided. Returns a raw `access_token`; it is
  the caller's responsibility to exchange this for a Jump Token via the Token Service.

This strategy allows clear distinctions between the two radically different OAuth flows
without convoluting any core packages. For example, `ExpandSources` runs prior to Envoy
snapshot generation, ensuring that when `routeReg.FetchProxyControls()` is invoked, any
required routes for oauth2-proxy (e.g., `/-/wormhole/oauthmngr`, `/-/wormhole/oauth2`)
have already been established.

## OAuth2 Proxy

**TBD** - Our strategy hinges on deploying [oauth2-proxy](https://github.com/oauth2-proxy/manifests)
as part of Holepunch. Currently it is not part of our charts; however, we will need
to correct that and establish some baseline guidelines here, along with best practices
for establishing an OAuth client that can be generically applied to all SSOs.

## Additional Notes/Restrictions

* The intermediate redirect through `auth.example.com/-/wormhole/oauthmngr` is necessary because
  browsers only send cookies to domains they're scoped for. Since oauth2-proxy's session cookie
  is scoped to `auth.example.com`, it can only be captured by making a request to that domain.
  This approach leverages standard browser cookie behavior rather than requiring response
  interception mechanisms.
* The `nonce` established will remain time-bound (5 minute TTL) and single use. Additional
  restrictions should be applied to limit nonce reuse, such as binding to client characteristics
  and enforcing strict validation at each step of the flow.
* Users must authenticate separately for each subdomain. This is intentional design to provide
  security isolation between subdomains, as each subdomain may represent different applications,
  teams, or security boundaries. While the oauth2-proxy session on `auth.example.com` persists,
  users will go through the OAuth flow for each new subdomain to establish a subdomain-specific
  session.
* The implementation of the `EstablishPreAuthentication` will have a final say as to which endpoints
  will be allowed to skip auth (e.g., `/oauth2/start` would be allowed while other endpoints
  could be rejected). Careful review and testing of the underlying interface implementation will
  be required as this cannot be avoided.
* Holepunch Auth uses the new session cookie as part of a broader authorization strategy. This means
  we do not directly require observing scenarios where the user's oauth2-proxy issued
  access_token has been revoked. Instead, user revocation and access management will flow down through
  the Token Service.
* Redirects are relayed through the `errs.NewRedirectErr` function, with any required cookie
  attached via `errs.WithSetCookie`.

## Route Registry Requirements

This strategy necessitates a single change on the route registry side. Holepunch reserves
the `/-/wormhole/` path prefix for its own use. Any user-supplied route configuration that
contains this prefix will be rejected at registration time.
