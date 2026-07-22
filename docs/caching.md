# Holepunch Caching Strategy

Holepunch leverages caching in select cases in order to realize its
goal of keeping the entire gateway level (including all authentication,
authorization, and policy enforcement) well under a 10ms average.
At the same time we take strides to ensure the reliability of the
authorization process and any changes to the routing rules
can be realized as quickly as possible.

## Technology

At this time we primarily focus on using the Cloud Native
Computing Foundation project, [NATS](https://nats.io/)
as the caching technology. There does exist a performance
difference between NATS a traditional key/value storage
solutions (e.g., Redis/Valkey). However, those differences
are not currently large enough to justify the administrative
overhead of managing a separate service.

The connection and associated interface for all caching
should be managed out of the `internal/ctls/streams` package:

* Leverages JetStream
* Individual buckets are generated based upon need (e.g., `tokenBucket`)
* Buckets are limited to in-memory storage and offer configurable replication
* We make attempts at HA; however, its not strictly required since
  the caching is only meant to improve performance and Holepunch
  will operate without it.

*Note* even through we deploy NATS by default, it is possible
we will need to expand support to other key/value solutions
in the future. As such, even though we expect tokens to be cached
securely (and preferably in-memory) we will take steps to
encrypt tokens being stored. But please note that these cannot
be stored in a one-way hash.

## Webhooks

Since Holepunch is designed to operate relatively independently
from the Token and Route services we offer a series of webhooks
that can be called to force immediate changes on the managed
state.

* `/api/v1/webhook/routes` - Force an immediate refresh of the state
  against the Route Registry.

* `/api/v1/webhook/invalidate` - Remove any provided token(s) from the
  cache immediately. Expected JSON body structure:

  ```json
  {
    "token_id": "c520c08c-0325-48c4-8bd1-57bde8c7c382",
    "subtokens": [
        {
            "token_id": "6f1dd5eb-d058-433f-89b7-1f87980b1d0d",
            "external_id": "56e05ec3-46d8-4d12-9892-fe2097b34d74"
        }
    ]
  }
  ```

The webhooks are designed to be run asynchronously and offer a
**best effort** at updating any cached state. In the worse case
scenario the `--tokens-ttl` (`$HOLEPUNCH_TOKENS_TTL`) will act
as a final line of defense, capping the maximum amount of time
any token can be cached for before needing to re-validate
against the Token Service.

## Types

There exists several types of tokens that Holepunch handles
and caches within the established limits.

### Wormhole Access Token (WAT)

The WAT is the primary token a user includes with every request
on the `X-Token` header. All authentication/authorization decisions
spawn from this token.

The tokens structure will align with: `<tokenID>.<randomStr>`.

* Key: `wat:v1:<token_id>`

Obviously the key itself offer no security, instead lookups
relating to authentication rely on an encrypted
(using [crypto/aes](https://pkg.go.dev/crypto/aes))
to compare the proposed WAT to the previously validated one.

A proposed token, rejected via the Token Service with a 401
response, will be briefly cached to avoid exposing the
Token Service to a large influx of invalid tokens. The lifetime
of these token will also observe the `--token-ttl` but
will not be maintained with the hot cache strategy.

### Jump Token

These shorted lived JSON Web Tokens are cached along side a WAT.
When a request has been validated the Jump Token replaces the
WAT in the user's `X-Token` header. The validation of a WAT will
always result in a Jump Token.

This token is stored along side the appropriate WAT and is
never accepted by Wormhole for the purpose of
authentication/authorization. Currently the only known consumer is
the Airlock project through the Wormhole CLI service.

### Wormhole OAuth Session (WOS)

For sessions based access we rely on the
[oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
service to manage and authenticate cookies associated with the
request. However, once that step has been completed Holepunch
must still potentially exchange the `access_token`
with Token Service for the appropriate Jump Token.

It's this exchange that we have the responsibility
to cache, similar to the WAT.

* Key: `wos:v1:<sha256sum of oauth access_token>`

### Wormhole Access Subtoken (WAS)

The WAS is injected into valid community requests on the `X-Subtoken` header
and can be used by the upstream service as a sort of *impersonation WAT*.
This is scoped to that given community of services only.

* Key: `was:v1:<parent_id>:<external_id>`

The WAS tracked in this manner aims to provide a mechanism by which requests
can retrieve and inject this into the appropriate community.

**NOTE**: A subtoken used in a request is no different than any
other WAT. The WAS is only cached since it may need included
in future requests from a validated WAT/WAC.

The tokens structure will align with: `<tokenID>.<randomStr>`.

## Hot Cache Strategy

Holepunch will take strides where possible to maintain a hot-cache
of known tokens. The process roughly follows:

1. Any successfully validated WAT is cached and added to the token management
   FIFO message queue.
2. A worker waits to act upon messages from this queue until ~1 minutes prior to
   the token's defined expiration. This avoids cases where all tokens will attempt
   to refresh during the same window, while still providing plenty of time
   for the token service to process requests.
3. The WAT is re-validated against the Token Service and the cache updated.
   Any associated Job Tokens are also updated.
4. If this WAT appears with a ParentID and ExternalID it means it's associated
   with a WAS. In this case that is also re-validated at this time.
5. The token is finally re-introduced to the end of the queue.

If at any point during this process the Token Service indicates the parent
token is invalid then it, along with all related subtokens, will be
invalidated.

## Token Expiration

Any cached tokens will have its expiration stored along side. This
`exp` will always be validated when a cache hit is encountered
before using the details.
