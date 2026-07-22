# Holepunch

Within Wormhole, Holepunch is the gateway management engine that turns registered
routes into live [Envoy](https://www.envoyproxy.io/) configurations. It accepts
browser or automated requests, checks user credentials through Token Service and Route
Registry policy, injects Wormhole specific headers, and routes approved traffic toward
[Piko](https://github.com/andydunstall/piko) tunnel endpoints. This lets users reach HPC
apps at durable URLs while the app remains behind a well established and vetted
gateway layer.

## Table of Contents

- [Runtime Components](#runtime-components)
- [Deployment](#deployment)
- [Admin API](#admin-api)
- [Development](#development)
- [Governance](#governance)

## Runtime Components

The `holepunch` binary exposes these long-run services:

| Command  | Purpose                                                                        |
|----------|--------------------------------------------------------------------------------|
| `xds`    | Envoy v3 xDS control plane for listeners, routes, clusters, and snapshots.     |
| `auth`   | Envoy external authorization gRPC service.                                     |
| `cacher` | Long-running route cache publisher that reads Route Registry and writes state. |
| `admin`  | HTTP admin API for state inspection, cache refresh, and invalidation.          |

The runtime flow is:

1. Envoy starts and discovers dynamic resources via [xDS](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration).
2. The `holepunch cacher` fetches Route Registry entries and publishes route controls
   through [NATS](https://nats.io/).
3. `holepunch xds` reads the cached controls and emits Envoy listeners, routes, clusters,
   WebSocket upgrades, header mutation, and optional tracing.
4. Envoy calls `holepunch auth` for every request.
5. Auth validates `X-Token` credentials or OAuth session cookies, exchanges with
   Token Service for a short-lived JWT, evaluates Route Registry rules, and
   injects any required subtokens for community routes.

### How Holepunch Fits Into Wormhole

The core goal for Holepunch is to consolidate details on the desired Wormhole
routes and users (gathered from the Route Registry and Token Service respectively)
and ensure a well-structure and managed gateway is offered.

```mermaid
flowchart LR
    Client["Browser or code"]
    Envoy["Envoy proxy"]
    Auth["Holepunch auth"]
    XDS["Holepunch xDS"]
    Cache["NATS route/token cache"]
    Registry["Route Registry"]
    Token["Token Service"]
    Piko["Piko tunnel"]
    App["User app"]

    Client --> Envoy
    Envoy --> Auth
    Auth --> Token
    Auth --> Registry
    Envoy --> Piko
    Piko --> App
    XDS --> Envoy
    Cache --> XDS
    Registry --> Cache
```

## Deployment

Holepunch is designed to be deployed along side the Token Service and Route Registry
on a Kubernetes cluster. The charts can be reviewed and deployed from the `helm/`
directory:

```shell
helm upgrade --install -n holepunch-namespace .
```

### Required Secrets:

The deployment requires that several secrets be manually established in advance
of running any Helm commands:

* `nats-auth`: Used 
  - `username`/`password`: Credentials used by Holepunch to access/modify all stores and subscriptions.

* `holepunch-secrets`: Mounted as environment variables into Holepunch deployments.
  - `HOLEPUNCH_NATS_HOST`: Required to access our NATS instance (e.g., `nats://user:pass@nats.namespace.svc.cluster.local:4222`)

### Configuration

All commands support CLI flags with matching `HOLEPUNCH_*` environment
variables. Review command-specific options before deployment:

```shell
holepunch --help
```

These configurations can be injected into your deployment via
`holepunch.env`:

```yaml
  holepunch:
    env:
      HOLEPUNCH_REGISTRY_HOST: https://route-registry.namespace.svc.cluster.local:5001
      HOLEPUNCH_TOKEN_HOST: https://token-service.namespace.svc.cluster.local:8080
```

### Builds

To build the binary version of Holepunch from source
simply:

```shell
make build
```

Release binaries are written to `binaries/`. However, most deployments
would instead rely upon a container registry:

```shell
make build-container
```

## Admin API

The admin API is intended for operators and troubleshooting. It is currently
unauthenticated and must be kept unreachable from untrusted networks. It
is not required for deployments; however, does provide the Route Registry
and Token Service mechanism by which internal state can be immediately updated,
as opposed to waiting for [cache timeouts](docs/caching.md).

| Endpoint                     | Method | Purpose                                                    |
|------------------------------|--------|------------------------------------------------------------|
| `/api/v1/healthz`            | `GET`  | Health check.                                              |
| `/api/v1/version`            | `GET`  | Server version metadata.                                   |
| `/api/v1/state/ctls`         | `GET`  | Current route registry destinations and internal controls. |
| `/api/v1/webhook/routes`     | `POST` | Trigger an async update to the route registry cache.       |
| `/api/v1/webhook/invalidate` | `POST` | Remove specified token/subtoken entries from cache.        |

## Development

For local development we advise installing the following:

- [Go](https://go.dev/)
- [golangci-lint](https://github.com/golangci/golangci-lint)
- [govulncheck](https://go.dev/doc/security/vuln/)
- [Podman](https://podman.io/)
- [Podman Compose](https://github.com/containers/podman-compose)

The only required dependency for local development remains Go, and can
be installed at the correct version using [Spack](https://spack.io):

```shell
spack env activate -d .
spack install
```

Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for additional
details, and refer to `make help` for a comprehensive list of supported
commands aimed at improving your development/testing pipelines.

In addition it is possible to start the local compose environment:

```shell
make dev
```

The stack builds a Linux dev binary, starts Envoy, Holepunch admin/auth/cacher/xDS,
Jaeger, mock APIs, NATS, oauth2-proxy, Redis, and Dex. It can take approximately 30 seconds
before Envoy has received dynamic clusters.

We can make a basic `/whoami` request to identify all headers the upstream
application will see:

```shell
$ curl -s -H "X-Token: c520c08c-0325-48c4-8bd1-57bde8c7c382.foo" http://localhost:3128/whoami
{
  "Host": "mock-api:9001",
  "X-Request-Id": "51df78b4-38b8-9494-bd9f-4fdc0fbd13c5",
  ...
}
```

Additional details and functionality for the local development environment
can be found in the [docs/local-deployment.md](docs/local-deployment.md).

## Governance

Contributions are welcome. Contributors should look in [CONTRIBUTING.md](CONTRIBUTING.md)
for project guidelines on how to create and structure pull requests.

This project is licensed under the Apache 2.0 license with LLVM exception. The
full license text is available in `LICENSE`.

LLNL-CODE-2020712
