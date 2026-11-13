# Local Development Deployment

We support a local deployment utilizing either
[Podman Compose](https://github.com/containers/podman-compose)
or [Docker Compose](https://docs.docker.com/compose/) (whichever
you choose) to realize a rough approximation of what a Holepunch
along with Envoy deployment would look like. The primary proxy target
is a simple Flask server (`tools/mock-api`) acting as a range of mock
API servers.

## Prerequisites and Startup

* Go 1.26 or newer.
* A running Podman machine or Docker engine with a Compose provider.
* Python 3 for the automated flow tests; `curl` and `jq` for manual inspection.
* Available local ports: 3128, 4180, 5556, 8081, 8082, 9001, 9002, 9901,
  16686, 9411, and 4317.

Start the deployment from the repository root:

```shell
make dev
# Or build and start in the background:
make dev-up
# Select a runtime explicitly if both are installed:
# make dev-up CONTAINER_RUNTIME=docker
```

Both startup targets rebuild the Linux executable for the host's Go architecture,
then recreate the containers.

Allow at least 30 seconds for startup (longer on the first run while images and
mock-server dependencies download). Containers being started does not mean Envoy
has received its routes yet. Check status and unauthenticated readiness with:

```shell
make dev-ps
curl -fsS http://127.0.0.1:3128/ping | jq
make dev-test
```

`make dev-test` waits up to 120 seconds for routing and the initial auth redirect,
then exits nonzero on any failed assertion.

## What Runs Locally

| Service                      | Role                                                     |
|------------------------------|----------------------------------------------------------|
| Envoy                        | Application proxy                                        |
| Holepunch Auth               | Session validation and browser-bound flow creation       |
| Holepunch oauthmngr + NATS   | Session hand-off callbacks and single-use flow ledger     |
| oauth2-proxy + Redis         | OAuth/session validation and session storage             |
| Dex                          | Local OIDC provider with development users               |
| Mock API                     | Route registry, token exchange, and `/whoami` upstream   |
| Holepunch admin, cacher, xDS | Reporting, cached configuration, and Envoy configuration |
| Mock socket, Jaeger          | WebSocket upstream and trace UI                          |

Redis is **oauth2-proxy's session store**, not the flow ledger. Its configuration
must agree with `HOLEPUNCH_OAUTH_PROXY_SESSION_STORE=redis`. The shared auth host
is served by Envoy on port 3128; port 4180 is oauth2-proxy's direct diagnostic
endpoint, not the browser entry point.

## Token Requests

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

Now with with support for communities you'll find the `X-Subtoken` injected on
requests that are valid members of a community. This token can be used in subsequent
requests to the same community:

```shell
$ curl -s -H "X-Token: 6f1dd5eb-d058-433f-89b7-1f87980b1d0d.sub" http://localhost:3128/whoami -i
HTTP/1.1 200 OK
...

$ curl -s -H "X-Token: 6f1dd5eb-d058-433f-89b7-1f87980b1d0d.sub" http://localhost:3128/rewrite | jq 
{
  "code": 16,
  "message": "Unauthorized",
  "details": [
    "subtoken does not align with required community: "
  ]
}
```

## Browser OAuth Flow

For manual browser testing, add the following entries to your host system's
`/etc/hosts` file:

```text
# Utilized for Holepunch dev environment
127.0.0.1       envoy.holepunch.localwormhole
127.0.0.1       app.holepunch.localwormhole
127.0.0.1       auth.holepunch.localwormhole
127.0.0.1       dex.holepunch.localwormhole
```

Navigate to
[http://envoy.holepunch.localwormhole:3128/whoami](http://envoy.holepunch.localwormhole:3128/whoami).
The development credentials are:

* `foo@example.com`/`password`
* `bar@example.com`/`password` (authenticates with Dex but cannot exchange for a Jump Token)

Utilize your browser's network inspection tools to verify the flow.

## Admin API

You can also reach the administrative API for Holepunch. For example,
`/api/v1/state/ctls` offers a moment in time view of the services
understanding of routing and authorization.

```shell
curl -s http://127.0.0.1:8082/api/v1/state/ctls | jq
```

Inspect the generated route kinds:

```shell
curl -fsS http://127.0.0.1:8082/api/v1/state/ctls |
  jq 'to_entries[] | {id: .key, host: .value.source, kind: .value.kind}'
```

Expect `upstream` and `oauth-callback` routes on each application
host, plus `oauth2-proxy` and `oauth-callback` routes on the auth
host. This report is the admin service's reconstruction, not proof Envoy
accepted xDS. For applied configuration, inspect
[Envoy config dump](http://127.0.0.1:9901/config_dump); traces are available in
[Jaeger](http://127.0.0.1:16686).
