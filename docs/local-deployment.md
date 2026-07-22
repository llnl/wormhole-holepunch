# Local Development Deployment

We support a local deployment utilizing either
[Podman Compose](https://github.com/containers/podman-compose)
or [Docker Compose](https://docs.docker.com/compose/) (whichever
you choose) to realize a rough approximation of what a Holepunch
along with Envoy deployment would look like. The primary proxy target
is a simple Flask server (`tools/mock-api`) acting as a range of mock
API servers.

Starting the service is as simple as:

```shell
λ make dev
mkdir -p binaries/
GOOS=linux GOARCH=arm64 go build ...
mv binaries/holepunch-linux-arm64 binaries/holepunch-dev
podman compose -p holepunch-dev -f /example/wormhole-holepunch/build/dev/compose.yaml down
...
```

**Note** the development instance will take ~30 seconds to startup
before request can be accepted. You'll notice messages like this
appear once everything is up and running the test clusters are available:

```shell
[envoy]            | [2026-03-13 05:25:31.986][1][info][upstream] [source/common/upstream/cds_api_helper.cc:71] cds: added/updated 2 cluster(s), skipped 0 unmodified cluster(s)
```

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

## Oauth Request

In order to test Holepunch support for the oauth2 code flow
(relying upon [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)),
you will first need to add several entries to your host systems
`/etc/hosts` file:

```
# Utilized for Holepunch dev environment
127.0.0.1       envoy.holepunch.localwormhole
127.0.0.1       dex.holepunch.localwormhole
127.0.0.1       oauth.holepunch.localwormhole
```

Next from your browser navigate to:
[envoy.holepunch.localwormhole:3128/whoami](http://envoy.holepunch.localwormhole:3128/whoami).
You'll be prompted to login through Dex, the provided dev
credentials are:

* `foo@example.com`/`password`
* `bar@exampel.com`/`password` (user prevented from generating a Jump Token).

The [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) will handle the
authentication flow and cookie management (see the `_wormhole_holepunch_test`
cookie in your browser).

## Admin API

You can also reach the administrative API for Holepunch. For example,
`/api/v1/state/ctls` offers a moment in time view of the services
understanding of routing and authorization.

```shell
curl -s http://127.0.0.1:8082/api/v1/state/ctls | jq
```
