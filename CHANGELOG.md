# Changelog

## v0.2.0 (September 1, 2026)

### Admin Changes

* Introduce new check and allowlist config for redirect verification
  ([!14](https://github.com/llnl/wormhole-holepunch/pull/14))
* Updated storage related arguments and improved underlying interfaces
  ([!16](https://github.com/llnl/wormhole-holepunch/pull/16))

### Bug & Development Fixes

* Fix bug in Makefile and container build process
  ([!15](https://github.com/llnl/wormhole-holepunch/pull/15))
* Leverage Envoy context for supply key request details
  ([!3](https://github.com/llnl/wormhole-holepunch/pull/3))
* Improve Envoy resource header identification and testing
  ([!4](https://github.com/llnl/wormhole-holepunch/pull/4))
* Go version *1.26.7*
  ([!11](https://github.com/llnl/wormhole-holepunch/pull/11))
* GitHub actions
  ([!1](https://github.com/llnl/wormhole-holepunch/pull/1),
  [!8](https://github.com/llnl/wormhole-holepunch/pull/7))
* Introduce `--development` flag and improve local dev environment
  ([!9](https://github.com/llnl/wormhole-holepunch/pull/9))
* Improve `internal/ctls/errs` package and custom header handling
  ([!10](https://github.com/llnl/wormhole-holepunch/pull/10))
* Patch default Envoy to *v1.38.4* and control panel
  ([!12](https://github.com/llnl/wormhole-holepunch/pull/12))
* Bump go.opentelemetry.io/otel *v1.44.0*
  ([!6](https://github.com/llnl/wormhole-holepunch/pull/6))
* Bump Bump google.golang.org/grpc *v1.82.1*
  ([!5](https://github.com/llnl/wormhole-holepunch/pull/5))

## v0.1.0 (July 24, 2026)

* Initial open source release
