ARG GO_VERSION=latest
FROM docker.io/library/golang:${GO_VERSION} AS build

WORKDIR /holepunch
COPY  . .

# Limit to avoid resource issues when building.
ARG GOMAXPROCS=4

RUN make build-wasm

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.8

COPY --from=build /holepunch/binaries/*.wasm /plugins/
