ARG GO_VERSION=latest
FROM docker.io/library/golang:${GO_VERSION} AS build

ARG WASM_PLUGIN

WORKDIR /holepunch
COPY . .

RUN test -n "${WASM_PLUGIN}" && \
    make build-wasm WASM_PLUGIN=${WASM_PLUGIN} && \
    cp "binaries/${WASM_PLUGIN}.wasm" /holepunch/plugin.wasm

FROM scratch

COPY --from=build /holepunch/plugin.wasm /plugin.wasm
