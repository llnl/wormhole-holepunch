define _build
	CGO_ENABLED=0 \
	${GOCMD} build \
		${BUILD_FLAGS} \
		-ldflags "${LDFLAGS}" \
		-tags "${BUILD_TAGS}" \
		-o ${BUILDDIR}${1} \
		cmd/${1}/main.go;
endef

define CROSS_build
	CGO_ENABLED=0 \
	GOOS=${1} \
	GOARCH=${2} \
	${GOCMD} build \
		${BUILD_FLAGS} \
		-ldflags "${LDFLAGS}" \
		-tags "${BUILD_TAGS}" \
		-o ${BUILDDIR}${3}-${1}-${2} \
		cmd/${3}/main.go;
endef

.PHONY: build #B Build application locally in project builds directory.
build: build-dir
	$(foreach bt,holepunch,$(call _build,$(bt)))

.PHONY: build-linux #B Build application for GOOS=linux in project builds directory.
build-linux: build-dir
	$(call CROSS_build,linux,amd64,holepunch)
	$(call CROSS_build,linux,arm64,holepunch)

.PHONY: build-linux-dev #B Build application for GOOS=linux for the current GOARCH.
build-linux-dev: build-dir
	$(call CROSS_build,linux,${GOARCH},holepunch)
	mv ${BUILDDIR}holepunch-linux-${GOARCH} ${BUILDDIR}holepunch-dev

define WASM_build
	CGO_ENABLED=0 \
	GOOS=wasip1 \
	GOARCH=wasm \
	${GOCMD} build \
		${BUILD_FLAGS} \
		-buildmode=c-shared \
		-ldflags "-s -w" \
		-o ${BUILDDIR}${1}.wasm \
		./cmd/plugins/${1} && \
	chmod 644 ${BUILDDIR}${1}.wasm;
endef

# Every directory beneath cmd/plugins is a proxy-wasm plugin module.
WASM_PLUGINS := $(notdir $(wildcard cmd/plugins/*))
WASM_PLUGIN ?=

ifneq ($(strip $(WASM_PLUGIN)),)
ifneq ($(words $(WASM_PLUGIN)),1)
$(error WASM_PLUGIN must name exactly one plugin; available plugins: $(WASM_PLUGINS))
endif
ifeq ($(filter $(WASM_PLUGIN),$(WASM_PLUGINS)),)
$(error Unknown WASM_PLUGIN '$(WASM_PLUGIN)'; available plugins: $(WASM_PLUGINS))
endif
WASM_PLUGINS_TO_BUILD := $(WASM_PLUGIN)
else
WASM_PLUGINS_TO_BUILD := $(WASM_PLUGINS)
endif

.PHONY: build-wasm #B Build proxy-wasm plugins; set WASM_PLUGIN to build only one.
build-wasm: build-dir
	$(foreach p,$(WASM_PLUGINS_TO_BUILD),$(call WASM_build,$(p)))

HOLEPUNCH_IMAGE ?= ghcr.io/llnl/wormhole-holepunch
HOLEPUNCH_TAG ?= local

HOLEPUNCH_PLUGIN_IMAGE_PREFIX ?= ${HOLEPUNCH_IMAGE}

.PHONY: build-container #B Build Holepunch, combined plugin, and individual proxy-wasm plugin images.
build-container:
	mkdir -p certs
	${CONTAINER_RUNTIME} build \
		-f build/image/Containerfile \
		--build-arg GO_VERSION=${GO_SEMVER} \
		--target holepunch \
		-t ${HOLEPUNCH_IMAGE}:${HOLEPUNCH_TAG} \
		.
	${CONTAINER_RUNTIME} build \
		-f build/image/plugins.Containerfile \
		--build-arg GO_VERSION=${GO_SEMVER} \
		-t ${HOLEPUNCH_IMAGE}-plugins:${HOLEPUNCH_TAG} \
		.
	set -e; for plugin in ${WASM_PLUGINS}; do \
		${CONTAINER_RUNTIME} build \
			-f build/image/wasm.Containerfile \
			--build-arg GO_VERSION=${GO_SEMVER} \
			--build-arg WASM_PLUGIN=$$plugin \
			-t ${HOLEPUNCH_PLUGIN_IMAGE_PREFIX}-$$plugin:${HOLEPUNCH_TAG} \
			.; \
	done

.PHONY: sbom #B Generate SBOM for the application using cyclonedx-gomod.
sbom:
	cyclonedx-gomod mod -licenses=true -json -output bom.json  .

.PHONY: vendor #B Vendor all dependencies using Go.
vendor:
	${GOCMD} mod tidy
	${GOCMD} mod vendor

.PHONY: dev #D Deploy local dev/test environment using Compose (foreground).
dev: build-linux-dev build-wasm dev-down dev-permissions
	${CONTAINER_RUNTIME} compose -p holepunch-dev -f ${ROOT_DIR}/build/dev/compose.yaml up

.PHONY: dev-up #D Build and deploy the local dev/test environment in the background.
dev-up: build-linux-dev build-wasm dev-down dev-permissions
	${CONTAINER_RUNTIME} compose -p holepunch-dev -f ${ROOT_DIR}/build/dev/compose.yaml up -d

.PHONY: dev-test #D Test the full local OAuth middleware flow (requires make dev or dev-up).
dev-test:
	python3 ${ROOT_DIR}/tools/dev-auth-test.py

.PHONY: dev-down #D Shutdown the local  podman-compose environment.
dev-down:
	${CONTAINER_RUNTIME} compose -p holepunch-dev -f ${ROOT_DIR}/build/dev/compose.yaml down

DEV_DATA_DIRS := nats-data redis-data
DEV_CLEAN_IMAGE ?= docker.io/library/golang:${GO_SEMVER}

# Data directories are written by the containers and may be owned by root (or a mapped
# UID), so the contents are removed from within a container rather than the host.
.PHONY: dev-clean #D Shutdown the local environment and remove all persisted NATS/Redis data.
dev-clean: dev-down
	${CONTAINER_RUNTIME} run --rm \
		-v ${ROOT_DIR}/build/dev:/dev-data:z \
		-w /dev-data \
		${DEV_CLEAN_IMAGE} \
		sh -c 'for d in $(DEV_DATA_DIRS); do if [ -d "$$d" ]; then find "$$d" -mindepth 1 -delete; fi; done'

.PHONY: dev-stats #D Identify resource usage of local podman-compose environment.
dev-stats:
	${CONTAINER_RUNTIME} compose -p holepunch-dev -f ${ROOT_DIR}/build/dev/compose.yaml stats

.PHONY: dev-ps #D Identify status of local podman-compose environment.
dev-ps:
	${CONTAINER_RUNTIME} compose -p holepunch-dev -f ${ROOT_DIR}/build/dev/compose.yaml ps

.PHONY: build-dir
build-dir:
	mkdir -p ${BUILDDIR}

.PHONY: dev-permissions
DEV_PERM_FILES := dex.yaml envoy.yaml oauth2-proxy.cfg static.yaml

dev-permissions:
	chmod 664 $(addprefix build/dev/,$(DEV_PERM_FILES))
