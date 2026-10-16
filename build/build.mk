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

HOLEPUNCH_IMAGE ?= ghcr.io/llnl/wormhole-holepunch
HOLEPUNCH_TAG ?= local

.PHONY: build-container #B Build a development Holepunch container.
build-container:
	mkdir -p certs
	${CONTAINER_RUNTIME} build \
		-f build/image/Containerfile \
		--build-arg GO_VERSION=${GO_SEMVER} \
		-t ${HOLEPUNCH_IMAGE}:${HOLEPUNCH_TAG} \
		.

.PHONY: sbom #B Generate SBOM for the application using cyclonedx-gomod.
sbom:
	cyclonedx-gomod mod -licenses=true -json -output bom.json  .

.PHONY: vendor #B Vendor all dependencies using Go.
vendor:
	${GOCMD} mod tidy
	${GOCMD} mod vendor

.PHONY: dev #D Deploy local dev/test environment using podman-compose.
dev: build-linux-dev dev-down dev-permissions
	${CONTAINER_RUNTIME} compose -p holepunch-dev -f ${ROOT_DIR}/build/dev/compose.yaml up

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
