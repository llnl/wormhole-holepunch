SHELL := bash
.ONESHELL:
.DELETE_ON_ERROR:
.DEFAULT_GOAL := build
MAKEFLAGS += --no-builtin-rules

#
# Project & structure variables
PKG = github.com/llnl/wormhole-holepunch
INTERNAL_PKG = ${PKG}/internal
COVER_REPORT := cover.out
BUILDDIR ?= binaries/
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PREFIX ?= /usr/local
INSTALL_PREFIX := $(if $(DESTDIR),$(DESTDIR)/$(PREFIX),$(PREFIX))

#
# Version variables
GITCOMMIT := $(shell if git status >/dev/null 2>/dev/null; then \
	echo $$(git log --pretty=format:'%h' -n 1 2>/dev/null)$$(git diff --quiet || echo '_'); \
fi)
GITBRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GOVERSION := $(shell go version | cut -c12- | awk '{ gsub (" ", "-", $$0); print}')
BUILDDATE := $(shell date -u +"%Y-%m-%dT%T%z")
VERSION := $(if $(GITCOMMIT),$(shell cat VERSION).dev.${GITCOMMIT},$(shell cat VERSION))
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

#
# Go variables
GOCMD ?= go
CGO_ENABLED = 0
BUILD_FLAGS ?= -trimpath
BUILD_TAGS = netgo
LDFLAGS = -X ${INTERNAL_PKG}/version.version=${VERSION} \
		  -X ${INTERNAL_PKG}/version.gitCommit=${GITCOMMIT} \
		  -X ${INTERNAL_PKG}/version.gitBranch=${GITBRANCH} \
		  -X ${INTERNAL_PKG}/version.goVersion=${GOVERSION} \
		  -X ${INTERNAL_PKG}/version.buildDate=${BUILDDATE} \
		  -s \
		  -w

CONTAINER_RUNTIME ?= podman

include build/build.mk
include test/test.mk

RED := \033[31m
GREEN := \033[32m
RESET := \033[0m

#
# Miscellaneous
.PHONY: clean #M Remove all temporary build, packaging, and testing objects.
clean:
	${GOCMD} clean
	@rm -rf $(BUILDDIR) ${COVER_REPORT} bom/

.PHONY: version #M Display current version and Git details.
version:
	@printf "Version: ${VERSION}\n"
	@printf "Git Commit: ${GITCOMMIT}\n"
	@printf "Git Branch: ${GITBRANCH}\n"
	@printf "Go Version: ${GOVERSION}\n"
	@printf "Built: ${BUILDDATE}\n"

.PHONY: mocks #M Rebuild all mocks (https://github.com/golang/mock)
mocks:
	@bash ./test/scripts/mocks.bash

.PHONY: help
help:
	@printf "${GREEN}Usage: make [target] ...${RESET}\n\n"
	@printf "${GREEN}Build & Install${RESET}\n"
	@sed -ne '/@sed/!s/#B //p' $(MAKEFILE_LIST) | sed 's/^\.PHONY: //' | sed 's/^\([^ ]*\) /\1: /'
	@printf "\n${GREEN}Test${RESET}\n"
	@sed -ne '/@sed/!s/#T //p' $(MAKEFILE_LIST) | sed 's/^\.PHONY: //' | sed 's/^\([^ ]*\) /\1: /'
	@printf "\n${GREEN}Development${RESET}\n"
	@sed -ne '/@sed/!s/#D //p' $(MAKEFILE_LIST) | sed 's/^\.PHONY: //' | sed 's/^\([^ ]*\) /\1: /'
	@printf "\n${GREEN}Miscellaneous${RESET}\n"
	@sed -ne '/@sed/!s/#M //p' $(MAKEFILE_LIST) | sed 's/^\.PHONY: //' | sed 's/^\([^ ]*\) /\1: /'
