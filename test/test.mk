EXCLUDED_DIRS := cmd internal/cmd test tools
EXCLUSION_PATTERN = $(shell echo $(EXCLUDED_DIRS) | tr ' ' '|')
EXCLUSION_REGEX = ${PKG}/(${EXCLUSION_PATTERN})
COVERAGE_PACKAGES = $(shell ${GOCMD} list ./... | grep -v -E '$(EXCLUSION_REGEX)')

.PHONY: test #T Run entire Go test suite locally, coverage report generated.
test:
	${GOCMD} test -p 1 -coverprofile ${COVER_REPORT} -cover -run Test -tags netgo -timeout 2m $(COVERAGE_PACKAGES)
	${GOCMD} tool cover -func=${COVER_REPORT}


.PHONY: test-package #T Run Go test targeting specific package (e.g., 'test-package PACKAGE=internal/registry')
test-package:
	@if [ -z "$(PACKAGE)" ]; then \
		echo "Error: You must specify a package name (e.g. make test-package PACKAGE=internal/registry)"; \
		exit 1; \
	fi
	${GOCMD} test -p 1 -coverprofile ${COVER_REPORT} -cover -run Test -tags netgo -timeout 2m -v ./${PACKAGE}
	${GOCMD} tool cover -func=${COVER_REPORT}

.PHONY: test-fuzz #T Run all fuzzing tests.
test-fuzz:
	${GOCMD} test -run Fuzz -tags fuzz,netgo -timeout 2m -v ./...

.PHONY: test-quality #T Go static linting (requires: https://github.com/golangci/golangci-lint).
test-quality:
	golangci-lint -j 2 run

.PHONY: test-vuln #T Go vulnerability check (see for overview: https://go.dev/blog/vuln)
test-vuln:
	govulncheck ./...

.PHONY: coverage #M Analyze Go coverage profile.
coverage:
	${GOCMD} tool cover -func=${COVER_REPORT}
