.PHONY: fuzz docker-build check hooks vuln tidy-check docs-check lint-go docs build build-plain test test-race test-cover lint vet fmt clean login serve smoke e2e upgrade-check sqlcipher-check container-test

# fmt uses process substitution; force bash so `make lint` works under a POSIX /bin/sh
SHELL := /bin/bash

BIN := ./bin/wpp-mcp
PKGS := ./...
GO := go
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.Version=$(VERSION)

# --- SQLCipher linkage -------------------------------------------------------
# mattn/go-sqlite3 with the `libsqlite3` tag links `-lsqlite3`. We point that
# at SQLCipher through a private symlink so the binary encrypts the store.
# Install SQLCipher first: Fedora `dnf install sqlcipher-devel`, Debian/Ubuntu
# `apt install libsqlcipher-dev`, macOS `brew install sqlcipher`.
SQLCIPHER_LIB ?= $(firstword $(wildcard \
	/usr/lib64/libsqlcipher.so \
	/usr/lib/x86_64-linux-gnu/libsqlcipher.so \
	/usr/lib/aarch64-linux-gnu/libsqlcipher.so \
	/usr/lib/libsqlcipher.so \
	/opt/homebrew/opt/sqlcipher/lib/libsqlcipher.dylib \
	/usr/local/opt/sqlcipher/lib/libsqlcipher.dylib))
SQLCIPHER_INC ?= $(firstword $(wildcard \
	/usr/include/sqlcipher \
	/opt/homebrew/opt/sqlcipher/include/sqlcipher \
	/usr/local/opt/sqlcipher/include/sqlcipher))
LINKDIR := $(CURDIR)/build/sqlcipher
LIBEXT := $(if $(filter %.dylib,$(SQLCIPHER_LIB)),dylib,so)

export CGO_ENABLED := 1
export CGO_CFLAGS := -I$(SQLCIPHER_INC) -DSQLITE_HAS_CODEC
export CGO_LDFLAGS := -L$(LINKDIR) -Wl,-rpath,$(dir $(SQLCIPHER_LIB))
# Tests that need SQLCipher fail instead of skipping when built through make.
export WPP_MCP_REQUIRE_CIPHER := 1
TAGS := -tags "libsqlite3 sqlite_fts5"

sqlcipher-check:
	@if [ -z "$(SQLCIPHER_LIB)" ] || [ -z "$(SQLCIPHER_INC)" ]; then \
		echo "SQLCipher not found. Install it (Fedora: dnf install sqlcipher-devel; Debian/Ubuntu: apt install libsqlcipher-dev; macOS: brew install sqlcipher)"; \
		echo "or run the suite in a container with: make container-test"; exit 1; fi
	@mkdir -p $(LINKDIR)
	@ln -sf $(SQLCIPHER_LIB) $(LINKDIR)/libsqlite3.$(LIBEXT)

build: sqlcipher-check
	mkdir -p bin
	$(GO) build $(TAGS) -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/wpp-mcp

# Plain SQLite build without encryption support. The binary refuses to run
# unless -no-encryption (or WPP_MCP_NO_ENCRYPTION=1) is set.
build-plain:
	mkdir -p bin
	env -u CGO_CFLAGS -u CGO_LDFLAGS $(GO) build -tags sqlite_fts5 -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/wpp-mcp

test: sqlcipher-check
	$(GO) test $(TAGS) $(PKGS)

test-race: sqlcipher-check
	$(GO) test $(TAGS) -race $(PKGS)

test-cover: sqlcipher-check
	$(GO) test $(TAGS) -race -coverprofile=cover.out $(PKGS)
	$(GO) tool cover -func=cover.out | tail -1

vet: sqlcipher-check
	$(GO) vet $(TAGS) $(PKGS)

fmt:
	@diff -u <(echo -n) <(gofmt -d .) || (echo "gofmt differences found"; exit 1)

# golangci-lint and govulncheck versions are pinned here and in CI.
GOLANGCI_VERSION := v2.12.2
GOVULNCHECK_VERSION := v1.6.0

lint-go: sqlcipher-check
	@command -v golangci-lint >/dev/null || { echo "golangci-lint missing: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)"; exit 1; }
	golangci-lint run ./...

lint: vet fmt lint-go

vuln: sqlcipher-check
	@command -v govulncheck >/dev/null || { echo "govulncheck missing: go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)"; exit 1; }
	govulncheck -tags libsqlite3,sqlite_fts5 ./...

# Run every fuzz target for FUZZTIME (default 20s each). Failing inputs are
# saved under testdata/fuzz/ and replayed by `make test` from then on.
FUZZTIME ?= 20s
fuzz: sqlcipher-check
	FUZZTIME=$(FUZZTIME) GO=$(GO) TAGS="libsqlite3 sqlite_fts5" scripts/fuzz.sh

# go.mod and go.sum must already be tidy.
tidy-check:
	$(GO) mod tidy -diff

# docs/tools.md must match the tool registry.
docs-check:
	@env -u CGO_CFLAGS -u CGO_LDFLAGS $(GO) run ./cmd/wpp-mcp tools -markdown | diff -u docs/tools.md - || { echo "docs/tools.md is stale: run make docs"; exit 1; }

# Everything CI runs, in one command.
check: lint vuln tidy-check docs-check test-race smoke e2e
	@echo "all gates passed"

# Use the repository's commit-msg and pre-push hooks.
hooks:
	git config core.hooksPath .githooks
	@echo "hooks installed: commit messages are checked, and push runs make lint test"

e2e: build
	$(GO) test -tags "libsqlite3 sqlite_fts5 e2e" ./e2e/...

login: build
	$(BIN) login

serve: build
	$(BIN) serve

smoke: build
	$(BIN) smoke

# Build the runtime image locally with the git version baked in.
docker-build:
	$(CONTAINER) build --target runtime --build-arg VERSION=$(VERSION) -t ghcr.io/murandido/mcp-wpp:latest .

# Run lint, unit, smoke and e2e tests inside Debian with SQLCipher, for hosts
# without it installed. Uses podman when available, else docker.
CONTAINER ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
container-test:
	$(CONTAINER) build -f Dockerfile --target test -t wpp-mcp:test .

# Regenerate docs/tools.md from the tool registry.
docs:
	env -u CGO_CFLAGS -u CGO_LDFLAGS $(GO) run ./cmd/wpp-mcp tools -markdown > docs/tools.md

clean:
	rm -rf bin build cover.out

upgrade-check: sqlcipher-check
	$(GO) get go.mau.fi/whatsmeow@main
	$(GO) mod tidy
	$(GO) build $(TAGS) ./...
	$(GO) test $(TAGS) $(PKGS)
