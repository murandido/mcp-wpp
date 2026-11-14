.PHONY: build build-plain test test-race test-cover lint vet fmt clean login serve smoke e2e upgrade-check sqlcipher-check container-test

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

lint: vet fmt

e2e: build
	$(GO) test -tags "libsqlite3 sqlite_fts5 e2e" ./e2e/...

login: build
	$(BIN) login

serve: build
	$(BIN) serve

smoke: build
	$(BIN) smoke

# Run lint, unit, smoke and e2e tests inside Debian with SQLCipher, for hosts
# without it installed. Uses podman when available, else docker.
CONTAINER ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
container-test:
	$(CONTAINER) build -f Dockerfile --target test -t wpp-mcp:test .

clean:
	rm -rf bin build cover.out

upgrade-check: sqlcipher-check
	$(GO) get go.mau.fi/whatsmeow@main
	$(GO) mod tidy
	$(GO) build $(TAGS) ./...
	$(GO) test $(TAGS) $(PKGS)
