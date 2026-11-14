# mcp-wpp

A single Go binary, `wpp-mcp`, that links to a personal WhatsApp account through [whatsmeow](https://github.com/tulir/whatsmeow), keeps an encrypted local cache, and exposes it to MCP clients with per-chat consent. `wpp-mcp serve` runs the daemon (stateless Streamable HTTP at `/mcp`, operator pages and admin API). `wpp-mcp stdio` bridges stdio MCP clients to it. Forked from sealjay/mcp-whatsapp.

## Structure

```text
cmd/wpp-mcp/         subcommands: serve, stdio, pair, login, access, outbox, keygen, encrypt, open-ui, tools, healthcheck, smoke
internal/client/     whatsmeow wrapper: send, download, media cache (sealed), events, history, retention, features
internal/crypto/     key file + HKDF sub-keys, SQLCipher connector, sealed media, plaintext→encrypted migration
internal/daemon/     HTTP server: Host/Origin + auth guards, UI login, /pair, /access, /outbox, /admin/*
internal/mcp/        mcp-go server: tool registrations, access middleware, confirmation (outbox), profiles, catalog
internal/store/      SQLite cache: queries, access policy (scoped views), FTS5 index, outbox, digest, retention
internal/transcribe/ OpenAI-compatible speech-to-text client
internal/security/   path allowlisting, filename sanitising, log redaction
e2e/                 end-to-end tests against the real binary (build tag e2e)
docs/                tools.md (generated), systemd/launchd units, Claude Code hook
```

The store directory (`-store`, `WPP_MCP_STORE`) holds `messages.db`, `whatsapp.db` (session and Signal keys), `token`, `.lock`, the media cache (`<chat>/<hex(message id)>/<file>`) and `uploads/` (the media root).

## Security invariants

These are what the project is for. A change that weakens one needs an explicit decision, not a side effect.

1. **Every tool is classified three times**, and tests fail otherwise: read-only or not (`readOnlyToolAccess` in `internal/mcp/tools.go`), a group (`toolGroup` in `internal/mcp/profiles.go`), and an access scope (`toolAccessScope` in `internal/mcp/access.go`). Unclassified tools fail closed.
2. **MCP reads go through `s.store()`**, the scoped store view. A new query that returns chat content must add `s.scopeClause(...)` (or `accessFilter`) in `internal/store`. A tool that names a chat must declare its argument in `toolAccessScope`, so the middleware checks it. Resources bypass tool middleware, so they check `allowedChat` themselves.
3. **Hidden and nonexistent chats must be indistinguishable**: same error text, no counts, no names. `request_chat_access` returns only an ID.
4. **Nothing personal is written in the clear.** Databases open only through `crypto.OpenSQLite` / `crypto.ReadOnlyConnector`, never `sql.Open("sqlite3", …)`. Media cache writes go through `Client.writeCacheFile`, and reads through `readCacheFile` / `ReadMedia`. The SQLCipher key travels as the `hexkey` URI parameter: a `PRAGMA key` after mattn's connection PRAGMAs cannot reopen an existing database.
5. **Every HTTP route is authenticated** except `/healthz`, `/readyz` and `/ui/login`. `/mcp` and `/admin/*` take the bearer token only, never the browser cookie. State-changing pages need a CSRF token. The Host/Origin guard wraps everything.
6. **Writes need consent**: with `-write`, tools that send or change the account create outbox proposals (`internal/mcp/outbox.go`). Only trivial self-visible actions are in `noConfirm`. Approval re-runs the access middleware.
7. **Pairing never goes through MCP.** `pairing_status` must not return QR payloads or codes.
8. **Logs stay redacted** through `security.Redactor`, and phone numbers are masked.

## Build and test

SQLCipher is required: `dnf install sqlcipher-devel`, `apt install libsqlcipher-dev` or `brew install sqlcipher`. The Makefile links mattn/go-sqlite3 (`-tags "libsqlite3 sqlite_fts5"`) against it through a symlink in `build/sqlcipher/`.

```bash
make build           # bin/wpp-mcp
make lint            # go vet + gofmt
make test            # unit tests; SQLCipher/FTS5 tests fail rather than skip (WPP_MCP_REQUIRE_CIPHER=1)
make test-race
make e2e             # real binary, encrypted throwaway stores, no WhatsApp account
make smoke
make container-test  # all of the above in Debian, for hosts without SQLCipher
make docs            # regenerate docs/tools.md (CI fails if it is stale)
```

A plain `go test ./...` also works: crypto and FTS tests skip, and the store falls back to LIKE search. Store tests use `openTestStore(t)` (seeded in-memory DB, `internal/store/testdata/seed.sql`). Access tests in `internal/mcp/access_test.go` show how to build a server over a real store without connecting to WhatsApp. Never point tests at a live account.

When adding a tool:

1. Register it in the right `tools_*.go`.
2. Classify it in the three maps above.
3. Update the counts in `internal/mcp/tools_test.go`.
4. Run `make docs`.

## Tool descriptions

- State the purpose, side effects, reversibility, return shape and when to use another tool. Keep it to three sentences where possible.
- Reuse `jidDesc` / `recipientDesc` for JID arguments. Recipients take phone digits without `+`.
- Read-only cache tools start with `offlineSafePrefix`.
- Text results that carry message content start with `untrustedPreamble`.

## whatsmeow upgrades

`make upgrade-check` bumps whatsmeow to `@main`, tidies, builds and tests. CI runs it weekly and keeps a rolling issue. `scripts/mdtest-parity.sh` fails if a whatsmeow method we call disappears.

## Git, versions and releases

- Branch from `main` (`feat/<slug>`, `fix/<slug>`), use conventional commits, and open focused pull requests. CI must pass (lint, unit, e2e, container, secrets scan, docs freshness).
- Versions come from Git tags (`git describe` → `main.Version` via `-ldflags`). Do not add a version file. Pre-1.0, a minor bump may break things; mark those commits with `!` and a `BREAKING CHANGE:` footer.
- Release: tag `vX.Y.Z` on a clean `main`. `.github/workflows/release.yml` publishes multi-arch images to `ghcr.io/murandido/mcp-wpp`.

## Language

Repository content (code, comments, docs, commit messages) is in English.
