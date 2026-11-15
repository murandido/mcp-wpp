# mcp-wpp

A single Go binary, `wpp-mcp`, that links to a personal WhatsApp account through [whatsmeow](https://github.com/tulir/whatsmeow), keeps an encrypted local cache, and exposes it to MCP clients with per-chat consent. `wpp-mcp serve` runs the daemon (stateless Streamable HTTP at `/mcp`, operator pages and admin API). `wpp-mcp stdio` bridges stdio MCP clients to it. Forked from sealjay/mcp-whatsapp.

## Structure

```text
cmd/wpp-mcp/         subcommands: serve, stdio, pair, login, access, outbox, token, audit, keygen, encrypt, open-ui, tools, healthcheck, smoke
internal/client/     whatsmeow wrapper: send, download, media cache (sealed), events, history, retention, features
internal/auth/       caller identity on the request context, client token format and hashing
internal/crypto/     key file + HKDF sub-keys, SQLCipher connector, sealed media, plaintext→encrypted migration
internal/daemon/     HTTP server: Host/Origin + auth guards, UI login, /pair, /access, /outbox, /admin/*
internal/mcp/        mcp-go server: tool registrations, access middleware, confirmation (outbox), profiles, catalog
internal/store/      SQLite cache: queries, access policy (scoped views), FTS5 index, outbox, digest, retention, API tokens, audit log
internal/transcribe/ OpenAI-compatible speech-to-text client
internal/security/   path allowlisting, filename sanitising, log redaction
e2e/                 end-to-end tests against the real binary (build tag e2e)
docs/                tools.md (generated), systemd/launchd units, Claude Code hook
```

The store directory (`-store`, `WPP_MCP_STORE`) holds `messages.db`, `whatsapp.db` (session and Signal keys), `token`, `.lock`, the media cache (`<chat>/<hex(message id)>/<file>`) and `uploads/` (the media root).

## Security invariants

These are what the project is for. A change that weakens one needs an explicit decision, not a side effect.

1. **Every tool is classified three times**, and tests fail otherwise: read-only or not (`readOnlyToolAccess` in `internal/mcp/tools.go`), a group (`toolGroup` in `internal/mcp/profiles.go`), and an access scope (`toolAccessScope` in `internal/mcp/access.go`). Unclassified tools fail closed.
2. **MCP reads go through `s.store(ctx)`**, the scoped store view. A new query that returns chat content must add `s.scopeClause(...)` in `internal/store` (`accessFilter` alone ignores a client token's chat set; pair it with `s.tokenFilter`). A tool that names a chat must declare its argument in `toolAccessScope`, so the middleware checks it. Resources bypass tool middleware, so they check `allowedChat` themselves.
3. **Hidden and nonexistent chats must be indistinguishable**: same error text, no counts, no names. `request_chat_access` returns only an ID.
4. **Nothing personal is written in the clear.** Databases open only through `crypto.OpenSQLite` / `crypto.ReadOnlyConnector`, never `sql.Open("sqlite3", …)`. Media cache writes go through `Client.writeCacheFile`, and reads through `readCacheFile` / `ReadMedia`. The SQLCipher key travels as the `hexkey` URI parameter: a `PRAGMA key` after mattn's connection PRAGMAs cannot reopen an existing database.
5. **Every HTTP route is authenticated** except `/healthz`, `/readyz` and `/ui/login`. `/mcp` and `/admin/*` take a bearer token only, never the browser cookie. State-changing pages need a CSRF token. The Host/Origin guard wraps everything.
6. **Writes need consent**: with `-write`, tools that send or change the account create outbox proposals (`internal/mcp/outbox.go`). Only trivial self-visible actions are in `noConfirm`. Approval re-runs the access middleware.
7. **Pairing never goes through MCP.** `pairing_status` must not return QR payloads or codes.
8. **Logs stay redacted** through `security.Redactor`, and phone numbers are masked.
9. **Identity travels with the request.** `authGuard` attaches an `auth.Identity` (operator, or client token with scopes and chats) to the request context, and MCP handlers read it with `auth.Caller(ctx)`. Client tokens (`internal/store/tokens.go`) are accepted on `/mcp` only, stored as SHA-256 and compared in constant time; unknown, revoked and expired tokens get the same 401. `scopeMiddleware` requires `send` for every tool that is not read-only. A token's chat set narrows, never widens, the access policy: reads go through `s.store(ctx)` (`Store.ScopedTo`, applied in SQL by `scopeClause`) and chat checks through `allowedChat(ctx, …)`, so new code must pass the request context rather than build its own scoped store.
10. **Everything is audited, nothing is quoted.** `auditMiddleware` (outermost) records every tool call and the resource middleware every read: actor, tool, the chat from `toolAccessScope`, outcome (`ok`, `error`, `denied`, `proposed`, set with `markAudit`) and duration. `daemon.auditAdmin` records state-changing operator requests with a whitelist of fields. Never add message text, other arguments, results or secrets to an audit entry.

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
make check           # every CI gate: lint (vet, gofmt, golangci-lint), govulncheck, tidy, docs, race tests, smoke, e2e
make hooks           # once per clone: commit-msg check and a pre-push `make lint test`
```

Lint findings are fixed, not silenced. A `//nolint` needs the linter name and a reason, and `nolintlint` enforces that. Repository-wide exclusions live in `.golangci.yml` with a justification. Ubuntu and Debian SQLCipher packages include FTS5, but Fedora's does not; there, FTS tests skip locally. The container stage (`WPP_MCP_REQUIRE_FTS5=1`) always requires it.

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

- Commit subjects are `type(scope): summary`, with `!` before the colon for breaking changes, e.g. `feat(access): …`, `fix(crypto)!: …`. Allowed types: feat, fix, chore, docs, refactor, perf, test, build, ci, style, revert. The scope is the area touched: `access`, `crypto`, `daemon`, `mcp`, `store`, `client`, `pairing`, `outbox`, `cli`, `docker`, `ci`, `docs`, `deps`. `scripts/check-commit-msg.sh` enforces it in the commit-msg hook and in CI, for commits and PR titles alike.
- Branch from `main` (`feat/<slug>`, `fix/<slug>`) and open focused pull requests. The required check is **All gates**: commits, `make check`, the container test stage, CodeQL and the secrets scan. `main` is squash-merged only, with the PR title as the commit subject (`scripts/protect-main.sh` configures this).
- Versions come from Git tags (`git describe` → `main.Version` via `-ldflags`). Do not add a version file. Pre-1.0, a minor bump may break things; mark those commits with `!` and a `BREAKING CHANGE:` footer.
- Release: tag `vX.Y.Z` on a clean `main`. `.github/workflows/release.yml` publishes multi-arch images to `ghcr.io/murandido/mcp-wpp`.

## Language

Repository content (code, comments, docs, commit messages) is in English.
