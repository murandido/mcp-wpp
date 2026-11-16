# mcp-wpp

A single Go binary, `wpp-mcp`, that links to a personal WhatsApp account through [whatsmeow](https://github.com/tulir/whatsmeow), keeps an encrypted local cache, and exposes it to MCP clients with per-chat consent. `wpp-mcp serve` runs the daemon (stateless Streamable HTTP at `/mcp`, operator pages and admin API). `wpp-mcp stdio` bridges stdio MCP clients to it. Forked from sealjay/mcp-whatsapp.

## Structure

```text
cmd/wpp-mcp/         subcommands: serve, stdio, pair, login, access, outbox, schedule, token, oauth, audit, keygen, encrypt, backup, restore, rekey, open-ui, tools, healthcheck, smoke
internal/alert/      session alerts: state machine (down/logged out/up) and webhook notifier with retries
internal/backup/     encrypted backup archives, verify, restore, key rotation (crash-safe, see rekey.go)
internal/client/     whatsmeow wrapper: send, download, media cache (sealed), events, history, retention, features, read state and mentions
internal/auth/       caller identity on the request context, client token format and hashing
internal/clientip/   client address behind a request (X-Forwarded-For only from loopback/private peers), for rate limits
internal/crypto/     key file + HKDF sub-keys, SQLCipher connector, sealed media, plaintext→encrypted migration
internal/daemon/     HTTP server: Host/Origin + auth guards, UI login, /pair, /access, /outbox, /admin/*
internal/mcp/        mcp-go server: tool registrations, audit, scope and access middlewares, send policy and confirmation (outbox), scheduler, profiles, catalog
internal/metrics/    Prometheus text exposition for GET /admin/metrics
internal/oauth/      OAuth 2.1 authorization server: metadata, DCR, CIMD fetch (SSRF-guarded), authorize page, operator approval, token, revoke
internal/store/      SQLite cache: queries, access policy (scoped views), send policy, FTS5 index, outbox and scheduled messages, digest and read state, retention, API tokens, OAuth clients and grants, audit log
internal/webhook/    signed outgoing webhooks for live incoming messages: filters, bounded queue, coalescing, retries
internal/transcribe/ OpenAI-compatible speech-to-text client
internal/ocr/        local Tesseract OCR for images: stdin/stdout only, timeout, size and output bounds
internal/security/   path allowlisting, filename sanitising, log redaction
e2e/                 end-to-end tests against the real binary (build tag e2e)
docs/                tools.md (generated), systemd/launchd units, Claude Code hook
```

The store directory (`-store`, `WPP_MCP_STORE`) holds `messages.db`, `whatsapp.db` (session and Signal keys), `token`, `.lock`, the media cache (`<chat>/<hex(message id)>/<file>`) and `uploads/` (the media root). Maintenance commands use hidden entries there: `.rekey-state` (an unfinished key rotation; `serve` refuses to start while it exists), `.pre-restore` and `.restore-staging`.

## Security invariants

These are what the project is for. A change that weakens one needs an explicit decision, not a side effect.

1. **Every tool is classified three times**, and tests fail otherwise: read-only or not (`readOnlyToolAccess` in `internal/mcp/tools.go`), a group (`toolGroup` in `internal/mcp/profiles.go`), and an access scope (`toolAccessScope` in `internal/mcp/access.go`). Unclassified tools fail closed.
2. **MCP reads go through `s.store(ctx)`**, the scoped store view. A new query that returns chat content must add `s.scopeClause(...)` in `internal/store` (`accessFilter` alone ignores a client token's chat set; pair it with `s.tokenFilter`). A tool that names a chat must declare its argument in `toolAccessScope`, so the middleware checks it. Resources bypass tool middleware, so they check `allowedChat` themselves.
3. **Hidden and nonexistent chats must be indistinguishable**: same error text, no counts, no names. `request_chat_access` returns only an ID.
4. **Nothing personal is written in the clear.** Databases open only through `crypto.OpenSQLite` / `crypto.ReadOnlyConnector`, never `sql.Open("sqlite3", …)`. Media cache writes go through `Client.writeCacheFile`, and reads through `readCacheFile` / `ReadMedia`. The one exception is `internal/backup`, which copies sealed files verbatim and, in `rekey`, re-seals them in memory with `crypto.MediaCipher`; it never writes plaintext, not even to temporary files. Database copies use `crypto.SnapshotDatabase` (online backup API between two keyed connections). The SQLCipher key travels as the `hexkey` URI parameter: a `PRAGMA key` after mattn's connection PRAGMAs cannot reopen an existing database.
5. **Every HTTP route is authenticated** except `/healthz`, `/readyz`, `/ui/login` and, with `-oauth`, the exact paths in `oauth.IsPublicPath`. `/mcp` and `/admin/*` take a bearer token only, never the browser cookie. State-changing pages need a CSRF token. The Host/Origin guard wraps everything. Rejected bearer credentials are counted per client IP (`clientip.FromRequest`) and lock it out with 429 before any token is compared; `/mcp` is token-bucket limited per client token. Both keep bounded memory.
6. **Writes need consent**: with `-write`, a tool that sends or changes the account follows the target chat's send policy (`chat_send_policy`, `internal/mcp/sendpolicy.go`): `none` refuses it, `confirm` creates an outbox proposal (`internal/mcp/outbox.go`), `direct` acts. Chats without a policy use the default from `-confirm-sends`; tools that target no chat always use the default. The send policy is resolved from the `toolAccessScope` argument after the access check, so it never widens visibility and a hidden chat still gets "chat not found". Only trivial self-visible actions are in `noConfirm`, and `none` still refuses them. A chat's send window (`internal/mcp/sendwindow.go`, read in `-timezone`) is resolved after the policy: outside it, `deferrable` message tools become scheduled items or deferred proposals for the next opening, and every other write to the chat is refused. Approval re-runs the access middleware and the send policy. Outbox items record their creator (`created_by`, from `auth.Caller(ctx)`, or `store.WithCreator`); an item whose client token has been revoked is refused at approval and at send time (`CreatorRevoked`). With `-self-approve`, `approve`/`reject`/`outbox` typed in the account's own chat call the same `ApproveProposal`/`RejectProposal` (`internal/mcp/selfapprove.go`); `client.selfCommandOf` accepts only live, recent messages in the own chat from the account and from a device other than the daemon's own, so nothing the daemon sends can approve, and write tools may not target the own chat while it is on.
7. **Pairing never goes through MCP.** `pairing_status` must not return QR payloads or codes.
8. **Logs stay redacted** through `security.Redactor`, and phone numbers are masked.
9. **Identity travels with the request.** `authGuard` attaches an `auth.Identity` (operator, or client token with scopes and chats) to the request context, and MCP handlers read it with `auth.Caller(ctx)`. Client tokens (`internal/store/tokens.go`) are accepted on `/mcp` only, stored as SHA-256 and compared in constant time; unknown, revoked and expired tokens get the same 401. `scopeMiddleware` requires `send` for every tool that is not read-only. A token's chat set narrows, never widens, the access policy: reads go through `s.store(ctx)` (`Store.ScopedTo`, applied in SQL by `scopeClause`) and chat checks through `allowedChat(ctx, …)`, so new code must pass the request context rather than build its own scoped store.
10. **Everything is audited, nothing is quoted.** `auditMiddleware` (outermost) records every tool call and the resource middleware every read: actor, tool, the chat from `toolAccessScope`, outcome (`ok`, `error`, `denied`, `proposed`, set with `markAudit`) and duration. `daemon.auditAdmin` records state-changing operator requests with a whitelist of fields. Never add message text, other arguments, results or secrets to an audit entry.
11. **Scheduled messages are writes too.** `schedule_message` follows the send policy when it is created; the scheduler (`RunScheduler`, `-write` only) re-checks access and the send policy at send time, sends through the rate-limited send path, and claims each item atomically (`ClaimScheduled`) so nothing is sent twice. The scheduler also moves an item due outside its chat's send window to the next opening (`deferIfClosed`). Operator schedules (`wpp-mcp schedule`, creator `operator:cli`, through the daemon or, when it is down, straight into the store) need no approval and ignore send windows, but still require a visible chat.
12. **Webhooks only report allowed chats.** `internal/webhook` re-checks `ChatAllowed` when each batch is sent, never sends history sync or the account's own messages, leaves text out unless `-webhook-include-text`, never sends media bytes, and never logs the URL or secret (only the host).
13. **Operational output carries no personal data.** Metric labels take values from fixed sets (tool names, outcomes, states); alert payloads hold an event kind, a time and a fixed message. Backup archives exclude the key file and the token.
14. **OAuth only mints client tokens.** An OAuth access token is an `api_tokens` row with scopes, chats, an `audience` and a `grant_id`, so everything in invariant 9 applies and it never opens `/admin/*` or the pages. Approval is operator-only, over the bearer admin API (`wpp-mcp oauth approve`), never from the public authorization page; the short code alone completes nothing (the page's opaque request ID and the client's PKCE verifier are also needed). `authGuard` refuses any token whose audience is set and is not the OAuth server's `<public-url>/mcp`, including every audience-bound token when OAuth is off. Redirects go only to an exact entry of the redirect allowlist and are built from the configured value, never from request text; an unknown client or redirect URI gets an error page, never a redirect. Client metadata documents are fetched only from Anthropic origins rebuilt by `cimdFetchURL` (never a caller-chosen host), through `oauth.NewFetchClient` (no redirects, dial-time address guard). Refresh tokens rotate and a reused one revokes its grant.

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

Lint findings are fixed, not silenced. A `//nolint` needs the linter name and a reason, and `nolintlint` enforces that. Repository-wide exclusions live in `.golangci.yml` with a justification. Ubuntu and Debian SQLCipher packages include FTS5, but Fedora's does not; there, FTS tests skip locally. The container stage (`WPP_MCP_REQUIRE_FTS5=1`) always requires it. OCR tests that run the real `tesseract` skip when it is missing, except in the container stage (`WPP_MCP_REQUIRE_TESSERACT=1`).

A plain `go test ./...` also works: crypto and FTS tests skip, and the store falls back to LIKE search, which stays case- and accent-insensitive through `unaccent_lower`, a SQL function the crypto connector registers on every connection (so test databases must be opened through it too). Store tests use `openTestStore(t)` (seeded in-memory DB, `internal/store/testdata/seed.sql`). Access tests in `internal/mcp/access_test.go` show how to build a server over a real store without connecting to WhatsApp. Never point tests at a live account.

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
