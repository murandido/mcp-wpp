# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/murandido/mcp-wpp/security/advisories/new). Do not open a public issue. Include the version (`wpp-mcp -version`), your setup (native or Docker, flags), and steps to reproduce. You can expect an acknowledgement within a week.

Issues in WhatsApp's protocol handling belong to [whatsmeow](https://github.com/tulir/whatsmeow).

## Threat model

`mcp-wpp` assumes:

- **The model is not trusted with everything.** Any chat it can read may contain prompt injection, and anything it reads reaches the model provider. The consent policy decides what it can read; the outbox decides what it can send.
- **Other local processes and web pages are not trusted.** Every route needs the bearer token (except health probes, the single-use UI login and, with `-oauth`, the OAuth endpoints), Host and Origin must be loopback or explicitly allowed, and browser sessions use HttpOnly, SameSite=Strict cookies with CSRF tokens.
- **Remote MCP clients are trusted only as far as their token says.** A client token works on `/mcp` only, carries scopes (`read`, `send`) and an optional chat set that narrows the access policy, and can expire or be revoked at once. Only its SHA-256 is stored. The operator token is the only credential for `/admin/*` and the operator pages.
- **OAuth connections are approved by you, on the server.** With `serve -oauth`, a remote connector obtains one-hour, audience-bound access tokens and rotating refresh tokens, but only after the operator approves its short code with `wpp-mcp oauth approve` (the bearer-only admin API). The public authorization page has no approve button and no password. Redirects go only to the configured allowlist, PKCE S256 is required, a reused refresh token revokes the connection, and client metadata documents are fetched only from `claude.ai` and `claude.com`, without redirects and never from private or loopback addresses; other clients use dynamic registration.
- **Social engineering is the main OAuth risk.** Anyone who can reach your server can start a flow from their own claude.ai account and ask you to approve the code their page shows; approving it connects *their* account to *your* WhatsApp. Only approve a code you see on your own screen, in a flow you just started. `wpp-mcp oauth pending` shows each request's client, redirect host, scopes, source IP and age, and `wpp-mcp oauth revoke` ends a connection at once.
- **Guessing tokens is slow.** A client IP that presents 20 rejected bearer credentials in a minute (`-auth-fail-limit`) is locked out for five minutes; during the lock-out every authenticated route answers 429 before the token is compared. Behind a reverse proxy on the same host or a private network, the client IP is the rightmost `X-Forwarded-For` entry; from public peers that header is ignored. Each client token is also limited to 120 `/mcp` requests per minute (`-mcp-rate`), so one connector cannot monopolise the daemon. Both limits keep bounded state in memory and reset on restart.
- **Actions leave a trace.** Every tool call, resource read and operator action is recorded in the encrypted audit log (actor, tool, chat, outcome, duration) for `-audit-days` (90 by default). Message text, other arguments and results are never recorded.
- **The disk is not trusted.** Databases are SQLCipher-encrypted and cached media is AES-256-GCM sealed. The key lives in a separate file, Docker secret or systemd credential.
- **The operator is trusted.** Anyone who can read the key file and the store, or run commands as your user, can read everything. Protect your account and back up the key.
- **Backups are as sensitive as the store, minus the key.** `wpp-mcp backup` archives the databases and media still encrypted with the store's key, and never includes the key file or the token. Anyone holding both an archive and its key can read it, so keep them apart. If a key may have leaked, rotate it with `wpp-mcp rekey`; archives made before the rotation stay readable with the old key.
- **Monitoring is not a side channel.** `/admin/metrics` needs the bearer token, and neither its labels nor session alert payloads carry JIDs, names, numbers or message content. The alert URL and header are treated as secrets and never logged.

## Out of scope

- Compromise of the machine or user account running the daemon.
- WhatsApp detecting or restricting the unofficial client.
- Data you export on purpose (`output_path`, approved sends).
- Recovering deleted data from SSD or copy-on-write blocks. Use full-disk encryption.
