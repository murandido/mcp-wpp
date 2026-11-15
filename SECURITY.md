# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/murandido/mcp-wpp/security/advisories/new). Do not open a public issue. Include the version (`wpp-mcp -version`), your setup (native or Docker, flags), and steps to reproduce. You can expect an acknowledgement within a week.

Issues in WhatsApp's protocol handling belong to [whatsmeow](https://github.com/tulir/whatsmeow).

## Threat model

`mcp-wpp` assumes:

- **The model is not trusted with everything.** Any chat it can read may contain prompt injection, and anything it reads reaches the model provider. The consent policy decides what it can read; the outbox decides what it can send.
- **Other local processes and web pages are not trusted.** Every route needs the bearer token (except health probes and the single-use UI login), Host and Origin must be loopback or explicitly allowed, and browser sessions use HttpOnly, SameSite=Strict cookies with CSRF tokens.
- **Remote MCP clients are trusted only as far as their token says.** A client token works on `/mcp` only, carries scopes (`read`, `send`) and an optional chat set that narrows the access policy, and can expire or be revoked at once. Only its SHA-256 is stored. The operator token is the only credential for `/admin/*` and the operator pages.
- **Actions leave a trace.** Every tool call, resource read and operator action is recorded in the encrypted audit log (actor, tool, chat, outcome, duration) for `-audit-days` (90 by default). Message text, other arguments and results are never recorded.
- **The disk is not trusted.** Databases are SQLCipher-encrypted and cached media is AES-256-GCM sealed. The key lives in a separate file, Docker secret or systemd credential.
- **The operator is trusted.** Anyone who can read the key file and the store, or run commands as your user, can read everything. Protect your account and back up the key.
- **Backups are as sensitive as the store, minus the key.** `wpp-mcp backup` archives the databases and media still encrypted with the store's key, and never includes the key file or the token. Anyone holding both an archive and its key can read it, so keep them apart. If a key may have leaked, rotate it with `wpp-mcp rekey`; archives made before the rotation stay readable with the old key.

## Out of scope

- Compromise of the machine or user account running the daemon.
- WhatsApp detecting or restricting the unofficial client.
- Data you export on purpose (`output_path`, approved sends).
- Recovering deleted data from SSD or copy-on-write blocks. Use full-disk encryption.
