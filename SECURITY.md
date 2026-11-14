# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/murandido/mcp-wpp/security/advisories/new). Do not open a public issue. Include the version (`wpp-mcp -version`), your setup (native or Docker, flags), and steps to reproduce. You can expect an acknowledgement within a week.

Issues in WhatsApp's protocol handling belong to [whatsmeow](https://github.com/tulir/whatsmeow).

## Threat model

`mcp-wpp` assumes:

- **The model is not trusted with everything.** Any chat it can read may contain prompt injection, and anything it reads reaches the model provider. The consent policy decides what it can read; the outbox decides what it can send.
- **Other local processes and web pages are not trusted.** Every route needs the bearer token (except health probes and the single-use UI login), Host and Origin must be loopback or explicitly allowed, and browser sessions use HttpOnly, SameSite=Strict cookies with CSRF tokens.
- **The disk is not trusted.** Databases are SQLCipher-encrypted and cached media is AES-256-GCM sealed. The key lives in a separate file, Docker secret or systemd credential.
- **The operator is trusted.** Anyone who can read the key file and the store, or run commands as your user, can read everything. Protect your account and back up the key.

## Out of scope

- Compromise of the machine or user account running the daemon.
- WhatsApp detecting or restricting the unofficial client.
- Data you export on purpose (`output_path`, approved sends).
- Recovering deleted data from SSD or copy-on-write blocks. Use full-disk encryption.
