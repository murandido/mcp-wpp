# mcp-wpp

[![CI](https://github.com/murandido/mcp-wpp/actions/workflows/ci.yml/badge.svg)](https://github.com/murandido/mcp-wpp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/murandido/mcp-wpp)](LICENSE)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![MCP](https://img.shields.io/badge/MCP-server-6366f1)](https://modelcontextprotocol.io/)

**A privacy-first WhatsApp MCP server.** Let an AI assistant read, search and summarise *the chats you choose*. The store is encrypted, the server is read-only unless you opt in, and nothing gets sent without your approval.

`wpp-mcp` links to your own WhatsApp account as a linked device (through [whatsmeow](https://github.com/tulir/whatsmeow)), keeps a local encrypted cache, and exposes it to MCP clients such as Claude Code and Claude Desktop. It is a hardened fork of [sealjay/mcp-whatsapp](https://github.com/sealjay/mcp-whatsapp).

## Why another WhatsApp MCP?

Your WhatsApp history is some of the most personal data you have. Connecting it to an LLM combines the three ingredients of the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): private data, untrusted content (anyone can message you), and the ability to communicate externally. `mcp-wpp` is built around limiting each of them:

| Risk | What mcp-wpp does |
|---|---|
| The AI sees chats it has no business reading | **Per-chat consent.** Nothing is visible until you allow it. The AI can *ask* for a chat, and you approve or reject the request. Hidden chats behave exactly like chats that do not exist. |
| A malicious message tells the AI to send your data somewhere | **Read-only by default.** With `-write`, every send becomes a **proposal you approve** from the CLI or a web page. Access is checked again when the proposal runs. |
| Someone copies your disk, backup or container volume | **Encryption at rest**: SQLCipher for both databases and AES-256-GCM for cached media, keyed from a file you keep elsewhere. |
| Another program or web page talks to the daemon | **Bearer token on every route**, **Host/Origin checks** against DNS rebinding, an optional 0600 Unix socket, and a **stdio bridge** so clients never need a port or a token. |
| A message forges other messages, or a pairing QR leaks to the model | Message bodies cannot start new lines that look like headers, results are labelled as third-party data, and pairing never goes through MCP. |
| Runaway sends get the number banned | Daemon-side rate limits that clients cannot bypass. |

Plus: accent-insensitive full-text search (`nao` finds `não`), a cross-chat `digest` tool, pairing by phone-number code, optional retention, local voice-note transcription, and a small default tool surface (12 read-only tools out of 49).

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/murandido/mcp-wpp.git && cd mcp-wpp
mkdir -p data secrets
(umask 077; docker run --rm ghcr.io/murandido/mcp-wpp:latest keygen -out - > secrets/wpp_mcp_key)
docker compose up -d

docker compose exec wpp-mcp wpp-mcp pair -phone +5511999999999   # type the code on your phone
docker compose exec wpp-mcp wpp-mcp access list                   # after the first sync
docker compose exec wpp-mcp wpp-mcp access allow "Family"
```

> **Back up `secrets/wpp_mcp_key`.** Without it `data/` cannot be read, and nobody can recover it.

The container runs as your user (`WPP_UID`/`WPP_GID`, default 1000) with a read-only root filesystem, no capabilities, and its port published on `127.0.0.1` only. Build locally with `docker compose build`.

### Native (Linux, macOS)

Requirements: Go 1.26+, a C toolchain, and SQLCipher (`dnf install sqlcipher-devel`, `apt install libsqlcipher-dev` or `brew install sqlcipher`).

```bash
git clone https://github.com/murandido/mcp-wpp.git && cd mcp-wpp
make build && install -m 0755 bin/wpp-mcp ~/.local/bin/

export WPP_MCP_STORE=~/.local/share/wpp-mcp
wpp-mcp keygen                       # writes ~/.config/wpp-mcp/key (0600); back it up
wpp-mcp serve &                      # or install the systemd/launchd unit in docs/
wpp-mcp pair -phone +5511999999999
wpp-mcp access allow "Family"
```

## Connect an MCP client

`wpp-mcp stdio` bridges a stdio MCP client to the running daemon. It reads the token from the store directory, so your client config holds neither a port nor a secret.

**Claude Code**

```bash
claude mcp add whatsapp -e WPP_MCP_STORE=$HOME/.local/share/wpp-mcp -- wpp-mcp stdio
# with Docker:
claude mcp add whatsapp -- docker compose -f /path/to/mcp-wpp/compose.yaml exec -T wpp-mcp wpp-mcp stdio
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "whatsapp": {
      "command": "/home/you/.local/bin/wpp-mcp",
      "args": ["stdio"],
      "env": { "WPP_MCP_STORE": "/home/you/.local/share/wpp-mcp" }
    }
  }
}
```

**HTTP clients** can use `http://127.0.0.1:8765/mcp` (stateless Streamable HTTP) with `Authorization: Bearer <token>`, where the token is in `<store>/token` (or set `WPP_MCP_TOKEN`).

## Pairing

| How | Command |
|---|---|
| Pairing code (no camera needed) | `wpp-mcp pair -phone +<country code><number>`, then on the phone go to *Settings → Linked devices → Link a device → Link with phone number instead* |
| QR in the terminal | `wpp-mcp pair` |
| QR or code in a browser | `wpp-mcp open-ui` prints a single-use login link to `/pair` |
| Headless or container start | set `WPP_MCP_PAIR_PHONE=+...` and read the code in the logs |

`pair` talks to a running daemon, or pairs directly when none is running. Code requests are rate-limited (3 per minute, 5 per hour) because WhatsApp blocks numbers that request too many.

## Choosing what the AI can see

The cache keeps every chat, so allowing a chat later gives the AI its history. What the AI sees is controlled by a policy:

- **`allowlist`** (default): only chats you allowed.
- **`all`**: every chat except those you denied.

```bash
wpp-mcp access list [search]           # chats with their state
wpp-mcp access allow "Ana"             # by name (must be unique) or JID
wpp-mcp access deny 123456789@g.us     # hide, also in mode "all"
wpp-mcp access reset "Ana"             # back to the mode's default
wpp-mcp access mode all                # or allowlist
```

When you ask about someone the AI cannot see, it calls `request_chat_access`. It gets back a request ID, never the names that matched. Review requests with:

```bash
wpp-mcp access requests
wpp-mcp access approve 3               # or: approve 3 <jid>  /  reject 3
```

You can do the same on the `/access` page (`wpp-mcp open-ui -page /access`).

## Sending, with approval

`serve` is read-only unless you pass `-write` (`WPP_MCP_WRITE=1`). With `-write`, each send, reply, reaction, edit, deletion, poll, group or privacy change, and transcription upload returns a `proposal_id` instead of acting:

```bash
wpp-mcp outbox                 # what the AI wants to send, with the chat name and text
wpp-mcp outbox approve 7       # sends now; the chat must still be allowed
wpp-mcp outbox reject 7
```

Proposals expire after 15 minutes. Read receipts, typing and presence skip the queue. `-confirm-sends=false` restores immediate sends if you really want them.

## Encryption at rest

- `messages.db` and `whatsapp.db` (your session and Signal keys) are SQLCipher databases. Cached media files are sealed with AES-256-GCM, each bound to its path.
- Each purpose has its own sub-key, derived (HKDF-SHA256) from a 32-byte master key in a key file. The key file is looked up in this order: `-key-file`, `WPP_MCP_KEY_FILE`, the Docker secret `/run/secrets/wpp_mcp_key`, a systemd credential `wpp_mcp_key`, then `~/.config/wpp-mcp/key`. Group- or world-readable key files are refused.
- Plaintext and encrypted stores are never mixed. A binary built without SQLCipher refuses to run rather than silently writing cleartext.
- To migrate an existing plaintext store, stop the daemon and run `wpp-mcp encrypt`.
- If the store already lives on an encrypted disk and you prefer no key file, use `-no-encryption` (`WPP_MCP_NO_ENCRYPTION=1`).
- Files you export with `download_media`'s `output_path` are plaintext by design.

## Operations

### Backups

`wpp-mcp backup -out FILE` writes a consistent snapshot of the store while `serve` keeps running. The databases are copied with SQLite's online backup API inside a single read transaction, so the copy is consistent and the daemon keeps writing during it. The archive is a plain tar with mode 0600:

- `messages.db` and `whatsapp.db`, still SQLCipher-encrypted with your key;
- the media cache, byte for byte (files stay sealed);
- `manifest.json`: format version, creation time, wpp-mcp version, a key fingerprint, a schema summary and the SHA-256 of every file.

Nothing is decrypted on the way, not even into temporary files. Two things are left out on purpose. **The key file** is not included: an archive that carried its key would protect nothing, so back the key up separately (a password manager works). Without it the backup cannot be read. **The token** is not included either: it is a credential, and `serve` makes a new one when it is missing. `uploads/` is not included because it holds your own outbound files.

```bash
wpp-mcp backup -out ~/backups/wpp-$(date +%F).tar
wpp-mcp backup verify ~/backups/wpp-2026-11-15.tar   # checksums, key, database integrity, media authentication
```

With Docker, write the archive into the mounted data directory (run `mkdir -p data/backups` on the host first):

```bash
docker compose exec -T wpp-mcp wpp-mcp backup -out /data/backups/wpp-$(date +%F).tar
```

`-out -` streams the archive to stdout instead. Verification fails with a clear message if the configured key is not the one the backup was made with.

To restore, stop the daemon. `restore` takes the store lock and refuses a store that already holds data unless you pass `-force`. It extracts and verifies the whole archive before it touches anything. With `-force`, the current files are moved to `<store>/.pre-restore` and deleted only once the restored store opens; if it does not, they are put back. The token and `uploads/` are kept.

```bash
wpp-mcp restore -in ~/backups/wpp-2026-11-15.tar            # into an empty store
wpp-mcp restore -force -in ~/backups/wpp-2026-11-15.tar     # replace the current data

docker compose stop wpp-mcp
docker compose run --rm wpp-mcp restore -force -in /data/backups/wpp-2026-11-15.tar
docker compose start wpp-mcp
```

A restored store needs the key it was backed up with. The WhatsApp session in `whatsapp.db` is restored too, so the device is still linked unless it was removed from the phone in the meantime.

### Key rotation

`wpp-mcp rekey -new-key-file NEW` re-encrypts both databases and every cached media file with sub-keys derived from a new master key, then checks that everything opens with it. Stop the daemon first: `rekey` takes the store lock.

```bash
wpp-mcp keygen -out ~/.config/wpp-mcp/key.new
wpp-mcp rekey -new-key-file ~/.config/wpp-mcp/key.new
mv ~/.config/wpp-mcp/key ~/.config/wpp-mcp/key.old && mv ~/.config/wpp-mcp/key.new ~/.config/wpp-mcp/key
```

With Docker:

```bash
(umask 077; docker run --rm ghcr.io/murandido/mcp-wpp:latest keygen -out - > secrets/wpp_mcp_key.new)
docker compose stop wpp-mcp
docker compose run --rm -v ./secrets/wpp_mcp_key.new:/run/secrets/wpp_mcp_key_new:ro wpp-mcp rekey -new-key-file /run/secrets/wpp_mcp_key_new
mv secrets/wpp_mcp_key secrets/wpp_mcp_key.old && mv secrets/wpp_mcp_key.new secrets/wpp_mcp_key
docker compose up -d
```

`rekey` writes complete new-key copies of everything first, and only then swaps them in, keeping the old files until the end. If it is interrupted, every file is still readable with the old key or the new one. `serve` refuses to start until you rerun the same `rekey` command, which finishes the job. Before the swap starts, `rekey -abort` drops the copies instead. Keep the old key: backups made before the rotation still need it.

### Metrics

`GET /admin/metrics` serves Prometheus text metrics. Like every `/admin/` route it needs the bearer token. No label holds a JID, name or number.

| Metric | Meaning |
|---|---|
| `wpp_mcp_build_info{version}` | Running version |
| `wpp_mcp_uptime_seconds`, `wpp_mcp_start_time_seconds` | Process uptime |
| `wpp_mcp_whatsapp_paired`, `_connected`, `_authenticated` | Device linked, websocket up, session accepted by WhatsApp (0/1) |
| `wpp_mcp_whatsapp_connection_state{state}` | Last connection event, one-hot |
| `wpp_mcp_messages_received_total`, `wpp_mcp_messages_sent_total` | Live messages in and out since start |
| `wpp_mcp_seconds_since_last_message_received` | Present once a message has arrived since start |
| `wpp_mcp_tool_calls_total{tool,outcome}` | MCP tool executions, `ok` or `error` (calls refused by the access policy or held as proposals are not executions) |
| `wpp_mcp_outbox_pending`, `wpp_mcp_access_requests_pending` | Waiting for your decision |
| `wpp_mcp_chats_cached`, `wpp_mcp_chats_visible` | Chats in the cache, and those the access policy shows |
| `wpp_mcp_alerts_total{event,result}` | Session alert deliveries (with `-alert-url`) |

```yaml
# prometheus.yml
scrape_configs:
  - job_name: wpp-mcp
    metrics_path: /admin/metrics
    authorization:
      credentials_file: /etc/prometheus/wpp-mcp-token   # a copy of <store>/token
    static_configs:
      - targets: ["127.0.0.1:8765"]
```

A scraper on another Docker network reaches the daemon under another hostname: add it with `-allowed-host`.

### Session alerts

With `-alert-url`, `serve` POSTs a short alert when a paired session has not been authenticated for longer than `-alert-after` (default 5m), when WhatsApp logs the device out, and when the session recovers after one of those. Brief reconnects stay silent. Delivery runs in the background and is retried with backoff (network errors, 429 and 5xx) for about a minute. Alerts never contain chat data, names or numbers.

The default body is JSON:

```json
{"event":"session_down","since":"2026-11-15T09:12:00Z","message":"WhatsApp session has not been authenticated for 5m0s"}
```

`event` is `session_down`, `logged_out` or `session_up`, and `since` is when the outage began. For [ntfy.sh](https://ntfy.sh), use the plain-text format. The body is then the message, and `Title`, `Tags` and `Priority` headers make it a readable notification:

```bash
wpp-mcp serve -alert-url https://ntfy.sh/<your-secret-topic> -alert-format text
# a protected topic or a self-hosted server:
WPP_MCP_ALERT_HEADER="Authorization: Bearer tk_..." wpp-mcp serve -alert-url https://ntfy.example.com/wpp -alert-format text
```

Treat the alert URL and header as secrets; they are never logged. The Docker health check (`wpp-mcp healthcheck`, which probes `/readyz`) needs no change.

## Configuration

Global flags go before the command: `wpp-mcp -store DIR serve -write`.

| Flag | Environment | Default | Purpose |
|---|---|---|---|
| `-store` | `WPP_MCP_STORE` | `./store` | Databases, token and media cache |
| `-key-file` | `WPP_MCP_KEY_FILE` | see above | Encryption key |
| `-no-encryption` | `WPP_MCP_NO_ENCRYPTION` | off | Keep the store unencrypted |
| `-debug` | `WPP_MCP_DEBUG=1` | off | Show JIDs and bodies in logs (redacted by default) |
| `serve -addr` | `WPP_MCP_ADDR` | `127.0.0.1:8765` | `host:port` or `unix:/path.sock` (0600) |
| `serve -allow-remote` | | off | Allow a non-loopback bind (put TLS in front) |
| `serve -allowed-host` | `WPP_MCP_ALLOWED_HOSTS` | | Extra Host/Origin values, e.g. a reverse-proxy name |
| | `WPP_MCP_TOKEN` | generated | Bearer token (else `<store>/token`) |
| `serve -write` | `WPP_MCP_WRITE` | off | Expose tools that send or change the account |
| `serve -confirm-sends` | `WPP_MCP_CONFIRM_SENDS` | on | With `-write`, sends wait for approval |
| `serve -tools` | `WPP_MCP_TOOLS` | `default` | Groups or tool names: `core`, `access`, `messaging`, `transcribe`, `labels`, `contacts`, `groups`, `privacy`, `polls`, `all` |
| `serve -disable-tools` | `WPP_MCP_DISABLE_TOOLS` | | Groups or tool names to hide |
| `serve -max-sends-per-hour` | `WPP_MCP_MAX_SENDS_PER_HOUR` | 30 | Outbound cap |
| `serve -retain-days` | `WPP_MCP_RETAIN_DAYS` | 0 (keep) | Delete messages and media older than N days |
| `serve -enable-labels` | `WPP_MCP_LABELS` | off | WhatsApp Business label sync and tools |
| `serve -full-history` | `WPP_MCP_FULL_HISTORY` | off | Ask for a full history sync when pairing |
| `serve -alert-url` | `WPP_MCP_ALERT_URL` | | POST session alerts here (see [Session alerts](#session-alerts)) |
| `serve -alert-after` | `WPP_MCP_ALERT_AFTER` | `5m` | How long a paired session may stay unauthenticated before alerting |
| `serve -alert-format` | `WPP_MCP_ALERT_FORMAT` | `json` | `json`, or `text` for ntfy.sh |
| `serve -alert-header` | `WPP_MCP_ALERT_HEADER` | | Extra `Name: value` header on alert requests, e.g. auth |
| | `WPP_MCP_PAIR_PHONE` | | Print a pairing code at startup when unpaired |
| | `WPP_MCP_MEDIA_ROOT` | `<store>/uploads` | Only directory `send_file` may read from and `output_path` may write to |
| | `WPP_MCP_TRANSCRIBE_URL` | | OpenAI-compatible speech-to-text endpoint |
| | `WPP_MCP_TRANSCRIBE_ALLOW_PRIVATE_HTTP` | off | Allow plain HTTP to a private-network service (e.g. the compose `speaches` profile) |
| | `WPP_MCP_TRANSCRIBE_ALLOW_REMOTE` | off | Allow a non-loopback HTTPS service |

The complete tool list, with each tool's group, read-only status, approval requirement and chat scope, is in **[docs/tools.md](docs/tools.md)**. `wpp-mcp tools` prints the same list.

## Running as a service

- **systemd** (Linux): [`docs/systemd/wpp-mcp.service`](docs/systemd/wpp-mcp.service) is a hardened user unit that receives the key as a credential, optionally sealed to the TPM.
- **launchd** (macOS): [`docs/launchd/com.murandido.wpp-mcp.plist`](docs/launchd/com.murandido.wpp-mcp.plist).
- **Docker**: [`compose.yaml`](compose.yaml); `docker compose --profile transcribe up -d` adds local transcription.
- **Claude Code hook**: [`docs/hooks/setup.sh`](docs/hooks/setup.sh) starts the daemon with your session.

## Development

```bash
make build          # needs SQLCipher; see Native above
make lint test e2e smoke
make container-test # the full suite in Debian with SQLCipher, no local install needed
make docs           # regenerate docs/tools.md
```

Tests never touch a real WhatsApp account. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## Limitations

- **Unofficial API.** whatsmeow speaks WhatsApp's multi-device protocol; WhatsApp does not sanction this, and accounts can be restricted. Prefer read-only use and keep send volumes low.
- **History is what WhatsApp sends.** The cache holds messages delivered while the daemon was running, plus what the phone shares during sync. It is not a complete archive.
- **The trifecta is reduced, not removed.** An allowed chat can still contain prompt injection, and anything the AI reads goes to your model provider. Allow only the chats you need.
- **Deleted is not erased.** Retention and `encrypt` remove data from the files, but SSDs and copy-on-write filesystems can keep old blocks. Data that was ever written unencrypted is only fully protected by full-disk encryption.
- **Log redaction is obfuscation**, not anonymisation.

## Credits

Built on [whatsmeow](https://github.com/tulir/whatsmeow) by Tulir Asokan. Forked from [sealjay/mcp-whatsapp](https://github.com/sealjay/mcp-whatsapp) by Chris Lloyd-Jones, itself derived from [lharries/whatsapp-mcp](https://github.com/lharries/whatsapp-mcp) by Luke Harries. MIT licensed; see [LICENSE](LICENSE).

This project is not affiliated with, endorsed by, or associated with Meta Platforms, Inc. or WhatsApp. "WhatsApp" is a trademark of Meta Platforms, Inc., used here only to describe interoperability.
