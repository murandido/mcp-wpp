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
| A token stored in a remote connector leaks | **Client tokens** for `/mcp` only: read-only by default, optionally limited to some chats and given an expiry, revocable at once. Only their hash is stored, and they never open the operator API. |
| You cannot tell what a client read or did | An **audit log** of every tool call, resource read and operator action (who, which tool, which chat, the outcome), without message text or arguments. `wpp-mcp audit` shows it. |
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

The container runs as your user (`WPP_UID`/`WPP_GID`, default 1000) with a read-only root filesystem, no capabilities, and its port published on `127.0.0.1` only.

To update, `docker compose pull && docker compose up -d`. Pin a release with `WPP_MCP_TAG=0.1.0` instead of `latest`. To build from source instead, run `WPP_MCP_VERSION=$(git describe --tags --always) docker compose build`, so `wpp-mcp -version` reports what you built.

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

**HTTP clients** use `http://127.0.0.1:8765/mcp` (stateless Streamable HTTP, or your reverse proxy's HTTPS URL) with `Authorization: Bearer <token>`. Give each connector **its own client token** rather than the operator token in `<store>/token`:

```bash
wpp-mcp token create claude-ai                      # read-only, sees what the access policy allows
wpp-mcp token create phone -chats 5511999999999 -expires 90d
wpp-mcp token create assistant -scope read,send     # can propose sends (needs serve -write)
wpp-mcp token list                                  # status and last use; never the secret
wpp-mcp token revoke claude-ai                      # refused from the next request on
```

The token (`wppmcp_` and 64 hex characters) is printed once and only its SHA-256 is stored. Client tokens work on `/mcp` only. `-chats` narrows what the token sees to those chats, and only when the access policy allows them as well; other chats look nonexistent to it. A `read` token gets an error from every tool that sends or changes the account. With `send`, writes still go through `-write`, the outbox approval and the access policy. Unknown, revoked and expired tokens all get the same 401. The operator token keeps full access. It is the only one accepted on `/admin/*` and for browser login, and the local CLI and `wpp-mcp stdio` use it.

`wpp-mcp audit` shows who called what: `-since 7d`, `-actor claude-ai`, `-chat <jid>`, `-limit N`.

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

Proposals expire after 15 minutes. Read receipts, typing and presence skip the queue.

### Send policy per chat

Each chat has a send policy, separate from whether the AI can see it:

- **`none`**: the AI's write tools are refused for this chat, even with `-write`. This includes read receipts and typing.
- **`confirm`**: writes become proposals in the outbox (the behaviour above).
- **`direct`**: writes act immediately, without a proposal.

```bash
wpp-mcp access send "Ana" direct       # by name (must be unique) or JID
wpp-mcp access send 123456789@g.us none
wpp-mcp access send "Ana" reset        # back to the daemon's default
```

`wpp-mcp access list` shows the policy in its `SEND` column, and the `/access` page has a control per chat. Chats without a policy use the daemon's default: `confirm`, or `direct` with `-confirm-sends=false`. Tools that target no chat (privacy settings, `create_group`, status message) always use the default. A send policy never makes a hidden chat visible: a write to a hidden chat still answers "chat not found". Without `-write` no write tool is exposed, whatever the policies say.

### Scheduled messages

With `-write`, the daemon can send a text message later by itself, so no external routine or temporary send window is needed:

```bash
wpp-mcp schedule "Ana" "2026-11-16 06:00" Good morning!        # local time (-tz, $TZ, or the system zone)
wpp-mcp schedule -tz America/Sao_Paulo "Ana" 2026-11-16 06:00 Good morning!
wpp-mcp schedule 123456789@g.us 2026-11-16T06:00:00-03:00 Good morning!
wpp-mcp outbox                 # pending proposals and scheduled messages, with local and UTC times
wpp-mcp outbox cancel 12       # withdraw a scheduled message (or a pending proposal)
wpp-mcp outbox history         # outcomes: sent (with the message ID), failed, missed, cancelled
```

The AI can do the same with the `schedule_message` tool, under the chat's send policy: `none` refuses it, `confirm` makes a proposal that you can approve until the send time and that is then scheduled, and `direct` schedules it at once. Your own `wpp-mcp schedule` needs no approval, but the chat must exist, be visible to the AI and not have send policy `none`.

Send times must be in the future and at most 30 days ahead. At the send time the daemon checks access and the send policy again (a chat hidden meanwhile is not sent to), then sends through the usual rate limiter. Each message is claimed once, so it is never sent twice. Scheduled messages are kept in the encrypted database and survive restarts; one that came due while the daemon was down is still sent if it is at most one hour late, and marked `missed` otherwise. If the account is paired but momentarily disconnected, the daemon waits for the connection within that hour. A daemon started without `-write` neither exposes `schedule_message` nor sends scheduled messages; they stay queued until a `-write` daemon runs.

## Catching up

The `digest` tool answers "what did I miss": per allowed chat, the new messages since a cut-off. It can keep only unread messages (`only_unread`, using the read receipts your phone sends and `mark_read`), only messages that @-mention you (`mentions_only`), or only those matching `keywords`, and it can group by `sender` instead of chat.

## Encryption at rest

- `messages.db` and `whatsapp.db` (your session and Signal keys) are SQLCipher databases. Cached media files are sealed with AES-256-GCM, each bound to its path.
- Each purpose has its own sub-key, derived (HKDF-SHA256) from a 32-byte master key in a key file. The key file is looked up in this order: `-key-file`, `WPP_MCP_KEY_FILE`, the Docker secret `/run/secrets/wpp_mcp_key`, a systemd credential `wpp_mcp_key`, then `~/.config/wpp-mcp/key`. Group- or world-readable key files are refused.
- Plaintext and encrypted stores are never mixed. A binary built without SQLCipher refuses to run rather than silently writing cleartext.
- To migrate an existing plaintext store, stop the daemon and run `wpp-mcp encrypt`.
- If the store already lives on an encrypted disk and you prefer no key file, use `-no-encryption` (`WPP_MCP_NO_ENCRYPTION=1`).
- Files you export with `download_media`'s `output_path` are plaintext by design.

## Configuration

Global flags go before the command: `wpp-mcp -store DIR serve -write`.

| Flag | Environment | Default | Purpose |
|---|---|---|---|
| `-store` | `WPP_MCP_STORE` | `./store` | Databases, token and media cache |
| `-key-file` | `WPP_MCP_KEY_FILE` | see above | Encryption key |
| `-no-encryption` | `WPP_MCP_NO_ENCRYPTION` | off | Keep the store unencrypted |
| `-debug` | `WPP_MCP_DEBUG=1` | off | Show JIDs and bodies in logs (redacted by default) |
| `schedule -tz` | `TZ` | system zone | Time zone for `wpp-mcp schedule` times without an offset |
| `serve -addr` | `WPP_MCP_ADDR` | `127.0.0.1:8765` | `host:port` or `unix:/path.sock` (0600) |
| `serve -allow-remote` | | off | Allow a non-loopback bind (put TLS in front) |
| `serve -allowed-host` | `WPP_MCP_ALLOWED_HOSTS` | | Extra Host/Origin values, e.g. a reverse-proxy name |
| | `WPP_MCP_TOKEN` | generated | Operator bearer token (else `<store>/token`); clients get their own with `wpp-mcp token create` |
| `serve -write` | `WPP_MCP_WRITE` | off | Expose tools that send or change the account |
| `serve -confirm-sends` | `WPP_MCP_CONFIRM_SENDS` | on | With `-write`, the default send policy for chats without one: `confirm` (on) or `direct` (off); see `wpp-mcp access send` |
| `serve -tools` | `WPP_MCP_TOOLS` | `default` | Groups or tool names: `core`, `access`, `messaging`, `transcribe`, `labels`, `contacts`, `groups`, `privacy`, `polls`, `all` |
| `serve -disable-tools` | `WPP_MCP_DISABLE_TOOLS` | | Groups or tool names to hide |
| `serve -max-sends-per-hour` | `WPP_MCP_MAX_SENDS_PER_HOUR` | 30 | Outbound cap |
| `serve -retain-days` | `WPP_MCP_RETAIN_DAYS` | 0 (keep) | Delete messages and media older than N days |
| `serve -audit-days` | `WPP_MCP_AUDIT_DAYS` | 90 | Keep the audit log N days; 0 disables auditing |
| `serve -enable-labels` | `WPP_MCP_LABELS` | off | WhatsApp Business label sync and tools |
| `serve -full-history` | `WPP_MCP_FULL_HISTORY` | off | Ask for a full history sync when pairing |
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
