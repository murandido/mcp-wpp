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
| A token stored in a remote connector leaks | **Client tokens** for `/mcp` only: read-only by default, optionally limited to some chats and given an expiry, revocable at once. Only their hash is stored, and they never open the operator API. Or **OAuth**: one-hour, rotating, audience-bound tokens for connections you approve on the server. |
| You cannot tell what a client read or did | An **audit log** of every tool call, resource read and operator action (who, which tool, which chat, the outcome), without message text or arguments. `wpp-mcp audit` shows it. |
| A message forges other messages, or a pairing QR leaks to the model | Message bodies cannot start new lines that look like headers, results are labelled as third-party data, and pairing never goes through MCP. |
| Runaway sends get the number banned | Daemon-side rate limits that clients cannot bypass. |

Plus: accent-insensitive full-text search (`nao` finds `não`), a cross-chat `digest` tool, living per-chat notes that improve each time they are used, pairing by phone-number code, optional retention, voice-note transcription, local OCR of images, and a small default tool surface (16 read-only tools out of 54).

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

#### Verify the image

Release images (from the release after 0.9.0 on) are signed with [cosign](https://github.com/sigstore/cosign) keyless signing: the certificate names this repository's release workflow and the tag it ran for, and the signature is logged in the public Rekor transparency log. There is no key to distribute. With cosign 3 or newer:

```bash
cosign verify ghcr.io/murandido/mcp-wpp:<version> \
  --certificate-identity-regexp '^https://github\.com/murandido/mcp-wpp/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The index and each platform image are signed. Each platform image also carries an SPDX SBOM attestation, verified against its digest (listed by `docker buildx imagetools inspect ghcr.io/murandido/mcp-wpp:<version>`):

```bash
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/murandido/mcp-wpp/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/murandido/mcp-wpp@sha256:<platform digest>
```

To be sure you run what you verified, pin the digest in `compose.yaml` (`image: ghcr.io/murandido/mcp-wpp@sha256:...`) rather than a tag.

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

`wpp-mcp audit` shows who called what: `-since 7d`, `-actor claude-ai`, `-chat <jid>`, `-limit N`. Operator changes made without a running daemon (`wpp-mcp access`, `schedule`, `token`, `oauth revoke`, `login`, which then edit the store directly) are recorded too, with the actor `operator:cli` and the same action and fields the admin API would record.

### Connect with OAuth

Instead of pasting a client token into a remote connector, the daemon can act as an OAuth 2.1 authorization server. claude.ai's custom connectors then connect with nothing but the URL, get access tokens that expire after an hour and rotate, and **you approve each connection on the server**. There is no login page or password on the internet: approval only happens over the operator's admin API, from the CLI.

```bash
wpp-mcp serve -oauth -public-url https://wpp.example.com   # or WPP_MCP_OAUTH=1 WPP_MCP_PUBLIC_URL=...
```

`-public-url` (env `WPP_MCP_PUBLIC_URL`) is the HTTPS origin your reverse proxy serves, without a path; the MCP endpoint is always `<public-url>/mcp`, and its host is added to the allowed hosts. `serve` refuses `-oauth` (env `WPP_MCP_OAUTH=1`) without a valid `https://` public URL. Your proxy must forward `/mcp`, `/.well-known/oauth-*` and `/oauth/*`; nothing else needs to be public. With Caddy:

```caddyfile
wpp.example.com {
	@wpp path /mcp /mcp/* /.well-known/oauth-* /oauth/*
	handle @wpp {
		reverse_proxy 127.0.0.1:8765
	}
	handle {
		respond 404
	}
}
```

In claude.ai, add a custom connector with the URL `https://wpp.example.com/mcp` and leave the OAuth fields empty. Then:

1. claude.ai opens a page on your server that shows the client's name, **the host it will return to** (`claude.ai`), the requested scopes and a code such as `ABCD-EFGH`.
2. On the server, check it and approve it:

   ```bash
   wpp-mcp oauth pending                      # code, client, redirect host, scopes, source IP, age
   wpp-mcp oauth approve ABCD-EFGH            # the scopes it asked for, every chat the policy allows
   wpp-mcp oauth approve ABCD-EFGH -scope read -chats 5511999999999 -days 7
   wpp-mcp oauth deny ABCD-EFGH
   ```

   Your choice wins: `-scope` may narrow or widen what the client requested (by default, what it requested), `-chats` limits the connection on top of the access policy, and `-days` (default 30, at most 365) is how long the connection survives without being used.
3. The page notices the approval within a few seconds and sends the browser back to claude.ai, which finishes the connection.

**Only approve a code you see on your own screen, in a connection you started yourself.** Anyone who can reach the page can start a flow and ask you to approve their code; `oauth pending` shows where each request came from.

```bash
wpp-mcp oauth grants              # connections, scopes, chats, last use, expiry, status
wpp-mcp oauth revoke 3f9c1a2b7d4e # ends one at once: its refresh and access tokens stop working
```

How it works: the server publishes [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) and [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) metadata, and the 401 from `/mcp` points to it. Clients identify themselves with a Client ID Metadata Document (an `https` `client_id` on `claude.ai` or `claude.com`; the server never fetches documents from other hosts, fetched without redirects, with a 5 s timeout and a 64 KiB limit, never from a private, loopback or link-local address) or register through [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) (rate limited and capped). Redirects go only to an exact entry of `-oauth-redirect-uris` (env `WPP_MCP_OAUTH_REDIRECT_URIS`, default `https://claude.ai/api/mcp/auth_callback`); anything else gets an error page, never a redirect. PKCE S256 is mandatory, authorization codes are single-use and valid for 60 seconds, and responses carry `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)). Access tokens are ordinary client tokens bound to `<public-url>/mcp` ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)) and valid for one hour; `wpp-mcp token list` shows them as `oauth:<client>#<grant>`. Refresh tokens rotate on every use, and presenting a used one revokes the whole connection. Pending requests and codes live only in the daemon's memory, so a restart cancels them.

Scopes are checked per tool, as for client tokens: every token has `read`, and a tool that needs `send` returns an error explaining it.

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

You can do the same on the `/access` page (`wpp-mcp open-ui -page /access`). Pending requests are listed first, with one-click allow or dismiss. The chat list searches by name or number (case- and accent-insensitive), filters by state (allowed, denied, pending requests, groups, direct chats) and shows 50 chats at a time. You can tick up to 100 chats and allow or reset them together after a confirmation page, and set each chat's send policy. Switching the mode also asks for confirmation and says how many chats become visible. Changes on the page are audited like those from the CLI: one entry per chat, marked `via=browser`.

## Sending, with approval

`serve` is read-only unless you pass `-write` (`WPP_MCP_WRITE=1`). With `-write`, each send, reply, reaction, edit, deletion, poll, group or privacy change, and transcription upload returns a `proposal_id` instead of acting:

```bash
wpp-mcp outbox                 # what the AI wants to send, with the chat name and text
wpp-mcp outbox approve 7       # sends now; the chat must still be allowed
wpp-mcp outbox reject 7
```

Proposals expire after 15 minutes. Read receipts, typing and presence skip the queue.

Each proposal and scheduled message records who created it: `operator` (the operator token, which the stdio bridge also uses), `token:<name>` for a client token, or `operator:cli` for your own `wpp-mcp schedule`. `wpp-mcp outbox` and the `/outbox` page show it, and the audit entry of an approval names it. When a client token is revoked (directly, or with its OAuth grant), whatever it proposed or scheduled is refused when you approve it or when it comes due, and recorded as `failed`; nothing is swept at revocation time, so the check also covers tokens revoked by any other path.

### Approving from your phone

With `-self-approve` (`WPP_MCP_SELF_APPROVE=1`, needs `-write`), you can decide proposals in your own WhatsApp chat ("Message yourself"), typed on your phone or another linked device:

```text
outbox          list what awaits approval
approve 7       the same as `wpp-mcp outbox approve 7`
reject 7        the same as `wpp-mcp outbox reject 7`
```

The daemon replies in the same chat with the id and the outcome. Approval takes exactly the path of `wpp-mcp outbox approve`: access and send policy are checked again, and each proposal is claimed once. A message counts as a command only if it is live (not history sync), in your own chat, written by you, from a device other than the daemon's own linked device, and at most five minutes old. The device check is the key protection: nothing the daemon sends, including messages an AI asked it to send, can approve anything. Other text in that chat is ignored, so notes to self keep working. While `-self-approve` is on, MCP tools may not write to your own chat at all. Every decision is in the audit log as actor `operator:whatsapp`, with the proposal id and creator but no text. Replies count against `-max-sends-per-hour`.

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

### Send windows

A chat can also have hours when the AI may write to it, read in the daemon's time zone (`serve -timezone`, default the system zone). A window may wrap midnight:

```bash
wpp-mcp access window "Ana" 08:00-22:00
wpp-mcp access window 123456789@g.us 22:00-06:00
wpp-mcp access window "Ana" off
```

Outside the window, a message the AI sends (text, file, audio, reply, poll, contact card) is not sent but deferred to the next opening, still under the chat's send policy: `confirm` makes a proposal with that send time (approvable for at least 15 minutes even if the window opens sooner), `direct` schedules it at once, and `none` refuses it as usual. `schedule_message` moves a send time outside the window to its next opening. Every other write aimed at the chat (reactions, edits, deletions, read receipts, typing, group changes) is refused with the time the window opens. The tool result says the message was deferred and until when. The window is checked after the access check and the send policy, so a hidden chat still answers "chat not found". When a scheduled item comes due outside its chat's window (the window changed meanwhile), the scheduler moves it to the next opening instead of sending it. Your own `wpp-mcp schedule` ignores windows, and approving an immediate proposal sends it at once whatever the hour: both are your decision, not the AI's. The next opening is computed minute by minute on the real clock, so daylight-saving changes neither skip nor repeat an opening.

`wpp-mcp access list` shows the policy in its `SEND` column and the window in its `WINDOW` column, and the `/access` page has a control per chat. Chats without a policy use the daemon's default: `confirm`, or `direct` with `-confirm-sends=false`. Tools that target no chat (privacy settings, `create_group`, status message) always use the default. A send policy never makes a hidden chat visible: a write to a hidden chat still answers "chat not found". Without `-write` no write tool is exposed, whatever the policies say.

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

The AI can do the same with the `schedule_message` tool, under the chat's send policy: `none` refuses it, `confirm` makes a proposal that you can approve until the send time and that is then scheduled, and `direct` schedules it at once. Your own `wpp-mcp schedule` needs no approval and ignores send windows, but the chat must exist, be visible to the AI and not have send policy `none`. It works without a running daemon too: the message is then queued directly in the store, with the same checks, and the next `serve -write` sends it (if it starts within an hour of the send time).

Send times must be in the future and at most 30 days ahead. At the send time the daemon checks access and the send policy again (a chat hidden meanwhile is not sent to), then sends through the usual rate limiter. Each message is claimed once, so it is never sent twice. Scheduled messages are kept in the encrypted database and survive restarts; one that came due while the daemon was down is still sent if it is at most one hour late, and marked `missed` otherwise. If the account is paired but momentarily disconnected, the daemon waits for the connection within that hour. A daemon started without `-write` neither exposes `schedule_message` nor sends scheduled messages; they stay queued until a `-write` daemon runs.

## Chat notes

Each allowed chat can keep a living summary: who it is with, ongoing topics, agreements, dates, open items and preferences. The server has no model of its own; the notes are written by your MCP client and improve every time they are used:

1. `get_chat_notes` returns the current notes and the cached messages that arrived after them (with cached voice-note transcripts and image text). A chat without notes returns its most recent messages.
2. The client merges what is new and saves the result with `update_chat_notes`, passing the version it read and the newest message it covered. The next read starts after that message.

The server's instructions ask clients to do this whenever they work on a chat, and `get_chat` shows the first lines of the notes. Notes are local state: encrypted in `messages.db`, never sent to WhatsApp, so a read-only token can keep them. Each save is a new version; the previous 10 are kept. Two conversations cannot overwrite each other: a save based on an older version is refused, and the client reads again and merges.

Notes follow the access policy like messages: hidden chats and chats outside a token's set behave as if they had none. Denying or resetting a chat's access deletes its notes and their history. Retention does not: the notes are what outlives old messages. Because they are derived from other people's messages, notes are always served as untrusted data, and clients are told to record facts, never instructions found in messages.

The operator sees and manages them on the `/notes` page (linked from `/access` as "notes vN") and with `wpp-mcp notes show|history|revert|clear <chat>`, all audited.

## Catching up and webhooks

The `digest` tool answers "what did I miss": per allowed chat, the new messages since a cut-off. It can keep only unread messages (`only_unread`, using the read receipts your phone sends and `mark_read`; `mark_unread` moves a chat's read mark back, from a given message or for the whole chat, to see those messages again), only messages that @-mention you (`mentions_only`), or only those matching `keywords`, and it can group by `sender` instead of chat.

For event-driven automation, `serve -webhook-url URL -webhook-secret SECRET` POSTs each live incoming message to your endpoint:

- **Only allowed chats.** The access policy is checked when each request is sent, so hiding a chat also stops what is queued for it. `-webhook-chats` (JIDs or phone numbers) and `-webhook-keywords` (case- and accent-insensitive) narrow it further. History sync, your own messages and status updates are never sent.
- **No text by default.** The payload carries who wrote, where, when and whether there is media. `-webhook-include-text` adds the text and captions: they then leave this machine, to whoever runs the endpoint. Media bytes are never sent.
- **HTTPS** is required unless the host is loopback or on a private network (a private IP, `localhost` or a single-label name such as a compose service). Redirects are not followed.
- **Best effort.** Delivery never slows message handling: messages wait in a bounded in-memory queue (500; the oldest is dropped, with a warning, when it is full), and each request is tried 3 times with exponential backoff (2 s, 4 s) and a 10 s timeout. Messages from the same chat within 10 seconds are sent together. Anything still queued when the daemon stops is lost, and a retry can repeat a request: deduplicate on `delivery_id`.

Each request is a JSON object with one or more messages of one chat:

```json
{
  "version": 1,
  "type": "messages.received",
  "delivery_id": "6f1c0b6a1f6e4e0b9d0f3c2a5b7e8d91",
  "chat": {"jid": "120363000000000001@g.us", "name": "Family", "is_group": true},
  "messages": [
    {
      "id": "3EB0C8F1A2B3C4D5E6F7",
      "timestamp": "2026-11-15T12:03:04Z",
      "sender": {"jid": "447700900123@s.whatsapp.net", "name": "Alice"},
      "has_media": true,
      "media_type": "image"
    }
  ]
}
```

With `-webhook-include-text`, each message also has `"text": "..."` (omitted when empty).

### Verifying a request

The headers are `X-Wpp-Mcp-Timestamp` (Unix seconds), `X-Wpp-Mcp-Signature: sha256=<hex>`, `X-Wpp-Mcp-Delivery` and `X-Wpp-Mcp-Event`. The signature is the HMAC-SHA256, keyed with the secret, of `<timestamp>.<raw body>`. Compare it in constant time and reject timestamps more than five minutes old, so a captured request cannot be replayed.

```go
func verify(secret string, r *http.Request, body []byte) bool {
	ts := r.Header.Get("X-Wpp-Mcp-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || math.Abs(time.Since(time.Unix(sec, 0)).Seconds()) > 300 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(r.Header.Get("X-Wpp-Mcp-Signature")))
}
```

```bash
# $TS is the X-Wpp-Mcp-Timestamp header, body.json the raw request body
printf '%s.' "$TS" | cat - body.json | openssl dgst -sha256 -hmac "$WPP_MCP_WEBHOOK_SECRET" | sed 's/^.* /sha256=/'
```

Generate the secret with `openssl rand -hex 32` (16 characters at least).

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
| `wpp_mcp_tool_calls_denied_total{tool}` | Tool calls and media resource reads (`tool="resource:whatsapp://media/"`) refused by a token's scope or chat set, the access policy or a `none` send policy, counted even with `-audit-days 0` |
| `wpp_mcp_http_refusals_total{code,route}` | Refused HTTP requests: `code` is `401` (authentication), `403` (Host/Origin guard, CSRF) or `429` (rate limits); `route` is `mcp`, `admin`, `oauth`, `ui_login`, `probe`, `page` or `other` |
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

## Text in images

`serve -ocr` (`WPP_MCP_OCR=1`) enables the read-only `extract_image_text` tool, which reads the text in an image message, or in a document that is a PNG, JPEG or WebP image, with a local [Tesseract](https://github.com/tesseract-ocr/tesseract). Nothing leaves the machine: the image is downloaded through the usual media path, decrypted in memory and piped to `tesseract stdin stdout -l <langs>`, so no plaintext file is written. Each run has a 30 s timeout, a 20 MB image limit and a bounded output, and at most two run at once. The text is cached in the encrypted database (once per message) and removed with the message by retention. Like every result that carries message content, it is labelled as third-party data.

The Docker image includes Tesseract with Portuguese and English data. Natively, install `tesseract` and the language data for `-ocr-langs` (default `por+eng`): `dnf install tesseract tesseract-langpack-por`, `apt install tesseract-ocr tesseract-ocr-por tesseract-ocr-eng` or `brew install tesseract tesseract-lang`. If `-ocr` is set but the binary is missing, `serve` logs a warning and the tool reports OCR as unavailable.

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
| `serve -oauth` | `WPP_MCP_OAUTH` | off | Serve an OAuth 2.1 authorization server for remote connectors (see [Connect with OAuth](#connect-with-oauth)) |
| `serve -public-url` | `WPP_MCP_PUBLIC_URL` | | Public `https://host` of the daemon, required with `-oauth`; the issuer, with the resource at `/mcp` |
| `serve -oauth-redirect-uris` | `WPP_MCP_OAUTH_REDIRECT_URIS` | `https://claude.ai/api/mcp/auth_callback` | Comma-separated redirect URI allowlist, matched exactly |
| `serve -mcp-rate` | `WPP_MCP_RATE` | 120 | `/mcp` requests per minute per client token (token bucket, burst of half that); the operator token is exempt; over it, 429 with `Retry-After` and a JSON-RPC error body; 0 disables |
| `serve -auth-fail-limit` | `WPP_MCP_AUTH_FAIL_LIMIT` | 20 | Rejected bearer credentials per client IP per minute before a 5-minute lock-out, during which every authenticated route answers 429 before checking the token; requests without credentials are not counted; 0 disables |
| | `WPP_MCP_TOKEN` | generated | Operator bearer token (else `<store>/token`); clients get their own with `wpp-mcp token create` |
| `serve -write` | `WPP_MCP_WRITE` | off | Expose tools that send or change the account |
| `serve -self-approve` | `WPP_MCP_SELF_APPROVE` | off | With `-write`, decide proposals from your own WhatsApp chat (see [Approving from your phone](#approving-from-your-phone)) |
| `serve -timezone` | `WPP_MCP_TIMEZONE` | system zone | IANA time zone that per-chat send windows are read in (`wpp-mcp access window`) |
| `serve -confirm-sends` | `WPP_MCP_CONFIRM_SENDS` | on | With `-write`, the default send policy for chats without one: `confirm` (on) or `direct` (off); see `wpp-mcp access send` |
| `serve -tools` | `WPP_MCP_TOOLS` | `default` | Groups or tool names: `core`, `access`, `messaging`, `transcribe`, `labels`, `contacts`, `groups`, `privacy`, `polls`, `all` |
| `serve -disable-tools` | `WPP_MCP_DISABLE_TOOLS` | | Groups or tool names to hide |
| `serve -max-sends-per-hour` | `WPP_MCP_MAX_SENDS_PER_HOUR` | 30 | Outbound cap |
| `serve -retain-days` | `WPP_MCP_RETAIN_DAYS` | 0 (keep) | Delete messages and media older than N days |
| `serve -audit-days` | `WPP_MCP_AUDIT_DAYS` | 90 | Keep the audit log N days; 0 disables auditing |
| `serve -enable-labels` | `WPP_MCP_LABELS` | off | WhatsApp Business label sync and tools |
| `serve -full-history` | `WPP_MCP_FULL_HISTORY` | off | Ask for a full history sync when pairing |
| `serve -ocr` | `WPP_MCP_OCR` | off | Extract text from images with the local `tesseract` binary (see [Text in images](#text-in-images)) |
| `serve -ocr-langs` | `WPP_MCP_OCR_LANGS` | `por+eng` | Tesseract languages joined by `+`; their language data must be installed |
| `serve -webhook-url` | `WPP_MCP_WEBHOOK_URL` | | POST live incoming messages from allowed chats here (see [Catching up and webhooks](#catching-up-and-webhooks)) |
| `serve -webhook-secret` | `WPP_MCP_WEBHOOK_SECRET` | | HMAC-SHA256 signing secret, required with a URL |
| `serve -webhook-include-text` | `WPP_MCP_WEBHOOK_INCLUDE_TEXT` | off | Include message text and captions: they leave the machine |
| `serve -webhook-chats` | `WPP_MCP_WEBHOOK_CHATS` | all allowed | Comma-separated chat JIDs or phone numbers |
| `serve -webhook-keywords` | `WPP_MCP_WEBHOOK_KEYWORDS` | | Comma-separated words; only matching messages |
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
make fuzz           # every fuzz target for 20s (FUZZTIME=5m for longer); CI fuzzes weekly
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
