// Command wpp-mcp is a single-binary WhatsApp bridge that runs as an
// HTTP MCP daemon (default 127.0.0.1:8765). Subcommands:
//
//	login  — one-shot interactive QR pairing (writes session to store/whatsapp.db)
//	serve  — long-running HTTP daemon: serves MCP at /mcp and pairing UI at /pair
//	smoke  — non-interactive boot-check used by CI (no network, no listener)
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/murandido/mcp-wpp/internal/crypto"
	mcpsrv "github.com/murandido/mcp-wpp/internal/mcp"
	"github.com/murandido/mcp-wpp/internal/security"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "dev"

const usage = `wpp-mcp: a hardened WhatsApp MCP server

Usage:
  wpp-mcp [global flags] <command> [flags]
  wpp-mcp -version

Commands:
  keygen       Create the encryption key file (back it up!)
  serve        Run the daemon: keeps the WhatsApp session and cache, serves MCP at /mcp
  pair         Link WhatsApp: -phone +<number> for a pairing code, or a QR in the terminal
  access       Decide which chats the AI can see (list, allow, deny, mode, requests, approve)
  token        API tokens for MCP clients: scoped, chat-limited, revocable (create, list, revoke)
  audit        Show the audit log of tool calls and operator actions
  stdio        Bridge an MCP client over stdin/stdout to the running daemon
  outbox       Approve, reject or cancel what the AI proposed or scheduled (with serve -write)
  schedule     Have the daemon send a message at a later time (with serve -write)
  open-ui      Print a single-use browser login link (-page /pair, /access or /outbox)
  encrypt      Encrypt an existing plaintext store in place (daemon must be stopped)
  login        Pair without a daemon (pair falls back to this automatically)
  tools        List the MCP tools and their groups (-markdown for docs)
  healthcheck  Probe local daemon readiness (for container health checks)
  smoke        Non-interactive boot check (CI)
  help         Show this help

Global flags (before the command):
  -store DIR   Directory holding the databases and token (default ./store, env WPP_MCP_STORE)
  -key-file F  Encryption key file (env WPP_MCP_KEY_FILE; default ~/.config/wpp-mcp/key,
               /run/secrets/wpp_mcp_key in Docker, or a systemd credential)
  -no-encryption  Keep the store unencrypted (env WPP_MCP_NO_ENCRYPTION=1)
  -debug       Show full JIDs, names and message bodies in logs (default: redacted)
  -version     Print version and exit

serve flags:
  -addr ADDR             host:port or unix:/path.sock (default 127.0.0.1:8765, env WPP_MCP_ADDR)
  -allow-remote          Allow binding to a non-loopback address
  -allowed-host LIST     Extra Host/Origin values to accept, e.g. a reverse proxy hostname
  -write                 Expose tools that send or change the account (default: read-only)
  -confirm-sends         With -write, default send policy: confirm (true, default) or direct (false)
  -tools LIST            Tool groups or names to expose (default: core,messaging,transcribe,labels,access)
  -disable-tools LIST    Tool groups or names to hide
  -max-sends-per-hour N  Outbound send cap (default 30)
  -retain-days N         Delete cached messages and media older than N days (default 0: keep)
  -audit-days N          Keep the audit log N days (default 90, env WPP_MCP_AUDIT_DAYS; 0 disables it)
  -enable-labels         Enable WhatsApp Business label sync and tools
  -full-history          Ask the phone for a full history sync on a new pairing
  -webhook-url URL       POST live incoming messages from allowed chats here (signed)
  -webhook-secret S      HMAC-SHA256 signing secret, required with -webhook-url
  -webhook-include-text  Include message text in webhooks (it leaves the machine)
  -webhook-chats LIST    Only these chats (JIDs or phone numbers)
  -webhook-keywords LIST Only messages containing one of these words

Every HTTP route except /healthz and /readyz requires the operator bearer
token that serve stores in <store>/token (or WPP_MCP_TOKEN). /mcp also
accepts client tokens from ` + "`wpp-mcp token create`" + `, which is what remote
connectors should use.
`

func main() {
	privateUmask()
	mcpsrv.Version = strings.TrimPrefix(Version, "v")

	// Handle -version / --version before subcommand dispatch so it works
	// regardless of the command that follows (or if none is given).
	for _, a := range os.Args[1:] {
		if a == "-version" || a == "--version" {
			fmt.Printf("wpp-mcp %s\n", Version)
			os.Exit(0)
		}
		// Stop scanning at the first non-flag token: that's the subcommand,
		// and a later `-version` belongs to the subcommand's FlagSet.
		if len(a) == 0 || a[0] != '-' {
			break
		}
	}

	var (
		storeDir string
		debug    bool
	)
	fs := flag.NewFlagSet("wpp-mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	defaultStore := os.Getenv("WPP_MCP_STORE")
	if defaultStore == "" {
		defaultStore = "./store"
	}
	fs.StringVar(&storeDir, "store", defaultStore, "directory holding messages.db and whatsapp.db (env WPP_MCP_STORE)")
	noEnc := os.Getenv("WPP_MCP_NO_ENCRYPTION")
	encryption.disabled = noEnc == "1" || strings.EqualFold(noEnc, "true")
	fs.StringVar(&encryption.keyFile, "key-file", crypto.DefaultKeyPath(), "encryption key file (env WPP_MCP_KEY_FILE; default: Docker secret, systemd credential, or ~/.config/wpp-mcp/key)")
	fs.BoolVar(&encryption.disabled, "no-encryption", encryption.disabled, "store databases and media unencrypted (env WPP_MCP_NO_ENCRYPTION=1)")
	fs.BoolVar(&debug, "debug", false, "show full JIDs, names and message bodies in logs (default: redacted)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	args := fs.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	if os.Getenv("WPP_MCP_DEBUG") == "1" {
		debug = true
	}
	redactor := &security.Redactor{Debug: debug}

	cmd, rest := args[0], args[1:]
	var code int
	switch cmd {
	case "pair":
		code = runPair(storeDir, redactor, rest)
	case "login":
		code = runLogin(storeDir, redactor, rest)
	case "serve":
		code = runServe(storeDir, redactor, rest)
	case "smoke":
		code = runSmoke(storeDir, redactor, rest)
	case "outbox":
		code = runOutbox(storeDir, rest)
	case "schedule":
		code = runSchedule(storeDir, rest)
	case "access":
		code = runAccess(storeDir, rest)
	case "token":
		code = runToken(storeDir, rest)
	case "audit":
		code = runAudit(storeDir, rest)
	case "tools":
		code = runTools(rest)
	case "keygen":
		code = runKeygen(rest)
	case "encrypt":
		code = runEncrypt(storeDir, redactor, rest)
	case "stdio":
		code = runStdio(storeDir, rest)
	case "open-ui":
		code = runOpenUI(storeDir, rest)
	case "healthcheck":
		code = runHealthcheck(rest)
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usage)
		code = 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		code = 2
	}
	os.Exit(code)
}
