package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/daemon"
	mcpsrv "github.com/murandido/mcp-wpp/internal/mcp"
	"github.com/murandido/mcp-wpp/internal/ratelimit"
	"github.com/murandido/mcp-wpp/internal/security"
	"github.com/murandido/mcp-wpp/internal/store"
)

func runServe(storeDir string, redactor *security.Redactor, args []string) int {
	var (
		addr          string
		allowRemote   bool
		write         bool
		labelsEnabled bool
		allowedHosts  string
		tools         string
		disableTools  string
		maxPerHour    int
		retainDays    int
		confirmSends  = true
	)
	for _, b := range []struct {
		env string
		dst *bool
	}{{"WPP_MCP_WRITE", &write}, {"WPP_MCP_LABELS", &labelsEnabled}, {"WPP_MCP_CONFIRM_SENDS", &confirmSends}} {
		if value := os.Getenv(b.env); value != "" {
			v, err := strconv.ParseBool(value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s must be a boolean (for example, 1 or 0)\n", b.env)
				return 2
			}
			*b.dst = v
		}
	}
	maxPerHour = ratelimit.DefaultConfig().MaxSendsPerHour
	if value := os.Getenv("WPP_MCP_MAX_SENDS_PER_HOUR"); value != "" {
		v, err := strconv.Atoi(value)
		if err != nil {
			fmt.Fprintln(os.Stderr, "WPP_MCP_MAX_SENDS_PER_HOUR must be an integer")
			return 2
		}
		maxPerHour = v
	}
	if value := os.Getenv("WPP_MCP_RETAIN_DAYS"); value != "" {
		v, err := strconv.Atoi(value)
		if err != nil {
			fmt.Fprintln(os.Stderr, "WPP_MCP_RETAIN_DAYS must be an integer")
			return 2
		}
		retainDays = v
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&addr, "addr", "", "listen address: host:port or unix:/path.sock (default 127.0.0.1:8765, env WPP_MCP_ADDR)")
	fs.BoolVar(&allowRemote, "allow-remote", false, "allow binding to a non-loopback address")
	fs.StringVar(&allowedHosts, "allowed-host", os.Getenv("WPP_MCP_ALLOWED_HOSTS"), "extra comma-separated Host/Origin values to accept, e.g. a reverse proxy hostname (env WPP_MCP_ALLOWED_HOSTS)")
	fullHistoryFlag := registerFullHistory(fs)
	hooks, err := registerWebhookFlags(fs, os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fs.BoolVar(&write, "write", write, "expose tools that send messages or change the WhatsApp account (env WPP_MCP_WRITE); default is read-only")
	fs.BoolVar(&labelsEnabled, "enable-labels", labelsEnabled, "enable WhatsApp Business label sync and tools (env WPP_MCP_LABELS)")
	fs.StringVar(&tools, "tools", os.Getenv("WPP_MCP_TOOLS"), "comma-separated tool groups or names to expose: default, all, core, messaging, transcribe, labels, access, contacts, groups, privacy, polls (env WPP_MCP_TOOLS)")
	fs.StringVar(&disableTools, "disable-tools", os.Getenv("WPP_MCP_DISABLE_TOOLS"), "comma-separated tool groups or names to hide (env WPP_MCP_DISABLE_TOOLS)")
	fs.IntVar(&maxPerHour, "max-sends-per-hour", maxPerHour, "cap on outbound sends in any trailing hour (env WPP_MCP_MAX_SENDS_PER_HOUR)")
	fs.BoolVar(&confirmSends, "confirm-sends", confirmSends, "with -write, the default send policy for chats without one: proposals the user approves (wpp-mcp outbox); -confirm-sends=false acts immediately. Per chat: wpp-mcp access send (env WPP_MCP_CONFIRM_SENDS)")
	fs.IntVar(&retainDays, "retain-days", retainDays, "delete cached messages and media older than N days; 0 keeps everything (env WPP_MCP_RETAIN_DAYS)")
	auditDays, auditErr := registerAuditDays(fs)
	if auditErr != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", auditErr)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditDays < 0 {
		fmt.Fprintln(os.Stderr, "-audit-days must be 0 or more")
		return 2
	}
	if retainDays < 0 {
		fmt.Fprintln(os.Stderr, "-retain-days must be 0 or more")
		return 2
	}
	fullHistory, fullHistoryErr := resolveFullHistory(fs, *fullHistoryFlag, os.Getenv)
	if fullHistoryErr != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", fullHistoryErr)
		return 2
	}
	if maxPerHour < 1 {
		fmt.Fprintln(os.Stderr, "-max-sends-per-hour must be at least 1")
		return 2
	}
	webhookCfg := hooks.config()
	if webhookCfg.Enabled() {
		if err := webhookCfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			return 2
		}
	}
	selection := &mcpsrv.ToolSelection{Enable: mcpsrv.ParseToolList(tools), Disable: mcpsrv.ParseToolList(disableTools)}

	addr = resolveAddr(addr)
	if !allowRemote && !isLoopbackAddr(addr) {
		fmt.Fprintf(os.Stderr, "refusing to bind to non-loopback address %q; pass -allow-remote if you mean it\n", addr)
		return 2
	}

	authToken, err := daemon.ResolveToken(os.Getenv("WPP_MCP_TOKEN"), tokenPath(storeDir), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	lock, err := store.TryLock(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	defer lock.Release()

	absStore, err := filepath.Abs(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve store dir: %v\n", err)
		return 1
	}
	allowedMediaRoot := os.Getenv("WPP_MCP_MEDIA_ROOT")
	if allowedMediaRoot == "" {
		allowedMediaRoot = filepath.Join(absStore, "uploads")
	}
	allowedMediaRoot = filepath.Clean(allowedMediaRoot)
	if mkErr := os.MkdirAll(allowedMediaRoot, 0o700); mkErr != nil {
		fmt.Fprintf(os.Stderr, "warn: could not create media root %q: %v\n", allowedMediaRoot, mkErr)
	}
	// Operator UX: make the media root obvious on boot so users know where
	// to drop outbound attachments.
	fmt.Fprintf(os.Stderr, "media root: %s (drop outbound files here)\n", allowedMediaRoot)

	st, keys, err := openStore(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		return 1
	}
	defer st.Close()

	if !st.FTSEnabled() {
		fmt.Fprintln(os.Stderr, "warn: this SQLCipher build lacks FTS5; message search falls back to accent-sensitive substring matching (the Docker image has FTS5)")
	}
	limits := ratelimit.DefaultConfig()
	limits.MaxSendsPerHour = maxPerHour
	if limits.NonContactMaxPerHour > maxPerHour {
		limits.NonContactMaxPerHour = maxPerHour
	}

	c, err := client.New(ctx, client.Config{
		Keys:             keys,
		RateLimiter:      ratelimit.New(limits),
		StoreDir:         storeDir,
		Store:            st,
		Logger:           client.NewStderrLogger("Client", "INFO", false),
		AllowedMediaRoot: allowedMediaRoot,
		Redactor:         redactor,
		LabelsEnabled:    labelsEnabled,
		FullHistory:      fullHistory,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client: %v\n", err)
		return 1
	}

	if err := startWebhook(ctx, webhookCfg, c, st, redactor); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		return 2
	}

	drv := newProductionDriver(c)

	// The daemon owns the pair cache, so build it first, then hand the cache
	// to the MCP server (so pairing_status can surface the live QR), then
	// mount the MCP HTTP handler back onto the daemon.
	dcfg := daemon.Config{
		Addr:          addr,
		Driver:        drv,
		AuthToken:     authToken,
		AllowedHosts:  mcpsrv.ParseToolList(allowedHosts),
		AutoPairPhone: os.Getenv("WPP_MCP_PAIR_PHONE"),
		Access:        st,
		Tokens:        st,
	}
	var auditor mcpsrv.Auditor
	if *auditDays > 0 {
		dcfg.Audit, auditor = st, st
	}
	d, err := daemon.New(dcfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon.New: %v\n", err)
		return 1
	}

	mcpServer, err := mcpsrv.NewServerWithOptions(c, d.Cache(), mcpsrv.Options{
		ReadOnly:      !write,
		LabelsEnabled: labelsEnabled,
		Tools:         selection,
		ConfirmSends:  confirmSends,
		Audit:         auditor,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tools: %v\n", err)
		return 2
	}
	switch {
	case write && confirmSends:
		fmt.Fprintln(os.Stderr, "write mode: sends and account changes wait for approval (wpp-mcp outbox), unless a chat's send policy says otherwise (wpp-mcp access send)")
	case write:
		fmt.Fprintln(os.Stderr, "write mode WITHOUT confirmation: tools send messages and change the account immediately, except in chats whose send policy is confirm or none (wpp-mcp access send)")
	default:
		fmt.Fprintln(os.Stderr, "read-only mode (default): pass -write to enable sending and scheduled messages")
	}
	fmt.Fprintf(os.Stderr, "tools (%d): %s\n", len(mcpServer.ToolNames()), strings.Join(mcpServer.ToolNames(), ", "))
	if labelsEnabled {
		fmt.Fprintln(os.Stderr, "WhatsApp Business label sync and tools are enabled")
	}
	d.SetMCPMount(mcpServer.AttachHTTP)
	if write {
		// Per-chat send policies can ask for confirmation even when the
		// default is direct, and scheduled messages are listed and
		// cancelled there, so the outbox is served in every write mode.
		d.SetOutbox(mcpServer)
		// Scheduled messages are sent only in write mode; read-only
		// daemons leave them queued.
		go mcpServer.RunScheduler(ctx, mcpsrv.SchedulerInterval)
	}
	if retainDays > 0 {
		fmt.Fprintf(os.Stderr, "retention: messages and media older than %d day(s) are deleted hourly\n", retainDays)
		go c.RunRetention(ctx, time.Duration(retainDays)*24*time.Hour)
	}
	startAuditPruning(ctx, st, *auditDays)

	fmt.Fprintf(os.Stderr, "wpp-mcp listening on %s (MCP at /mcp; bearer token in %s)\n", displayAddr(addr), tokenPath(storeDir))
	if !c.IsLoggedIn() {
		fmt.Fprintln(os.Stderr, "unpaired: run `wpp-mcp pair -phone +<number>` or `wpp-mcp open-ui` for the QR page")
	}
	if err := d.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "daemon: %v\n", err)
		return 1
	}
	return 0
}

// resolveAddr applies the -addr / WPP_MCP_ADDR / default precedence.
func resolveAddr(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("WPP_MCP_ADDR"); env != "" {
		return env
	}
	return "127.0.0.1:8765"
}

// isLoopbackAddr reports whether addr's host resolves to a loopback IP.
// Hostnames (including "localhost") are resolved via DNS; all returned
// addresses must be loopback for the check to pass. Non-loopback binds
// require -allow-remote.
func isLoopbackAddr(addr string) bool {
	if strings.HasPrefix(addr, "unix:") {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	// If it parses directly as an IP, check without DNS.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// Resolve hostname and require every address to be loopback.
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}
