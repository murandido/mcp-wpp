package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/murandido/mcp-wpp/internal/oauth"
	"github.com/murandido/mcp-wpp/internal/store"
)

const auditUsage = `wpp-mcp audit: show what MCP clients and the operator did.

Usage:
  wpp-mcp audit [-since 24h] [-actor NAME] [-chat JID] [-limit N]

  -since D    only entries newer than D (Go duration or days, e.g. 90m, 24h, 7d; default 24h)
  -actor A    operator, a token name, or token:<name>
  -chat J     only entries that targeted this chat JID
  -limit N    at most N entries, newest first (default 100, max 1000)

Each MCP tool call and resource read records the actor, the tool, the chat
it targeted, the outcome (ok, error, denied, proposed) and its duration;
never arguments, message text or results. Operator actions on the admin API
and pages are recorded too. Entries older than serve's -audit-days (default
90) are deleted. Works with or without a running daemon.
`

// defaultAuditDays is how long audit entries are kept.
const defaultAuditDays = 90

// registerAuditDays adds -audit-days to fs, defaulting to WPP_MCP_AUDIT_DAYS
// or 90.
func registerAuditDays(fs *flag.FlagSet) (*int, error) {
	days := defaultAuditDays
	if v := os.Getenv("WPP_MCP_AUDIT_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("WPP_MCP_AUDIT_DAYS must be an integer")
		}
		days = n
	}
	return fs.Int("audit-days", days, "keep the audit log of tool calls and operator actions for N days; 0 disables auditing (env WPP_MCP_AUDIT_DAYS)"), nil
}

// auditEnabled reports whether the environment leaves auditing on, for
// commands that write to the store without the daemon.
func auditEnabled() bool {
	return os.Getenv("WPP_MCP_AUDIT_DAYS") != "0"
}

// startAuditPruning reports the audit setting and prunes old entries in the
// background.
func startAuditPruning(ctx context.Context, st *store.Store, days int) {
	if days <= 0 {
		fmt.Fprintln(os.Stderr, "audit: disabled (-audit-days 0)")
		return
	}
	fmt.Fprintf(os.Stderr, "audit: tool calls and operator actions are logged and kept %d day(s) (wpp-mcp audit)\n", days)
	go st.RunAuditPruning(ctx, time.Duration(days)*24*time.Hour, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "warn: "+format+"\n", args...)
	})
}

// parseAge parses a Go duration or a whole number of days ("90d").
func parseAge(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid number of days %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q (use e.g. 12h or 30d)", s)
	}
	return d, nil
}

func runAudit(storeDir string, args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, auditUsage) }
	since := fs.String("since", "24h", "only entries newer than this")
	actor := fs.String("actor", "", "operator, a token name, or token:<name>")
	chat := fs.String("chat", "", "only entries that targeted this chat JID")
	limit := fs.Int("limit", 100, "maximum entries")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	age, err := parseAge(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		return 2
	}
	f := store.AuditFilter{Since: time.Now().Add(-age), Actor: *actor, ChatJID: *chat, Limit: *limit}

	be, err := openAdminBackend(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		return 1
	}
	defer be.close()
	ctx, cancel := quick()
	defer cancel()
	entries, err := be.audit(ctx, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "no audit entries in the last %s\n", *since)
		return 0
	}
	printAudit(os.Stdout, entries)
	return 0
}

func printAudit(w io.Writer, entries []store.AuditEntry) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tACTOR\tACTION\tCHAT\tOUTCOME\tMS\tDETAIL")
	for _, e := range entries {
		chat := e.ChatJID
		if chat == "" {
			chat = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			e.At.Local().Format("2006-01-02 15:04:05"), e.Actor, e.Action, chat, e.Outcome, e.Duration, e.Detail)
	}
	tw.Flush()
}

// --- token and audit backends ------------------------------------------------

// adminBackend runs token and audit commands over the daemon's admin API or,
// without a daemon, on the store directly.
type adminBackend interface {
	createToken(ctx context.Context, in store.NewAPIToken) (store.APIToken, string, error)
	listTokens(ctx context.Context) ([]tokenRow, error)
	revokeToken(ctx context.Context, ref string) (store.APIToken, error)
	audit(ctx context.Context, f store.AuditFilter) ([]store.AuditEntry, error)
	listGrants(ctx context.Context) ([]oauth.GrantView, error)
	revokeGrant(ctx context.Context, id string) (store.OAuthGrant, error)
	close()
}

// tokenRow is a token with its status.
type tokenRow struct {
	store.APIToken
	Status string `json:"status"`
}

func openAdminBackend(storeDir string) (adminBackend, error) {
	if dc, err := newDaemonClient(storeDir, ""); err == nil && daemonUp(dc) {
		return &httpAdmin{api: &httpAccess{dc: dc}}, nil
	}
	lock, err := store.TryLock(storeDir)
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable and the store is locked: %w", err)
	}
	st, _, err := openStore(storeDir)
	if err != nil {
		lock.Release()
		return nil, err
	}
	return &directAdmin{st: st, release: lock.Release}, nil
}

type directAdmin struct {
	st      *store.Store
	release func()
}

// record logs an operator action taken without the daemon (which would
// otherwise have recorded it on its admin API).
func (d *directAdmin) record(ctx context.Context, action, detail string, failed bool) {
	if !auditEnabled() {
		return
	}
	outcome := store.OutcomeOK
	if failed {
		outcome = store.OutcomeError
	}
	_ = d.st.RecordAudit(ctx, store.AuditEntry{Actor: "operator", Kind: store.AuditAdmin, Action: action, Detail: detail + " via=cli", Outcome: outcome})
}

func (d *directAdmin) createToken(ctx context.Context, in store.NewAPIToken) (store.APIToken, string, error) {
	t, plain, err := d.st.CreateAPIToken(ctx, in)
	d.record(ctx, "token create", fmt.Sprintf("name=%s scopes=%s chats=%s", in.Name, strings.Join(in.Scopes, ","), strings.Join(in.Chats, ",")), err != nil)
	return t, plain, err
}

func (d *directAdmin) listTokens(ctx context.Context) ([]tokenRow, error) {
	list, err := d.st.ListAPITokens(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]tokenRow, 0, len(list))
	for _, t := range list {
		out = append(out, tokenRow{APIToken: t, Status: t.Status(now)})
	}
	return out, nil
}

func (d *directAdmin) revokeToken(ctx context.Context, ref string) (store.APIToken, error) {
	t, err := d.st.RevokeAPIToken(ctx, ref)
	d.record(ctx, "token revoke", "ref="+ref, err != nil)
	return t, err
}

func (d *directAdmin) audit(ctx context.Context, f store.AuditFilter) ([]store.AuditEntry, error) {
	return d.st.ListAudit(ctx, f)
}

func (d *directAdmin) close() { d.st.Close(); d.release() }

type httpAdmin struct{ api *httpAccess }

func (h *httpAdmin) createToken(ctx context.Context, in store.NewAPIToken) (store.APIToken, string, error) {
	var out struct {
		Token  tokenRow `json:"token"`
		Secret string   `json:"secret"`
	}
	err := h.api.call(ctx, http.MethodPost, "/admin/tokens", in, &out)
	return out.Token.APIToken, out.Secret, err
}

func (h *httpAdmin) listTokens(ctx context.Context) ([]tokenRow, error) {
	var out struct {
		Tokens []tokenRow `json:"tokens"`
	}
	err := h.api.call(ctx, http.MethodGet, "/admin/tokens", nil, &out)
	return out.Tokens, err
}

func (h *httpAdmin) revokeToken(ctx context.Context, ref string) (store.APIToken, error) {
	var out struct {
		Token tokenRow `json:"token"`
	}
	err := h.api.call(ctx, http.MethodPost, "/admin/tokens/"+url.PathEscape(ref)+"/revoke", nil, &out)
	return out.Token.APIToken, err
}

func (h *httpAdmin) audit(ctx context.Context, f store.AuditFilter) ([]store.AuditEntry, error) {
	q := url.Values{}
	if !f.Since.IsZero() {
		q.Set("since", f.Since.UTC().Format(time.RFC3339))
	}
	if f.Actor != "" {
		q.Set("actor", f.Actor)
	}
	if f.ChatJID != "" {
		q.Set("chat", f.ChatJID)
	}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	var out struct {
		Entries []store.AuditEntry `json:"entries"`
	}
	err := h.api.call(ctx, http.MethodGet, "/admin/audit?"+q.Encode(), nil, &out)
	if err != nil && strings.Contains(err.Error(), "404") {
		return nil, fmt.Errorf("the daemon runs with auditing disabled (-audit-days 0)")
	}
	return out.Entries, err
}

func (h *httpAdmin) close() {}
