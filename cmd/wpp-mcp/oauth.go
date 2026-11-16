package main

import (
	"context"
	"errors"
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
	"github.com/murandido/mcp-wpp/internal/security"
	"github.com/murandido/mcp-wpp/internal/store"
)

const oauthHelp = `wpp-mcp oauth: approve and manage OAuth connections (serve -oauth).

Usage:
  wpp-mcp oauth pending
  wpp-mcp oauth approve <code> [-scope read|read,send] [-chats JID,...] [-days 30]
  wpp-mcp oauth deny <code>
  wpp-mcp oauth grants
  wpp-mcp oauth revoke <grant id>

A connector that starts the OAuth flow shows a page with a short code such
as ABCD-EFGH. Nothing is connected until you approve that code here.

  pending   requests waiting for you: code, client, the host it returns to,
            requested scopes, the address it came from and its age
  approve   approve one. Without -scope the client gets the scopes it asked
            for; -scope replaces them (your choice wins, wider or narrower).
            -chats limits the connection to these chats on top of the access
            policy. -days (default 30, at most 365) is how long the
            connection lasts without being used; each use extends it.
  deny      refuse one; the client is told access was denied
  grants    approved connections and their status
  revoke    end a connection at once: its refresh token and access tokens
            stop working

Only approve a code you see on your own screen, in a connection you started
yourself: anyone can start a flow and ask you to approve their code.

pending, approve and deny need the running daemon (requests live in its
memory); grants and revoke also work on the store without it.
`

func runOAuth(storeDir string, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(os.Stderr, oauthHelp)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "pending":
		return oauthPending(storeDir)
	case "approve":
		return oauthApprove(storeDir, rest)
	case "deny":
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: wpp-mcp oauth deny <code>")
			return 2
		}
		return oauthDeny(storeDir, rest[0])
	case "grants", "list", "ls":
		return oauthGrants(storeDir)
	case "revoke":
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: wpp-mcp oauth revoke <grant id>")
			return 2
		}
		return oauthRevoke(storeDir, rest[0])
	default:
		fmt.Fprintf(os.Stderr, "oauth: unknown command %q\n\n%s", cmd, oauthHelp)
		return 2
	}
}

// oauthDaemon returns the admin API of the running daemon, which holds the
// pending requests.
func oauthDaemon(storeDir string) (*httpAccess, error) {
	dc, err := newDaemonClient(storeDir, "")
	if err != nil {
		return nil, err
	}
	if !daemonUp(dc) {
		return nil, errors.New("the daemon is not running: pending requests live in its memory (start `wpp-mcp serve -oauth`)")
	}
	return &httpAccess{dc: dc}, nil
}

// oauthCall wraps a 404 from a daemon started without -oauth.
func oauthCall(ctx context.Context, api *httpAccess, method, path string, in, out any) error {
	err := api.call(ctx, method, path, in, out)
	if err != nil && strings.Contains(err.Error(), "404") {
		return errors.New("the daemon runs without OAuth (start it with -oauth and -public-url)")
	}
	return err
}

func oauthPending(storeDir string) int {
	api, err := oauthDaemon(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	ctx, cancel := quick()
	defer cancel()
	var out struct {
		Pending []oauth.PendingView `json:"pending"`
	}
	if err := oauthCall(ctx, api, http.MethodGet, "/admin/oauth/pending", nil, &out); err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	if len(out.Pending) == 0 {
		fmt.Fprintln(os.Stderr, "no pending authorization requests")
		return 0
	}
	printPending(os.Stdout, out.Pending, time.Now())
	return 0
}

// termSafe drops control characters from client-supplied text before it is
// printed to a terminal.
func termSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

func printPending(w io.Writer, list []oauth.PendingView, now time.Time) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CODE\tCLIENT\tREDIRECT HOST\tSCOPES\tSOURCE IP\tAGE\tCLIENT ID")
	for _, p := range list {
		age := now.Sub(p.CreatedAt).Round(time.Second)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Code, termSafe(p.ClientName), termSafe(p.RedirectHost),
			strings.Join(p.Scopes, ","), p.SourceIP, age, termSafe(p.ClientID))
	}
	tw.Flush()
}

func oauthApprove(storeDir string, args []string) int {
	var code string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		code, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("oauth approve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, oauthHelp) }
	scope := fs.String("scope", "", "read or read,send (default: what the client requested)")
	chats := fs.String("chats", "", "comma-separated chat JIDs or phone digits (default: the access policy)")
	days := fs.Int("days", 30, "days the connection lasts without use (1-365)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if code == "" && len(rest) == 1 {
		code, rest = rest[0], nil
	}
	if code == "" || len(rest) > 0 {
		fmt.Fprintln(os.Stderr, "usage: wpp-mcp oauth approve <code> [-scope read|read,send] [-chats JID,...] [-days 30]")
		return 2
	}
	api, err := oauthDaemon(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	ctx, cancel := quick()
	defer cancel()
	in := oauth.ApproveRequest{Code: oauth.NormalizeCode(code), Scopes: splitList(*scope), Chats: splitList(*chats), Days: *days}
	var out struct {
		Request oauth.PendingView `json:"request"`
	}
	if err := oauthCall(ctx, api, http.MethodPost, "/admin/oauth/approve", in, &out); err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	r := out.Request
	chatsDesc := "every chat the access policy allows"
	if len(r.ApprovedChats) > 0 {
		chatsDesc = strings.Join(r.ApprovedChats, ",")
	}
	fmt.Fprintf(os.Stderr, "Approved %s: client %q (returns to %s, from %s), scopes %s, chats: %s, %d day(s) without use.\n",
		r.Code, termSafe(r.ClientName), termSafe(r.RedirectHost), r.SourceIP, strings.Join(r.ApprovedScopes, ","), chatsDesc, r.RefreshDays)
	fmt.Fprintln(os.Stderr, "The browser page continues on its own. `wpp-mcp oauth grants` lists the connection once the client has finished.")
	return 0
}

func oauthDeny(storeDir, code string) int {
	api, err := oauthDaemon(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	ctx, cancel := quick()
	defer cancel()
	var out struct {
		Request oauth.PendingView `json:"request"`
	}
	if err := oauthCall(ctx, api, http.MethodPost, "/admin/oauth/deny", map[string]string{"code": oauth.NormalizeCode(code)}, &out); err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Denied %s (client %q).\n", out.Request.Code, termSafe(out.Request.ClientName))
	return 0
}

func oauthGrants(storeDir string) int {
	be, err := openAdminBackend(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	defer be.close()
	ctx, cancel := quick()
	defer cancel()
	list, err := be.listGrants(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "no OAuth connections")
		return 0
	}
	printGrants(os.Stdout, list)
	return 0
}

func printGrants(w io.Writer, list []oauth.GrantView) {
	when := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.Local().Format("2006-01-02 15:04")
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "GRANT\tCLIENT\tSTATUS\tSCOPES\tCHATS\tCREATED\tLAST USED\tEXPIRES")
	for _, g := range list {
		chats := "policy"
		if g.Chats != nil {
			chats = strings.Join(g.Chats, ",")
		}
		created, expires := g.CreatedAt, g.RefreshExpiresAt
		status := g.Status
		if g.RevokeReason != "" && g.Status == "revoked" {
			status += " (" + g.RevokeReason + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", g.ID, termSafe(g.ClientName), status, strings.Join(g.Scopes, ","), chats,
			when(&created), when(g.LastUsedAt), when(&expires))
	}
	tw.Flush()
}

func oauthRevoke(storeDir, id string) int {
	be, err := openAdminBackend(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	defer be.close()
	ctx, cancel := quick()
	defer cancel()
	g, err := be.revokeGrant(ctx, id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oauth: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "grant %s (client %q) revoked; its tokens no longer work\n", g.ID, termSafe(g.ClientName))
	return 0
}

// --- backends ------------------------------------------------------------------

func (d *directAdmin) listGrants(ctx context.Context) ([]oauth.GrantView, error) {
	list, err := d.st.ListOAuthGrants(ctx)
	if err != nil {
		return nil, err
	}
	return oauth.GrantViews(list, time.Now()), nil
}

func (d *directAdmin) revokeGrant(ctx context.Context, id string) (store.OAuthGrant, error) {
	g, err := d.st.RevokeOAuthGrant(ctx, id, "revoked by operator")
	d.record(ctx, "oauth revoke", "id="+id, err != nil)
	return g, err
}

func (h *httpAdmin) listGrants(ctx context.Context) ([]oauth.GrantView, error) {
	var out struct {
		Grants []oauth.GrantView `json:"grants"`
	}
	err := oauthCall(ctx, h.api, http.MethodGet, "/admin/oauth/grants", nil, &out)
	return out.Grants, err
}

func (h *httpAdmin) revokeGrant(ctx context.Context, id string) (store.OAuthGrant, error) {
	var out struct {
		Grant oauth.GrantView `json:"grant"`
	}
	err := oauthCall(ctx, h.api, http.MethodPost, "/admin/oauth/grants/"+url.PathEscape(id)+"/revoke", nil, &out)
	return out.Grant.OAuthGrant, err
}

// --- serve flags -----------------------------------------------------------------

type oauthFlags struct {
	enabled   bool
	publicURL string
	redirects string
}

func registerOAuthFlags(fs *flag.FlagSet, getenv func(string) string) (*oauthFlags, error) {
	f := &oauthFlags{publicURL: getenv("WPP_MCP_PUBLIC_URL"), redirects: getenv("WPP_MCP_OAUTH_REDIRECT_URIS")}
	if v := getenv("WPP_MCP_OAUTH"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, errors.New("WPP_MCP_OAUTH must be a boolean (for example, 1 or 0)")
		}
		f.enabled = b
	}
	fs.BoolVar(&f.enabled, "oauth", f.enabled, "serve an OAuth 2.1 authorization server for remote connectors; needs -public-url (env WPP_MCP_OAUTH)")
	fs.StringVar(&f.publicURL, "public-url", f.publicURL, "https origin clients reach this daemon at, e.g. https://wpp.example.com (env WPP_MCP_PUBLIC_URL)")
	fs.StringVar(&f.redirects, "oauth-redirect-uris", f.redirects, "comma-separated OAuth redirect URI allowlist (default "+oauth.DefaultRedirectURI+", env WPP_MCP_OAUTH_REDIRECT_URIS)")
	return f, nil
}

// server builds the OAuth server, or returns nil when OAuth is off.
func (f *oauthFlags) server(st *store.Store, redactor *security.Redactor) (*oauth.Server, error) {
	if !f.enabled {
		return nil, nil
	}
	if f.publicURL == "" {
		return nil, errors.New("-oauth needs -public-url https://<host> (env WPP_MCP_PUBLIC_URL)")
	}
	redirects, err := oauth.ParseRedirectURIs(f.redirects)
	if err != nil {
		return nil, err
	}
	return oauth.New(oauth.Config{
		PublicURL:    f.publicURL,
		RedirectURIs: redirects,
		Store:        st,
		Logf: func(format string, args ...any) {
			fmt.Fprintln(os.Stderr, redactor.Line(fmt.Sprintf(format, args...)))
		},
	})
}

// validate checks the flags before anything is opened.
func (f *oauthFlags) validate() error {
	if !f.enabled {
		return nil
	}
	if _, err := oauth.ParsePublicURL(f.publicURL); err != nil {
		return fmt.Errorf("-oauth: %w", err)
	}
	_, err := oauth.ParseRedirectURIs(f.redirects)
	return err
}
