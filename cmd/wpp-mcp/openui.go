package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// runOpenUI asks the daemon for a single-use browser login link. The link
// expires after two minutes and sets an HttpOnly, SameSite=Strict session
// cookie, so the bearer token itself never reaches the browser.
func runOpenUI(storeDir string, args []string) int {
	fs := flag.NewFlagSet("open-ui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "", "daemon address (default 127.0.0.1:8765, env WPP_MCP_ADDR)")
	page := fs.String("page", "/pair", "page to open after login: /pair, /access or /outbox")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	resolved := resolveAddr(*addr)
	if strings.HasPrefix(resolved, "unix:") {
		fmt.Fprintln(os.Stderr, "open-ui needs a TCP listener; browsers cannot reach a Unix socket")
		return 2
	}
	dc, err := newDaemonClient(storeDir, resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open-ui: %v\n", err)
		return 1
	}
	ctx, cancel := quick()
	defer cancel()
	resp, err := dc.do(ctx, http.MethodPost, "/admin/ui-login?next="+url.QueryEscape(*page), nil, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "open-ui: daemon unreachable (is `wpp-mcp serve` running?): %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "open-ui: daemon returned %s\n", resp.Status)
		return 1
	}
	var out struct {
		Path      string `json:"path"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintf(os.Stderr, "open-ui: %v\n", err)
		return 1
	}
	fmt.Printf("%s%s\n", dc.base, out.Path)
	fmt.Fprintf(os.Stderr, "Open the link above in your browser within %ds. It works once.\n", out.ExpiresIn)
	return 0
}
