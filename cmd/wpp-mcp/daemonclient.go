package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/daemon"
)

// tokenPath is where serve keeps its bearer token and where local clients
// (stdio, open-ui, pair, access) read it. WPP_MCP_TOKEN_FILE overrides it.
func tokenPath(storeDir string) string {
	if p := os.Getenv("WPP_MCP_TOKEN_FILE"); p != "" {
		return p
	}
	return filepath.Join(storeDir, daemon.TokenFileName)
}

// displayAddr renders a listen address for humans.
func displayAddr(addr string) string {
	if strings.HasPrefix(addr, "unix:") {
		return addr
	}
	return "http://" + addr
}

// daemonClient talks to a running serve process over TCP or a Unix socket.
type daemonClient struct {
	base  string // URL prefix, e.g. http://127.0.0.1:8765
	token string
	http  *http.Client
}

func newDaemonClient(storeDir, addr string) (*daemonClient, error) {
	addr = resolveAddr(addr)
	token, err := daemon.ResolveToken(os.Getenv("WPP_MCP_TOKEN"), tokenPath(storeDir), false)
	if err != nil {
		return nil, fmt.Errorf("read daemon token (is `wpp-mcp serve` using the same -store?): %w", err)
	}
	transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 0}
	base := "http://" + addr
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		base = "http://localhost"
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
	}
	return &daemonClient{base: base, token: token, http: &http.Client{Transport: transport}}, nil
}

// do sends an authenticated request. The caller closes the response body.
func (c *daemonClient) do(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.http.Do(req)
}

// quick is a short timeout for admin calls.
func quick() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}
