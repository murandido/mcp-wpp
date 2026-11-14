package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startGuardedServer(t *testing.T, cfg Config) string {
	t.Helper()
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.Driver == nil {
		cfg.Driver = newFakePairDriver(true)
	}
	if cfg.AuthToken == "" {
		cfg.AuthToken = testToken
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Run(ctx) }()
	<-s.listenerOK
	return "http://" + s.BoundAddr()
}

func status(t *testing.T, c *http.Client, req *http.Request) int {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestNew_RequiresToken(t *testing.T) {
	if _, err := New(Config{Addr: "127.0.0.1:0", Driver: newFakePairDriver(true)}); err == nil {
		t.Fatal("New without AuthToken must fail")
	}
	if _, err := New(Config{Addr: "127.0.0.1:0", Driver: newFakePairDriver(true), AuthToken: "short"}); err == nil {
		t.Fatal("New with a short AuthToken must fail")
	}
}

func TestHostGuard_RejectsRebindingHostAndOrigin(t *testing.T) {
	base := startGuardedServer(t, Config{AllowedHosts: []string{"wpp.example.com"}})
	cases := []struct {
		name, host, origin string
		want               int
	}{
		{"loopback ip", "", "", http.StatusOK},
		{"localhost any port", "localhost:9999", "", http.StatusOK},
		{"ipv6 loopback", "[::1]:8765", "", http.StatusOK},
		{"allowed proxy host", "wpp.example.com", "https://wpp.example.com", http.StatusOK},
		{"rebinding host", "evil.example:8765", "", http.StatusForbidden},
		{"rebinding origin", "", "http://evil.example:8765", http.StatusForbidden},
		{"null origin", "", "null", http.StatusForbidden},
		{"file origin", "", "file://", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, base+"/pair", nil)
			if tc.host != "" {
				req.Host = tc.host
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if got := status(t, http.DefaultClient, req); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAuthGuard_FailsClosed(t *testing.T) {
	base := startGuardedServer(t, Config{})
	for path, want := range map[string]int{
		"/healthz":        http.StatusOK,
		"/readyz":         0, // public; 200 or 503 depending on connection
		"/mcp":            http.StatusUnauthorized,
		"/pair":           http.StatusUnauthorized,
		"/admin/anything": http.StatusUnauthorized,
		"/does-not-exist": http.StatusUnauthorized,
	} {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		got := status(t, rawClient, req)
		if want == 0 {
			if got == http.StatusUnauthorized {
				t.Errorf("%s must be public, got 401", path)
			}
			continue
		}
		if got != want {
			t.Errorf("%s without credentials: got %d, want %d", path, got, want)
		}
	}
}

func mintLogin(t *testing.T, base, next string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+adminLoginPath+"?next="+next, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mint status %d", resp.StatusCode)
	}
	var out struct{ Path string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Path
}

func TestUILogin_CookieGrantsPagesButNotMCP(t *testing.T) {
	base := startGuardedServer(t, Config{})
	path := mintLogin(t, base, "/pair")

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Transport: rawClient.Transport, Jar: jar}
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	if got := status(t, browser, req); got != http.StatusOK {
		t.Fatalf("login redirect to /pair: got %d", got)
	}
	req, _ = http.NewRequest(http.MethodGet, base+"/pair", nil)
	if got := status(t, browser, req); got != http.StatusOK {
		t.Fatalf("/pair with session cookie: got %d", got)
	}
	req, _ = http.NewRequest(http.MethodPost, base+"/mcp", strings.NewReader("{}"))
	if got := status(t, browser, req); got != http.StatusUnauthorized {
		t.Fatalf("/mcp must not accept the session cookie: got %d", got)
	}
	req, _ = http.NewRequest(http.MethodPost, base+adminLoginPath, nil)
	if got := status(t, browser, req); got != http.StatusUnauthorized {
		t.Fatalf("/admin must not accept the session cookie: got %d", got)
	}

	// The code is single-use.
	noRedirect := &http.Client{Transport: rawClient.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ = http.NewRequest(http.MethodGet, base+path, nil)
	if got := status(t, noRedirect, req); got != http.StatusUnauthorized {
		t.Fatalf("reused login code: got %d, want 401", got)
	}
}

func TestUILogin_RejectsOffsiteLanding(t *testing.T) {
	for _, p := range []string{"", "https://evil.example", "//evil.example", "/mcp", "/admin/x", `/\evil`, "pair"} {
		if safeLanding(p) {
			t.Errorf("safeLanding(%q) = true", p)
		}
	}
	for _, p := range []string{"/pair", "/access", "/outbox?x=1"} {
		if !safeLanding(p) {
			t.Errorf("safeLanding(%q) = false", p)
		}
	}
}

func TestUIAuth_CodeExpires(t *testing.T) {
	a := newUIAuth()
	now := time.Now()
	a.now = func() time.Time { return now }
	code := a.mintCode()
	now = now.Add(loginCodeTTL + time.Second)
	if _, ok := a.redeem(code); ok {
		t.Fatal("expired code redeemed")
	}
}

func TestResolveToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")

	if _, err := ResolveToken("", path, false); err == nil {
		t.Fatal("missing token file without create must fail")
	}
	tok, err := ResolveToken("", path, true)
	if err != nil || len(tok) != 64 {
		t.Fatalf("create: %q %v", tok, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("token mode %04o, want 0600", fi.Mode().Perm())
	}
	again, err := ResolveToken("", path, true)
	if err != nil || again != tok {
		t.Fatalf("token not stable: %q vs %q (%v)", again, tok, err)
	}
	if env, _ := ResolveToken("from-env-0123456789", path, true); env != "from-env-0123456789" {
		t.Fatalf("env token ignored: %q", env)
	}
	if _, err := ResolveToken("short", path, true); err == nil {
		t.Fatal("short env token accepted")
	}
	_ = os.Chmod(path, 0o644)
	if _, err := ResolveToken("", path, false); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable token accepted: %v", err)
	}
}

func TestListen_UnixSocketIsPrivate(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "run", "wpp.sock")
	ln, err := listen("unix:" + sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %04o, want 0600", fi.Mode().Perm())
	}
}
