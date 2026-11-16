package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// cimdServer is a TLS server publishing metadata documents. Its documents
// use the server's own URL as client_id unless a handler overrides it.
type cimdServer struct {
	ts    *httptest.Server
	hits  atomic.Int32
	docs  map[string]func(w http.ResponseWriter, self string)
	trust *http.Client
}

func newCIMDServer(t *testing.T) *cimdServer {
	t.Helper()
	c := &cimdServer{docs: map[string]func(http.ResponseWriter, string){}}
	c.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		h, ok := c.docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		h(w, c.ts.URL+r.URL.Path)
	}))
	t.Cleanup(c.ts.Close)
	pool := c.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	// The production client, minus the address guard (the test server is
	// on loopback) and trusting the test CA.
	c.trust = newFetchClient(nil, pool)
	return c
}

func (c *cimdServer) url(path string) string { return c.ts.URL + path }

func writeDoc(doc map[string]any) func(http.ResponseWriter, string) {
	return func(w http.ResponseWriter, self string) {
		if _, ok := doc["client_id"]; !ok {
			doc["client_id"] = self
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}
}

func TestCIMD_Validation(t *testing.T) {
	c := newCIMDServer(t)
	ctx := context.Background()
	c.docs["/good"] = writeDoc(map[string]any{"client_name": "Claude", "redirect_uris": []string{DefaultRedirectURI}})
	c.docs["/mismatch"] = writeDoc(map[string]any{"client_id": "https://other.test/doc", "client_name": "Claude", "redirect_uris": []string{DefaultRedirectURI}})
	c.docs["/noname"] = writeDoc(map[string]any{"redirect_uris": []string{DefaultRedirectURI}})
	c.docs["/noredirects"] = writeDoc(map[string]any{"client_name": "Claude"})
	c.docs["/confidential"] = writeDoc(map[string]any{"client_name": "C", "redirect_uris": []string{DefaultRedirectURI}, "token_endpoint_auth_method": "private_key_jwt"})
	c.docs["/huge"] = func(w http.ResponseWriter, self string) {
		_, _ = w.Write([]byte(`{"client_id":"` + self + `","client_name":"` + strings.Repeat("x", cimdMaxBody) + `","redirect_uris":["` + DefaultRedirectURI + `"]}`))
	}
	c.docs["/redirect"] = func(w http.ResponseWriter, self string) {
		w.Header().Set("Location", strings.TrimSuffix(self, "/redirect")+"/good")
		w.WriteHeader(http.StatusFound)
	}

	if doc, err := fetchCIMD(ctx, c.trust, c.url("/good"), c.url("/good")); err != nil || doc.Name != "Claude" {
		t.Fatalf("good document: %+v %v", doc, err)
	}
	for path, want := range map[string]string{
		"/mismatch":     "does not equal",
		"/noname":       "client_name",
		"/noredirects":  "redirect_uris",
		"/confidential": "not supported",
		"/huge":         "larger than",
		"/redirect":     "status 302",
		"/missing":      "status 404",
	} {
		before := c.hits.Load()
		_, err := fetchCIMD(ctx, c.trust, c.url(path), c.url(path))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
		if path == "/redirect" && c.hits.Load()-before != 1 {
			t.Errorf("redirect was followed")
		}
	}
}

func TestCIMD_URLRules(t *testing.T) {
	for _, bad := range []string{
		"http://claude.ai/oauth/client", "https://claude.ai", "https://claude.ai/",
		"https://u@claude.ai/x", "https://claude.ai/x?y=1", "https://claude.ai/x#f", "https://claude.ai/a/../b",
	} {
		if _, err := validCIMDURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := validCIMDURL("https://claude.ai/oauth/mcp-oauth-client-metadata"); err != nil {
		t.Error(err)
	}
}

// Documents are fetched only from Anthropic's origins, rebuilt on a constant
// base; any other host is refused before a request is made.
func TestCIMD_FetchOnlyAnthropicOrigins(t *testing.T) {
	for in, want := range map[string]string{
		"https://claude.ai/oauth/mcp-oauth-client-metadata": "https://claude.ai/oauth/mcp-oauth-client-metadata",
		"https://CLAUDE.com/a/b":                            "https://claude.com/a/b",
	} {
		u, _ := url.Parse(in)
		if got, ok := cimdFetchURL(u); !ok || got != want {
			t.Errorf("cimdFetchURL(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"https://evil.test/doc", "https://claude.ai.evil.test/doc", "https://claude.ai:8443/doc", "https://127.0.0.1/doc"} {
		u, _ := url.Parse(bad)
		if got, ok := cimdFetchURL(u); ok {
			t.Errorf("cimdFetchURL(%q) accepted as %q", bad, got)
		}
	}
}

// The production fetch client refuses loopback (and every other non-public
// address) at dial time.
func TestCIMD_PrivateAddressRefusedAtDial(t *testing.T) {
	c := newCIMDServer(t)
	c.docs["/good"] = writeDoc(map[string]any{"client_name": "Claude", "redirect_uris": []string{DefaultRedirectURI}})
	pool := c.ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	guarded := newFetchClient(dialGuard, pool)
	_, err := fetchCIMD(context.Background(), guarded, c.url("/good"), c.url("/good"))
	if err == nil || !strings.Contains(err.Error(), "non-public address") {
		t.Fatalf("loopback fetch: %v", err)
	}
	// A hostname is resolved first; the guard sees the address dialled.
	u, _ := url.Parse(c.url("/good"))
	byName := "https://localhost:" + u.Port() + "/good"
	if _, err := fetchCIMD(context.Background(), guarded, byName, byName); err == nil || !strings.Contains(err.Error(), "non-public address") {
		t.Fatalf("localhost fetch: %v", err)
	}
	if c.hits.Load() != 0 {
		t.Fatal("the guarded client reached the server")
	}
}

func TestDialGuard(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:443", "[::1]:443", "10.0.0.1:443", "172.16.5.4:443", "192.168.1.1:443", "169.254.169.254:80",
		"0.0.0.0:443", "[::]:443", "224.0.0.1:443", "[ff02::1]:443", "[fe80::1]:443", "[fc00::1]:443",
		"100.64.0.1:443", "[::ffff:127.0.0.1]:443", "[::ffff:10.0.0.1]:443", "[64:ff9b::a00:1]:443", "255.255.255.255:443",
		"example.com:443",
	} {
		if err := dialGuard("tcp", addr, nil); err == nil {
			t.Errorf("%s allowed", addr)
		}
	}
	for _, addr := range []string{"160.79.104.10:443", "[2607:6bc0::10]:443", "1.1.1.1:443"} {
		if err := dialGuard("tcp", addr, nil); err != nil {
			t.Errorf("%s refused: %v", addr, err)
		}
	}
	if err := dialGuard("udp", "1.1.1.1:53", nil); err == nil {
		t.Error("udp allowed")
	}
	if publicAddr(netip.MustParseAddr("192.0.2.1")) {
		t.Error("documentation range allowed")
	}
}

// End to end at the authorization endpoint: a CIMD client is fetched once,
// cached, and its redirect must also be in the allowlist.
func TestCIMD_Authorize(t *testing.T) {
	c := newCIMDServer(t)
	const anthropic = "https://claude.ai"
	c.docs["/client"] = writeDoc(map[string]any{"client_id": anthropic + "/client", "client_name": "Claude", "redirect_uris": []string{DefaultRedirectURI, "https://evil.test/cb"}})
	c.docs["/foreign"] = writeDoc(map[string]any{"client_id": anthropic + "/foreign", "client_name": "Evil", "redirect_uris": []string{"https://evil.test/cb"}})
	// Requests for claude.ai are served by the test server.
	target, _ := url.Parse(c.ts.URL)
	inner := c.trust.Transport
	routed := &http.Client{CheckRedirect: c.trust.CheckRedirect, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "claude.ai" {
			t.Errorf("fetched a non-Anthropic host: %s", r.URL.Host)
		}
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return inner.RoundTrip(r)
	})}
	f := newFixture(t, func(cfg *Config) { cfg.HTTPClient = routed })

	// A metadata document on any other host is refused without a request.
	resp, _ := f.get(PathAuthorize + "?" + authParams(c.url("/client")).Encode())
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || c.hits.Load() != 0 {
		t.Fatalf("foreign metadata host: %d %q hits=%d", resp.StatusCode, resp.Header.Get("Location"), c.hits.Load())
	}

	p := authParams(anthropic + "/client")
	code, _ := f.startAuthorize(p)
	if pend := f.srv.Pending(); len(pend) != 1 || pend[0].Code != code || pend[0].ClientName != "Claude" || pend[0].ClientKind != "cimd" {
		t.Fatalf("pending: %+v", pend)
	}
	f.startAuthorize(p)
	if c.hits.Load() != 1 {
		t.Fatalf("metadata fetched %d times, want 1 (cached)", c.hits.Load())
	}
	// In the document but not in the allowlist: an error page, no redirect.
	p.Set("redirect_uri", "https://evil.test/cb")
	resp, _ = f.get(PathAuthorize + "?" + p.Encode())
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("foreign redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// In the allowlist but not in the document: the same.
	p = authParams(anthropic + "/foreign")
	resp, _ = f.get(PathAuthorize + "?" + p.Encode())
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("redirect not in document: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// A bad document is an error page too.
	resp, _ = f.get(PathAuthorize + "?" + authParams(anthropic+"/missing").Encode())
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("missing document: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
