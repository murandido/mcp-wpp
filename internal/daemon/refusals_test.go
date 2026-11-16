package daemon

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
)

func TestRouteClass(t *testing.T) {
	for path, want := range map[string]string{
		"/mcp": RouteMCP, "/mcp/x": RouteMCP, "/admin/tokens": RouteAdmin, "/admin": RouteAdmin,
		"/oauth/token": RouteOAuth, "/.well-known/oauth-authorization-server": RouteOAuth,
		"/ui/login": RouteLogin, "/healthz": RouteProbe, "/readyz": RouteProbe,
		"/pair": RoutePage, "/pair/qr.png": RoutePage, "/access/chat": RoutePage, "/outbox": RoutePage,
		"/": RouteUnknown, "/447700900001@s.whatsapp.net": RouteUnknown, "/mcpx": RouteUnknown,
	} {
		if got := routeClass(path); got != want {
			t.Errorf("routeClass(%q) = %q, want %q", path, got, want)
		}
		if !slices.Contains(RouteClasses, routeClass(path)) {
			t.Errorf("routeClass(%q) outside RouteClasses", path)
		}
	}
}

func TestObserveRefusals_CountsGuardsAndLimits(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	base := startGuardedServer(t, Config{AuthFailLimit: 2, Refused: func(code int, route string) {
		mu.Lock()
		seen[http.StatusText(code)+" "+route]++
		mu.Unlock()
	}})
	c := &http.Client{}
	get := func(path, host, tok string) {
		r, _ := http.NewRequest(http.MethodGet, base+path, nil)
		if host != "" {
			r.Host = host
		}
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		status(t, c, r)
	}
	get("/healthz", "", "")                 // 200: not counted
	get("/pair", "", testToken)             // 200: not counted
	get("/pair", "evil.example", testToken) // 403 page
	get("/mcp", "", "bad")                  // 401 mcp
	get("/admin/tokens", "", "bad")         // 401 admin, now locked out
	get("/admin/tokens", "", testToken)     // 429 admin
	want := map[string]int{
		"Forbidden page":          1,
		"Unauthorized mcp":        1,
		"Unauthorized admin":      1,
		"Too Many Requests admin": 1,
	}
	// The hook runs once the handler returns, which can be just after the
	// client has read the response.
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if len(seen) != len(want) {
			return false
		}
		for k, v := range want {
			if seen[k] != v {
				return false
			}
		}
		return true
	}, "refusals counted")
}

func TestRefusalRecorder_ForwardsFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	h := observeRefusals(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("recorder hides http.Flusher")
		}
		_, _ = w.Write([]byte("x"))
		f.Flush()
	}), func(int, string) { t.Fatal("200 reported as a refusal") })
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if !rec.Flushed {
		t.Fatal("flush not forwarded")
	}
}
