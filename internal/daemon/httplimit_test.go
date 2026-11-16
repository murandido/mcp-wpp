package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/store"
)

type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time          { return c.t }
func (c *stepClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newStepClock() *stepClock { return &stepClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }

// fakeVerifier accepts a fixed set of client tokens.
type fakeVerifier map[string]store.APIToken

func (f fakeVerifier) VerifyAPIToken(_ context.Context, plain string) (store.APIToken, error) {
	if t, ok := f[plain]; ok {
		return t, nil
	}
	return store.APIToken{}, errors.New("invalid token")
}

func clientTok(n int) string { return fmt.Sprintf("%s%064x", auth.TokenPrefix, n) }

func TestAuthFailures_LocksOutAfterLimitAndCoolsDown(t *testing.T) {
	clk := newStepClock()
	a := newAuthFailures(3, time.Minute, 5*time.Minute)
	a.now = clk.now
	for i := 0; i < 2; i++ {
		a.fail("198.51.100.1")
	}
	if _, b := a.blocked("198.51.100.1"); b {
		t.Fatal("blocked below the limit")
	}
	// The window resets: two old failures plus two new ones stay below 3.
	clk.advance(61 * time.Second)
	a.fail("198.51.100.1")
	a.fail("198.51.100.1")
	if _, b := a.blocked("198.51.100.1"); b {
		t.Fatal("failures from an earlier window still counted")
	}
	a.fail("198.51.100.1")
	left, b := a.blocked("198.51.100.1")
	if !b || left != 5*time.Minute {
		t.Fatalf("blocked = %v, %v; want true, 5m", b, left)
	}
	if _, b := a.blocked("198.51.100.2"); b {
		t.Fatal("another IP is blocked")
	}
	// More failures during the cool-down do not extend it.
	clk.advance(time.Minute)
	a.fail("198.51.100.1")
	if left, _ := a.blocked("198.51.100.1"); left != 4*time.Minute {
		t.Fatalf("left = %v, want 4m", left)
	}
	clk.advance(4 * time.Minute)
	if _, b := a.blocked("198.51.100.1"); b {
		t.Fatal("still blocked after the cool-down")
	}
	if a.size() != 0 {
		t.Fatalf("entry kept after the cool-down: %d", a.size())
	}
}

func TestAuthFailures_BoundedMemory(t *testing.T) {
	clk := newStepClock()
	a := newAuthFailures(2, time.Minute, time.Minute)
	a.now = clk.now
	a.fail("203.0.113.1")
	a.fail("203.0.113.1") // blocked
	for i := 0; i < maxAuthFailKeys*2; i++ {
		clk.advance(time.Millisecond)
		a.fail(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if n := a.size(); n > maxAuthFailKeys {
		t.Fatalf("tracked %d keys, cap %d", n, maxAuthFailKeys)
	}
	if newAuthFailures(0, 0, 0) != nil {
		t.Fatal("limit 0 must disable the lock-out")
	}
	var off *authFailures
	off.fail("x")
	if _, b := off.blocked("x"); b {
		t.Fatal("nil limiter blocks")
	}
}

func TestIdentityLimiter_TokenBucket(t *testing.T) {
	clk := newStepClock()
	l := newIdentityLimiter(60) // 1/s, burst 30
	l.now = clk.now
	for i := 0; i < 30; i++ {
		if _, ok := l.allow("a"); !ok {
			t.Fatalf("request %d of the burst refused", i)
		}
	}
	wait, ok := l.allow("a")
	if ok || wait != time.Second {
		t.Fatalf("after burst: ok=%v wait=%v, want refused, 1s", ok, wait)
	}
	if _, ok := l.allow("b"); !ok {
		t.Fatal("another identity shares the bucket")
	}
	clk.advance(2 * time.Second)
	for i := 0; i < 2; i++ {
		if _, ok := l.allow("a"); !ok {
			t.Fatalf("refill %d refused", i)
		}
	}
	if _, ok := l.allow("a"); ok {
		t.Fatal("refilled more than the elapsed time allows")
	}
	if newIdentityLimiter(0) != nil {
		t.Fatal("rate 0 must disable the limiter")
	}
}

func TestIdentityLimiter_BoundedMemory(t *testing.T) {
	clk := newStepClock()
	l := newIdentityLimiter(10)
	l.now = clk.now
	for i := 0; i < maxRateKeys*3; i++ {
		l.allow(fmt.Sprintf("token:%d", i))
	}
	if n := l.size(); n > maxRateKeys {
		t.Fatalf("tracked %d keys, cap %d", n, maxRateKeys)
	}
}

func TestRetryAfter(t *testing.T) {
	for d, want := range map[time.Duration]string{0: "1", time.Millisecond: "1", 1500 * time.Millisecond: "2", 5 * time.Minute: "300"} {
		if got := retryAfter(d); got != want {
			t.Errorf("retryAfter(%v) = %s, want %s", d, got, want)
		}
	}
}

// limitedHandler composes the guards the way Server.Run does, with clocks
// the test controls.
func limitedHandler(t *testing.T, clk *stepClock, failLimit, rate int) http.Handler {
	t.Helper()
	fails := newAuthFailures(failLimit, time.Minute, 5*time.Minute)
	if fails != nil {
		fails.now = clk.now
	}
	lim := newIdentityLimiter(rate)
	if lim != nil {
		lim.now = clk.now
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	verifier := fakeVerifier{
		clientTok(1): {ID: 1, Name: "one", Scopes: []string{auth.ScopeRead}},
		clientTok(2): {ID: 2, Name: "two", Scopes: []string{auth.ScopeRead}},
	}
	return authGuard(mcpRateLimit(ok, lim), testToken, newUIAuth(), verifier, nil, fails)
}

func do(h http.Handler, path, remote, authz string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	r.RemoteAddr = remote
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthGuard_FailedBearerLockOut(t *testing.T) {
	clk := newStepClock()
	h := limitedHandler(t, clk, 3, 0)
	const attacker, other = "203.0.113.7:1000", "203.0.113.8:1000"
	for i := 0; i < 3; i++ {
		if w := do(h, "/mcp", attacker, "Bearer wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d, want 401", i, w.Code)
		}
	}
	// Locked out: even the right token gets 429, so guesses get no answer.
	w := do(h, "/admin/tokens", attacker, "Bearer "+testToken)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "300" {
		t.Fatalf("locked out: %d Retry-After=%q, want 429 300", w.Code, w.Header().Get("Retry-After"))
	}
	if w := do(h, "/mcp", attacker, "Bearer "+clientTok(1)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("client token during lock-out: %d", w.Code)
	}
	// Public routes and other clients are unaffected.
	if w := do(h, "/healthz", attacker, ""); w.Code != http.StatusOK {
		t.Fatalf("public route during lock-out: %d", w.Code)
	}
	if w := do(h, "/mcp", other, "Bearer "+clientTok(1)); w.Code != http.StatusOK {
		t.Fatalf("other client: %d", w.Code)
	}
	clk.advance(5 * time.Minute)
	if w := do(h, "/mcp", attacker, "Bearer "+testToken); w.Code != http.StatusOK {
		t.Fatalf("after cool-down: %d", w.Code)
	}
}

func TestAuthGuard_LockOutIgnoresUncredentialedAndSuccessful(t *testing.T) {
	clk := newStepClock()
	h := limitedHandler(t, clk, 2, 0)
	const ip = "198.51.100.20:1"
	// OAuth discovery: an MCP client first calls /mcp with no credentials.
	for i := 0; i < 10; i++ {
		if w := do(h, "/mcp", ip, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("no credentials: %d", w.Code)
		}
	}
	for i := 0; i < 10; i++ {
		if w := do(h, "/mcp", ip, "Bearer "+clientTok(1)); w.Code != http.StatusOK {
			t.Fatalf("valid token: %d", w.Code)
		}
	}
	do(h, "/mcp", ip, "Bearer wrong")
	if w := do(h, "/mcp", ip, "Bearer "+clientTok(1)); w.Code != http.StatusOK {
		t.Fatalf("one failure locked out: %d", w.Code)
	}
}

func TestAuthGuard_LockOutUsesForwardedClientBehindProxy(t *testing.T) {
	clk := newStepClock()
	h := limitedHandler(t, clk, 2, 0)
	proxied := func(client, authz string) int {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.RemoteAddr = "127.0.0.1:5555" // Caddy on the same host
		r.Header.Set("X-Forwarded-For", client)
		r.Header.Set("Authorization", authz)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	proxied("203.0.113.50", "Bearer bad")
	proxied("203.0.113.50", "Bearer bad")
	if c := proxied("203.0.113.50", "Bearer "+testToken); c != http.StatusTooManyRequests {
		t.Fatalf("attacker behind proxy: %d", c)
	}
	if c := proxied("203.0.113.51", "Bearer "+testToken); c != http.StatusOK {
		t.Fatalf("another client behind the same proxy: %d", c)
	}
}

func TestMCPRateLimit_PerIdentity(t *testing.T) {
	clk := newStepClock()
	h := limitedHandler(t, clk, 0, 4) // burst 2
	const ip = "198.51.100.30:1"
	for i := 0; i < 2; i++ {
		if w := do(h, "/mcp", ip, "Bearer "+clientTok(1)); w.Code != http.StatusOK {
			t.Fatalf("burst %d: %d", i, w.Code)
		}
	}
	w := do(h, "/mcp", ip, "Bearer "+clientTok(1))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the rate: %d", w.Code)
	}
	if w.Header().Get("Retry-After") != "15" {
		t.Fatalf("Retry-After = %q, want 15", w.Header().Get("Retry-After"))
	}
	var body struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.JSONRPC != "2.0" || body.Error.Code != -32000 || body.ID != nil {
		t.Fatalf("body %s (%v)", w.Body.String(), err)
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("content type %q", w.Header().Get("Content-Type"))
	}
	// Another token and the operator are not affected.
	if w := do(h, "/mcp", ip, "Bearer "+clientTok(2)); w.Code != http.StatusOK {
		t.Fatalf("other token: %d", w.Code)
	}
	for i := 0; i < 20; i++ {
		if w := do(h, "/mcp", ip, "Bearer "+testToken); w.Code != http.StatusOK {
			t.Fatalf("operator %d: %d", i, w.Code)
		}
	}
	clk.advance(15 * time.Second)
	if w := do(h, "/mcp", ip, "Bearer "+clientTok(1)); w.Code != http.StatusOK {
		t.Fatalf("after refill: %d", w.Code)
	}
}

func TestServer_HTTPLimitsWired(t *testing.T) {
	base := startGuardedServer(t, Config{AuthFailLimit: 2})
	c := &http.Client{}
	req := func(tok string) int {
		r, _ := http.NewRequest(http.MethodGet, base+"/admin/tokens", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return status(t, c, r)
	}
	req("nope")
	req("nope")
	if got := req(testToken); got != http.StatusTooManyRequests {
		t.Fatalf("after two failures: %d, want 429", got)
	}
}
