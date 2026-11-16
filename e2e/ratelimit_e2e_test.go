//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

func TestHardening_FailedBearerLockOut(t *testing.T) {
	h := newHarness(t, "-auth-fail-limit", "3")
	call := func(tok string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, "http://"+h.addr+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := call(h.token); resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token before: %d", resp.StatusCode)
	}
	for i := 0; i < 3; i++ {
		if resp := call("not-the-token"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bad token %d: %d", i, resp.StatusCode)
		}
	}
	resp := call(h.token)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("locked out: %d Retry-After=%q, want 429 with Retry-After", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Probes stay public.
	r, err := http.Get("http://" + h.addr + "/healthz") //nolint:gosec // test URL
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("/healthz during lock-out: %d", r.StatusCode)
	}
}
