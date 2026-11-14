package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

const (
	accAlice = "447700000001@s.whatsapp.net"
	accBob   = "447700000002@s.whatsapp.net"
)

func accessDaemon(t *testing.T) (string, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for jid, name := range map[string]string{accAlice: "Alice", accBob: "Bob"} {
		if err := st.StoreChat(jid, name, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return startGuardedServer(t, Config{Access: st}), st
}

func jsonCall(t *testing.T, c *http.Client, method, u, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAccessAPI_RequiresBearerAndUpdatesPolicy(t *testing.T) {
	base, st := accessDaemon(t)
	ctx := context.Background()

	if code, _ := jsonCall(t, rawClient, http.MethodGet, base+"/admin/access", ""); code != http.StatusUnauthorized {
		t.Fatalf("list without token: %d", code)
	}
	code, out := jsonCall(t, http.DefaultClient, http.MethodGet, base+"/admin/access", "")
	if code != http.StatusOK || out["mode"] != "allowlist" || len(out["chats"].([]any)) != 2 {
		t.Fatalf("list: %d %v", code, out)
	}
	if code, _ := jsonCall(t, http.DefaultClient, http.MethodPost, base+"/admin/access/chat", `{"jid":"`+accAlice+`","state":"allowed"}`); code != http.StatusOK {
		t.Fatalf("allow: %d", code)
	}
	if ok, _ := st.ChatAllowed(ctx, accAlice); !ok {
		t.Fatal("allow did not persist")
	}
	if code, _ := jsonCall(t, http.DefaultClient, http.MethodPost, base+"/admin/access/mode", `{"mode":"bogus"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid mode: %d", code)
	}

	id, err := st.CreateAccessRequest(ctx, "bob", "test")
	if err != nil {
		t.Fatal(err)
	}
	code, out = jsonCall(t, http.DefaultClient, http.MethodGet, base+"/admin/access/requests?status=pending", "")
	if code != http.StatusOK || len(out["requests"].([]any)) != 1 {
		t.Fatalf("requests: %d %v", code, out)
	}
	if code, _ := jsonCall(t, http.DefaultClient, http.MethodPost, base+"/admin/access/requests/"+strconv.FormatInt(id, 10), `{"approve":true}`); code != http.StatusOK {
		t.Fatalf("approve: %d", code)
	}
	if ok, _ := st.ChatAllowed(ctx, accBob); !ok {
		t.Fatal("approval did not allow the chat")
	}
}

var csrfInput = regexp.MustCompile(`name="csrf_token" value="([0-9a-f]+)"`)

func TestAccessPage_CookieAndCSRF(t *testing.T) {
	base, st := accessDaemon(t)
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Transport: rawClient.Transport, Jar: jar}

	req, _ := http.NewRequest(http.MethodGet, base+"/access", nil)
	if got := status(t, browser, req); got != http.StatusUnauthorized {
		t.Fatalf("/access without session: %d", got)
	}
	req, _ = http.NewRequest(http.MethodGet, base+mintLogin(t, base, "/access"), nil)
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "Alice") {
		t.Fatalf("/access after login: %d", resp.StatusCode)
	}

	// A form post without the page's CSRF token is refused.
	resp, err = browser.PostForm(base+"/access/chat", url.Values{"jid": {accBob}, "state": {"allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("post without CSRF: %d", resp.StatusCode)
	}
	m := csrfInput.FindStringSubmatch(string(page))
	if m == nil {
		t.Fatal("no CSRF token on /access")
	}
	resp, err = browser.PostForm(base+"/access/chat", url.Values{"csrf_token": {m[1]}, "jid": {accBob}, "state": {"allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ok, _ := st.ChatAllowed(context.Background(), accBob); !ok {
		t.Fatalf("form post did not allow the chat (status %d)", resp.StatusCode)
	}
	// Tokens are single-use.
	resp, _ = browser.PostForm(base+"/access/chat", url.Values{"csrf_token": {m[1]}, "jid": {accBob}, "state": {"denied"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reused CSRF token: %d", resp.StatusCode)
	}
}
