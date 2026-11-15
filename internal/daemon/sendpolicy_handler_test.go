package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/murandido/mcp-wpp/internal/store"
)

func TestAccessAPI_SendPolicy(t *testing.T) {
	base, st := accessDaemon(t)
	ctx := context.Background()
	if code, _ := jsonCall(t, rawClient, http.MethodPost, base+"/admin/access/send", `{"jid":"`+accAlice+`","send":"direct"}`); code != http.StatusUnauthorized {
		t.Fatalf("send policy without token: %d", code)
	}
	if code, _ := jsonCall(t, http.DefaultClient, http.MethodPost, base+"/admin/access/send", `{"jid":"`+accAlice+`","send":"direct"}`); code != http.StatusOK {
		t.Fatalf("set send policy: %d", code)
	}
	if p, _ := st.ChatSendPolicy(ctx, accAlice); p != store.SendDirect {
		t.Fatalf("policy = %q", p)
	}
	if ok, _ := st.ChatAllowed(ctx, accAlice); ok {
		t.Fatal("a send policy must not make the chat visible")
	}
	if code, _ := jsonCall(t, http.DefaultClient, http.MethodPost, base+"/admin/access/send", `{"jid":"`+accAlice+`","send":"always"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid send policy: %d", code)
	}
	_, out := jsonCall(t, http.DefaultClient, http.MethodGet, base+"/admin/access?query=Alice", "")
	chats, _ := out["chats"].([]any)
	if len(chats) != 1 || chats[0].(map[string]any)["send"] != "direct" {
		t.Fatalf("list does not report the send policy: %v", out)
	}
}

func TestAccessPage_SendPolicyNeedsCSRF(t *testing.T) {
	base, st := accessDaemon(t)
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Transport: rawClient.Transport, Jar: jar}
	req, _ := http.NewRequest(http.MethodGet, base+mintLogin(t, base, "/access"), nil)
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), `action="/access/send"`) {
		t.Fatal("/access has no send policy control")
	}
	resp, err = browser.PostForm(base+"/access/send", url.Values{"jid": {accBob}, "send": {"none"}})
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
	resp, err = browser.PostForm(base+"/access/send", url.Values{"csrf_token": {m[1]}, "jid": {accBob}, "send": {"none"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if p, _ := st.ChatSendPolicy(context.Background(), accBob); p != store.SendNone {
		t.Fatalf("form post did not set the policy (status %d): %q", resp.StatusCode, p)
	}
}
