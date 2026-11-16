package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

// The /notes page shows the current notes escaped, lists earlier versions,
// and reverts or clears only with a CSRF token; changes are audited.
func TestNotesPage_ShowRevertClear(t *testing.T) {
	s, st := accessPageDaemon(t, nil)
	ctx := context.Background()
	if _, err := st.UpdateChatNotes(ctx, accAlice, "Alice: <script>alert(1)</script> likes tea.", "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateChatNotes(ctx, accAlice, "Alice: likes coffee now.", "", 1); err != nil {
		t.Fatal(err)
	}

	// /access links to the notes.
	if _, body, _ := s.get("/access?q=alice"); !strings.Contains(body, `href="/notes?jid=`+url.QueryEscape(accAlice)+`"`) || !strings.Contains(body, "notes v2") {
		t.Fatalf("access page does not link the notes:\n%s", body)
	}

	code, body, _ := s.get("/notes?jid=" + url.QueryEscape(accAlice))
	if code != http.StatusOK || !strings.Contains(body, "Version 2") || !strings.Contains(body, "likes coffee now") ||
		!strings.Contains(body, "&lt;script&gt;") || strings.Contains(body, "<script>alert") {
		t.Fatalf("notes page (%d):\n%s", code, body)
	}

	// Without a CSRF token nothing changes.
	if code, _, _ := s.post("/notes/revert", url.Values{"jid": {accAlice}, "version": {"1"}}); code == http.StatusSeeOther {
		t.Fatal("revert accepted without a CSRF token")
	}
	v := url.Values{"csrf_token": {s.token("/notes?jid=" + url.QueryEscape(accAlice))}, "jid": {accAlice}, "version": {"1"}}
	if code, loc, _ := s.post("/notes/revert", v); code != http.StatusSeeOther || loc != "/notes?done=reverted&jid="+url.QueryEscape(accAlice) {
		t.Fatalf("revert: %d %q", code, loc)
	}
	if n, _ := st.GetChatNotes(ctx, accAlice); n.Version != 3 || !strings.Contains(n.Summary, "likes tea") {
		t.Fatalf("after revert: %+v", n)
	}

	// Clearing needs the confirmation box.
	v = url.Values{"csrf_token": {s.token("/notes?jid=" + url.QueryEscape(accAlice))}, "jid": {accAlice}}
	if _, loc, _ := s.post("/notes/clear", v); !strings.Contains(loc, "error=") {
		t.Fatalf("clear without confirmation: %q", loc)
	}
	v = url.Values{"csrf_token": {s.token("/notes?jid=" + url.QueryEscape(accAlice))}, "jid": {accAlice}, "confirm": {"yes"}}
	if _, loc, _ := s.post("/notes/clear", v); !strings.Contains(loc, "done=cleared") {
		t.Fatalf("clear: %q", loc)
	}
	if n, _ := st.GetChatNotes(ctx, accAlice); n.Version != 0 {
		t.Fatalf("after clear: %+v", n)
	}

	entries, _ := st.ListAudit(ctx, store.AuditFilter{ChatJID: accAlice})
	var actions []string
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "POST /notes/") {
			actions = append(actions, e.Action+" "+e.Outcome)
		}
		if strings.Contains(e.Detail, "coffee") || strings.Contains(e.Detail, "tea") {
			t.Fatalf("audit quotes the notes: %+v", e)
		}
	}
	if strings.Join(actions, ",") != "POST /notes/clear ok,POST /notes/clear error,POST /notes/revert ok,POST /notes/revert error" {
		t.Fatalf("audit: %v", actions)
	}
}

// The admin API serves `wpp-mcp notes` with a bearer token only.
func TestNotesAPI(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.StoreChat(accAlice, "Alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateChatNotes(ctx, accAlice, "v1", "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateChatNotes(ctx, accAlice, "v2", "", 1); err != nil {
		t.Fatal(err)
	}
	base := startGuardedServer(t, Config{Access: st, Audit: st})
	do := func(method, path, body string, bearer bool) (int, string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		if bearer {
			req.Header.Set("Authorization", "Bearer "+testToken)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := rawClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	if code, _ := do(http.MethodGet, "/admin/notes?jid="+url.QueryEscape(accAlice), "", false); code != http.StatusUnauthorized {
		t.Fatalf("without bearer: %d", code)
	}
	code, body := do(http.MethodGet, "/admin/notes?jid="+url.QueryEscape(accAlice), "", true)
	var got struct {
		Notes   store.ChatNotes          `json:"notes"`
		History []store.ChatNotesVersion `json:"history"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || got.Notes.Summary != "v2" || len(got.History) != 1 {
		t.Fatalf("get: %d %s", code, body)
	}
	if code, body := do(http.MethodPost, "/admin/notes/revert", `{"jid":"`+accAlice+`","version":1}`, true); code != http.StatusOK || !strings.Contains(body, `"version":3`) {
		t.Fatalf("revert: %d %s", code, body)
	}
	if code, _ := do(http.MethodPost, "/admin/notes/clear", `{"jid":"`+accAlice+`"}`, true); code != http.StatusOK {
		t.Fatalf("clear: %d", code)
	}
	entries, _ := st.ListAudit(ctx, store.AuditFilter{ChatJID: accAlice})
	if len(entries) != 2 || entries[0].Action != "POST /admin/notes/clear" || entries[1].Detail != "version=1" {
		t.Fatalf("audit: %+v", entries)
	}
}
