package daemon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

const accGroup = "120363000000000001@g.us"

// pageSession is a logged-in browser on /access that does not follow
// redirects, so tests can check where a form sends it.
type pageSession struct {
	t    *testing.T
	base string
	c    *http.Client
}

func accessPageDaemon(t *testing.T, extra map[string]string) (*pageSession, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	chats := map[string]string{accAlice: "Alice", accBob: "Bob", accGroup: "Família Ávila"}
	for k, v := range extra {
		chats[k] = v
	}
	now := time.Now()
	for jid, name := range chats {
		if err := st.StoreChat(jid, name, now); err != nil {
			t.Fatal(err)
		}
	}
	base := startGuardedServer(t, Config{Access: st, Audit: st})
	jar, _ := cookiejar.New(nil)
	s := &pageSession{t: t, base: base, c: &http.Client{
		Transport:     rawClient.Transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	// The login link sets the session cookie and redirects to /access.
	if code, _, _ := s.get(mintLogin(t, base, "/access")); code != http.StatusSeeOther && code != http.StatusFound && code != http.StatusOK {
		t.Fatalf("login: %d", code)
	}
	return s, st
}

func (s *pageSession) get(path string) (int, string, http.Header) {
	s.t.Helper()
	resp, err := s.c.Get(s.base + path)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// post sends a form and returns the status, the redirect target and body.
func (s *pageSession) post(path string, v url.Values) (int, string, string) {
	s.t.Helper()
	resp, err := s.c.PostForm(s.base+path, v)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), string(b)
}

// token loads path and returns a fresh CSRF token from it.
func (s *pageSession) token(path string) string {
	s.t.Helper()
	code, body, _ := s.get(path)
	m := csrfInput.FindStringSubmatch(body)
	if code != http.StatusOK || m == nil {
		s.t.Fatalf("no CSRF token on %s (status %d)", path, code)
	}
	return m[1]
}

func TestAccessPage_SearchFilterPagination(t *testing.T) {
	extra := map[string]string{}
	for i := 0; i < 120; i++ {
		extra[fmt.Sprintf("4477009%05d@s.whatsapp.net", i)] = fmt.Sprintf("Contact %03d", i)
	}
	s, _ := accessPageDaemon(t, extra)

	code, body, hdr := s.get("/access")
	if code != http.StatusOK || !strings.Contains(body, "Showing 1&ndash;50 of 123") || !strings.Contains(body, "Show more") {
		t.Fatalf("first page: %d\n%s", code, body)
	}
	if n := strings.Count(body, `name="chat" value=`); n != 50 {
		t.Fatalf("first page lists %d chats, want 50", n)
	}
	// Every inline style and script carries this response's nonce.
	csp := hdr.Get("Content-Security-Policy")
	m := regexp.MustCompile(`'nonce-([0-9a-f]+)'`).FindStringSubmatch(csp)
	if m == nil || !strings.Contains(body, `<script nonce="`+m[1]+`">`) || !strings.Contains(body, `<style nonce="`+m[1]+`">`) || !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("CSP %q does not match the page", csp)
	}

	if _, body, _ = s.get("/access?page=3"); !strings.Contains(body, "Showing 101&ndash;123 of 123") || strings.Contains(body, "Show more") {
		t.Fatalf("last page:\n%s", body)
	}
	// Past the end falls back to the last page; nonsense falls back to page 1.
	if _, body, _ = s.get("/access?page=999"); !strings.Contains(body, "of 123") {
		t.Fatal("page past the end shows nothing")
	}
	if code, body, _ = s.get("/access?page=-4&filter=bogus"); code != http.StatusOK || !strings.Contains(body, "Showing 1&ndash;50 of 123") {
		t.Fatalf("invalid params: %d", code)
	}

	for _, tc := range []struct {
		query, want, notWant string
	}{
		{"?q=FAMILIA+avila", "Família Ávila", "Contact 001"},
		{"?q=" + url.QueryEscape("+44 7700-000002"), "Bob", "Alice"},
		{"?q=contact+11", "Contact 110", "Alice"},
		{"?filter=groups", "Família Ávila", "Bob"},
		{"?filter=direct&q=b", "Bob", "Família"},
		{"?filter=allowed", "No chats in this filter", "Alice"},
	} {
		if _, body, _ := s.get("/access" + tc.query); !strings.Contains(body, tc.want) || strings.Contains(body, tc.notWant) {
			t.Errorf("%s: want %q and not %q", tc.query, tc.want, tc.notWant)
		}
	}
	// An oversized query is cut, not an error; links keep the list state.
	if code, _, _ = s.get("/access?q=" + strings.Repeat("x", 5000)); code != http.StatusOK {
		t.Fatalf("long query: %d", code)
	}
	if _, body, _ = s.get("/access?q=contact&filter=direct"); !strings.Contains(body, `href="/access?filter=direct&amp;page=2&amp;q=contact"`) {
		t.Fatal("next link does not keep the search and filter")
	}
}

func TestAccessPage_BulkAllowAndReset(t *testing.T) {
	s, st := accessPageDaemon(t, nil)
	ctx := context.Background()
	sel := url.Values{"chat": {accAlice, accBob}, "state": {"allowed"}, "filter": {"direct"}}

	// Without a CSRF token neither step does anything.
	if code, _, _ := s.post("/access/bulk/review", sel); code != http.StatusForbidden {
		t.Fatalf("review without CSRF: %d", code)
	}
	apply := url.Values{"jid": {accAlice, accBob}, "state": {"allowed"}, "confirm": {"yes"}}
	if code, _, _ := s.post("/access/bulk", apply); code != http.StatusForbidden {
		t.Fatalf("apply without CSRF: %d", code)
	}

	// Review shows the count and changes nothing.
	sel.Set("csrf_token", s.token("/access"))
	code, _, body := s.post("/access/bulk/review", sel)
	if code != http.StatusOK || !strings.Contains(body, "Allow 2 chat(s)?") || strings.Count(body, `name="jid"`) != 2 {
		t.Fatalf("review: %d\n%s", code, body)
	}
	if ok, _ := st.ChatAllowed(ctx, accAlice); ok {
		t.Fatal("review must not change access")
	}

	// Applying needs the confirmation.
	m := csrfInput.FindStringSubmatch(body)
	noConfirm := url.Values{"csrf_token": {m[1]}, "jid": {accAlice}, "state": {"allowed"}}
	if _, loc, _ := s.post("/access/bulk", noConfirm); !strings.Contains(loc, "error=") {
		t.Fatalf("apply without confirm: %q", loc)
	}
	if ok, _ := st.ChatAllowed(ctx, accAlice); ok {
		t.Fatal("unconfirmed bulk action changed access")
	}

	apply.Set("csrf_token", s.token("/access"))
	apply.Set("filter", "direct")
	code, loc, _ := s.post("/access/bulk", apply)
	if code != http.StatusSeeOther || loc != "/access?done=allowed&filter=direct&n=2" {
		t.Fatalf("apply: %d %q", code, loc)
	}
	for _, j := range []string{accAlice, accBob} {
		if ok, _ := st.ChatAllowed(ctx, j); !ok {
			t.Fatalf("%s not allowed", j)
		}
	}
	if _, body, _ := s.get(loc); !strings.Contains(body, "Allowed 2 chat(s).") {
		t.Fatal("no notice after the bulk action")
	}

	// The audit has one entry per chat, like single changes.
	entries, err := st.ListAudit(ctx, store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		if e.Action == "POST /access/bulk" && e.Outcome == store.OutcomeOK {
			got[e.ChatJID] = e.Detail
		}
	}
	if len(got) != 2 || got[accAlice] != "state=allowed batch=2 via=browser" || got[accBob] == "" {
		t.Fatalf("bulk audit: %v", got)
	}

	// Reset goes through the same two steps.
	reset := url.Values{"csrf_token": {s.token("/access")}, "jid": {accBob}, "state": {"reset"}, "confirm": {"yes"}}
	if _, loc, _ := s.post("/access/bulk", reset); loc != "/access?done=reset&n=1" {
		t.Fatalf("reset: %q", loc)
	}
	if ok, _ := st.ChatAllowed(ctx, accBob); ok {
		t.Fatal("reset did not hide the chat")
	}

	// Unknown chats are left out; a selection of only unknown chats fails.
	bogus := url.Values{"csrf_token": {s.token("/access")}, "chat": {"999@s.whatsapp.net"}, "state": {"allowed"}}
	if _, loc, _ := s.post("/access/bulk/review", bogus); !strings.Contains(loc, "error=") {
		t.Fatalf("unknown chats: %q", loc)
	}
	// Denying in bulk is not offered.
	deny := url.Values{"csrf_token": {s.token("/access")}, "chat": {accAlice}, "state": {"denied"}}
	if _, loc, _ := s.post("/access/bulk/review", deny); !strings.Contains(loc, "error=") {
		t.Fatalf("bulk deny: %q", loc)
	}
}

func TestAccessPage_BulkCap(t *testing.T) {
	extra := map[string]string{}
	var jids []string
	for i := 0; i <= maxBulkChats; i++ {
		jid := fmt.Sprintf("4477008%05d@s.whatsapp.net", i)
		extra[jid] = fmt.Sprintf("Member %03d", i)
		jids = append(jids, jid)
	}
	s, st := accessPageDaemon(t, extra)
	for _, path := range []string{"/access/bulk/review", "/access/bulk"} {
		field := "chat"
		if path == "/access/bulk" {
			field = "jid"
		}
		v := url.Values{"csrf_token": {s.token("/access")}, field: jids, "state": {"allowed"}, "confirm": {"yes"}}
		if _, loc, _ := s.post(path, v); !strings.Contains(loc, "error=") || !strings.Contains(loc, "at+most+100") {
			t.Fatalf("%s with %d chats: %q", path, len(jids), loc)
		}
	}
	if p, _ := st.ListAccessPage(context.Background(), store.AccessListOptions{Filter: store.AccessFilterAllowed}); p.Total != 0 {
		t.Fatalf("an oversized batch allowed %d chats", p.Total)
	}
}

func TestAccessPage_SendPolicyChangeIsAudited(t *testing.T) {
	s, st := accessPageDaemon(t, nil)
	ctx := context.Background()
	v := url.Values{"csrf_token": {s.token("/access")}, "jid": {accAlice}, "send": {"direct"}, "q": {"ali"}}
	if code, loc, _ := s.post("/access/send", v); code != http.StatusSeeOther || loc != "/access?q=ali" {
		t.Fatalf("set: %d %q", code, loc)
	}
	if p, _ := st.ChatSendPolicy(ctx, accAlice); p != store.SendDirect {
		t.Fatalf("policy = %q", p)
	}
	if _, body, _ := s.get("/access?q=ali"); !strings.Contains(body, `<option value="direct" selected>`) {
		t.Fatal("page does not show the new policy")
	}
	v = url.Values{"csrf_token": {s.token("/access")}, "jid": {accAlice}, "send": {"always"}}
	if _, loc, _ := s.post("/access/send", v); !strings.Contains(loc, "error=") {
		t.Fatalf("invalid policy: %q", loc)
	}
	entries, _ := st.ListAudit(ctx, store.AuditFilter{ChatJID: accAlice}) // newest first
	var details []string
	for _, e := range entries {
		if e.Action == "POST /access/send" {
			details = append(details, e.Outcome+" "+e.Detail)
		}
	}
	if len(details) != 2 || details[0] != "error send=always via=browser" || details[1] != "ok send=direct via=browser" {
		t.Fatalf("send policy audit: %v", details)
	}
}

func TestAccessPage_ModeChangeNeedsConfirmation(t *testing.T) {
	s, st := accessPageDaemon(t, nil)
	ctx := context.Background()
	if err := st.SetChatAccess(ctx, accBob, store.AccessDenied, ""); err != nil {
		t.Fatal(err)
	}
	if _, body, _ := s.get("/access"); !strings.Contains(body, `href="/access/mode?mode=all"`) || strings.Contains(body, `action="/access/mode"`) {
		t.Fatal("the list page must link to the confirmation, not post the mode")
	}
	// A direct post without the confirmation changes nothing.
	v := url.Values{"csrf_token": {s.token("/access")}, "mode": {"all"}}
	if _, loc, _ := s.post("/access/mode", v); !strings.Contains(loc, "error=") {
		t.Fatalf("unconfirmed mode post: %q", loc)
	}
	if m, _ := st.AccessMode(ctx); m != store.AccessAllowlist {
		t.Fatalf("mode changed without confirmation: %s", m)
	}

	code, body, _ := s.get("/access/mode?mode=all")
	if code != http.StatusOK || !strings.Contains(body, "The AI will see <strong>2</strong> of 3 cached chats") || !strings.Contains(body, "Yes, switch to all") {
		t.Fatalf("confirmation page: %d\n%s", code, body)
	}
	if m, _ := st.AccessMode(ctx); m != store.AccessAllowlist {
		t.Fatal("the confirmation page changed the mode")
	}
	m := csrfInput.FindStringSubmatch(body)
	v = url.Values{"csrf_token": {m[1]}, "mode": {"all"}, "confirm": {"yes"}}
	if code, loc, _ := s.post("/access/mode", v); code != http.StatusSeeOther || loc != "/access" {
		t.Fatalf("confirmed: %d %q", code, loc)
	}
	if m, _ := st.AccessMode(ctx); m != store.AccessAll {
		t.Fatalf("mode = %s", m)
	}
	if _, body, _ := s.get("/access"); !strings.Contains(body, "ALL chats are visible") {
		t.Fatal("page does not show mode all")
	}
	// Asking to confirm the current mode or a bogus one goes back.
	for _, q := range []string{"all", "everything"} {
		if code, _, _ := s.get("/access/mode?mode=" + q); code != http.StatusSeeOther {
			t.Fatalf("confirm %q: %d", q, code)
		}
	}
	entries, _ := st.ListAudit(ctx, store.AuditFilter{}) // newest first
	var modes []string
	for _, e := range entries {
		if e.Action == "POST /access/mode" {
			modes = append(modes, e.Outcome+" "+e.Detail)
		}
	}
	if len(modes) != 2 || modes[0] != "ok mode=all via=browser" || modes[1] != "error mode=all via=browser" {
		t.Fatalf("mode audit: %v", modes)
	}
}

func TestAccessPage_EscapesChatNames(t *testing.T) {
	const evil = `<script>alert("x")</script><img src=x onerror=alert(1)>`
	const evilJID = "447700000099@s.whatsapp.net"
	s, st := accessPageDaemon(t, map[string]string{evilJID: evil})
	if _, err := st.CreateAccessRequest(context.Background(), "alert", `<b>reason</b>`); err != nil {
		t.Fatal(err)
	}
	check := func(where, body string) {
		t.Helper()
		if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") || strings.Contains(body, "<b>reason") {
			t.Fatalf("%s renders a chat name or reason unescaped", where)
		}
		if !strings.Contains(body, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;") {
			t.Fatalf("%s does not show the escaped name", where)
		}
	}
	_, body, _ := s.get("/access?q=alert")
	check("list", body)
	if strings.Count(body, "&lt;script&gt;alert") < 2 { // in the list and in the request's matches
		t.Fatal("the request's match is not shown")
	}
	v := url.Values{"csrf_token": {s.token("/access")}, "chat": {evilJID}, "state": {"allowed"}}
	_, _, body = s.post("/access/bulk/review", v)
	check("bulk review", body)
	// The error banner echoes text from the URL, escaped and bounded.
	_, body, _ = s.get("/access?error=" + url.QueryEscape(evil+strings.Repeat("y", 1000)))
	if strings.Contains(body, "<img src=x") || strings.Contains(body, strings.Repeat("y", maxShownError)) {
		t.Fatal("error banner is not escaped or not bounded")
	}
	if _, body, _ = s.get("/access?done=" + url.QueryEscape(evil) + "&n=3"); strings.Contains(body, `class="card ok"`) {
		t.Fatal("notice accepts arbitrary codes")
	}
}

func TestAccessPage_PendingRequestsOnTop(t *testing.T) {
	s, st := accessPageDaemon(t, nil)
	ctx := context.Background()
	id, err := st.CreateAccessRequest(ctx, "Alice", "summarise her messages")
	if err != nil {
		t.Fatal(err)
	}
	other, err := st.CreateAccessRequest(ctx, "Bob", "")
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := s.get("/access")
	req, mode := strings.Index(body, "Pending requests from the AI (2)"), strings.Index(body, "<h2>Mode</h2>")
	if req < 0 || mode < 0 || req > mode || !strings.Contains(body, "summarise her messages") {
		t.Fatalf("pending requests are not shown first (%d, %d)", req, mode)
	}
	if _, body, _ = s.get("/access?filter=pending"); !strings.Contains(body, "Showing 1&ndash;2 of 2") {
		t.Fatal("pending filter does not list the matched chats")
	}

	v := url.Values{"csrf_token": {s.token("/access")}, "decision": {"approve"}, "jid": {accAlice}}
	if code, loc, _ := s.post(fmt.Sprintf("/access/requests/%d", id), v); code != http.StatusSeeOther || strings.Contains(loc, "error") {
		t.Fatalf("approve: %d %q", code, loc)
	}
	if ok, _ := st.ChatAllowed(ctx, accAlice); !ok {
		t.Fatal("approval did not allow the chat")
	}
	v = url.Values{"csrf_token": {s.token("/access")}, "decision": {"reject"}}
	if _, loc, _ := s.post(fmt.Sprintf("/access/requests/%d", other), v); strings.Contains(loc, "error") {
		t.Fatalf("dismiss: %q", loc)
	}
	if ok, _ := st.ChatAllowed(ctx, accBob); ok {
		t.Fatal("dismissing allowed the chat")
	}
	if _, body, _ = s.get("/access"); strings.Contains(body, "Pending requests from the AI") {
		t.Fatal("decided requests are still pending")
	}
}
