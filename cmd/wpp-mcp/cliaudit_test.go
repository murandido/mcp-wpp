package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/daemon"
	"github.com/murandido/mcp-wpp/internal/store"
)

const cliTestJID = "447700900001@s.whatsapp.net"

// nullDriver is a paired WhatsApp driver that does nothing.
type nullDriver struct{}

func (nullDriver) IsLoggedIn() bool { return true }
func (nullDriver) StartPairing(context.Context, func(string), func(), func()) error {
	return nil
}
func (nullDriver) Connect(context.Context, func()) error { return nil }
func (nullDriver) Logout(context.Context) error          { return nil }
func (nullDriver) Disconnect()                           {}

func openCLITestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.StoreChat(cliTestJID, "Alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	return st
}

// startAuditDaemon runs a daemon over st and returns an HTTP backend that
// talks to it, as `wpp-mcp access` does when the daemon is up.
func startAuditDaemon(t *testing.T, st *store.Store) *httpAccess {
	t.Helper()
	token := randomTestToken(t)
	d, err := daemon.New(daemon.Config{Addr: "127.0.0.1:0", Driver: nullDriver{}, AuthToken: token, Access: st, Tokens: st, Audit: st})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for d.BoundAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	return &httpAccess{dc: &daemonClient{base: "http://" + d.BoundAddr(), token: token, http: &http.Client{}}}
}

func lastAudit(t *testing.T, st *store.Store) store.AuditEntry {
	t.Helper()
	list, err := st.ListAudit(context.Background(), store.AuditFilter{Limit: 1})
	if err != nil || len(list) != 1 {
		t.Fatalf("audit: %v %v", list, err)
	}
	return list[0]
}

// TestCLIAudit_MatchesDaemon runs each state-changing command through the
// daemon's admin API and through the direct fallback, and checks that both
// leave the same audit entry apart from the actor.
func TestCLIAudit_MatchesDaemon(t *testing.T) {
	t.Setenv("WPP_MCP_AUDIT_DAYS", "")
	ctx := context.Background()
	viaAPI := openCLITestStore(t)
	api := startAuditDaemon(t, viaAPI)
	apiAdmin := &httpAdmin{api: api}
	offline := openCLITestStore(t)
	direct := &directAccess{st: offline, release: func() {}}
	directAdm := &directAdmin{st: offline, release: func() {}}

	reqID := func(st *store.Store) int64 {
		id, err := st.CreateAccessRequest(ctx, "Alice", "summarise")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	newTok := store.NewAPIToken{Name: "laptop", Scopes: []string{"read"}, Chats: []string{cliTestJID}, ExpiresAt: &expires}

	steps := []struct {
		name          string
		http, offline func() error
		wantAction    string
		wantDetail    string
	}{
		{"mode", func() error { return api.setMode(ctx, "all") }, func() error { return direct.setMode(ctx, "all") },
			routeAccessMode, "mode=all"},
		{"allow", func() error { return api.setChat(ctx, cliTestJID, store.AccessAllowed) }, func() error { return direct.setChat(ctx, cliTestJID, store.AccessAllowed) },
			routeAccessChat, "state=" + store.AccessAllowed},
		{"reset", func() error { return api.setChat(ctx, cliTestJID, "reset") }, func() error { return direct.setChat(ctx, cliTestJID, "reset") },
			routeAccessChat, "state=reset"},
		{"send", func() error { return api.setSend(ctx, cliTestJID, "none") }, func() error { return direct.setSend(ctx, cliTestJID, "none") },
			routeAccessSend, "send=none"},
		{"decide", func() error { return api.decide(ctx, reqID(viaAPI), true, []string{cliTestJID}) },
			func() error { return direct.decide(ctx, reqID(offline), true, []string{cliTestJID}) },
			routeAccessDecide, "id=1 approve=true"},
		{"token create", func() error { _, _, err := apiAdmin.createToken(ctx, newTok); return err },
			func() error { _, _, err := directAdm.createToken(ctx, newTok); return err },
			routeClientCreate, "chats=" + cliTestJID + " expires_at=2030-01-02T03:04:05Z name=laptop scopes=read"},
		{"token revoke", func() error { _, err := apiAdmin.revokeToken(ctx, "laptop"); return err },
			func() error { _, err := directAdm.revokeToken(ctx, "laptop"); return err },
			routeClientRevoke, "ref=laptop"},
		{"failed revoke", func() error { _, err := apiAdmin.revokeToken(ctx, "nope"); return err },
			func() error { _, err := directAdm.revokeToken(ctx, "nope"); return err },
			routeClientRevoke, "ref=nope"},
	}
	for _, s := range steps {
		errHTTP, errOff := s.http(), s.offline()
		if (errHTTP == nil) != (errOff == nil) {
			t.Fatalf("%s: api err %v, offline err %v", s.name, errHTTP, errOff)
		}
		a, o := lastAudit(t, viaAPI), lastAudit(t, offline)
		if o.Actor != cliActor || a.Actor != "operator" {
			t.Fatalf("%s: actors %q / %q", s.name, a.Actor, o.Actor)
		}
		if a.Action != s.wantAction || a.Detail != s.wantDetail {
			t.Fatalf("%s: daemon recorded %q %q, want %q %q", s.name, a.Action, a.Detail, s.wantAction, s.wantDetail)
		}
		if o.Action != a.Action || o.Detail != a.Detail || o.ChatJID != a.ChatJID || o.Outcome != a.Outcome || o.Kind != a.Kind {
			t.Fatalf("%s: offline %+v differs from daemon %+v", s.name, o, a)
		}
		if strings.Contains(o.Detail, "note") || strings.Contains(o.Detail, "wppmcp_") {
			t.Fatalf("%s: unlisted field or secret in %q", s.name, o.Detail)
		}
	}
}

func TestCLIAudit_GrantRevokeAndDisabled(t *testing.T) {
	ctx := context.Background()
	st := openCLITestStore(t)
	adm := &directAdmin{st: st, release: func() {}}
	t.Setenv("WPP_MCP_AUDIT_DAYS", "")
	if _, err := adm.revokeGrant(ctx, "g-missing"); err == nil {
		t.Fatal("revoking an unknown grant succeeded")
	}
	e := lastAudit(t, st)
	if e.Action != routeGrantRevoke || e.Detail != "id=g-missing" || e.Outcome != store.OutcomeError || e.Actor != cliActor {
		t.Fatalf("grant revoke entry %+v", e)
	}

	t.Setenv("WPP_MCP_AUDIT_DAYS", "0")
	direct := &directAccess{st: st, release: func() {}}
	if err := direct.setMode(ctx, "all"); err != nil {
		t.Fatal(err)
	}
	if got := lastAudit(t, st); got.Action != routeGrantRevoke {
		t.Fatalf("recorded with auditing off: %+v", got)
	}
}

// randomTestToken returns a fresh operator token for a test daemon, so no
// token-shaped literal lives in the repository.
func randomTestToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
