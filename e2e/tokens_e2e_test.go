//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var clientTokenRE = regexp.MustCompile(`wppmcp_[0-9a-f]{64}`)

// createToken runs `wpp-mcp token create` and returns the printed token.
func (h *harness) createToken(t *testing.T, args ...string) string {
	t.Helper()
	out, err := h.cli(t, append([]string{"token", "create"}, args...)...)
	if err != nil {
		t.Fatalf("token create: %s %v", out, err)
	}
	tok := clientTokenRE.FindString(out)
	if tok == "" || !strings.Contains(out, "shown only once") {
		t.Fatalf("token create output: %s", out)
	}
	return tok
}

// as returns a copy of the harness that authenticates with token.
func (h *harness) as(token string) *harness {
	c := *h
	c.token = token
	return &c
}

func (h *harness) mcpStatus(t *testing.T, token string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "http://"+h.addr+"/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestTokens_CreateUseRevokeAudit(t *testing.T) {
	h := newHarness(t, "-write")
	h.initializeMCP()

	tok := h.createToken(t, "connector", "-expires", "30d")
	client := h.as(tok)
	if res := client.callTool("get_status", map[string]any{}); res.IsError {
		t.Fatalf("get_status with a client token: %s", res.Text)
	}
	// The default scope is read: writes are refused before any proposal.
	res := client.callTool("send_message", map[string]any{"recipient": "447700000001", "message": "hi"})
	if !res.IsError || !strings.Contains(res.Text, "send scope") {
		t.Fatalf("send_message with a read token: %+v", res)
	}
	// Client tokens never open the operator API.
	req, _ := http.NewRequest(http.MethodGet, "http://"+h.addr+"/admin/access", nil)
	if resp, err := client.do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("client token on /admin: %v %v", resp, err)
	}

	out, err := h.cli(t, "token", "list")
	if err != nil || !strings.Contains(out, "connector") || !strings.Contains(out, "active") || strings.Contains(out, tok) {
		t.Fatalf("token list: %s %v", out, err)
	}

	if out, err := h.cli(t, "token", "revoke", "connector"); err != nil {
		t.Fatalf("revoke: %s %v", out, err)
	}
	if code := h.mcpStatus(t, tok); code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", code)
	}
	if code := h.mcpStatus(t, h.token); code != http.StatusOK {
		t.Fatalf("operator token after revoke: %d", code)
	}

	out, err = h.cli(t, "audit", "-since", "1h")
	if err != nil {
		t.Fatalf("audit: %s %v", out, err)
	}
	for _, want := range []string{"TIME", "token:connector", "get_status", "send_message", "denied", "POST /admin/tokens/{ref}/revoke", "operator"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, tok) || strings.Contains(out, `"hi"`) {
		t.Fatalf("audit output leaks content:\n%s", out)
	}
	out, err = h.cli(t, "audit", "-actor", "connector")
	if err != nil || strings.Contains(out, "POST /admin") || !strings.Contains(out, "get_status") {
		t.Fatalf("audit -actor: %s %v", out, err)
	}
}

func TestTokens_CLIWithoutDaemon(t *testing.T) {
	bin := binPath(t)
	store := t.TempDir()
	key := keygen(t, bin)
	d, err := startServe(t, bin, store, []string{"-key-file", key})
	if err != nil {
		t.Fatal(err)
	}
	d.stop()
	// Point the CLI at a port nobody listens on, so it uses the store.
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(bin, append([]string{"-store", store, "-key-file", key}, args...)...)
		cmd.Env = append(os.Environ(), "WPP_MCP_ADDR="+addr, "WPP_MCP_KEY_FILE=")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s %v", args, out, err)
		}
		return string(out)
	}
	out := run("token", "create", "offline", "-scope", "read,send", "-chats", "447700000001")
	tok := clientTokenRE.FindString(out)
	if tok == "" {
		t.Fatalf("token create offline: %s", out)
	}
	if out := run("token", "list"); !strings.Contains(out, "offline") || !strings.Contains(out, "read,send") || !strings.Contains(out, "447700000001@s.whatsapp.net") || strings.Contains(out, tok) {
		t.Fatalf("token list offline: %s", out)
	}
	run("token", "revoke", "offline")
	// The same actions and fields the admin API records, by the CLI actor.
	if out := run("audit", "-actor", "operator:cli"); !strings.Contains(out, "POST /admin/tokens ") ||
		!strings.Contains(out, "POST /admin/tokens/{ref}/revoke") || !strings.Contains(out, "ref=offline") || strings.Contains(out, tok) {
		t.Fatalf("offline audit: %s", out)
	}
}
