//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func (h *harness) cli(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(h.bin, append([]string{"-store", h.store}, args...)...)
	cmd.Env = append(os.Environ(), "WPP_MCP_ADDR="+h.addr)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// allow authorises jid through the CLI, so tests of other guards are not
// stopped by the access gate first.
func (h *harness) allow(t *testing.T, jid string) {
	t.Helper()
	if out, err := h.cli(t, "access", "allow", jid); err != nil {
		t.Fatalf("access allow %s: %s %v", jid, out, err)
	}
}

func TestAccess_RequestReviewFlow(t *testing.T) {
	h := newHarness(t)
	h.initializeMCP()

	if out, err := h.cli(t, "access", "mode"); err != nil || strings.TrimSpace(out) != "allowlist" {
		t.Fatalf("default mode: %q %v", out, err)
	}

	res := h.callTool("request_chat_access", map[string]any{"query": "Alice", "reason": "the user asked about dinner plans"})
	if res.IsError {
		t.Fatalf("request_chat_access: %s", res.Text)
	}
	var req struct {
		ID     int64  `json:"request_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(res.Text), &req); err != nil || req.Status != "pending" {
		t.Fatalf("request reply: %s", res.Text)
	}

	out, err := h.cli(t, "access", "requests")
	if err != nil || !strings.Contains(out, `"Alice"`) || !strings.Contains(out, "dinner plans") {
		t.Fatalf("requests listing: %q %v", out, err)
	}
	if out, err := h.cli(t, "access", "reject", "1"); err != nil {
		t.Fatalf("reject: %s %v", out, err)
	}
	if out, _ := h.cli(t, "access", "requests"); !strings.Contains(out, "no pending requests") {
		t.Fatalf("rejected request still pending: %s", out)
	}

	// Decide on a chat ahead of time by JID, and switch modes, through the
	// running daemon.
	if out, err := h.cli(t, "access", "allow", "447700000001@s.whatsapp.net"); err != nil {
		t.Fatalf("allow by JID: %s %v", out, err)
	}
	if out, err := h.cli(t, "access", "mode", "all"); err != nil {
		t.Fatalf("set mode: %s %v", out, err)
	}
	if out, _ := h.cli(t, "access", "mode"); strings.TrimSpace(out) != "all" {
		t.Fatalf("mode after set: %q", out)
	}
	if out, err := h.cli(t, "access", "allow", "nobody-by-this-name"); err == nil || !strings.Contains(out, "no cached chat matches") {
		t.Fatalf("unknown name must fail helpfully: %q %v", out, err)
	}
}

func TestAccess_CLIWithoutDaemon(t *testing.T) {
	bin := binPath(t)
	store := t.TempDir()
	key := keygen(t, bin)
	d, err := startServe(t, bin, store, []string{"-key-file", key})
	if err != nil {
		t.Fatal(err)
	}
	d.stop()
	out, err := exec.Command(bin, "-store", store, "-key-file", key, "access", "mode", "all").CombinedOutput()
	if err != nil {
		t.Fatalf("offline access: %s %v", out, err)
	}
	out, err = exec.Command(bin, "-store", store, "-key-file", key, "access", "mode").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "all" {
		t.Fatalf("offline mode read: %q %v", out, err)
	}
}
