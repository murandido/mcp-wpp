//go:build e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOutbox_ProposeReviewApprove(t *testing.T) {
	h := newHarness(t, "-write")
	h.initializeMCP()
	const jid = "447700000001@s.whatsapp.net"
	h.allow(t, jid)

	res := h.callTool("send_message", map[string]any{"recipient": jid, "message": "dinner at 8?"})
	var prop struct {
		ID     int64  `json:"proposal_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(res.Text), &prop); err != nil || prop.Status != "awaiting_approval" {
		t.Fatalf("send_message should only propose: %s", res.Text)
	}
	out, err := h.cli(t, "outbox")
	if err != nil || !strings.Contains(out, "dinner at 8?") {
		t.Fatalf("outbox listing: %q %v", out, err)
	}
	// Approval runs the real send; the test daemon is not paired, so it fails
	// and says why.
	out, err = h.cli(t, "outbox", "approve", "1")
	if err == nil || !strings.Contains(out, "failed") {
		t.Fatalf("approve on an unpaired daemon: %q %v", out, err)
	}
	if out, _ := h.cli(t, "outbox", "approve", "1"); !strings.Contains(out, "not pending") {
		t.Fatalf("second approve must be refused: %q", out)
	}

	h.callTool("send_message", map[string]any{"recipient": jid, "message": "never mind"})
	if out, err := h.cli(t, "outbox", "reject", "2"); err != nil {
		t.Fatalf("reject: %q %v", out, err)
	}
	if out, _ := h.cli(t, "outbox"); !strings.Contains(out, "nothing awaiting") {
		t.Fatalf("queue after reject: %q", out)
	}
}

func TestOutbox_ConfirmationCanBeDisabled(t *testing.T) {
	h := newHarness(t, "-write", "-confirm-sends=false")
	h.initializeMCP()
	h.allow(t, "447700000001@s.whatsapp.net")
	res := h.callTool("send_message", map[string]any{"recipient": "447700000001@s.whatsapp.net", "message": "x"})
	if strings.Contains(res.Text, "proposal_id") {
		t.Fatalf("-confirm-sends=false must act immediately: %s", res.Text)
	}
}
