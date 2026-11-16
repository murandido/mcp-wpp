//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/crypto"
	"github.com/murandido/mcp-wpp/internal/store"
)

const (
	aliceJID  = "447700000001@s.whatsapp.net"
	secretJID = "447700000002@s.whatsapp.net"
)

// seedChats caches two chats in the encrypted store before the daemon
// starts, as a history sync would.
func seedChats(t *testing.T) func(string) {
	return func(dir string) {
		t.Helper()
		keys, err := crypto.LoadKeyFile(os.Getenv("WPP_MCP_KEY_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		st, err := store.OpenWithKeys(dir, keys)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		for jid, name := range map[string]string{aliceJID: "Alice", secretJID: "Secret Bob"} {
			if err := st.StoreChat(jid, name, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSendPolicy_AccessSend(t *testing.T) {
	h := newSeededHarness(t, seedChats(t), "-write")
	h.initializeMCP()
	h.allow(t, "Alice")
	send := func(jid string) toolResult {
		return h.callTool("send_message", map[string]any{"recipient": jid, "message": "hello"})
	}

	if out, err := h.cli(t, "access", "send", "Alice", "none"); err != nil {
		t.Fatalf("access send none: %s %v", out, err)
	}
	out, err := h.cli(t, "access", "list")
	if err != nil || !strings.Contains(out, "SEND") || !strings.Contains(out, "none") {
		t.Fatalf("access list must show the send policy: %s %v", out, err)
	}
	if res := send(aliceJID); !res.IsError || !strings.Contains(res.Text, `send policy "none"`) {
		t.Fatalf("send with policy none: %+v", res)
	}

	if out, err := h.cli(t, "access", "send", aliceJID, "direct"); err != nil {
		t.Fatalf("access send direct: %s %v", out, err)
	}
	// Direct: no proposal; the unpaired daemon fails the real send.
	if res := send(aliceJID); strings.Contains(res.Text, "proposal_id") || !strings.Contains(res.Text, "Not connected") {
		t.Fatalf("send with policy direct: %+v", res)
	}

	if out, err := h.cli(t, "access", "send", "Alice", "reset"); err != nil {
		t.Fatalf("access send reset: %s %v", out, err)
	}
	if res := send(aliceJID); !strings.Contains(res.Text, "proposal_id") {
		t.Fatalf("default policy with -confirm-sends: %+v", res)
	}

	// A send policy never makes a hidden chat visible.
	if out, err := h.cli(t, "access", "send", "Secret Bob", "direct"); err != nil {
		t.Fatalf("access send on a hidden chat: %s %v", out, err)
	}
	if res := send(secretJID); !strings.Contains(res.Text, "chat not found") || strings.Contains(res.Text, "policy") {
		t.Fatalf("hidden chat with policy direct: %+v", res)
	}

	if out, err := h.cli(t, "access", "send", "Alice", "sometimes"); err == nil {
		t.Fatalf("an unknown policy must be refused: %s", out)
	}
}

func TestSchedule_CLIOutboxCancel(t *testing.T) {
	h := newSeededHarness(t, seedChats(t), "-write")
	h.initializeMCP()
	h.allow(t, "Alice")

	day := time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")
	out, err := h.cli(t, "schedule", "-tz", "UTC", "Alice", day, "06:00", "bom", "dia")
	if err != nil || !strings.Contains(out, "scheduled #1") || !strings.Contains(out, day+" 06:00 UTC") {
		t.Fatalf("schedule: %q %v", out, err)
	}
	out, err = h.cli(t, "outbox")
	if err != nil || !strings.Contains(out, "[scheduled]") || !strings.Contains(out, "bom dia") || !strings.Contains(out, "06:00 UTC") {
		t.Fatalf("outbox listing: %q %v", out, err)
	}
	if out, err := h.cli(t, "outbox", "cancel", "1"); err != nil {
		t.Fatalf("cancel: %q %v", out, err)
	}
	if out, _ := h.cli(t, "outbox"); !strings.Contains(out, "nothing awaiting") {
		t.Fatalf("outbox after cancel: %q", out)
	}
	if out, _ := h.cli(t, "outbox", "cancel", "1"); !strings.Contains(out, "nothing to cancel") {
		t.Fatalf("second cancel: %q", out)
	}

	// Refusals: unknown chat, hidden chat, past time.
	if out, err := h.cli(t, "schedule", "Nobody", day+" 06:00", "x"); err == nil || !strings.Contains(out, "no cached chat matches") {
		t.Fatalf("unknown chat: %q %v", out, err)
	}
	if out, err := h.cli(t, "schedule", secretJID, day+" 06:00", "x"); err == nil || !strings.Contains(out, "hidden") {
		t.Fatalf("hidden chat: %q %v", out, err)
	}
	if out, err := h.cli(t, "schedule", "Alice", "2020-01-01T06:00:00Z", "x"); err == nil || !strings.Contains(out, "past") {
		t.Fatalf("past time: %q %v", out, err)
	}

	// The AI's schedule_message becomes a proposal (default confirm) that
	// approval turns into a scheduled message.
	res := h.callTool("schedule_message", map[string]any{"recipient": aliceJID, "message": "lembrete", "send_at": time.Now().Add(2 * time.Hour).Format(time.RFC3339)})
	var prop struct {
		ID     int64  `json:"proposal_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(res.Text), &prop); err != nil || prop.Status != "awaiting_approval" {
		t.Fatalf("schedule_message: %s", res.Text)
	}
	if out, _ := h.cli(t, "outbox"); !strings.Contains(out, "needs approval") || !strings.Contains(out, "lembrete") {
		t.Fatalf("pending scheduled proposal: %q", out)
	}
	out, err = h.cli(t, "outbox", "approve", "2")
	if err != nil || !strings.Contains(out, "scheduled for") {
		t.Fatalf("approve scheduled proposal: %q %v", out, err)
	}
	if out, _ := h.cli(t, "outbox", "scheduled"); !strings.Contains(out, "#2") || !strings.Contains(out, "lembrete") {
		t.Fatalf("approved item is scheduled: %q", out)
	}
}

// The scheduler sends at the send time. The test daemon is unpaired, so the
// real send fails and the failure is recorded.
func TestSchedule_SchedulerRecordsOutcome(t *testing.T) {
	h := newSeededHarness(t, seedChats(t), "-write")
	h.allow(t, "Alice")
	at := time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339)
	if out, err := h.cli(t, "schedule", "Alice", at, "soon"); err != nil {
		t.Fatalf("schedule: %q %v", out, err)
	}
	deadline := time.Now().Add(15 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		out, _ = h.cli(t, "outbox", "history")
		if strings.Contains(out, "[failed]") {
			if !strings.Contains(out, "Not connected") {
				t.Fatalf("recorded failure: %q", out)
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("the scheduled message was not handled: %q", out)
}

func TestSchedule_ReadOnlyHasNoScheduling(t *testing.T) {
	h := newSeededHarness(t, seedChats(t))
	h.initializeMCP()
	h.allow(t, "Alice")
	if out, err := h.cli(t, "schedule", "Alice", time.Now().Add(time.Hour).Format(time.RFC3339), "x"); err == nil {
		t.Fatalf("scheduling on a read-only daemon must fail: %q", out)
	}
}

// Without a daemon, `wpp-mcp schedule` queues the message in the store, and
// the next -write daemon sends it.
func TestSchedule_OfflineQueuedThenSent(t *testing.T) {
	bin := binPath(t)
	dir := t.TempDir()
	key := keygen(t, bin)
	keys, err := crypto.LoadKeyFile(key)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenWithKeys(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StoreChat(aliceJID, "Alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	st.Close()

	offline := func(args ...string) (string, error) {
		cmd := exec.Command(bin, append([]string{"-store", dir, "-key-file", key}, args...)...)
		// Point the CLI at a port nobody listens on, so it never finds a
		// daemon (not even one the developer runs on the default port).
		cmd.Env = append(os.Environ(), "WPP_MCP_KEY_FILE=", fmt.Sprintf("WPP_MCP_ADDR=127.0.0.1:%d", freePort(t)))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	at := time.Now().Add(4 * time.Second).UTC().Format(time.RFC3339)
	if out, err := offline("schedule", "Alice", at, "offline", "hello"); err == nil || !strings.Contains(out, "hidden") {
		t.Fatalf("a hidden chat must be refused offline too: %q %v", out, err)
	}
	if out, err := offline("access", "allow", "Alice"); err != nil {
		t.Fatalf("allow: %q %v", out, err)
	}
	out, err := offline("schedule", "Alice", at, "offline", "hello")
	if err != nil || !strings.Contains(out, "scheduled #1") || !strings.Contains(out, "queued in the store") {
		t.Fatalf("offline schedule: %q %v", out, err)
	}

	d, err := startServe(t, bin, dir, []string{"-key-file", key}, "-write")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)
	d.stop()

	st, err = store.OpenWithKeys(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, err := st.GetProposal(context.Background(), 1)
	// The test daemon is unpaired, so the send itself fails; it was tried.
	if err != nil || p.Status != store.OutboxFailed || !strings.Contains(p.Result, "Not connected") || p.CreatedBy != store.CreatorOperatorCLI {
		t.Fatalf("offline item after the daemon ran: %+v %v", p, err)
	}
}
