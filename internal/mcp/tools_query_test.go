package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// fakePairCache is a minimal pairingCache for exercising pairing_status
// without standing up the daemon's real PairCache.
type fakePairCache struct {
	paired  bool
	qr      string
	expired bool
}

func (f fakePairCache) Paired() bool  { return f.paired }
func (f fakePairCache) QR() string    { return f.qr }
func (f fakePairCache) Expired() bool { return f.expired }

// callPairingStatus invokes the pairing_status handler and decodes its JSON
// "setup_state" envelope into a map.
func callPairingStatus(t *testing.T, s *Server) map[string]any {
	t.Helper()
	tool, ok := s.MCP().ListTools()["pairing_status"]
	if !ok || tool == nil || tool.Handler == nil {
		t.Fatal("pairing_status not registered")
	}
	res, err := tool.Handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("pairing_status handler: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("pairing_status returned no content")
	}
	text, ok := mcp.AsTextContent(res.Content[0])
	if !ok {
		t.Fatalf("pairing_status content not text: %T", res.Content[0])
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(text.Text), &env); err != nil {
		t.Fatalf("decode envelope %q: %v", text.Text, err)
	}
	if env["type"] != "setup_state" {
		t.Errorf("type = %v, want setup_state", env["type"])
	}
	return env
}

// A nil pairing cache (smoke/tests) yields the error envelope without touching
// the WhatsApp client — so passing a nil client here must not panic.
func TestPairingStatus_NilCache(t *testing.T) {
	env := callPairingStatus(t, NewServer(nil, nil, false))
	if env["state"] != "error" {
		t.Errorf("state = %v, want error", env["state"])
	}
	if env["detail"] != "pairing cache unavailable" {
		t.Errorf("detail = %v, want pairing cache unavailable", env["detail"])
	}
}

// A pending QR is never handed to the model: linking a device is an
// operator action, and a prompt-injected model must not be able to relay it.
func TestPairingStatus_NeverExposesQR(t *testing.T) {
	env := callPairingStatus(t, NewServer(nil, fakePairCache{qr: "2@QRPAYLOAD"}, false))
	if env["state"] != "awaiting_pairing" {
		t.Fatalf("state = %v, want awaiting_pairing", env["state"])
	}
	raw, _ := json.Marshal(env)
	if strings.Contains(string(raw), "QRPAYLOAD") {
		t.Fatalf("pairing_status leaked the QR payload: %s", raw)
	}
}

// An unpaired cache tells the model how the operator pairs, without a QR.
func TestPairingStatus_AwaitingPairingPointsAtCLI(t *testing.T) {
	env := callPairingStatus(t, NewServer(nil, fakePairCache{}, false))
	if env["state"] != "awaiting_pairing" {
		t.Fatalf("state = %v, want awaiting_pairing", env["state"])
	}
	if _, ok := env["qr_payload"]; ok {
		t.Errorf("qr_payload should be absent, got %v", env["qr_payload"])
	}
	if detail, _ := env["detail"].(string); !strings.Contains(detail, "wpp-mcp pair") {
		t.Errorf("detail = %v, want the operator pairing command", env["detail"])
	}
}

// An unpaired cache whose pairing session expired keeps the awaiting_qr state
// (supervisors switch on it) and flags expired so the caller knows the QR
// will not appear until a new session starts.
func TestPairingStatus_AwaitingPairingExpired(t *testing.T) {
	env := callPairingStatus(t, NewServer(nil, fakePairCache{expired: true}, false))
	if env["state"] != "awaiting_pairing" {
		t.Fatalf("state = %v, want awaiting_pairing", env["state"])
	}
	if env["expired"] != true {
		t.Errorf("expired = %v, want true", env["expired"])
	}
	if _, ok := env["qr_payload"]; ok {
		t.Errorf("qr_payload should be absent, got %v", env["qr_payload"])
	}
	if detail, _ := env["detail"].(string); !strings.Contains(detail, "expired") {
		t.Errorf("detail = %v, want an expiry message", env["detail"])
	}
}
