package metrics

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

var (
	sampleLine = regexp.MustCompile(`^([a-z_]+)(\{([a-z_]+="[^"\\\n]*")(,[a-z_]+="[^"\\\n]*")*\})? (-?[0-9.e+]+|NaN|[+-]Inf)$`)
	helpLine   = regexp.MustCompile(`^# HELP [a-z_]+ .+$`)
	typeLine   = regexp.MustCompile(`^# TYPE ([a-z_]+) (gauge|counter)$`)
	labelValue = regexp.MustCompile(`="([^"]*)"`)
)

func testSource() *Source {
	start := time.Unix(1_700_000_000, 0)
	tools := NewLabeledCounter("tool", "outcome")
	tools.Inc("list_chats", "ok")
	tools.Inc("list_chats", "ok")
	tools.Inc("send_message", "error")
	alerts := NewLabeledCounter("event", "result")
	alerts.Inc("session_down", "ok")
	return &Source{
		Version: "v1.2.3",
		Start:   start,
		Now:     func() time.Time { return start.Add(90 * time.Second) },
		Stats: func() client.Stats {
			return client.Stats{Paired: true, Connected: true, Authenticated: true, State: "connected",
				MessagesReceived: 5, MessagesSent: 2, LastReceived: start.Add(60 * time.Second)}
		},
		Counts: func(context.Context) (store.Counts, error) {
			return store.Counts{ChatsCached: 10, ChatsVisible: 3, OutboxPending: 1}, nil
		},
		ToolCalls: tools,
		Alerts:    alerts,
	}
}

func TestCollect_FormatAndValues(t *testing.T) {
	srv := httptest.NewServer(Handler(testSource().Collect))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)

	typed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		switch {
		case helpLine.MatchString(line):
		case typeLine.MatchString(line):
			name := typeLine.FindStringSubmatch(line)[1]
			if typed[name] {
				t.Errorf("family %s declared twice", name)
			}
			typed[name] = true
		case sampleLine.MatchString(line):
			name := sampleLine.FindStringSubmatch(line)[1]
			if !typed[name] {
				t.Errorf("sample before its TYPE line: %s", line)
			}
		default:
			t.Errorf("malformed exposition line: %q", line)
		}
	}
	for _, want := range []string{
		`wpp_mcp_build_info{version="v1.2.3"} 1`,
		"wpp_mcp_uptime_seconds 90",
		"wpp_mcp_whatsapp_authenticated 1",
		`wpp_mcp_whatsapp_connection_state{state="connected"} 1`,
		`wpp_mcp_whatsapp_connection_state{state="logged_out"} 0`,
		"wpp_mcp_messages_received_total 5",
		"wpp_mcp_messages_sent_total 2",
		"wpp_mcp_seconds_since_last_message_received 30",
		`wpp_mcp_tool_calls_total{tool="list_chats",outcome="ok"} 2`,
		`wpp_mcp_tool_calls_total{tool="send_message",outcome="error"} 1`,
		`wpp_mcp_alerts_total{event="session_down",result="ok"} 1`,
		"wpp_mcp_chats_cached 10",
		"wpp_mcp_chats_visible 3",
		"wpp_mcp_outbox_pending 1",
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

// TestCollect_NoPersonalData checks that every label value comes from a
// fixed vocabulary, whatever the connection state says.
func TestCollect_NoPersonalData(t *testing.T) {
	src := testSource()
	src.Stats = func() client.Stats {
		return client.Stats{State: "447700000001@s.whatsapp.net"}
	}
	var w Writer
	src.Collect(context.Background(), &w)
	body := string(w.Bytes())
	if strings.Contains(body, "@") || strings.Contains(body, "4477") {
		t.Fatalf("metrics leak a JID or number:\n%s", body)
	}
	allowed := map[string]bool{"v1.2.3": true, "list_chats": true, "send_message": true, "ok": true, "error": true, "session_down": true}
	for _, s := range connectionStates {
		allowed[s] = true
	}
	for _, m := range labelValue.FindAllStringSubmatch(body, -1) {
		if !allowed[m[1]] {
			t.Errorf("unexpected label value %q", m[1])
		}
	}
	if !strings.Contains(body, `wpp_mcp_whatsapp_connection_state{state="other"} 1`) {
		t.Fatal("an unknown state must be reported as other")
	}
}

func TestCollect_StoreErrorAndNoMessages(t *testing.T) {
	src := testSource()
	src.Counts = func(context.Context) (store.Counts, error) { return store.Counts{}, errors.New("boom") }
	src.Stats = func() client.Stats { return client.Stats{} }
	var w Writer
	src.Collect(context.Background(), &w)
	body := string(w.Bytes())
	if !strings.Contains(body, "wpp_mcp_store_up 0\n") || strings.Contains(body, "wpp_mcp_chats_cached") {
		t.Fatalf("store error handling:\n%s", body)
	}
	if strings.Contains(body, "seconds_since_last_message") {
		t.Fatal("no last-message gauge before any message arrives")
	}
}

func TestEscapeLabel(t *testing.T) {
	var w Writer
	w.Family("x", "help\nline", "gauge", Sample{Labels: []Label{{"l", "a\"b\\c\nd"}}, Value: 1})
	want := "# HELP x help\\nline\n# TYPE x gauge\nx{l=\"a\\\"b\\\\c\\nd\"} 1\n"
	if got := string(w.Bytes()); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
