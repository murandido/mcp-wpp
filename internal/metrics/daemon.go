package metrics

import (
	"context"
	"time"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/store"
)

// connectionStates is the closed set of client.ConnectionStatus states. Any
// other value is reported as "other", so a label can never echo arbitrary
// text.
var connectionStates = []string{
	"connected", "disconnected", "keepalive_timeout", "logged_out",
	"stream_replaced", "client_outdated", "temporary_ban", "connect_failure", "other",
}

// Source gathers the daemon's metrics. Function fields keep it testable
// without a WhatsApp connection.
type Source struct {
	Version string
	Start   time.Time
	Now     func() time.Time
	Stats   func() client.Stats
	Counts  func(context.Context) (store.Counts, error)
	// ToolCalls counts MCP tool executions by tool and outcome.
	ToolCalls *LabeledCounter
	// Alerts counts session alert deliveries by event and result; nil when
	// alerts are off.
	Alerts *LabeledCounter
}

// Collect writes every metric family.
func (s *Source) Collect(ctx context.Context, w *Writer) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	t := now()
	w.Family("wpp_mcp_build_info", "Build version of the running daemon.", "gauge",
		Sample{Labels: []Label{{"version", s.Version}}, Value: 1})
	w.Gauge("wpp_mcp_start_time_seconds", "Unix time the daemon started.", float64(s.Start.Unix()))
	w.Gauge("wpp_mcp_uptime_seconds", "Seconds since the daemon started.", t.Sub(s.Start).Seconds())

	if s.Stats != nil {
		st := s.Stats()
		w.Gauge("wpp_mcp_whatsapp_paired", "1 when a WhatsApp device identity is stored.", Bool(st.Paired))
		w.Gauge("wpp_mcp_whatsapp_connected", "1 when the WhatsApp websocket is connected.", Bool(st.Connected))
		w.Gauge("wpp_mcp_whatsapp_authenticated", "1 when WhatsApp has accepted the session on the current connection.", Bool(st.Authenticated))
		state := "other"
		for _, known := range connectionStates {
			if st.State == known {
				state = known
			}
		}
		samples := make([]Sample, 0, len(connectionStates))
		for _, known := range connectionStates {
			samples = append(samples, Sample{Labels: []Label{{"state", known}}, Value: Bool(known == state)})
		}
		w.Family("wpp_mcp_whatsapp_connection_state", "Last WhatsApp connection event (1 for the current state).", "gauge", samples...)
		w.Counter("wpp_mcp_messages_received_total", "Live incoming messages received since the daemon started.", float64(st.MessagesReceived))
		w.Counter("wpp_mcp_messages_sent_total", "Messages sent to WhatsApp since the daemon started.", float64(st.MessagesSent))
		if !st.LastReceived.IsZero() {
			w.Gauge("wpp_mcp_last_message_received_timestamp_seconds", "Unix time of the last incoming live message.", float64(st.LastReceived.Unix()))
			w.Gauge("wpp_mcp_seconds_since_last_message_received", "Seconds since the last incoming live message (absent until one arrives).", t.Sub(st.LastReceived).Seconds())
		}
	}

	if s.ToolCalls != nil {
		w.Family("wpp_mcp_tool_calls_total", "MCP tool executions by tool and outcome (ok or error).", "counter", s.ToolCalls.Samples()...)
	}
	if s.Alerts != nil {
		w.Family("wpp_mcp_alerts_total", "Session alert deliveries by event and result.", "counter", s.Alerts.Samples()...)
	}

	if s.Counts != nil {
		c, err := s.Counts(ctx)
		w.Gauge("wpp_mcp_store_up", "1 when the message store answered the metrics queries.", Bool(err == nil))
		if err == nil {
			w.Gauge("wpp_mcp_chats_cached", "Chats in the local cache.", float64(c.ChatsCached))
			w.Gauge("wpp_mcp_chats_visible", "Chats the access policy lets MCP clients see.", float64(c.ChatsVisible))
			w.Gauge("wpp_mcp_outbox_pending", "Outbox proposals waiting for a decision.", float64(c.OutboxPending))
			w.Gauge("wpp_mcp_access_requests_pending", "Chat access requests waiting for a decision.", float64(c.AccessRequests))
		}
	}
}
