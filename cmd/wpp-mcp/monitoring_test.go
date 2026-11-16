package main

import (
	"context"
	"strings"
	"testing"

	"github.com/murandido/mcp-wpp/internal/metrics"
)

func TestOperations_RefusalLabelsAreFixed(t *testing.T) {
	o := newOperations()
	o.observeRefusal(401, "mcp")
	o.observeRefusal(429, "admin")
	o.observeRefusal(418, "/secret/447700900001")
	o.observeDenied("get_chat")
	var w metrics.Writer
	o.source.Collect(context.Background(), &w)
	body := string(w.Bytes())
	for _, want := range []string{
		`wpp_mcp_http_refusals_total{code="401",route="mcp"} 1`,
		`wpp_mcp_http_refusals_total{code="429",route="admin"} 1`,
		`wpp_mcp_http_refusals_total{code="other",route="other"} 1`,
		`wpp_mcp_tool_calls_denied_total{tool="get_chat"} 1`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "4477") || strings.Contains(body, "secret") {
		t.Fatalf("request data reached a label:\n%s", body)
	}
}
