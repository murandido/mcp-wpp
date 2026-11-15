package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/alert"
	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/metrics"
	"github.com/murandido/mcp-wpp/internal/store"
)

// monitoringFlags are serve's metrics and session alert settings.
type monitoringFlags struct {
	alertURL    string
	alertAfter  time.Duration
	alertHeader string
	alertFormat string

	headerName, headerValue string
}

func registerMonitoringFlags(fs *flag.FlagSet) *monitoringFlags {
	m := &monitoringFlags{alertAfter: 5 * time.Minute}
	fs.StringVar(&m.alertURL, "alert-url", os.Getenv("WPP_MCP_ALERT_URL"), "POST session alerts (down, logged out, recovered) to this URL (env WPP_MCP_ALERT_URL)")
	fs.StringVar(&m.alertHeader, "alert-header", os.Getenv("WPP_MCP_ALERT_HEADER"), `extra "Name: value" header on alert requests, e.g. for auth (env WPP_MCP_ALERT_HEADER)`)
	fs.StringVar(&m.alertFormat, "alert-format", envOr("WPP_MCP_ALERT_FORMAT", alert.FormatJSON), "alert body: json, or text for ntfy.sh (env WPP_MCP_ALERT_FORMAT)")
	fs.Func("alert-after", "alert when a paired session stays unauthenticated this long (default 5m, env WPP_MCP_ALERT_AFTER)", func(s string) error {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return fmt.Errorf("must be a positive duration such as 5m")
		}
		m.alertAfter = d
		return nil
	})
	if v := os.Getenv("WPP_MCP_ALERT_AFTER"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			m.alertAfter = d
		}
	}
	return m
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// validate checks the alert settings after flag parsing.
func (m *monitoringFlags) validate() error {
	if m.alertHeader != "" {
		if m.alertURL == "" {
			return fmt.Errorf("-alert-header needs -alert-url")
		}
		var err error
		if m.headerName, m.headerValue, err = alert.ParseHeader(m.alertHeader); err != nil {
			return err
		}
	}
	if m.alertURL != "" {
		_, err := alert.NewNotifier(alert.Config{URL: m.alertURL, Format: strings.ToLower(m.alertFormat)})
		return err
	}
	return nil
}

// operations is the metrics endpoint and the session alerter of one serve run.
type operations struct {
	toolCalls *metrics.LabeledCounter
	source    *metrics.Source
}

// startOperations starts the alerter (when configured) and prepares the
// metrics source. Call mount from daemon.Config.AdminMount and pass
// observeTool to the MCP server.
func (m *monitoringFlags) startOperations(ctx context.Context, c *client.Client, st *store.Store) (*operations, error) {
	ops := &operations{toolCalls: metrics.NewLabeledCounter("tool", "outcome")}
	ops.source = &metrics.Source{
		Version:   Version,
		Start:     time.Now(),
		Stats:     c.Stats,
		Counts:    st.Counts,
		ToolCalls: ops.toolCalls,
	}
	if m.alertURL == "" {
		return ops, nil
	}
	deliveries := metrics.NewLabeledCounter("event", "result")
	ops.source.Alerts = deliveries
	n, err := alert.NewNotifier(alert.Config{
		URL:         m.alertURL,
		Format:      strings.ToLower(m.alertFormat),
		HeaderName:  m.headerName,
		HeaderValue: m.headerValue,
		Logf:        func(f string, a ...any) { fmt.Fprintf(os.Stderr, "warn: "+f+"\n", a...) },
		Delivered:   func(kind, result string) { deliveries.Inc(kind, result) },
	})
	if err != nil {
		return nil, err
	}
	w := alert.NewWatcher(m.alertAfter, n, func() (bool, bool) { return c.IsLoggedIn(), c.IsAuthenticated() })
	c.OnLoggedOut(w.LoggedOut)
	go n.Run(ctx)
	go w.Run(ctx)
	fmt.Fprintf(os.Stderr, "session alerts: on (after %s unauthenticated, %s format)\n", m.alertAfter, strings.ToLower(m.alertFormat))
	return ops, nil
}

// mount registers GET /admin/metrics. Under /admin/ the daemon's guard
// accepts the operator bearer token only.
func (o *operations) mount(mux *http.ServeMux) {
	mux.Handle("GET /admin/metrics", metrics.Handler(o.source.Collect))
}

func (o *operations) observeTool(tool, outcome string) { o.toolCalls.Inc(tool, outcome) }
