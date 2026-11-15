package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// Payload formats.
const (
	// FormatJSON posts {"event","since","message"} as application/json.
	FormatJSON = "json"
	// FormatText posts the message as text/plain with ntfy.sh headers
	// (Title, Tags, Priority), so `-alert-url https://ntfy.sh/<topic>`
	// shows a readable notification.
	FormatText = "text"
)

// Config configures a Notifier.
type Config struct {
	URL    string
	Format string // FormatJSON (default) or FormatText
	// Header is an optional "Name: value" header, typically for auth.
	HeaderName, HeaderValue string
	// Client defaults to a client with a 10 s timeout.
	Client *http.Client
	// MaxAttempts per alert (default 6) and the first retry delay (default
	// 2 s), doubling up to MaxBackoff (default 1 min).
	MaxAttempts int
	Backoff     time.Duration
	MaxBackoff  time.Duration
	// Logf reports delivery failures. It never receives the URL or the
	// header value, which may hold secrets.
	Logf func(format string, args ...any)
	// Delivered, when set, is called once per alert with "ok" or "failed".
	Delivered func(kind, result string)
}

// ParseHeader splits a "Name: value" flag value.
func ParseHeader(s string) (name, value string, err error) {
	name, value, ok := strings.Cut(s, ":")
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	if !ok || name == "" || value == "" || strings.ContainsAny(name, " \t\r\n") || strings.ContainsAny(value, "\r\n") {
		return "", "", errors.New(`alert header must look like "Name: value"`)
	}
	return textproto.CanonicalMIMEHeaderKey(name), value, nil
}

// Notifier delivers alerts in the background.
type Notifier struct {
	cfg   Config
	queue chan Event
}

// NewNotifier validates cfg.
func NewNotifier(cfg Config) (*Notifier, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("alert URL must be an http:// or https:// URL")
	}
	switch cfg.Format {
	case "":
		cfg.Format = FormatJSON
	case FormatJSON, FormatText:
	default:
		return nil, fmt.Errorf("alert format must be %q or %q", FormatJSON, FormatText)
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 6
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 2 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = time.Minute
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Notifier{cfg: cfg, queue: make(chan Event, 16)}, nil
}

// Notify queues ev without blocking. When the queue is full (the receiver
// has been down for a long time) the alert is dropped and logged.
func (n *Notifier) Notify(ev Event) {
	select {
	case n.queue <- ev:
	default:
		n.cfg.Logf("alert queue full; dropped %s alert", ev.Kind)
		n.delivered(ev.Kind, "dropped")
	}
}

// Run delivers queued alerts until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-n.queue:
			if err := n.deliver(ctx, ev); err != nil {
				n.cfg.Logf("alert %s not delivered: %v", ev.Kind, err)
				n.delivered(ev.Kind, "failed")
			} else {
				n.delivered(ev.Kind, "ok")
			}
		}
	}
}

func (n *Notifier) delivered(kind, result string) {
	if n.cfg.Delivered != nil {
		n.cfg.Delivered(kind, result)
	}
}

// errPermanent marks a response that retrying will not fix.
type errPermanent struct{ status int }

func (e errPermanent) Error() string { return fmt.Sprintf("receiver answered %d", e.status) }

// deliver posts ev, retrying network errors, 429 and 5xx with backoff.
func (n *Notifier) deliver(ctx context.Context, ev Event) error {
	wait := n.cfg.Backoff
	var err error
	for attempt := 1; attempt <= n.cfg.MaxAttempts; attempt++ {
		if err = n.post(ctx, ev); err == nil {
			return nil
		}
		var perm errPermanent
		if errors.As(err, &perm) || attempt == n.cfg.MaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, n.cfg.MaxBackoff)
	}
	return err
}

func (n *Notifier) post(ctx context.Context, ev Event) error {
	var body []byte
	contentType := "application/json"
	if n.cfg.Format == FormatText {
		body = []byte(ev.Message + " (since " + ev.Since.UTC().Format(time.RFC3339) + ")")
		contentType = "text/plain; charset=utf-8"
	} else {
		var err error
		if body, err = json.Marshal(ev); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "wpp-mcp-alert")
	if n.cfg.Format == FormatText {
		title, tags, priority := "wpp-mcp: WhatsApp session down", "warning", "high"
		switch ev.Kind {
		case LoggedOut:
			title, tags = "wpp-mcp: WhatsApp logged out", "rotating_light"
		case SessionUp:
			title, tags, priority = "wpp-mcp: WhatsApp session restored", "white_check_mark", "default"
		}
		req.Header.Set("Title", title)
		req.Header.Set("Tags", tags)
		req.Header.Set("Priority", priority)
	}
	if n.cfg.HeaderName != "" {
		req.Header.Set(n.cfg.HeaderName, n.cfg.HeaderValue)
	}
	resp, err := n.cfg.Client.Do(req)
	if err != nil {
		// Strip the URL from transport errors: it may embed a secret topic.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return uerr.Err
		}
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("receiver answered %d", resp.StatusCode)
	default:
		return errPermanent{status: resp.StatusCode}
	}
}

// Watcher samples the session periodically and feeds a Monitor, sending the
// alerts it raises to a Notifier.
type Watcher struct {
	Monitor  *Monitor
	Notifier *Notifier
	// Probe reports whether a device is paired and whether WhatsApp has
	// authenticated the session. It must be cheap and non-blocking.
	Probe    func() (paired, authenticated bool)
	Interval time.Duration
	Now      func() time.Time

	loggedOut chan struct{}
}

// NewWatcher builds a Watcher with a 15 s sampling interval.
func NewWatcher(after time.Duration, n *Notifier, probe func() (bool, bool)) *Watcher {
	return &Watcher{Monitor: &Monitor{After: after}, Notifier: n, Probe: probe, Interval: 15 * time.Second, Now: time.Now, loggedOut: make(chan struct{}, 1)}
}

// LoggedOut signals a LoggedOut event. It never blocks, so it is safe to
// call from the WhatsApp event handler.
func (w *Watcher) LoggedOut() {
	select {
	case w.loggedOut <- struct{}{}:
	default:
	}
}

// Run samples until ctx ends. The Notifier must be running (Notifier.Run).
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	w.sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.loggedOut:
			if ev := w.Monitor.LoggedOut(w.Now()); ev != nil {
				w.Notifier.Notify(*ev)
			}
		case <-t.C:
			w.sample()
		}
	}
}

func (w *Watcher) sample() {
	paired, auth := w.Probe()
	if ev := w.Monitor.Observe(w.Now(), paired, auth); ev != nil {
		w.Notifier.Notify(*ev)
	}
}
