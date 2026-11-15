package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is advanced by hand.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func kind(ev *Event) string {
	if ev == nil {
		return ""
	}
	return ev.Kind
}

func TestMonitor_DownAfterThresholdThenUp(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	m := &Monitor{After: 5 * time.Minute}

	if ev := m.Observe(clk.Now(), true, true); ev != nil {
		t.Fatalf("healthy start raised %v", ev)
	}
	clk.Advance(time.Minute)
	wentDown := clk.Now()
	if ev := m.Observe(clk.Now(), true, false); ev != nil {
		t.Fatal("must wait for the threshold")
	}
	clk.Advance(4 * time.Minute)
	if ev := m.Observe(clk.Now(), true, false); ev != nil {
		t.Fatal("4m < 5m threshold")
	}
	clk.Advance(time.Minute)
	ev := m.Observe(clk.Now(), true, false)
	if kind(ev) != SessionDown || !ev.Since.Equal(wentDown) || !strings.Contains(ev.Message, "5m") {
		t.Fatalf("expected session_down since %v, got %+v", wentDown, ev)
	}
	clk.Advance(10 * time.Minute)
	if ev := m.Observe(clk.Now(), true, false); ev != nil {
		t.Fatal("session_down must be raised once")
	}
	ev = m.Observe(clk.Now(), true, true)
	if kind(ev) != SessionUp || !ev.Since.Equal(wentDown) || !strings.Contains(ev.Message, "15m") {
		t.Fatalf("expected session_up, got %+v", ev)
	}
	if ev := m.Observe(clk.Now(), true, true); ev != nil {
		t.Fatal("session_up must be raised once")
	}
}

func TestMonitor_ShortBlipIsSilent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	m := &Monitor{After: 5 * time.Minute}
	m.Observe(clk.Now(), true, false)
	clk.Advance(2 * time.Minute)
	if ev := m.Observe(clk.Now(), true, true); ev != nil {
		t.Fatalf("a recovery without a prior alert must be silent, got %v", ev)
	}
	// The outage clock restarts after a recovery.
	clk.Advance(time.Minute)
	m.Observe(clk.Now(), true, false)
	clk.Advance(4 * time.Minute)
	if ev := m.Observe(clk.Now(), true, false); ev != nil {
		t.Fatal("the threshold counts from the latest outage")
	}
}

func TestMonitor_LoggedOutAndUnpaired(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	m := &Monitor{After: 5 * time.Minute}
	if ev := m.Observe(clk.Now(), false, false); ev != nil {
		t.Fatal("an unpaired device never alerts")
	}
	clk.Advance(time.Hour)
	if ev := m.Observe(clk.Now(), false, false); ev != nil {
		t.Fatal("an unpaired device never alerts")
	}
	m.Observe(clk.Now(), true, true)
	clk.Advance(time.Minute)
	if kind(m.LoggedOut(clk.Now())) != LoggedOut {
		t.Fatal("expected logged_out")
	}
	if m.LoggedOut(clk.Now()) != nil {
		t.Fatal("logged_out must be raised once per logout")
	}
	clk.Advance(time.Hour)
	if ev := m.Observe(clk.Now(), false, false); ev != nil {
		t.Fatalf("no session_down after a logout, got %v", ev)
	}
	// Pairing again recovers.
	if kind(m.Observe(clk.Now(), true, true)) != SessionUp {
		t.Fatal("expected session_up after pairing again")
	}
}

func TestMonitor_DownThenLoggedOut(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	m := &Monitor{After: time.Minute}
	m.Observe(clk.Now(), true, false)
	clk.Advance(time.Minute)
	if kind(m.Observe(clk.Now(), true, false)) != SessionDown {
		t.Fatal("expected session_down")
	}
	if kind(m.LoggedOut(clk.Now())) != LoggedOut {
		t.Fatal("a logout after session_down is still reported")
	}
}

type received struct {
	header http.Header
	body   string
}

func receiver(t *testing.T, statuses ...int) (*httptest.Server, func() []received) {
	t.Helper()
	var mu sync.Mutex
	var got []received
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, received{header: r.Header.Clone(), body: string(b)})
		mu.Unlock()
		i := int(n.Add(1)) - 1
		if i < len(statuses) {
			w.WriteHeader(statuses[i])
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []received {
		mu.Lock()
		defer mu.Unlock()
		return append([]received(nil), got...)
	}
}

func TestNotifier_JSONWithHeaderAndRetry(t *testing.T) {
	srv, got := receiver(t, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusOK)
	name, value, err := ParseHeader("Authorization: Bearer s3cret")
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewNotifier(Config{URL: srv.URL, HeaderName: name, HeaderValue: value, Backoff: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := n.deliver(context.Background(), Event{Kind: SessionDown, Since: since, Message: "down"}); err != nil {
		t.Fatal(err)
	}
	reqs := got()
	if len(reqs) != 3 {
		t.Fatalf("expected 2 retries, got %d requests", len(reqs))
	}
	last := reqs[2]
	if last.header.Get("Authorization") != "Bearer s3cret" || last.header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", last.header)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(last.body), &body); err != nil {
		t.Fatal(err)
	}
	if body["event"] != SessionDown || body["since"] != "2026-01-01T12:00:00Z" || body["message"] != "down" || len(body) != 3 {
		t.Fatalf("body %v", body)
	}
}

func TestNotifier_TextFormatForNtfy(t *testing.T) {
	srv, got := receiver(t)
	n, err := NewNotifier(Config{URL: srv.URL, Format: FormatText})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.deliver(context.Background(), Event{Kind: LoggedOut, Since: time.Unix(0, 0), Message: "logged out"}); err != nil {
		t.Fatal(err)
	}
	r := got()[0]
	if !strings.HasPrefix(r.body, "logged out (since 1970-01-01T00:00:00Z)") || !strings.HasPrefix(r.header.Get("Content-Type"), "text/plain") {
		t.Fatalf("text body %q headers %v", r.body, r.header)
	}
	if r.header.Get("Title") == "" || r.header.Get("Tags") == "" || r.header.Get("Priority") != "high" {
		t.Fatalf("ntfy headers missing: %v", r.header)
	}
}

func TestNotifier_PermanentErrorNotRetried(t *testing.T) {
	srv, got := receiver(t, http.StatusUnauthorized, http.StatusOK)
	n, _ := NewNotifier(Config{URL: srv.URL, Backoff: time.Millisecond})
	if err := n.deliver(context.Background(), Event{Kind: SessionUp}); err == nil {
		t.Fatal("401 must fail")
	}
	if len(got()) != 1 {
		t.Fatal("4xx must not be retried")
	}
}

func TestNotifier_GivesUpAndNeverLogsURL(t *testing.T) {
	srv, _ := receiver(t, 500, 500, 500)
	var logs []string
	var results []string
	var mu sync.Mutex
	n, _ := NewNotifier(Config{
		URL: srv.URL + "/secret-topic", MaxAttempts: 3, Backoff: time.Millisecond, HeaderName: "X-Token", HeaderValue: "tok",
		Logf:      func(f string, a ...any) { mu.Lock(); logs = append(logs, f); mu.Unlock() },
		Delivered: func(kind, result string) { mu.Lock(); results = append(results, kind+"/"+result); mu.Unlock() },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Notify(Event{Kind: SessionDown})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := len(results) > 0
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 || results[0] != "session_down/failed" {
		t.Fatalf("results %v", results)
	}
	for _, l := range logs {
		if strings.Contains(l, "secret-topic") || strings.Contains(l, "tok") {
			t.Fatalf("log leaks the URL or header: %q", l)
		}
	}
}

func TestNotifier_UnreachableErrorOmitsURL(t *testing.T) {
	n, _ := NewNotifier(Config{URL: "http://127.0.0.1:1/secret-topic", MaxAttempts: 1})
	err := n.deliver(context.Background(), Event{Kind: SessionDown})
	if err == nil || strings.Contains(err.Error(), "secret-topic") {
		t.Fatalf("error %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, bad := range []string{"", "ftp://x", "not a url", "http://"} {
		if _, err := NewNotifier(Config{URL: bad}); err == nil {
			t.Errorf("URL %q accepted", bad)
		}
	}
	if _, err := NewNotifier(Config{URL: "https://ntfy.sh/x", Format: "xml"}); err == nil {
		t.Error("unknown format accepted")
	}
	for _, bad := range []string{"NoColon", ": v", "Name:", "Bad Name: v", "X: a\r\nInjected: 1"} {
		if _, _, err := ParseHeader(bad); err == nil {
			t.Errorf("header %q accepted", bad)
		}
	}
}

// TestWatcher_EndToEnd drives a Watcher with a fake clock and probe against
// an httptest receiver.
func TestWatcher_EndToEnd(t *testing.T) {
	srv, got := receiver(t)
	n, _ := NewNotifier(Config{URL: srv.URL, Backoff: time.Millisecond})
	var mu sync.Mutex
	clk := &fakeClock{t: time.Unix(1000, 0)}
	paired, auth := true, false
	w := NewWatcher(time.Minute, n, func() (bool, bool) { mu.Lock(); defer mu.Unlock(); return paired, auth })
	w.Interval = time.Millisecond
	w.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clk.Now() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	go w.Run(ctx)

	wait := func(count int) []received {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if r := got(); len(r) >= count {
				return r
			}
			time.Sleep(2 * time.Millisecond)
		}
		t.Fatalf("expected %d alerts, got %d", count, len(got()))
		return nil
	}
	time.Sleep(10 * time.Millisecond)
	mu.Lock()
	clk.Advance(2 * time.Minute)
	mu.Unlock()
	r := wait(1)
	if !strings.Contains(r[0].body, SessionDown) {
		t.Fatalf("first alert %s", r[0].body)
	}
	mu.Lock()
	auth = true
	mu.Unlock()
	r = wait(2)
	if !strings.Contains(r[1].body, SessionUp) {
		t.Fatalf("second alert %s", r[1].body)
	}
	// A logout also unpairs the device.
	mu.Lock()
	paired, auth = false, false
	mu.Unlock()
	w.LoggedOut()
	w.LoggedOut() // coalesced, and the monitor dedupes
	r = wait(3)
	if !strings.Contains(r[2].body, LoggedOut) {
		t.Fatalf("third alert %s", r[2].body)
	}
	time.Sleep(20 * time.Millisecond)
	if len(got()) != 3 {
		t.Fatalf("unexpected extra alerts: %d", len(got()))
	}
}
