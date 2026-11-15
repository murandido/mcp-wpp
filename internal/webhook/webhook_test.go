package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testSecret = "0123456789abcdef0123456789abcdef"
	chatA      = "447700000001@s.whatsapp.net"
	chatB      = "123456789@g.us"
	hiddenChat = "447700000002@s.whatsapp.net"
)

// fakeClock is a manual clock: Sleep records the duration and advances time
// at once.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// recorder is an httptest endpoint that records requests and answers with
// the queued status codes (200 once they run out).
type recorder struct {
	mu       sync.Mutex
	statuses []int
	reqs     []recorded
	srv      *httptest.Server
}

type recorded struct {
	header http.Header
	body   []byte
}

func newRecorder(t *testing.T, statuses ...int) *recorder {
	t.Helper()
	r := &recorder{statuses: statuses}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, recorded{header: req.Header.Clone(), body: body})
		status := http.StatusOK
		if len(r.statuses) > 0 {
			status, r.statuses = r.statuses[0], r.statuses[1:]
		}
		r.mu.Unlock()
		if status == http.StatusFound {
			http.Redirect(w, req, "/elsewhere", status)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) requests() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.reqs...)
}

func allowOnly(jids ...string) func(context.Context, string) (bool, error) {
	return func(_ context.Context, jid string) (bool, error) {
		for _, j := range jids {
			if j == jid {
				return true, nil
			}
		}
		return false, nil
	}
}

func newTestDispatcher(t *testing.T, cfg Config, url string, clock *fakeClock) *Dispatcher {
	t.Helper()
	cfg.URL = url
	if cfg.Secret == "" {
		cfg.Secret = testSecret
	}
	d, err := New(cfg, Options{Allowed: allowOnly(chatA, chatB), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func msg(chat, id, text string) Message {
	return Message{
		ChatJID: chat, ChatName: "Alice", ID: id, Text: text,
		Timestamp: time.Date(2026, 11, 15, 11, 59, 0, 0, time.UTC),
		SenderJID: chat, SenderName: "Alice",
	}
}

// drain delivers every batch that is due now.
func drain(d *Dispatcher, clock *fakeClock) {
	for {
		b, _ := d.next(clock.Now())
		if b == nil {
			return
		}
		d.deliver(context.Background(), b)
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		url, secret string
		ok          bool
	}{
		{"https://hooks.example.com/wa", testSecret, true},
		{"http://127.0.0.1:9000/hook", testSecret, true},
		{"http://localhost/hook", testSecret, true},
		{"http://192.168.1.20/hook", testSecret, true},
		{"http://n8n:5678/webhook/x", testSecret, true},
		{"http://hooks.example.com/wa", testSecret, false},
		{"http://8.8.8.8/hook", testSecret, false},
		{"ftp://127.0.0.1/hook", testSecret, false},
		{"https://hooks.example.com/wa", "", false},
		{"https://hooks.example.com/wa", "short", false},
	} {
		err := Config{URL: tc.url, Secret: tc.secret}.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("Validate(%q, secret len %d) = %v, want ok=%v", tc.url, len(tc.secret), err, tc.ok)
		}
		if err != nil && tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
			t.Errorf("error leaks the secret: %v", err)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	now := time.Unix(1_800_000_000, 0)
	sig := Sign(testSecret, now.Unix(), body)
	if !strings.HasPrefix(sig, "sha256=") || len(sig) != len("sha256=")+64 {
		t.Fatalf("signature = %q", sig)
	}
	ts := fmt.Sprint(now.Unix())
	if err := Verify(testSecret, sig, ts, body, now.Add(time.Minute), 5*time.Minute); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if Verify(testSecret, sig, ts, []byte(`{"hello":"there"}`), now, 5*time.Minute) == nil {
		t.Error("a changed body verified")
	}
	if Verify("another-secret-another-secret", sig, ts, body, now, 5*time.Minute) == nil {
		t.Error("a different secret verified")
	}
	if Verify(testSecret, sig, fmt.Sprint(now.Unix()+1), body, now, 5*time.Minute) == nil {
		t.Error("a changed timestamp verified")
	}
	if Verify(testSecret, sig, ts, body, now.Add(10*time.Minute), 5*time.Minute) == nil {
		t.Error("a replayed (stale) request verified")
	}
	// The README's openssl example gives this value:
	//   printf '1800000000.{"a":1}' | openssl dgst -sha256 -hmac 0123456789abcdef
	if got := Sign("0123456789abcdef", 1800000000, []byte(`{"a":1}`)); got != "sha256=d3e17924cac4a72ca2ee9e5700df170fdb5733eaf69ecd909fb0c18a962b03a5" {
		t.Errorf("Sign = %s, does not match the documented openssl recipe", got)
	}
}

func TestDeliver_PayloadWithoutText(t *testing.T) {
	rec := newRecorder(t)
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{}, rec.srv.URL, clock)
	m := msg(chatA, "m1", "secret plans")
	m.MediaType = "image"
	d.Enqueue(m)
	clock.Advance(DefaultWindow)
	drain(d, clock)

	reqs := rec.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if strings.Contains(string(r.body), "secret plans") {
		t.Fatalf("text sent without IncludeText: %s", r.body)
	}
	if err := Verify(testSecret, r.header.Get(HeaderSignature), r.header.Get(HeaderTimestamp), r.body, clock.Now(), 5*time.Minute); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if r.header.Get(HeaderEvent) != EventMessages || r.header.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", r.header)
	}
	var p Payload
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.Type != EventMessages || p.DeliveryID == "" || p.DeliveryID != r.header.Get(HeaderDelivery) {
		t.Errorf("envelope = %+v", p)
	}
	if p.Chat.JID != chatA || p.Chat.Name != "Alice" || p.Chat.IsGroup {
		t.Errorf("chat = %+v", p.Chat)
	}
	if len(p.Messages) != 1 {
		t.Fatalf("messages = %+v", p.Messages)
	}
	pm := p.Messages[0]
	if pm.ID != "m1" || !pm.HasMedia || pm.MediaType != "image" || pm.Sender.JID != chatA || pm.Sender.Name != "Alice" || pm.Text != "" || pm.Timestamp.IsZero() {
		t.Errorf("message = %+v", pm)
	}
	var raw map[string]any
	_ = json.Unmarshal(r.body, &raw)
	if _, ok := raw["messages"].([]any)[0].(map[string]any)["text"]; ok {
		t.Error("payload has a text key without IncludeText")
	}
}

func TestDeliver_PayloadWithText(t *testing.T) {
	rec := newRecorder(t)
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{IncludeText: true}, rec.srv.URL, clock)
	d.Enqueue(msg(chatA, "m1", "see you at 5"))
	clock.Advance(DefaultWindow)
	drain(d, clock)
	reqs := rec.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	var p Payload
	_ = json.Unmarshal(reqs[0].body, &p)
	if p.Messages[0].Text != "see you at 5" || p.Messages[0].HasMedia {
		t.Errorf("message = %+v", p.Messages[0])
	}
}

func TestCoalesceByChatWithinWindow(t *testing.T) {
	rec := newRecorder(t)
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{}, rec.srv.URL, clock)
	d.Enqueue(msg(chatA, "a1", ""))
	clock.Advance(3 * time.Second)
	d.Enqueue(msg(chatA, "a2", ""))
	d.Enqueue(msg(chatB, "b1", ""))
	// The first chat's window has not ended yet.
	clock.Advance(5 * time.Second)
	if b, wake := d.next(clock.Now()); b != nil || !wake.Equal(clock.Now().Add(2*time.Second)) {
		t.Fatalf("next = %v, %v; want nothing until the window ends", b, wake)
	}
	clock.Advance(2 * time.Second)
	drain(d, clock)
	reqs := rec.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests after the first window, want 1", len(reqs))
	}
	var p Payload
	_ = json.Unmarshal(reqs[0].body, &p)
	if p.Chat.JID != chatA || len(p.Messages) != 2 || p.Messages[0].ID != "a1" || p.Messages[1].ID != "a2" {
		t.Fatalf("batch = %+v", p)
	}
	clock.Advance(3 * time.Second)
	drain(d, clock)
	if len(rec.requests()) != 2 {
		t.Fatalf("second chat not delivered after its window")
	}
	if d.Queued() != 0 {
		t.Errorf("queued = %d", d.Queued())
	}
}

func TestFullBatchIsSentWithoutWaiting(t *testing.T) {
	rec := newRecorder(t)
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{MaxBatch: 2}, rec.srv.URL, clock)
	d.Enqueue(msg(chatA, "a1", ""))
	d.Enqueue(msg(chatA, "a2", ""))
	d.Enqueue(msg(chatA, "a3", ""))
	drain(d, clock)
	if n := len(rec.requests()); n != 1 {
		t.Fatalf("%d requests, want the full batch at once", n)
	}
}

func TestFilters(t *testing.T) {
	rec := newRecorder(t)
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{
		Chats:    []string{"+44 7700 000001", chatB},
		Keywords: []string{"reunião", "URGENT"},
	}, rec.srv.URL, clock)
	for _, m := range []Message{
		msg(chatA, "keep-accent", "a REUNIAO é amanhã"),
		msg(chatA, "keep-case", "this is urgent!"),
		msg(chatA, "drop-nokeyword", "nothing to see"),
		msg(chatB, "keep-group", "Urgent: call me"),
		msg("447700000099@s.whatsapp.net", "drop-chat", "urgent"),
	} {
		d.Enqueue(m)
	}
	clock.Advance(DefaultWindow)
	drain(d, clock)
	var ids []string
	for _, r := range rec.requests() {
		var p Payload
		_ = json.Unmarshal(r.body, &p)
		for _, m := range p.Messages {
			ids = append(ids, m.ID)
		}
	}
	got := strings.Join(ids, ",")
	for _, want := range []string{"keep-accent", "keep-case", "keep-group"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s not delivered (got %s)", want, got)
		}
	}
	if strings.Contains(got, "drop") {
		t.Errorf("filtered message delivered: %s", got)
	}
}

func TestHiddenChatIsNeverSent(t *testing.T) {
	rec := newRecorder(t)
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{}, rec.srv.URL, clock)
	d.Enqueue(msg(hiddenChat, "h1", "private"))
	clock.Advance(DefaultWindow)
	drain(d, clock)
	if n := len(rec.requests()); n != 0 {
		t.Fatalf("%d requests for a hidden chat", n)
	}

	// An access check that fails sends nothing either.
	d.opts.Allowed = func(context.Context, string) (bool, error) { return false, fmt.Errorf("db locked") }
	d.Enqueue(msg(chatA, "a1", ""))
	clock.Advance(DefaultWindow)
	drain(d, clock)
	if n := len(rec.requests()); n != 0 {
		t.Fatalf("%d requests when the access check failed", n)
	}
}

func TestRetryWithExponentialBackoff(t *testing.T) {
	rec := newRecorder(t, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusOK)
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{BaseBackoff: time.Second}, rec.srv.URL, clock)
	d.Enqueue(msg(chatA, "a1", ""))
	clock.Advance(DefaultWindow)
	drain(d, clock)
	reqs := rec.requests()
	if len(reqs) != 3 {
		t.Fatalf("%d attempts, want 3", len(reqs))
	}
	if got := fmt.Sprint(clock.sleeps); got != "[1s 2s]" {
		t.Errorf("backoff = %s, want [1s 2s]", got)
	}
	ids := map[string]bool{}
	for _, r := range reqs {
		ids[r.header.Get(HeaderDelivery)] = true
		if err := Verify(testSecret, r.header.Get(HeaderSignature), r.header.Get(HeaderTimestamp), r.body, clock.Now(), 5*time.Minute); err != nil {
			t.Errorf("retry signature: %v", err)
		}
	}
	if len(ids) != 1 {
		t.Errorf("retries carry %d delivery IDs, want 1", len(ids))
	}
}

func TestRetryGivesUpAfterAttempts(t *testing.T) {
	rec := newRecorder(t, 500, 500, 500, 500)
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{}, rec.srv.URL, clock)
	d.Enqueue(msg(chatA, "a1", ""))
	clock.Advance(DefaultWindow)
	drain(d, clock)
	if n := len(rec.requests()); n != DefaultAttempts {
		t.Fatalf("%d attempts, want %d", n, DefaultAttempts)
	}
	if got := fmt.Sprint(clock.sleeps); got != "[2s 4s]" {
		t.Errorf("backoff = %s", got)
	}
}

func TestNoRetryOnClientErrorOrRedirect(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusFound} {
		rec := newRecorder(t, status, status, status)
		clock := newFakeClock()
		d := newTestDispatcher(t, Config{}, rec.srv.URL, clock)
		d.Enqueue(msg(chatA, "a1", ""))
		clock.Advance(DefaultWindow)
		drain(d, clock)
		if n := len(rec.requests()); n != 1 {
			t.Errorf("status %d: %d requests, want 1 and no redirect followed", status, n)
		}
	}
}

func TestRetryOnNetworkError(t *testing.T) {
	rec := newRecorder(t)
	url := rec.srv.URL
	rec.srv.Close()
	clock := newFakeClock()
	d := newTestDispatcher(t, Config{}, url, clock)
	d.Enqueue(msg(chatA, "a1", ""))
	clock.Advance(DefaultWindow)
	drain(d, clock)
	if len(clock.sleeps) != DefaultAttempts-1 {
		t.Errorf("sleeps = %v, want %d retries", clock.sleeps, DefaultAttempts-1)
	}
}

type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) add(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *captureLogger) Infof(f string, a ...any)  { l.add(f, a...) }
func (l *captureLogger) Warnf(f string, a ...any)  { l.add(f, a...) }
func (l *captureLogger) Debugf(f string, a ...any) { l.add(f, a...) }

func TestQueueOverflowDropsOldest(t *testing.T) {
	rec := newRecorder(t)
	clock := newFakeClock()
	logs := &captureLogger{}
	d, err := New(Config{URL: rec.srv.URL, Secret: testSecret, QueueSize: 3, IncludeText: true},
		Options{Allowed: allowOnly(chatA, chatB), Clock: clock, Logger: logs})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		d.Enqueue(msg(chatA, fmt.Sprintf("a%d", i), fmt.Sprintf("body %d", i)))
		clock.Advance(time.Second)
	}
	if d.Queued() != 3 || d.Dropped() != 2 {
		t.Fatalf("queued %d dropped %d, want 3 and 2", d.Queued(), d.Dropped())
	}
	clock.Advance(DefaultWindow)
	drain(d, clock)
	var p Payload
	_ = json.Unmarshal(rec.requests()[0].body, &p)
	var ids []string
	for _, m := range p.Messages {
		ids = append(ids, m.ID)
	}
	if got := strings.Join(ids, ","); got != "a3,a4,a5" {
		t.Errorf("delivered %s, want the newest three", got)
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	var warned bool
	for _, l := range logs.lines {
		if strings.Contains(l, "queue full") {
			warned = true
		}
		if strings.Contains(l, "body") || strings.Contains(l, testSecret) {
			t.Errorf("log leaks content or secret: %s", l)
		}
	}
	if !warned {
		t.Error("no warning logged when dropping")
	}
}

func TestEnqueueNeverBlocksOnASlowEndpoint(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	d, err := New(Config{URL: srv.URL, Secret: testSecret, Window: time.Millisecond, QueueSize: 10, Timeout: 5 * time.Second},
		Options{Allowed: allowOnly(chatA)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		d.Enqueue(msg(chatA, fmt.Sprint(i), ""))
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("1000 enqueues took %s with a stuck endpoint", el)
	}
	if d.Queued() > 10 {
		t.Fatalf("queue grew to %d past its bound", d.Queued())
	}
}

func TestRunDeliversAfterWindow(t *testing.T) {
	got := make(chan Payload, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var p Payload
		_ = json.NewDecoder(r.Body).Decode(&p)
		got <- p
	}))
	t.Cleanup(srv.Close)
	d, err := New(Config{URL: srv.URL, Secret: testSecret, Window: 50 * time.Millisecond}, Options{Allowed: allowOnly(chatA)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	d.Enqueue(msg(chatA, "a1", ""))
	d.Enqueue(msg(chatA, "a2", ""))
	select {
	case p := <-got:
		if len(p.Messages) != 2 {
			t.Errorf("batch of %d, want 2", len(p.Messages))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing delivered")
	}
}
