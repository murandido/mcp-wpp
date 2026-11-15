// Package webhook posts live incoming WhatsApp messages to an operator's
// HTTP endpoint, signed with HMAC-SHA256.
//
// Only messages from chats the access policy allows are sent, after the
// optional chat and keyword filters. Message text is left out unless the
// operator opts in (Config.IncludeText); media bytes are never sent.
//
// Delivery never blocks message handling: Enqueue only appends to a bounded
// in-memory queue, and a single worker (Run) coalesces messages of the same
// chat that arrive within Config.Window into one request, then posts it with
// a timeout and retries with exponential backoff. When the queue is full the
// oldest queued message is dropped. Delivery is best effort: queued messages
// are lost when the daemon stops, and a retry after a timeout can deliver a
// request twice (receivers deduplicate on the delivery ID).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Request headers.
const (
	HeaderSignature = "X-Wpp-Mcp-Signature"
	HeaderTimestamp = "X-Wpp-Mcp-Timestamp"
	HeaderDelivery  = "X-Wpp-Mcp-Delivery"
	HeaderEvent     = "X-Wpp-Mcp-Event"
)

// EventMessages is the payload type of a batch of received messages.
const EventMessages = "messages.received"

// Defaults for the zero values of Config.
const (
	DefaultWindow    = 10 * time.Second
	DefaultMaxBatch  = 50
	DefaultQueueSize = 500
	DefaultAttempts  = 3
	DefaultBackoff   = 2 * time.Second
	DefaultTimeout   = 10 * time.Second
	// MinSecretLength is the shortest accepted signing secret.
	MinSecretLength = 16
)

// Config configures webhook delivery.
type Config struct {
	URL         string
	Secret      string
	IncludeText bool     // send message text and captions (they leave the machine)
	Chats       []string // only these chats (JIDs or phone numbers); empty: every allowed chat
	Keywords    []string // only messages whose text contains one of these (case- and accent-insensitive)

	Window      time.Duration // coalescing window per chat
	MaxBatch    int           // messages per request; a full batch is sent at once
	QueueSize   int           // messages held in memory, queued or waiting to be sent
	Attempts    int           // delivery attempts per request
	BaseBackoff time.Duration // wait before the second attempt; doubles each time
	Timeout     time.Duration // per attempt
}

// Enabled reports whether a webhook URL is configured.
func (c Config) Enabled() bool { return c.URL != "" }

// Validate checks the URL and secret. Plain HTTP is accepted only for a
// loopback or private-network host (a private IP, localhost, or a
// single-label name such as a Docker Compose service).
func (c Config) Validate() error {
	_, err := c.endpoint()
	return err
}

func (c Config) endpoint() (*url.URL, error) {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("webhook: -webhook-url must be an http(s) URL")
	}
	if u.Scheme != "https" && !isPrivateHost(u.Hostname()) {
		return nil, fmt.Errorf("webhook: %s is not a loopback or private-network host, so the URL must use https", u.Hostname())
	}
	if len(c.Secret) < MinSecretLength {
		return nil, fmt.Errorf("webhook: -webhook-secret is required with -webhook-url and must be at least %d characters (for example `openssl rand -hex 32`)", MinSecretLength)
	}
	return u, nil
}

// isPrivateHost reports whether host is loopback, a private-network IP, or a
// name public DNS cannot serve (localhost, a single label).
func isPrivateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	return !strings.Contains(host, ".")
}

// ParseList splits a comma-separated flag value, dropping empty items.
func ParseList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeChat turns a phone number into a user JID; JIDs pass through.
func normalizeChat(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "@") {
		return s
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	if digits == "" {
		return s
	}
	return digits + "@s.whatsapp.net"
}

// fold lowercases and strips diacritics: "Reunião" → "reuniao".
func fold(s string) string {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	out, _, err := transform.String(t, strings.ToLower(s))
	if err != nil {
		return strings.ToLower(s)
	}
	return out
}

// Message is a live incoming message to report.
type Message struct {
	ChatJID    string
	ChatName   string
	IsGroup    bool
	ID         string
	Timestamp  time.Time
	SenderJID  string
	SenderName string
	Text       string
	MediaType  string
}

// Payload is the JSON body of a request. One request carries one or more
// messages of a single chat.
type Payload struct {
	Version    int              `json:"version"`
	Type       string           `json:"type"`
	DeliveryID string           `json:"delivery_id"`
	Chat       PayloadChat      `json:"chat"`
	Messages   []PayloadMessage `json:"messages"`
}

// PayloadChat identifies the chat of a payload.
type PayloadChat struct {
	JID     string `json:"jid"`
	Name    string `json:"name,omitempty"`
	IsGroup bool   `json:"is_group"`
}

// PayloadMessage is one message of a payload.
type PayloadMessage struct {
	ID        string        `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	Sender    PayloadSender `json:"sender"`
	HasMedia  bool          `json:"has_media"`
	MediaType string        `json:"media_type,omitempty"`
	Text      string        `json:"text,omitempty"` // only with IncludeText
}

// PayloadSender identifies who sent a message.
type PayloadSender struct {
	JID  string `json:"jid"`
	Name string `json:"name,omitempty"`
}

// Sign returns the signature header value for body sent at timestamp (Unix
// seconds): "sha256=" + hex(HMAC-SHA256(secret, timestamp + "." + body)).
func Sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a request's signature and rejects timestamps further than
// tolerance from now. Receivers written in Go can use it directly.
func Verify(secret, signature, timestamp string, body []byte, now time.Time, tolerance time.Duration) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("webhook: bad timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return errors.New("webhook: timestamp outside the tolerance")
	}
	if !hmac.Equal([]byte(Sign(secret, ts, body)), []byte(signature)) {
		return errors.New("webhook: bad signature")
	}
	return nil
}

// Clock is the time source of a Dispatcher; tests replace it.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is done.
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Logger is the subset of whatsmeow's logger the dispatcher uses.
type Logger interface {
	Infof(msg string, args ...any)
	Warnf(msg string, args ...any)
	Debugf(msg string, args ...any)
}

// Options are the dispatcher's collaborators.
type Options struct {
	// Allowed reports whether the access policy allows a chat. It is
	// checked when a batch is sent, so revoking access stops queued
	// messages too. Required: a nil Allowed sends nothing.
	Allowed func(ctx context.Context, chatJID string) (bool, error)
	Logger  Logger
	// RedactJID masks a JID for logs (security.Redactor.JID).
	RedactJID func(string) string
	Clock     Clock
	// HTTPClient overrides the default client (tests). It must not follow
	// redirects.
	HTTPClient *http.Client
}

type batch struct {
	chat     string
	started  time.Time
	deadline time.Time
	msgs     []Message
}

// Dispatcher queues and delivers webhook requests.
type Dispatcher struct {
	cfg      Config
	endpoint string
	host     string
	opts     Options
	chats    map[string]bool
	keywords []string

	mu          sync.Mutex
	pending     map[string]*batch // per chat, waiting for its window to end
	ready       []*batch          // waiting to be sent, oldest first
	queued      int               // messages in pending and ready
	dropped     int
	lastDropLog time.Time
	wake        chan struct{}
}

// New validates cfg and returns a dispatcher. Call Run to start delivery.
func New(cfg Config, opts Options) (*Dispatcher, error) {
	u, err := cfg.endpoint()
	if err != nil {
		return nil, err
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = DefaultMaxBatch
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = DefaultAttempts
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = DefaultBackoff
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if opts.Clock == nil {
		opts.Clock = realClock{}
	}
	if opts.RedactJID == nil {
		opts.RedactJID = func(string) string { return "[chat]" }
	}
	if opts.Logger == nil {
		opts.Logger = nopLogger{}
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	d := &Dispatcher{
		cfg:      cfg,
		endpoint: u.String(),
		host:     u.Host,
		opts:     opts,
		pending:  map[string]*batch{},
		wake:     make(chan struct{}, 1),
	}
	if len(cfg.Chats) > 0 {
		d.chats = map[string]bool{}
		for _, c := range cfg.Chats {
			d.chats[normalizeChat(c)] = true
		}
	}
	for _, k := range cfg.Keywords {
		if k = fold(strings.TrimSpace(k)); k != "" {
			d.keywords = append(d.keywords, k)
		}
	}
	return d, nil
}

// Host is the endpoint's host, safe to log.
func (d *Dispatcher) Host() string { return d.host }

type nopLogger struct{}

func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Debugf(string, ...any) {}

// matches applies the chat and keyword filters.
func (d *Dispatcher) matches(m Message) bool {
	if d.chats != nil && !d.chats[m.ChatJID] {
		return false
	}
	if len(d.keywords) == 0 {
		return true
	}
	text := fold(m.Text)
	for _, k := range d.keywords {
		if strings.Contains(text, k) {
			return true
		}
	}
	return false
}

// Enqueue queues m if it passes the filters. It never blocks on the network.
func (d *Dispatcher) Enqueue(m Message) {
	if m.ChatJID == "" || !d.matches(m) {
		return
	}
	now := d.opts.Clock.Now()
	d.mu.Lock()
	if d.queued >= d.cfg.QueueSize {
		d.dropOldestLocked(now)
	}
	b := d.pending[m.ChatJID]
	if b == nil {
		b = &batch{chat: m.ChatJID, started: now, deadline: now.Add(d.cfg.Window)}
		d.pending[m.ChatJID] = b
	}
	b.msgs = append(b.msgs, m)
	d.queued++
	if len(b.msgs) >= d.cfg.MaxBatch {
		delete(d.pending, m.ChatJID)
		d.ready = append(d.ready, b)
	}
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// dropOldestLocked discards the oldest queued message.
func (d *Dispatcher) dropOldestLocked(now time.Time) {
	var b *batch
	if len(d.ready) > 0 {
		b = d.ready[0]
	} else {
		for _, p := range d.pending {
			if b == nil || p.started.Before(b.started) {
				b = p
			}
		}
	}
	if b == nil {
		return
	}
	b.msgs = b.msgs[1:]
	d.queued--
	d.dropped++
	if len(b.msgs) == 0 {
		if len(d.ready) > 0 && d.ready[0] == b {
			d.ready = d.ready[1:]
		} else {
			delete(d.pending, b.chat)
		}
	}
	if d.lastDropLog.IsZero() || now.Sub(d.lastDropLog) >= time.Minute {
		d.lastDropLog = now
		d.opts.Logger.Warnf("Webhook queue full (%d messages): dropped the oldest; %d dropped so far", d.cfg.QueueSize, d.dropped)
	}
}

// Dropped returns how many messages the full queue has discarded.
func (d *Dispatcher) Dropped() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dropped
}

// Queued returns how many messages wait to be sent.
func (d *Dispatcher) Queued() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queued
}

// next moves batches whose window has ended to the ready list and pops the
// oldest ready batch. With none ready, it returns the time the next window
// ends (zero when nothing is pending).
func (d *Dispatcher) next(now time.Time) (*batch, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var due []*batch
	for chat, b := range d.pending {
		if !now.Before(b.deadline) {
			due = append(due, b)
			delete(d.pending, chat)
		}
	}
	// Oldest first, so the ready list keeps arrival order.
	for i := 1; i < len(due); i++ {
		for j := i; j > 0 && due[j].started.Before(due[j-1].started); j-- {
			due[j], due[j-1] = due[j-1], due[j]
		}
	}
	d.ready = append(d.ready, due...)
	if len(d.ready) > 0 {
		b := d.ready[0]
		d.ready = d.ready[1:]
		d.queued -= len(b.msgs)
		return b, time.Time{}
	}
	var wake time.Time
	for _, b := range d.pending {
		if wake.IsZero() || b.deadline.Before(wake) {
			wake = b.deadline
		}
	}
	return nil, wake
}

// Run delivers queued batches until ctx is done. Messages still queued then
// are discarded.
func (d *Dispatcher) Run(ctx context.Context) {
	for {
		b, wake := d.next(d.opts.Clock.Now())
		if b != nil {
			d.deliver(ctx, b)
			if ctx.Err() != nil {
				return
			}
			continue
		}
		var (
			timer <-chan time.Time
			t     *time.Timer
		)
		if !wake.IsZero() {
			t = time.NewTimer(wake.Sub(d.opts.Clock.Now()))
			timer = t.C
		}
		select {
		case <-ctx.Done():
		case <-d.wake:
		case <-timer:
		}
		if t != nil {
			t.Stop()
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// payload builds the request body for b.
func (d *Dispatcher) payload(b *batch) (Payload, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Payload{}, err
	}
	first := b.msgs[0]
	p := Payload{
		Version:    1,
		Type:       EventMessages,
		DeliveryID: hex.EncodeToString(id),
		Chat:       PayloadChat{JID: b.chat, Name: first.ChatName, IsGroup: first.IsGroup},
		Messages:   make([]PayloadMessage, 0, len(b.msgs)),
	}
	for _, m := range b.msgs {
		if m.ChatName != "" {
			p.Chat.Name = m.ChatName
		}
		pm := PayloadMessage{
			ID:        m.ID,
			Timestamp: m.Timestamp.UTC(),
			Sender:    PayloadSender{JID: m.SenderJID, Name: m.SenderName},
			HasMedia:  m.MediaType != "",
			MediaType: m.MediaType,
		}
		if d.cfg.IncludeText {
			pm.Text = m.Text
		}
		p.Messages = append(p.Messages, pm)
	}
	return p, nil
}

// deliver sends one batch, retrying transient failures.
func (d *Dispatcher) deliver(ctx context.Context, b *batch) {
	if len(b.msgs) == 0 {
		return
	}
	chat := d.opts.RedactJID(b.chat)
	if d.opts.Allowed == nil {
		return
	}
	ok, err := d.opts.Allowed(ctx, b.chat)
	if err != nil || !ok {
		// Hidden chats are skipped silently; a policy read error fails closed.
		if err != nil {
			d.opts.Logger.Warnf("Webhook: access check failed for %s; not sent", chat)
		}
		return
	}
	p, err := d.payload(b)
	if err != nil {
		d.opts.Logger.Warnf("Webhook: build payload: %v", err)
		return
	}
	body, err := json.Marshal(p)
	if err != nil {
		d.opts.Logger.Warnf("Webhook: encode payload: %v", err)
		return
	}
	for attempt := 1; attempt <= d.cfg.Attempts; attempt++ {
		retry, err := d.post(ctx, p.DeliveryID, body)
		if err == nil {
			d.opts.Logger.Debugf("Webhook: delivered %d message(s) from %s to %s", len(p.Messages), chat, d.host)
			return
		}
		if !retry || attempt == d.cfg.Attempts {
			d.opts.Logger.Warnf("Webhook: delivery of %d message(s) from %s to %s failed after %d attempt(s): %v", len(p.Messages), chat, d.host, attempt, err)
			return
		}
		wait := d.cfg.BaseBackoff << (attempt - 1)
		d.opts.Logger.Debugf("Webhook: attempt %d to %s failed (%v); retrying in %s", attempt, d.host, err, wait)
		if d.opts.Clock.Sleep(ctx, wait) != nil {
			return
		}
	}
}

// post makes one attempt. It reports whether a failure is worth retrying.
// Errors never include the URL, which may carry a token.
func (d *Dispatcher) post(ctx context.Context, deliveryID string, body []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, errors.New("bad request")
	}
	ts := d.opts.Clock.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "wpp-mcp-webhook/1")
	req.Header.Set(HeaderEvent, EventMessages)
	req.Header.Set(HeaderDelivery, deliveryID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, Sign(d.cfg.Secret, ts, body))
	resp, err := d.opts.HTTPClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return true, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooEarly,
		resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return true, fmt.Errorf("HTTP %d", resp.StatusCode)
	default:
		// Redirects are not followed, and other client errors will not
		// succeed on a retry.
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
}
