package daemon

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/clientip"
)

// HTTP rate limits. The daemon is exposed to the internet through a reverse
// proxy, so two limits sit in front of the handlers:
//
//   - authFailures locks out a client IP that keeps presenting bearer
//     credentials the daemon rejects. While the lock lasts every
//     authenticated route answers 429 before the token is even compared, so
//     guessing gets no feedback.
//   - identityLimiter is a token bucket per authenticated client token on
//     /mcp, so one connector cannot monopolise the daemon. The operator is
//     exempt.
//
// Both keep a bounded number of keys and evict the least recently seen one
// when full: an attacker spraying addresses can at worst push its own
// earlier entries out, never grow memory or lock everyone out.

// Defaults applied by `wpp-mcp serve`.
const (
	DefaultAuthFailLimit  = 20
	DefaultAuthFailWindow = time.Minute
	DefaultAuthCooldown   = 5 * time.Minute
	DefaultMCPRate        = 120 // requests per minute per client token
)

const (
	maxAuthFailKeys = 4096
	maxRateKeys     = 1024
)

// authFailures counts rejected bearer attempts per client IP in a fixed
// window and blocks an IP for a cool-down once it reaches the limit.
type authFailures struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	cooldown time.Duration
	now      func() time.Time
	entries  map[string]*failEntry
}

type failEntry struct {
	start   time.Time // start of the current counting window
	count   int
	blocked time.Time // zero, or the end of the cool-down
	seen    time.Time
}

// newAuthFailures returns nil when limit is 0 (disabled).
func newAuthFailures(limit int, window, cooldown time.Duration) *authFailures {
	if limit <= 0 {
		return nil
	}
	if window <= 0 {
		window = DefaultAuthFailWindow
	}
	if cooldown <= 0 {
		cooldown = DefaultAuthCooldown
	}
	return &authFailures{limit: limit, window: window, cooldown: cooldown, now: time.Now, entries: map[string]*failEntry{}}
}

// blocked reports whether ip is in a cool-down and how long it has left.
func (a *authFailures) blocked(ip string) (time.Duration, bool) {
	if a == nil {
		return 0, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.entries[ip]
	if !ok || e.blocked.IsZero() {
		return 0, false
	}
	now := a.now()
	if left := e.blocked.Sub(now); left > 0 {
		return left, true
	}
	delete(a.entries, ip) // cool-down over: start afresh
	return 0, false
}

// fail records one rejected attempt from ip.
func (a *authFailures) fail(ip string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	e, ok := a.entries[ip]
	if !ok {
		if len(a.entries) >= maxAuthFailKeys {
			a.evict(now)
		}
		e = &failEntry{start: now}
		a.entries[ip] = e
	}
	e.seen = now
	if !e.blocked.IsZero() {
		return
	}
	if now.Sub(e.start) >= a.window {
		e.start, e.count = now, 0
	}
	e.count++
	if e.count >= a.limit {
		e.blocked = now.Add(a.cooldown)
	}
}

// evict drops finished entries and, if still full, the least recently seen.
func (a *authFailures) evict(now time.Time) {
	var oldest string
	var oldestAt time.Time
	for k, e := range a.entries {
		expired := now.Sub(e.start) >= a.window && (e.blocked.IsZero() || !now.Before(e.blocked))
		if expired {
			delete(a.entries, k)
			continue
		}
		if oldest == "" || e.seen.Before(oldestAt) {
			oldest, oldestAt = k, e.seen
		}
	}
	if len(a.entries) >= maxAuthFailKeys && oldest != "" {
		delete(a.entries, oldest)
	}
}

func (a *authFailures) size() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

// identityLimiter is a token bucket per key.
type identityLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newIdentityLimiter allows perMinute requests per minute per key, with a
// burst of half that (at least 1). It returns nil when perMinute is 0.
func newIdentityLimiter(perMinute int) *identityLimiter {
	if perMinute <= 0 {
		return nil
	}
	return &identityLimiter{
		rate:    float64(perMinute) / 60,
		burst:   math.Max(1, float64(perMinute)/2),
		now:     time.Now,
		buckets: map[string]*bucket{},
	}
}

// allow spends one token for key, or reports how long until one is free.
func (l *identityLimiter) allow(key string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxRateKeys {
			l.evict(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) / l.rate * float64(time.Second)), false
	}
	b.tokens--
	return 0, true
}

// evict drops full buckets (they hold no state worth keeping) and, if still
// full, the least recently used one.
func (l *identityLimiter) evict(now time.Time) {
	var oldest string
	var oldestAt time.Time
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
			continue
		}
		if oldest == "" || b.last.Before(oldestAt) {
			oldest, oldestAt = k, b.last
		}
	}
	if len(l.buckets) >= maxRateKeys && oldest != "" {
		delete(l.buckets, oldest)
	}
}

func (l *identityLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// retryAfter renders a Retry-After value in whole seconds, at least 1.
func retryAfter(d time.Duration) string {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
}

// tooManyAuthFailures is the lock-out answer. It never says whether the
// last credential was valid.
func tooManyAuthFailures(w http.ResponseWriter, left time.Duration) {
	w.Header().Set("Retry-After", retryAfter(left))
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "too many failed authentication attempts; retry later", http.StatusTooManyRequests)
}

// mcpRateLimit applies l to /mcp per client token. The operator and other
// paths pass through. The 429 carries a JSON-RPC error body, so MCP clients
// that parse the response see a structured error rather than plain text.
func mcpRateLimit(next http.Handler, l *identityLimiter) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMCPPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		id, ok := auth.FromContext(r.Context())
		if !ok || id.IsOperator() {
			next.ServeHTTP(w, r)
			return
		}
		wait, ok := l.allow("token:" + strconv.FormatInt(id.TokenID, 10))
		if ok {
			next.ServeHTTP(w, r)
			return
		}
		secs := retryAfter(wait)
		w.Header().Set("Retry-After", secs)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      nil,
			"error": map[string]any{
				"code":    -32000,
				"message": "rate limited: too many requests for this token, retry after " + secs + "s",
				"data":    map[string]any{"retry_after": json.Number(secs)},
			},
		})
	})
}

// requestIP is the key the failure limiter uses.
func requestIP(r *http.Request) string { return clientip.FromRequest(r) }
