package client

import (
	"sync/atomic"
	"time"

	"go.mau.fi/whatsmeow/types/events"
)

// clientStats holds the counters behind /admin/metrics. They carry no
// personal data: only counts and times.
type clientStats struct {
	received     atomic.Uint64
	sent         atomic.Uint64
	lastReceived atomic.Int64 // unix nanoseconds; 0 = none since start
	onLoggedOut  atomic.Pointer[func()]
}

// observe updates the counters from a whatsmeow event. It runs on the event
// loop, so it must never block: the logged-out hook is expected to return
// immediately (the alerter only queues an event).
func (s *clientStats) observe(evt any) {
	switch v := evt.(type) {
	case *events.Message:
		if !v.Info.IsFromMe {
			s.received.Add(1)
			s.lastReceived.Store(time.Now().UnixNano())
		}
	case *events.LoggedOut:
		if fn := s.onLoggedOut.Load(); fn != nil {
			(*fn)()
		}
	}
}

// countSent records one message delivered to WhatsApp.
func (c *Client) countSent() { c.stats.sent.Add(1) }

// Stats is a snapshot of the client's health and counters.
type Stats struct {
	// Paired: a device identity is stored (IsLoggedIn).
	Paired bool
	// Connected: the websocket is up.
	Connected bool
	// Authenticated: WhatsApp accepted the session on this connection
	// (whatsmeow's IsLoggedIn).
	Authenticated bool
	// State is the last connection event (see ConnectionStatus).
	State            string
	MessagesReceived uint64
	MessagesSent     uint64
	// LastReceived is when the last incoming live message arrived since the
	// daemon started; zero if none.
	LastReceived time.Time
}

// Stats returns a snapshot for metrics.
func (c *Client) Stats() Stats {
	s := Stats{
		State:            c.ConnectionStatus().State,
		MessagesReceived: c.stats.received.Load(),
		MessagesSent:     c.stats.sent.Load(),
	}
	if c.wa != nil {
		s.Paired = c.wa.Store != nil && c.wa.Store.ID != nil
		s.Connected = c.wa.IsConnected()
		s.Authenticated = c.wa.IsLoggedIn()
	}
	if ns := c.stats.lastReceived.Load(); ns != 0 {
		s.LastReceived = time.Unix(0, ns)
	}
	return s
}

// OnLoggedOut registers fn to run when WhatsApp ends the session (a
// LoggedOut event, or Logout). Unlike AddLoggedOutHandler it survives the
// whatsmeow client being replaced after pairing. fn runs on the event loop
// and must not block.
func (c *Client) OnLoggedOut(fn func()) { c.stats.onLoggedOut.Store(&fn) }
