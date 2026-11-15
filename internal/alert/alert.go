// Package alert notifies the operator when the WhatsApp session goes down,
// is logged out, or recovers, by POSTing to a webhook URL (any JSON
// receiver, or ntfy.sh with the plain-text format).
//
// Payloads never carry personal data: an event kind, a timestamp and a
// fixed message. Delivery runs on its own goroutine with retries, so the
// WhatsApp event loop is never blocked.
package alert

import (
	"fmt"
	"time"
)

// Event kinds.
const (
	SessionDown = "session_down"
	LoggedOut   = "logged_out"
	SessionUp   = "session_up"
)

// Event is one alert.
type Event struct {
	Kind string `json:"event"`
	// Since is when the session went down (for session_up: how long the
	// outage lasted is Since until now).
	Since   time.Time `json:"since"`
	Message string    `json:"message"`
}

// Monitor is the alert state machine. It is not safe for concurrent use;
// Watcher drives it from a single goroutine.
//
//   - A paired device that stays unauthenticated for longer than After
//     raises session_down once, with Since set to when it went down.
//   - A LoggedOut event raises logged_out immediately (once per logout).
//   - Once a session_down or logged_out alert went out, the next
//     authenticated observation raises session_up. Shorter outages that
//     never alerted recover silently.
//   - An unpaired device (never paired, or logged out) raises nothing more
//     until it is paired again.
type Monitor struct {
	After time.Duration

	downSince time.Time // zero while authenticated, or while unpaired and never alerted
	alerted   string    // kind of the last down alert sent, "" if none outstanding
}

// Observe feeds one health sample and returns the alert it triggers, if any.
func (m *Monitor) Observe(now time.Time, paired, authenticated bool) *Event {
	if authenticated {
		var ev *Event
		if m.alerted != "" {
			ev = &Event{Kind: SessionUp, Since: m.downSince, Message: fmt.Sprintf("WhatsApp session is back after %s", roundDur(now.Sub(m.downSince)))}
		}
		m.downSince, m.alerted = time.Time{}, ""
		return ev
	}
	if !paired {
		return nil
	}
	if m.downSince.IsZero() {
		m.downSince = now
	}
	if m.alerted == "" && now.Sub(m.downSince) >= m.After {
		m.alerted = SessionDown
		return &Event{Kind: SessionDown, Since: m.downSince, Message: fmt.Sprintf("WhatsApp session has not been authenticated for %s", roundDur(now.Sub(m.downSince)))}
	}
	return nil
}

// LoggedOut records that WhatsApp ended the session.
func (m *Monitor) LoggedOut(now time.Time) *Event {
	if m.alerted == LoggedOut {
		return nil
	}
	if m.downSince.IsZero() {
		m.downSince = now
	}
	m.alerted = LoggedOut
	return &Event{Kind: LoggedOut, Since: now, Message: "WhatsApp ended the session (logged out); link the device again with `wpp-mcp pair`"}
}

func roundDur(d time.Duration) time.Duration {
	if d < time.Minute {
		return d.Round(time.Second)
	}
	return d.Round(time.Minute)
}
