package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Per-chat send window: the time of day when the AI may write to a chat, for
// example 08:00-22:00. It is stored with the chat's send policy and read in
// the daemon's time zone (serve -timezone). A window may wrap midnight
// (22:00-06:00). The MCP layer defers messages outside the window to its
// next opening and refuses other writes (internal/mcp/sendwindow.go).

// SendWindow is a daily window [Start, End) in minutes after local midnight.
// Start > End wraps midnight. Start == End is not a valid window.
type SendWindow struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// ParseSendWindow reads "HH:MM-HH:MM" (a one-digit hour is accepted).
func ParseSendWindow(s string) (SendWindow, error) {
	from, to, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		return SendWindow{}, fmt.Errorf("send window %q must look like 08:00-22:00", s)
	}
	start, err := parseClock(from)
	if err != nil {
		return SendWindow{}, err
	}
	end, err := parseClock(to)
	if err != nil {
		return SendWindow{}, err
	}
	if start == end {
		return SendWindow{}, fmt.Errorf("send window %q is empty: start and end must differ (use \"off\" for no window)", s)
	}
	return SendWindow{Start: start, End: end}, nil
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	hour, err1 := strconv.Atoi(h)
	minute, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || len(h) == 0 || len(h) > 2 || len(m) != 2 || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid time of day %q: use HH:MM, 00:00 to 23:59", s)
	}
	return hour*60 + minute, nil
}

// String renders the window as "HH:MM-HH:MM".
func (w SendWindow) String() string {
	return fmt.Sprintf("%02d:%02d-%02d:%02d", w.Start/60, w.Start%60, w.End/60, w.End%60)
}

// Contains reports whether t falls inside the window, read on the wall clock
// of loc.
func (w SendWindow) Contains(t time.Time, loc *time.Location) bool {
	lt := t.In(loc)
	m := lt.Hour()*60 + lt.Minute()
	if w.Start < w.End {
		return m >= w.Start && m < w.End
	}
	return m >= w.Start || m < w.End
}

// NextOpening returns t when it is inside the window, else the first minute
// after t that is. It walks real minutes rather than building wall-clock
// times, so a start that falls into a DST gap (02:30 on a spring-forward
// night) opens at the first existing minute after it, and a repeated hour
// never opens twice.
func (w SendWindow) NextOpening(t time.Time, loc *time.Location) time.Time {
	if w.Contains(t, loc) {
		return t
	}
	c := t.Truncate(time.Minute).Add(time.Minute)
	// The window opens at least once a day; 50 hours also covers a 25-hour
	// day and one with a gap.
	for range 50 * 60 {
		if w.Contains(c, loc) {
			return c
		}
		c = c.Add(time.Minute)
	}
	return c // unreachable for a valid window
}

// sendPolicyTableV2 is chat_send_policy with a nullable policy (a chat may
// have a window but no explicit policy) and the send window.
const sendPolicyTableV2 = `
CREATE TABLE IF NOT EXISTS chat_send_policy (
	jid         TEXT PRIMARY KEY,
	policy      TEXT CHECK (policy IS NULL OR policy IN ('none', 'confirm', 'direct')),
	send_window TEXT,
	decided_at  TIMESTAMP NOT NULL
);
`

// migrateSendPolicy rebuilds a chat_send_policy table made by an older
// version (policy NOT NULL, no window), once, in a transaction, keeping
// every row.
func migrateSendPolicy(db *sql.DB) error {
	has, err := hasColumn(db, "chat_send_policy", "send_window")
	if err != nil || has {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{
		"ALTER TABLE chat_send_policy RENAME TO chat_send_policy_v1",
		sendPolicyTableV2,
		"INSERT INTO chat_send_policy (jid, policy, decided_at) SELECT jid, policy, decided_at FROM chat_send_policy_v1",
		"DROP TABLE chat_send_policy_v1",
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migrate chat_send_policy: %w", err)
		}
	}
	return tx.Commit()
}

// SetChatSendWindow sets the send window for jid ("08:00-22:00"), or clears
// it with "off", "reset" or "". The send policy is kept.
func (s *Store) SetChatSendWindow(ctx context.Context, jid, window string) error {
	jid = strings.TrimSpace(jid)
	if jid == "" {
		return errors.New("chat JID is required")
	}
	switch strings.TrimSpace(window) {
	case "", "off", "reset", "none":
		if _, err := s.db.ExecContext(ctx, "UPDATE chat_send_policy SET send_window = NULL WHERE jid = ?", jid); err != nil {
			return err
		}
		return s.pruneSendPolicy(ctx, jid)
	}
	w, err := ParseSendWindow(window)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO chat_send_policy (jid, send_window, decided_at) VALUES (?, ?, ?)
		ON CONFLICT(jid) DO UPDATE SET send_window = excluded.send_window, decided_at = excluded.decided_at`,
		jid, w.String(), time.Now().UTC())
	return err
}

// pruneSendPolicy drops a row that holds neither a policy nor a window.
func (s *Store) pruneSendPolicy(ctx context.Context, jid string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM chat_send_policy WHERE jid = ? AND policy IS NULL AND send_window IS NULL", jid)
	return err
}

// ChatSendWindow returns the send window for jid, or nil when it has none.
func (s *Store) ChatSendWindow(ctx context.Context, jid string) (*SendWindow, error) {
	var raw sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT send_window FROM chat_send_policy WHERE jid = ?", jid).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !raw.Valid) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read send window: %w", err)
	}
	w, err := ParseSendWindow(raw.String)
	if err != nil {
		return nil, fmt.Errorf("stored send window: %w", err)
	}
	return &w, nil
}
