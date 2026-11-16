package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Per-chat send policy, independent of read visibility.
//
//   - none:    write tools that target the chat are refused.
//   - confirm: they become outbox proposals the user approves.
//   - direct:  they act immediately.
//
// A chat without an explicit policy uses the daemon's default, derived from
// -confirm-sends (confirm when on, direct when off). The policy never widens
// visibility: a write still needs the chat to be visible under the access
// policy, and a hidden chat keeps answering "chat not found".
//
// The policy lives in its own table rather than as a column of chat_access
// because chat_access rows exist only for explicit read decisions, and its
// CHECK constraint (state IN ('allowed', 'denied')) cannot express "no read
// decision, but a send decision" without rebuilding that table. A sibling
// table keeps the two decisions independent (resetting one never clears the
// other), needs no migration of existing rows, and is created by a plain
// CREATE TABLE IF NOT EXISTS on old and new databases alike.

const sendPolicySchema = `
CREATE TABLE IF NOT EXISTS chat_send_policy (
	jid        TEXT PRIMARY KEY,
	policy     TEXT NOT NULL CHECK (policy IN ('none', 'confirm', 'direct')),
	decided_at TIMESTAMP NOT NULL
);
`

// Send policies. SendDefault means no explicit decision.
const (
	SendNone    = "none"
	SendConfirm = "confirm"
	SendDirect  = "direct"
	SendDefault = ""
)

// ValidSendPolicy reports whether p is one of none, confirm or direct.
func ValidSendPolicy(p string) bool {
	return p == SendNone || p == SendConfirm || p == SendDirect
}

// SetChatSendPolicy records the send policy for jid. SendDefault (or
// "reset") clears it, returning the chat to the daemon's default.
func (s *Store) SetChatSendPolicy(ctx context.Context, jid, policy string) error {
	jid = strings.TrimSpace(jid)
	if jid == "" {
		return errors.New("chat JID is required")
	}
	switch {
	case policy == SendDefault || policy == "reset" || policy == "default":
		_, err := s.db.ExecContext(ctx, "DELETE FROM chat_send_policy WHERE jid = ?", jid)
		return err
	case ValidSendPolicy(policy):
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO chat_send_policy (jid, policy, decided_at) VALUES (?, ?, ?)
			ON CONFLICT(jid) DO UPDATE SET policy = excluded.policy, decided_at = excluded.decided_at`,
			jid, policy, time.Now().UTC())
		return err
	default:
		return fmt.Errorf("send policy must be %q, %q, %q or \"reset\"", SendNone, SendConfirm, SendDirect)
	}
}

// ChatSendPolicy returns the explicit send policy for jid, or SendDefault.
func (s *Store) ChatSendPolicy(ctx context.Context, jid string) (string, error) {
	var p string
	err := s.db.QueryRowContext(ctx, "SELECT policy FROM chat_send_policy WHERE jid = ?", jid).Scan(&p)
	if errors.Is(err, sql.ErrNoRows) {
		return SendDefault, nil
	}
	if err != nil {
		return "", fmt.Errorf("read send policy: %w", err)
	}
	return p, nil
}

// applySendingSchema creates the send-policy table and brings the outbox
// table up to date (scheduled messages). It runs on every Open.
func applySendingSchema(db *sql.DB) error {
	if _, err := db.Exec(sendPolicySchema); err != nil {
		return fmt.Errorf("apply send policy schema: %w", err)
	}
	if _, err := db.Exec(outboxSchema); err != nil {
		return fmt.Errorf("apply outbox schema: %w", err)
	}
	if err := migrateOutbox(db); err != nil {
		return err
	}
	return migrateOutboxCreator(db)
}
