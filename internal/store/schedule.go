package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scheduled messages share the outbox table: a row with send_at set. Their
// lifecycle:
//
//	pending   → scheduled  the user approved the proposal (send policy confirm)
//	scheduled              created directly (policy direct, or by the operator)
//	scheduled → sent/failed the scheduler claimed it at send_at and sent it
//	scheduled → missed     the daemon was down more than MaxSendDelay past send_at
//	pending|scheduled → cancelled  `wpp-mcp outbox cancel`
//
// A pending scheduled proposal expires at send_at rather than after
// ProposalTTL: approving it later than that would be pointless.

const (
	// MaxScheduleAhead bounds how far in the future a message may be scheduled.
	MaxScheduleAhead = 30 * 24 * time.Hour
	// MaxSendDelay is how late a scheduled message may still be sent, for
	// items that came due while the daemon was down.
	MaxSendDelay = time.Hour
	// maxScheduled bounds the scheduled queue so a looping or injected model
	// cannot fill it.
	maxScheduled = 50
)

// ErrScheduleTime is returned for send times in the past or too far ahead.
var ErrScheduleTime = errors.New("invalid send time")

// ValidateSendAt checks that sendAt lies after now and at most
// MaxScheduleAhead ahead.
func ValidateSendAt(sendAt, now time.Time) error {
	if !sendAt.After(now) {
		return fmt.Errorf("%w: %s is in the past", ErrScheduleTime, sendAt.Format(time.RFC3339))
	}
	if sendAt.After(now.Add(MaxScheduleAhead)) {
		return fmt.Errorf("%w: %s is more than 30 days ahead", ErrScheduleTime, sendAt.Format(time.RFC3339))
	}
	return nil
}

// migrateOutbox adds send_at and the scheduling statuses to an outbox table
// created by an older version. SQLite cannot alter a CHECK constraint, so the
// table is rebuilt once, in a transaction, keeping every row and its ID.
func migrateOutbox(db *sql.DB) error {
	var ddl string
	if err := db.QueryRow("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'outbox'").Scan(&ddl); err != nil {
		return fmt.Errorf("read outbox schema: %w", err)
	}
	if strings.Contains(ddl, "send_at") {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	const cols = "id, tool, args_json, summary, status, result, created_at, expires_at, decided_at"
	for _, stmt := range []string{
		"ALTER TABLE outbox RENAME TO outbox_v1",
		outboxSchema,
		"INSERT INTO outbox (" + cols + ") SELECT " + cols + " FROM outbox_v1",
		"DROP TABLE outbox_v1",
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migrate outbox: %w", err)
		}
	}
	return tx.Commit()
}

// migrateOutboxCreator adds the creator columns to an outbox table made by an
// older version. Existing rows keep NULL (an unknown creator).
func migrateOutboxCreator(db *sql.DB) error {
	for _, col := range []struct{ name, typ string }{{"created_by", "TEXT"}, {"created_by_token", "INTEGER"}} {
		has, err := hasColumn(db, "outbox", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec("ALTER TABLE outbox ADD COLUMN " + col.name + " " + col.typ); err != nil {
				return fmt.Errorf("add column outbox.%s: %w", col.name, err)
			}
		}
	}
	return nil
}

// CreateScheduledProposal records a scheduled message awaiting approval.
// Approval (ClaimProposal) turns it into a scheduled item; until then it
// expires at sendAt.
func (s *Store) CreateScheduledProposal(ctx context.Context, tool, argsJSON, summary string, sendAt, now time.Time) (*Proposal, error) {
	if err := s.expireProposals(ctx); err != nil {
		return nil, err
	}
	var pending int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM outbox WHERE status = 'pending'").Scan(&pending); err != nil {
		return nil, err
	}
	if pending >= maxPendingProposals {
		return nil, fmt.Errorf("there are already %d actions awaiting approval; ask the user to review them first", pending)
	}
	return s.insertScheduled(ctx, OutboxPending, tool, argsJSON, summary, sendAt, now)
}

// ScheduleMessage records a message the scheduler sends at sendAt, without
// asking for approval (send policy direct, or an operator action).
func (s *Store) ScheduleMessage(ctx context.Context, tool, argsJSON, summary string, sendAt, now time.Time) (*Proposal, error) {
	return s.insertScheduled(ctx, OutboxScheduled, tool, argsJSON, summary, sendAt, now)
}

func (s *Store) insertScheduled(ctx context.Context, status, tool, argsJSON, summary string, sendAt, now time.Time) (*Proposal, error) {
	if err := ValidateSendAt(sendAt, now); err != nil {
		return nil, err
	}
	var queued int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM outbox WHERE send_at IS NOT NULL AND status IN ('pending', 'scheduled')").Scan(&queued); err != nil {
		return nil, err
	}
	if queued >= maxScheduled {
		return nil, fmt.Errorf("there are already %d scheduled messages; cancel some first", queued)
	}
	now = now.UTC()
	sendAt = sendAt.UTC().Truncate(time.Second)
	by, tokenID := creatorFrom(ctx)
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO outbox (tool, args_json, summary, status, created_at, expires_at, send_at, created_by, created_by_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		tool, argsJSON, summary, status, now, sendAt, sendAt, by, tokenID)
	if err != nil {
		return nil, fmt.Errorf("schedule message: %w", err)
	}
	id, _ := res.LastInsertId()
	return withCreator(&Proposal{ID: id, Tool: tool, ArgsJSON: argsJSON, Summary: summary, Status: status, CreatedAt: now, ExpiresAt: sendAt, SendAt: &sendAt}, by, tokenID), nil
}

// MarkMissedScheduled marks scheduled items more than maxLate past their
// send time as missed, and returns how many it marked.
func (s *Store) MarkMissedScheduled(ctx context.Context, now time.Time, maxLate time.Duration) (int64, error) {
	now = now.UTC()
	reason := fmt.Sprintf("not sent: the daemon was not running or not connected within %s of the send time", maxLate)
	res, err := s.db.ExecContext(ctx, "UPDATE outbox SET status = 'missed', decided_at = ?, result = ? WHERE status = 'scheduled' AND send_at < ?",
		now, reason, now.Add(-maxLate))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DueScheduled returns scheduled items whose send time has come, oldest
// first.
func (s *Store) DueScheduled(ctx context.Context, now time.Time) ([]Proposal, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+proposalColumns+" FROM outbox WHERE status = 'scheduled' AND send_at <= ? ORDER BY send_at, id", now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proposal
	for rows.Next() {
		p, err := scanProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ClaimScheduled atomically takes a due scheduled item so it is sent at most
// once (it moves to 'sent'; FinishProposal records the real outcome). It
// returns ErrProposalNotPending if the item was cancelled, already claimed,
// or is not due.
func (s *Store) ClaimScheduled(ctx context.Context, id int64, now time.Time) (*Proposal, error) {
	now = now.UTC()
	res, err := s.db.ExecContext(ctx, "UPDATE outbox SET status = 'sent', decided_at = ? WHERE id = ? AND status = 'scheduled' AND send_at <= ?", now, id, now)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrProposalNotPending
	}
	p, err := scanProposal(s.db.QueryRowContext(ctx, "SELECT "+proposalColumns+" FROM outbox WHERE id = ?", id))
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// NextScheduledAt returns the earliest send time among scheduled items, or
// nil when nothing is scheduled.
func (s *Store) NextScheduledAt(ctx context.Context) (*time.Time, error) {
	var next sql.NullTime
	// MIN() loses the column type, so order and take the first row instead.
	err := s.db.QueryRowContext(ctx, "SELECT send_at FROM outbox WHERE status = 'scheduled' ORDER BY send_at LIMIT 1").Scan(&next)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !next.Valid) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &next.Time, nil
}

// GetProposal returns one outbox item.
func (s *Store) GetProposal(ctx context.Context, id int64) (*Proposal, error) {
	p, err := scanProposal(s.db.QueryRowContext(ctx, "SELECT "+proposalColumns+" FROM outbox WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// CancelProposal withdraws a pending proposal or a scheduled message.
func (s *Store) CancelProposal(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "UPDATE outbox SET status = 'cancelled', decided_at = ? WHERE id = ? AND status IN ('pending', 'scheduled')", time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("nothing to cancel: the item is not pending or scheduled")
	}
	return nil
}
