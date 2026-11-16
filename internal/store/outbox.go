package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/auth"
)

// Outbox of proposed account actions awaiting the user's approval, and of
// scheduled messages. When a chat's send policy is "confirm", write tools
// record a proposal here instead of acting; the user approves or rejects it
// outside the conversation. Scheduled messages (send_at set) live in the
// same table so `wpp-mcp outbox` is the single place to see what will be
// sent; see schedule.go for their lifecycle.

const outboxSchema = `
CREATE TABLE IF NOT EXISTS outbox (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	tool        TEXT NOT NULL,
	args_json   TEXT NOT NULL,
	summary     TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'pending'
	            CHECK (status IN ('pending', 'scheduled', 'sent', 'failed', 'rejected', 'expired', 'missed', 'cancelled')),
	result      TEXT,
	created_at  TIMESTAMP NOT NULL,
	expires_at  TIMESTAMP NOT NULL,
	decided_at  TIMESTAMP,
	send_at     TIMESTAMP,
	created_by  TEXT,
	created_by_token INTEGER
);
`

// Outbox statuses.
const (
	OutboxPending   = "pending"   // awaiting the user's approval
	OutboxScheduled = "scheduled" // approved, waiting for send_at
	OutboxSent      = "sent"
	OutboxFailed    = "failed"
	OutboxRejected  = "rejected"
	OutboxExpired   = "expired"   // nobody decided in time
	OutboxMissed    = "missed"    // the daemon was down too long past send_at
	OutboxCancelled = "cancelled" // the user withdrew it
)

// ProposalTTL is how long a proposal waits for a decision.
const ProposalTTL = 15 * time.Minute

const maxPendingProposals = 20

// Proposal is one pending or decided action.
type Proposal struct {
	ID        int64      `json:"id"`
	Tool      string     `json:"tool"`
	ArgsJSON  string     `json:"args_json"`
	Summary   string     `json:"summary"`
	Status    string     `json:"status"`
	Result    string     `json:"result,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	// SendAt is set for scheduled messages: when the daemon sends it.
	SendAt *time.Time `json:"send_at,omitempty"`
	// CreatedBy is who made the item: "operator", "token:<name>" or
	// CreatorOperatorCLI; "" for items made before it was recorded.
	CreatedBy string `json:"created_by,omitempty"`
	// CreatorTokenID is the client token that made the item, 0 for the
	// operator. Approving or sending an item whose token has been revoked
	// is refused (see CreatorRevoked).
	CreatorTokenID int64 `json:"created_by_token_id,omitempty"`
}

// CreatorOperatorCLI marks items the operator scheduled with `wpp-mcp
// schedule`. MCP calls made with the operator token are recorded as
// "operator", so the two stay distinguishable.
const CreatorOperatorCLI = "operator:cli"

type creatorKey struct{}

// WithCreator overrides the creator recorded for items created with ctx
// (operator commands). Without it, the creator is the caller on ctx
// (auth.Caller).
func WithCreator(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, creatorKey{}, actor)
}

// creatorFrom returns the actor and client token ID (nil for none) to
// record for a new item.
func creatorFrom(ctx context.Context) (string, any) {
	if a, ok := ctx.Value(creatorKey{}).(string); ok && a != "" {
		return a, nil
	}
	id := auth.Caller(ctx)
	if id.TokenID != 0 {
		return id.Actor(), id.TokenID
	}
	return id.Actor(), nil
}

func withCreator(p *Proposal, by string, tokenID any) *Proposal {
	p.CreatedBy = by
	if t, ok := tokenID.(int64); ok {
		p.CreatorTokenID = t
	}
	return p
}

// ErrProposalNotPending is returned when deciding a proposal that is not
// pending (already decided, or expired).
var ErrProposalNotPending = errors.New("proposal is not pending")

// expireProposals marks stale pending proposals expired.
func (s *Store) expireProposals(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status = 'expired', decided_at = ? WHERE status = 'pending' AND expires_at < ?",
		time.Now().UTC(), time.Now().UTC())
	return err
}

// CreateProposal records a pending action.
func (s *Store) CreateProposal(ctx context.Context, tool, argsJSON, summary string) (*Proposal, error) {
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
	now := time.Now().UTC()
	by, tokenID := creatorFrom(ctx)
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO outbox (tool, args_json, summary, status, created_at, expires_at, created_by, created_by_token) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)",
		tool, argsJSON, summary, now, now.Add(ProposalTTL), by, tokenID)
	if err != nil {
		return nil, fmt.Errorf("create proposal: %w", err)
	}
	id, _ := res.LastInsertId()
	return withCreator(&Proposal{ID: id, Tool: tool, ArgsJSON: argsJSON, Summary: summary, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(ProposalTTL)}, by, tokenID), nil
}

func scanProposal(row interface{ Scan(...any) error }) (Proposal, error) {
	var p Proposal
	var result sql.NullString
	var decided, sendAt sql.NullTime
	err := row.Scan(&p.ID, &p.Tool, &p.ArgsJSON, &p.Summary, &p.Status, &result, &p.CreatedAt, &p.ExpiresAt, &decided, &sendAt, &p.CreatedBy, &p.CreatorTokenID)
	p.Result = result.String
	if decided.Valid {
		t := decided.Time
		p.DecidedAt = &t
	}
	if sendAt.Valid {
		t := sendAt.Time
		p.SendAt = &t
	}
	return p, err
}

const proposalColumns = "id, tool, args_json, summary, status, result, created_at, expires_at, decided_at, send_at, COALESCE(created_by, ''), COALESCE(created_by_token, 0)"

// ListProposals returns proposals with status ("" for all; a comma-separated
// list such as "pending,scheduled" for several), newest first.
func (s *Store) ListProposals(ctx context.Context, status string) ([]Proposal, error) {
	if err := s.expireProposals(ctx); err != nil {
		return nil, err
	}
	q := "SELECT " + proposalColumns + " FROM outbox"
	var args []any
	if status != "" {
		var marks []string
		for _, st := range strings.Split(status, ",") {
			marks = append(marks, "?")
			args = append(args, strings.TrimSpace(st))
		}
		q += " WHERE status IN (" + strings.Join(marks, ", ") + ")"
	}
	q += " ORDER BY id DESC LIMIT 200"
	rows, err := s.db.QueryContext(ctx, q, args...)
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

// ClaimProposal atomically moves a pending proposal out of the queue so it
// can be executed exactly once, and returns it. A proposal with a send time
// (a scheduled message) moves to 'scheduled' instead: the scheduler sends it
// at send_at.
func (s *Store) ClaimProposal(ctx context.Context, id int64) (*Proposal, error) {
	if err := s.expireProposals(ctx); err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE outbox SET status = CASE WHEN send_at IS NULL THEN 'sent' ELSE 'scheduled' END, decided_at = ?
		WHERE id = ? AND status = 'pending'`, time.Now().UTC(), id)
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

// FinishProposal records the outcome of an executed proposal.
func (s *Store) FinishProposal(ctx context.Context, id int64, failed bool, result string) error {
	status := "sent"
	if failed {
		status = "failed"
	}
	_, err := s.db.ExecContext(ctx, "UPDATE outbox SET status = ?, result = ? WHERE id = ?", status, result, id)
	return err
}

// RejectProposal discards a pending proposal.
func (s *Store) RejectProposal(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "UPDATE outbox SET status = 'rejected', decided_at = ? WHERE id = ? AND status = 'pending'", time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrProposalNotPending
	}
	return nil
}

// CreatorRevoked reports whether p was created with a client token that has
// since been revoked (or no longer exists). Items made by the operator are
// never refused. ApproveProposal and the scheduler check it, so revoking a
// token stops everything it proposed or scheduled, whichever way it was
// revoked (token revoke, OAuth grant revocation), without a sweep.
func (s *Store) CreatorRevoked(ctx context.Context, p *Proposal) (bool, error) {
	if p == nil || p.CreatorTokenID == 0 {
		return false, nil
	}
	var revoked bool
	err := s.db.QueryRowContext(ctx, "SELECT revoked_at IS NOT NULL FROM api_tokens WHERE id = ?", p.CreatorTokenID).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("check proposal creator: %w", err)
	}
	return revoked, nil
}
