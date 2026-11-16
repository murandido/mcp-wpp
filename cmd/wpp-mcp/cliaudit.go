package main

import (
	"context"
	"fmt"
	"time"

	"github.com/murandido/mcp-wpp/internal/daemon"
	"github.com/murandido/mcp-wpp/internal/store"
)

// cliActor is the audit actor for operator commands that change the store
// directly because no daemon is running. Through the daemon the same
// commands are recorded by its admin API with the actor "operator".
const cliActor = "operator:cli"

// auditRecorder is what cliAudit writes to. *store.Store implements it.
type auditRecorder interface {
	RecordAudit(ctx context.Context, e store.AuditEntry) error
}

// Admin API routes the offline fallbacks stand in for. The audit action is
// the route pattern, exactly as the daemon records it.
const (
	routeAccessMode   = "POST /admin/access/mode"
	routeAccessChat   = "POST /admin/access/chat"
	routeAccessSend   = "POST /admin/access/send"
	routeAccessWindow = "POST /admin/access/window"
	routeSchedule     = "POST /admin/outbox/schedule"
	routeAccessDecide = "POST /admin/access/requests/{id}"
	routeClientCreate = "POST /admin/tokens"
	routeClientRevoke = "POST /admin/tokens/{ref}/revoke"
	routeGrantRevoke  = "POST /admin/oauth/grants/{id}/revoke"
	routePairCode     = "POST /admin/pair/code"
	// actionLoginQR is QR pairing without a daemon. The daemon's QR page is
	// a GET flow with no audited request, so it has its own action.
	actionLoginQR = "cli login qr"
)

// cliAudit records an offline operator action the way the daemon's admin
// API would record the equivalent request: action is the route pattern,
// path its path values and body the JSON body the HTTP backend sends. Only
// the daemon's whitelisted fields reach the entry (daemon.AdminAuditEntry),
// never secrets or message text. Auditing follows WPP_MCP_AUDIT_DAYS, and a
// failed write never fails the command.
func cliAudit(ctx context.Context, rec auditRecorder, start time.Time, action string, path [][2]string, body any, err error) {
	if rec == nil || !auditEnabled() {
		return
	}
	e := daemon.AdminAuditEntry(action, path, daemon.AuditFields(body))
	e.At = start.UTC()
	e.Actor = cliActor
	e.Duration = time.Since(start).Milliseconds()
	if err != nil {
		e.Outcome = store.OutcomeError
	}
	_ = rec.RecordAudit(context.WithoutCancel(ctx), e)
}

// Request bodies shared by the HTTP and direct backends, so both describe an
// operation identically.

func accessModeBody(mode string) map[string]string { return map[string]string{"mode": mode} }

func accessChatBody(jid, state string) map[string]string {
	return map[string]string{"jid": jid, "state": state, "note": "set with wpp-mcp access"}
}

func accessSendBody(jid, policy string) map[string]string {
	return map[string]string{"jid": jid, "send": policy}
}

func accessDecideBody(approve bool, jids []string) map[string]any {
	return map[string]any{"approve": approve, "jids": jids}
}

func idPath(name string, v any) [][2]string { return [][2]string{{name, fmt.Sprint(v)}} }
