package mcp

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/murandido/mcp-wpp/internal/auth"
	"github.com/murandido/mcp-wpp/internal/store"
)

// Auditor records audit entries. *store.Store implements it.
type Auditor interface {
	RecordAudit(ctx context.Context, e store.AuditEntry) error
}

// Outcomes a middleware can force on the current call's audit entry. Calls
// nobody marks are "ok" or, when the result is an error, "error".
const (
	auditDenied   = store.OutcomeDenied
	auditProposed = store.OutcomeProposed
)

// mediaResourceAction names media resource reads in the audit log.
const mediaResourceAction = "resource:" + mediaURIPrefix

type auditNoteKey struct{}

type auditNote struct{ outcome string }

// markAudit sets the outcome of the call being audited on ctx, if any.
func markAudit(ctx context.Context, outcome string) {
	if n, ok := ctx.Value(auditNoteKey{}).(*auditNote); ok {
		n.outcome = outcome
	}
}

func withAuditNote(ctx context.Context) (context.Context, *auditNote) {
	n := &auditNote{}
	return context.WithValue(ctx, auditNoteKey{}, n), n
}

// auditEntry builds the common part of an entry for the caller on ctx.
func auditEntry(ctx context.Context, kind, action, chat string, start time.Time) store.AuditEntry {
	id := auth.Caller(ctx)
	return store.AuditEntry{
		At:       start.UTC(),
		Actor:    id.Actor(),
		TokenID:  id.TokenID,
		Kind:     kind,
		Action:   action,
		ChatJID:  chat,
		Duration: time.Since(start).Milliseconds(),
	}
}

// record writes e, detached from the request's cancellation so a client that
// hangs up does not erase its trace. A failed write is not the caller's
// problem and never changes the tool result.
func (s *Server) record(ctx context.Context, e store.AuditEntry) {
	_ = s.auditor.RecordAudit(context.WithoutCancel(ctx), e)
}

// auditMiddleware is the outermost tool middleware: it sees every call,
// including those the scope and access checks refuse, and reports refused
// ones to the ObserveDenied hook even when auditing is off. It records the tool,
// the chat named by the tool's toolAccessScope argument, the outcome and the
// duration; never other arguments, message text or results.
func (s *Server) auditMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		ctx, note := withAuditNote(ctx)
		res, err := next(ctx, req)
		if note.outcome == auditDenied && s.onDenied != nil {
			s.onDenied(req.Params.Name)
		}
		if s.auditor == nil {
			return res, err
		}
		var chat string
		if scope := toolAccessScope[req.Params.Name]; scope.chatArg != "" {
			chat = s.auditChat(req.GetString(scope.chatArg, ""))
		}
		e := auditEntry(ctx, store.AuditTool, req.Params.Name, chat, start)
		switch {
		case note.outcome != "":
			e.Outcome = note.outcome
		case err != nil || res == nil || res.IsError:
			e.Outcome = store.OutcomeError
		default:
			e.Outcome = store.OutcomeOK
		}
		s.record(ctx, e)
		return res, err
	}
}

// auditChat resolves a chat argument to the JID it targets.
func (s *Server) auditChat(ref string) string {
	if s.client == nil {
		return ref
	}
	return s.chatJIDFor(ref)
}

// auditResourceMiddleware records resource reads the same way.
func (s *Server) auditResourceMiddleware(next server.ResourceHandlerFunc) server.ResourceHandlerFunc {
	return func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		start := time.Now()
		ctx, note := withAuditNote(ctx)
		out, err := next(ctx, req)
		if note.outcome == auditDenied && s.onDenied != nil {
			s.onDenied(mediaResourceAction)
		}
		if s.auditor == nil {
			return out, err
		}
		chat, _, _ := parseMediaURI(req.Params.URI)
		e := auditEntry(ctx, store.AuditResource, mediaResourceAction, s.auditChat(chat), start)
		switch {
		case note.outcome != "":
			e.Outcome = note.outcome
		case err != nil:
			e.Outcome = store.OutcomeError
		default:
			e.Outcome = store.OutcomeOK
		}
		s.record(ctx, e)
		return out, err
	}
}
