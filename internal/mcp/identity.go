package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/murandido/mcp-wpp/internal/auth"
)

// Caller identity. The daemon's auth guard attaches an auth.Identity to the
// HTTP request context, and mcp-go's Streamable HTTP server derives every
// handler context from it, so tool and resource handlers see the caller
// with auth.Caller(ctx):
//
//   - the operator (operator token, stdio bridge, in-process callers) is
//     limited by the access policy only;
//   - a client token needs the read scope for read-only tools and the send
//     scope for every other tool, and its chat set, if any, narrows what
//     the access policy allows (store(ctx) and allowedChat).

// requiredScope is the token scope a tool needs. Tools that are not
// classified read-only need send, so an unclassified tool fails closed.
func requiredScope(tool string) string {
	if readOnlyToolAccess[tool] {
		return auth.ScopeRead
	}
	return auth.ScopeSend
}

// scopeMiddleware refuses tools the caller's token is not scoped for. It
// runs before the access check and the outbox, so a read-only token can
// neither send nor propose.
func (s *Server) scopeMiddleware(next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := auth.Caller(ctx)
		if need := requiredScope(req.Params.Name); !id.Has(need) {
			markAudit(ctx, auditDenied)
			return mcp.NewToolResultError("this API token is not allowed to use " + req.Params.Name + ": it needs the " + need + " scope. Nothing was done; the user can create a token with `wpp-mcp token create <name> -scope read,send`."), nil
		}
		return next(ctx, req)
	}
}
