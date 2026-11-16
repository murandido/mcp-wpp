package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ObserveToolCalls reports every tool execution to fn with the tool name and
// "ok" or "error". The hook sits innermost, after the access and
// confirmation middleware, so it sees executions only: a call refused by the
// access policy or turned into an outbox proposal is not counted (approved
// proposals run outside the MCP chain and show up as sent messages). Tool
// names are a fixed, registered set, so they carry no personal data.
func (s *Server) ObserveToolCalls(fn func(tool, outcome string)) {
	s.mcp.Use(func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			res, err := next(ctx, req)
			outcome := "ok"
			if err != nil || (res != nil && res.IsError) {
				outcome = "error"
			}
			fn(req.Params.Name, outcome)
			return res, err
		}
	})
}

// ObserveDenied reports every refused tool call or resource read to fn: a
// token without the scope, a chat outside the access policy or the token's
// chat set, or a send policy of none (the calls the audit log marks
// "denied"). fn receives the tool name, or the resource action for media
// reads; both come from fixed sets. Call it before serving.
func (s *Server) ObserveDenied(fn func(tool string)) { s.onDenied = fn }
