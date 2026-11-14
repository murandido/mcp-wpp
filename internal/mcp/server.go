// Package mcp wires mark3labs/mcp-go to the internal/client and internal/store
// packages, exposing the WhatsApp bridge over MCP Streamable HTTP.
package mcp

import (
	"net/http"
	"sort"

	"github.com/mark3labs/mcp-go/server"

	"github.com/murandido/mcp-wpp/internal/client"
)

// pairingCache is the minimal pairing-state surface pairing_status needs.
// *daemon.PairCache satisfies it. The smoke command and tests pass nil, in
// which case pairing_status reports an "error" envelope.
type pairingCache interface {
	Paired() bool
	QR() string
	Expired() bool
}

// Server holds the MCP server, its bound WhatsApp client, and an optional
// pairing cache (used only by pairing_status).
type Server struct {
	client        *client.Client
	mcp           *server.MCPServer
	cache         pairingCache
	readOnly      bool
	labelsEnabled bool
}

// NewServer constructs an MCP server with all tools registered against the
// provided WhatsApp client. cache may be nil (smoke/tests); pairing_status is
// the only tool that consults it.
// Version is reported as serverInfo.version. cmd/wpp-mcp sets it from its
// -ldflags build version so the two cannot drift.
var Version = "dev"

// Options configures the tool surface.
type Options struct {
	// ReadOnly removes every tool not classified read-only in
	// readOnlyToolAccess.
	ReadOnly bool
	// LabelsEnabled registers the WhatsApp Business label tools.
	LabelsEnabled bool
	// Tools selects tool groups/names. A nil Tools exposes every registered
	// tool (tests and smoke); the daemon always passes a selection.
	Tools *ToolSelection
}

// NewServer registers every tool (no read-only or profile filtering).
func NewServer(c *client.Client, cache pairingCache, labelsEnabled bool) *Server {
	s, _ := NewServerWithOptions(c, cache, Options{LabelsEnabled: labelsEnabled})
	return s
}

// NewReadOnlyServer excludes tools that can mutate the WhatsApp account.
func NewReadOnlyServer(c *client.Client, cache pairingCache, labelsEnabled bool) *Server {
	s, _ := NewServerWithOptions(c, cache, Options{ReadOnly: true, LabelsEnabled: labelsEnabled})
	return s
}

// NewServerWithOptions builds the server with the requested tool surface. It
// fails only when Tools names an unknown tool or group.
func NewServerWithOptions(c *client.Client, cache pairingCache, opts Options) (*Server, error) {
	var enabled map[string]bool
	if opts.Tools != nil {
		var err error
		if enabled, err = opts.Tools.resolve(); err != nil {
			return nil, err
		}
	}
	instructions := ""
	if opts.ReadOnly {
		instructions = "This server is in read-only mode: tools cannot send messages or mutate the WhatsApp account. Downloads and history requests can still retrieve data and write the local cache. An explicit media download may ask your own phone to re-upload an expired attachment; it never notifies the sender or chat. Pairing remains an operator action."
	}
	mcpSrv := server.NewMCPServer(
		"whatsapp",
		Version,
		server.WithToolCapabilities(true),
		server.WithInstructions(instructions),
	)
	s := &Server{client: c, mcp: mcpSrv, cache: cache, readOnly: opts.ReadOnly, labelsEnabled: opts.LabelsEnabled}
	s.registerTools()
	for name := range s.mcp.ListTools() {
		if opts.ReadOnly && !readOnlyToolAccess[name] {
			s.mcp.DeleteTools(name)
			continue
		}
		if enabled != nil && !enabled[name] {
			s.mcp.DeleteTools(name)
		}
	}
	s.registerResources()
	return s, nil
}

// ToolNames returns the advertised tool names, sorted.
func (s *Server) ToolNames() []string {
	var names []string
	for name := range s.mcp.ListTools() {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// MCP returns the underlying mcp-go server (tests only).
func (s *Server) MCP() *server.MCPServer { return s.mcp }

// AttachHTTP mounts the MCP Streamable HTTP handler on mux at /mcp. The
// actual listener lifecycle is owned by the caller (internal/daemon).
func (s *Server) AttachHTTP(mux *http.ServeMux) {
	// Stateless: nothing here is session-scoped (the pairing cache is process-wide
	// device state), so legacy clients get no Mcp-Session-Id either.
	httpHandler := server.NewStreamableHTTPServer(s.mcp, server.WithStateLess(true))
	mux.Handle("/mcp", httpHandler)
}
