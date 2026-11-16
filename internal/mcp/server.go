// Package mcp wires mark3labs/mcp-go to the internal/client and internal/store
// packages, exposing the WhatsApp bridge over MCP Streamable HTTP.
package mcp

import (
	"net/http"
	"sort"
	"time"

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
	confirmSends  bool
	auditor       Auditor
	// now is the scheduling clock; nil means time.Now (see SetClock).
	now func() time.Time
	// schedWake nudges the scheduler when a message is scheduled.
	schedWake chan struct{}
	// loc is the time zone send windows are read in; nil means time.Local.
	loc *time.Location
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
	// ConfirmSends makes write tools record a proposal for the user to
	// approve instead of acting (see outbox.go).
	ConfirmSends bool
	// Tools selects tool groups/names. A nil Tools exposes every registered
	// tool (tests and smoke); the daemon always passes a selection.
	Tools *ToolSelection
	// Audit, when set, records every tool call and resource read (audit.go).
	Audit Auditor
	// Timezone is the zone per-chat send windows are read in (serve
	// -timezone); nil means the process's local zone.
	Timezone *time.Location
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
	instructions := accessInstructions
	if opts.ReadOnly {
		instructions += " This server is in read-only mode: tools cannot send messages or mutate the WhatsApp account. Downloads and history requests can still retrieve data and write the local cache. An explicit media download may ask your own phone to re-upload an expired attachment; it never notifies the sender or chat. Pairing remains an operator action."
	}
	s := &Server{client: c, cache: cache, readOnly: opts.ReadOnly, labelsEnabled: opts.LabelsEnabled, confirmSends: opts.ConfirmSends && !opts.ReadOnly, auditor: opts.Audit, schedWake: make(chan struct{}, 1), loc: opts.Timezone}
	if !s.readOnly {
		instructions += " Depending on the chat, sending and other account changes may need the user's approval: such tools then return a proposal_id and send nothing until the user approves it. The user can also turn sending off for a chat; respect that refusal. A chat may have a send window: outside it, messages are deferred to its next opening (the result says `deferred: true` and when) and other changes are refused."
	}
	s.mcp = server.NewMCPServer(
		"whatsapp",
		Version,
		server.WithToolCapabilities(true),
		server.WithInstructions(instructions),
		// The first middleware is outermost. Auditing sees every call,
		// refused ones included. The token scope and chat access are
		// checked before any proposal is recorded.
		server.WithToolHandlerMiddleware(s.auditMiddleware),
		server.WithToolHandlerMiddleware(s.scopeMiddleware),
		server.WithToolHandlerMiddleware(s.accessMiddleware),
		server.WithToolHandlerMiddleware(s.confirmMiddleware),
		server.WithResourceHandlerMiddleware(s.auditResourceMiddleware),
	)
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
	//
	// mcp-go's own DNS-rebinding check refuses any non-loopback Host on a
	// loopback listener, which breaks a reverse proxy on the same host that
	// keeps the public Host (Caddy's default). The daemon's hostGuard wraps
	// this handler and performs the same check against loopback names plus
	// the operator's -allowed-host list, so the inner check is turned off.
	httpHandler := server.NewStreamableHTTPServer(s.mcp, server.WithStateLess(true), server.WithDisableLocalhostProtection(true))
	mux.Handle("/mcp", httpHandler)
}
