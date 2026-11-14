package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// pairDriver is the minimal surface the Server needs from the underlying
// WhatsApp client. Production wiring (cmd/wpp-mcp/production_driver.go)
// satisfies this via *client.Client. Tests substitute a fake.
type pairDriver interface {
	IsLoggedIn() bool
	// StartPairing begins an unpaired session. onQR is invoked every time
	// whatsmeow emits a new pairing code. onSuccess is invoked once
	// pairing succeeds. onExpired is invoked if the session ends without
	// pairing (WhatsApp closes an unused session once its QR codes run out,
	// or the socket dropped); a new StartPairing call is needed after it.
	StartPairing(ctx context.Context, onQR func(code string), onSuccess func(), onExpired func()) error
	// Connect attaches event handlers (including LoggedOut) on an already-
	// paired session. onLoggedOut fires when the remote device revokes the
	// session.
	Connect(ctx context.Context, onLoggedOut func()) error
	Logout(ctx context.Context) error
	Disconnect()
}

// Config configures a daemon Server. Addr may be "host:port" or "host:0"
// (the latter only for tests). MCPMount, if non-nil, is called once the
// mux is being built so the caller can attach additional handlers (in
// practice, the /mcp Streamable HTTP handler from internal/mcp).
//
// Addr may also be "unix:/path/to.sock" to listen on a Unix socket, which is
// created with mode 0600.
//
// AuthToken is required. /mcp and /admin/* accept only
// `Authorization: Bearer <token>`; browser pages accept the bearer token or
// a session cookie minted through /admin/ui-login → /ui/login. Only /healthz,
// /readyz and /ui/login are public.
//
// AllowedHosts extends the Host/Origin allowlist beyond loopback names, for
// example the public hostname of an HTTPS reverse proxy. Entries are a bare
// hostname (any port) or host:port.
type Config struct {
	Addr         string
	Driver       pairDriver
	MCPMount     func(mux *http.ServeMux)
	AuthToken    string
	AllowedHosts []string
	// AutoPairPhone, when set and the device is unpaired at startup, makes
	// the daemon request a pairing code for this number once and print it
	// to stderr (headless and container setups).
	AutoPairPhone string
	// Access, when set, enables the consent workflow: /admin/access/* for
	// the CLI and the /access page.
	Access AccessStore
	// Outbox, when set, serves send proposals for approval: /admin/outbox/*
	// and the /outbox page.
	Outbox Outbox
	// AdminMount, if non-nil, registers extra operator endpoints. They are
	// served under /admin/* (bearer only) or as browser pages.
	AdminMount func(mux *http.ServeMux)
}

// Server is the long-lived daemon process. Safe for a single Run call.
type Server struct {
	cfg   Config
	cache *PairCache
	flow  *pairFlow

	mu         sync.Mutex
	httpServer *http.Server
	boundAddr  string
	listenerOK chan struct{} // closed once the listener is bound (tests use this)
}

// New constructs a Server but does not start any goroutines yet.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		return nil, errors.New("daemon.New: Addr required")
	}
	if cfg.Driver == nil {
		return nil, errors.New("daemon.New: Driver required")
	}
	if len(cfg.AuthToken) < 16 {
		return nil, errors.New("daemon.New: AuthToken of at least 16 characters required")
	}
	cache := NewPairCache()
	return &Server{
		cfg:        cfg,
		cache:      cache,
		flow:       newPairFlow(cfg.Driver, cache),
		listenerOK: make(chan struct{}),
	}, nil
}

// Cache exposes the pair cache so the MCP server can answer pairing_status
// (and for tests). The daemon owns the cache, so callers must construct the
// daemon before wiring the cache into the MCP server.
func (s *Server) Cache() *PairCache { return s.cache }

// SetMCPMount installs the MCP HTTP mount after construction. The daemon owns
// the pair cache, so serve.go builds the daemon first, hands its cache to the
// MCP server, then mounts the MCP handler here. cfg.MCPMount is read in Run,
// so setting it any time before Run takes effect.
func (s *Server) SetMCPMount(fn func(mux *http.ServeMux)) { s.cfg.MCPMount = fn }

// SetOutbox installs the proposal queue after construction, for the same
// reason as SetMCPMount: the MCP server that implements it is built later.
func (s *Server) SetOutbox(ob Outbox) { s.cfg.Outbox = ob }

// BoundAddr returns the address the HTTP listener actually bound to, useful
// when Addr was "host:0". Only valid after <-s.listenerOK fires.
func (s *Server) BoundAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boundAddr
}

// Run starts the HTTP listener, begins the pairing state machine, and
// blocks until ctx is cancelled. On cancel, performs the shutdown
// sequence: drain HTTP → Disconnect driver.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	var coder pairCoder
	if pc, ok := s.cfg.Driver.(pairCoder); ok {
		coder = pc
	}
	handlers := newPairHandlers(s.cache, s.cfg.Driver, coder)
	handlers.flow = s.flow
	handlers.mount(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeProbe(w, http.StatusOK, "ok", true)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		driver, ok := s.cfg.Driver.(interface{ IsConnected() bool })
		ready := ok && s.cache.Paired() && driver.IsConnected()
		code := http.StatusServiceUnavailable
		if ready {
			code = http.StatusOK
		}
		writeProbe(w, code, "ready", ready)
	})
	if s.cfg.MCPMount != nil {
		s.cfg.MCPMount(mux)
	} else {
		// No MCP attached (tests). Provide a 503 so the shape is observable.
		mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "mcp not mounted", http.StatusServiceUnavailable)
		})
	}

	ui := newUIAuth()
	ui.mount(mux)
	if s.cfg.Access != nil {
		newAccessHandlers(s.cfg.Access).mount(mux)
	}
	if s.cfg.Outbox != nil {
		(&outboxHandlers{ob: s.cfg.Outbox}).mount(mux)
	}
	if s.cfg.AdminMount != nil {
		s.cfg.AdminMount(mux)
	}

	rootHandler := hostGuard(authGuard(securityHeaders(mux), s.cfg.AuthToken, ui), s.cfg.AllowedHosts)

	ln, err := listen(s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.mu.Lock()
	s.httpServer = &http.Server{
		Handler:           rootHandler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.boundAddr = ln.Addr().String()
	httpSrv := s.httpServer
	s.mu.Unlock()

	listenErrCh := make(chan error, 1)
	go func() { listenErrCh <- httpSrv.Serve(ln) }()

	close(s.listenerOK)

	// Drive the pairing state machine.
	if err := s.bootDriver(ctx); err != nil {
		_ = httpSrv.Shutdown(context.Background())
		return fmt.Errorf("boot driver: %w", err)
	}
	if s.cfg.AutoPairPhone != "" && !s.cache.Paired() {
		go autoPair(ctx, handlers, s.cfg.AutoPairPhone)
	}

	// Wait for cancellation or a listener failure.
	select {
	case <-ctx.Done():
	case err := <-listenErrCh:
		if err != nil && err != http.ErrServerClosed {
			s.cfg.Driver.Disconnect()
			return fmt.Errorf("http listen: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	s.cfg.Driver.Disconnect()
	return nil
}

func writeProbe(w http.ResponseWriter, code int, key string, value bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]bool{key: value})
}

// bootDriver inspects the driver's IsLoggedIn and either starts pairing
// or connects with the existing session. Safe to call only once per Run.
func (s *Server) bootDriver(ctx context.Context) error {
	onPairSuccess := func() {
		// Transition into Connect to install the LoggedOut handler.
		_ = s.cfg.Driver.Connect(ctx, s.onLoggedOut())
	}

	if s.cfg.Driver.IsLoggedIn() {
		s.cache.SetPaired()
		s.flow.bind(ctx, onPairSuccess)
		return s.cfg.Driver.Connect(ctx, s.onLoggedOut())
	}
	s.flow.bind(ctx, onPairSuccess)
	return s.flow.start()
}

// onLoggedOut returns a callback the driver invokes when the remote device
// revokes the session. Flips the cache to unpaired and kicks the pairing
// flow back up.
func (s *Server) onLoggedOut() func() {
	return func() {
		s.cache.Reset()
		_ = s.flow.start()
	}
}

// securityHeaders sets conservative defaults on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// listen opens a TCP listener, or a Unix socket for "unix:/path" addresses.
func listen(addr string) (net.Listener, error) {
	path, ok := strings.CutPrefix(addr, "unix:")
	if !ok {
		return net.Listen("tcp", addr)
	}
	if path == "" {
		return nil, errors.New("unix socket path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	// A stale socket from a crashed run would make bind fail. The store lock
	// already guarantees no other daemon owns this path.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	ln, err := withPrivateUmask(func() (net.Listener, error) { return net.Listen("unix", path) })
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln, nil
}
