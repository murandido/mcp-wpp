package daemon

import (
	"net/http"
	"strings"

	"github.com/murandido/mcp-wpp/internal/oauth"
)

// Route classes reported with refused requests. The set is fixed so a
// metric label can never carry a path, a query or anything else a client
// chose.
const (
	RouteMCP     = "mcp"
	RouteAdmin   = "admin"
	RouteOAuth   = "oauth"
	RouteLogin   = "ui_login"
	RouteProbe   = "probe"
	RoutePage    = "page"
	RouteUnknown = "other"
)

// RouteClasses lists every route class observeRefusals can report.
var RouteClasses = []string{RouteMCP, RouteAdmin, RouteOAuth, RouteLogin, RouteProbe, RoutePage, RouteUnknown}

// RefusalCodes are the status codes observeRefusals reports.
var RefusalCodes = []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests}

// routeClass maps a request path to a RouteClasses value.
func routeClass(path string) string {
	switch {
	case isMCPPath(path):
		return RouteMCP
	case path == "/admin" || strings.HasPrefix(path, "/admin/"):
		return RouteAdmin
	case oauth.IsPublicPath(path):
		return RouteOAuth
	case path == loginPath:
		return RouteLogin
	case path == "/healthz", path == "/readyz":
		return RouteProbe
	case path == "/pair", strings.HasPrefix(path, "/pair/"),
		path == "/access", strings.HasPrefix(path, "/access/"),
		path == "/outbox", strings.HasPrefix(path, "/outbox/"):
		return RoutePage
	}
	return RouteUnknown
}

// refusalRecorder remembers the status code without hiding the writer's
// optional interfaces: Flush is forwarded (the MCP handler streams), and
// Unwrap lets http.ResponseController reach the rest.
type refusalRecorder struct {
	http.ResponseWriter
	status int
}

func (r *refusalRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *refusalRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *refusalRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		if r.status == 0 {
			r.status = http.StatusOK
		}
		f.Flush()
	}
}

func (r *refusalRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// observeRefusals is the outermost handler: it reports every 401
// (authentication), 403 (Host/Origin guard, CSRF) and 429 (rate limits)
// response to fn with the status code and the route class. fn may be nil.
func observeRefusals(next http.Handler, fn func(code int, route string)) http.Handler {
	if fn == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &refusalRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		switch rec.status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
			fn(rec.status, routeClass(r.URL.Path))
		}
	})
}
