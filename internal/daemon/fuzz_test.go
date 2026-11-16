package daemon

import (
	"slices"
	"strings"
	"testing"
)

func FuzzLandingPath(f *testing.F) {
	for _, s := range []string{
		"/pair", "/access", "/outbox", "", "//evil.example/pair", `/\evil.example`, "https://evil.example/pair",
		"/pair?x=1", "/pair#x", "/%2fevil.example", "/../pair", "pair", "/access/", "javascript:alert(1)",
		"/pair\x00", "///pair", "\\\\evil/pair",
	} {
		f.Add(s)
	}
	allowed := make([]string, 0, len(landingPages))
	for _, v := range landingPages {
		allowed = append(allowed, v)
	}
	f.Fuzz(func(t *testing.T, p string) {
		target, ok := landingPath(p)
		if ok != safeLanding(p) {
			t.Fatalf("landingPath and safeLanding disagree on %q", p)
		}
		if !ok {
			if target != "" {
				t.Fatalf("refused %q but returned %q", p, target)
			}
			return
		}
		if !slices.Contains(allowed, target) {
			t.Fatalf("landingPath(%q) = %q is not a landing page", p, target)
		}
		if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.Contains(target, `\`) {
			t.Fatalf("landingPath(%q) = %q could leave the origin", p, target)
		}
	})
}

func FuzzRouteClassAndClassify(f *testing.F) {
	for _, s := range []string{"/mcp", "/admin/x", "/oauth/token", "/healthz", "/pair", "/", "/admin", "/.well-known/oauth-protected-resource/mcp", "/mcp/../admin"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if !slices.Contains(RouteClasses, routeClass(p)) {
			t.Fatalf("routeClass(%q) = %q outside the fixed set", p, routeClass(p))
		}
		// The admin API and /mcp are never public.
		if (p == "/admin" || strings.HasPrefix(p, "/admin/") || isMCPPath(p)) && classify(p) != classBearer {
			t.Fatalf("classify(%q) = %v, want bearer", p, classify(p))
		}
	})
}
