package oauth

import (
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// Fuzz targets for the parsing and validation surface of the OAuth server.
// `make fuzz` runs each for a short time; plain `go test` runs the seeds.

func FuzzCanonicalResource(f *testing.F) {
	for _, s := range []string{
		"https://wpp.example.com/mcp", "HTTPS://WPP.Example.COM:443/mcp/", "http://127.0.0.1:8765/mcp",
		"https://h/mcp?x=1", "https://h/mcp#frag", "https://user@h/mcp", "mcp", "", "https://[::1]:443/a%2Fb",
		"https://h/%E2%82%AC/", "urn:x:y", "//h/mcp",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out, ok := CanonicalResource(raw)
		if !ok {
			if out != "" {
				t.Fatalf("refused %q but returned %q", raw, out)
			}
			return
		}
		if strings.ContainsAny(out, "?#") {
			t.Fatalf("CanonicalResource(%q) = %q keeps a query or fragment", raw, out)
		}
		if strings.HasSuffix(out, "/") {
			t.Fatalf("CanonicalResource(%q) = %q keeps a trailing slash", raw, out)
		}
		scheme, rest, found := strings.Cut(out, "://")
		if !found || scheme == "" || scheme != strings.ToLower(scheme) || rest == "" {
			t.Fatalf("CanonicalResource(%q) = %q is not scheme://host", raw, out)
		}
		if scheme == "https" && strings.HasSuffix(strings.SplitN(rest, "/", 2)[0], ":443") {
			t.Fatalf("CanonicalResource(%q) = %q keeps the default port", raw, out)
		}
		if strings.Contains(strings.SplitN(rest, "/", 2)[0], "@") {
			t.Fatalf("CanonicalResource(%q) = %q has user info", raw, out)
		}
	})
}

func FuzzParsePublicURL(f *testing.F) {
	for _, s := range []string{
		"https://wpp.example.com", "https://wpp.example.com/", "HTTPS://WPP.EXAMPLE.COM:443", "https://h:8443",
		"http://h", "https://h/path", "https://h?x", "https://u:p@h", " https://h ", "", "https://", "https:h",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out, err := ParsePublicURL(raw)
		if err != nil {
			return
		}
		u, perr := url.Parse(out)
		if perr != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			t.Fatalf("ParsePublicURL(%q) = %q is not a bare https origin", raw, out)
		}
		if strings.HasSuffix(out, ":443") || out != strings.ToLower(out) {
			t.Fatalf("ParsePublicURL(%q) = %q is not canonical", raw, out)
		}
		if again, err := ParsePublicURL(out); err != nil || again != out {
			t.Fatalf("ParsePublicURL not idempotent: %q -> %q -> %q (%v)", raw, out, again, err)
		}
		// The resource derived from it must be accepted as a resource.
		if _, ok := CanonicalResource(out + "/mcp"); !ok {
			t.Fatalf("resource of %q refused", out)
		}
	})
}

func FuzzValidCIMDURL(f *testing.F) {
	for _, s := range []string{
		"https://claude.ai/oauth/claude-code-client-metadata", "https://claude.ai/", "https://claude.ai",
		"http://claude.ai/x", "https://claude.ai/a/../b", "https://claude.ai/./x", "https://u@claude.ai/x",
		"https://claude.ai/x?y", "https://claude.ai/x#y", "https:opaque", "https://claude.ai/%2e%2e/x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := validCIMDURL(raw)
		if err != nil {
			return
		}
		if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			t.Fatalf("validCIMDURL(%q) accepted %#v", raw, u)
		}
		if u.Path == "" || u.Path == "/" {
			t.Fatalf("validCIMDURL(%q) accepted a root path", raw)
		}
		for _, seg := range strings.Split(u.Path, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("validCIMDURL(%q) accepted a dot segment", raw)
			}
		}
	})
}

func FuzzParseRedirectURIs(f *testing.F) {
	for _, s := range []string{
		"", "https://claude.ai/api/mcp/auth_callback", "https://a/cb, http://127.0.0.1:33418/cb",
		"http://localhost/cb", "http://example.com/cb", "https://a/cb#x", "https://u@a/cb", "javascript:alert(1)",
		"http://[::1]:9/cb", "http://127.0.0.1.evil.com/cb", ",,,",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		list, err := ParseRedirectURIs(raw)
		if err != nil {
			return
		}
		if len(list) == 0 {
			t.Fatalf("ParseRedirectURIs(%q) accepted an empty list", raw)
		}
		for _, r := range list {
			u, perr := url.Parse(r)
			if perr != nil || u.Host == "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
				t.Fatalf("ParseRedirectURIs(%q) accepted %q", raw, r)
			}
			switch u.Scheme {
			case "https":
			case "http":
				host := u.Hostname()
				ip := net.ParseIP(host)
				if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
					t.Fatalf("ParseRedirectURIs(%q) accepted non-loopback http %q", raw, r)
				}
			default:
				t.Fatalf("ParseRedirectURIs(%q) accepted scheme %q", raw, u.Scheme)
			}
		}
	})
}

func FuzzAllowedRedirect(f *testing.F) {
	f.Add("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback")
	f.Add("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback/")
	f.Add("https://claude.ai/api/mcp/auth_callback", "HTTPS://claude.ai/api/mcp/auth_callback")
	f.Add("https://a/cb,http://127.0.0.1/cb", "http://127.0.0.1/cb?x=1")
	f.Fuzz(func(t *testing.T, allow, requested string) {
		s := &Server{redirects: strings.Split(allow, ",")}
		got, ok := s.allowedRedirect(requested)
		if ok != slices.Contains(s.redirects, requested) {
			t.Fatalf("allowedRedirect(%q) in %q = %v", requested, allow, ok)
		}
		if ok && got != requested {
			t.Fatalf("allowedRedirect(%q) returned %q", requested, got)
		}
		if !ok && got != "" {
			t.Fatalf("refused %q but returned %q", requested, got)
		}
	})
}

func FuzzPKCE(f *testing.F) {
	f.Add("dBjftJeZ4CVP-mB92K27uhbUJU1p1r7wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	f.Add(strings.Repeat("a", 42), "x")
	f.Add(strings.Repeat("~", 128), "")
	f.Add(strings.Repeat("a", 129), "y")
	f.Fuzz(func(t *testing.T, verifier, challenge string) {
		valid := verifierPattern.MatchString(verifier)
		if valid {
			if n := len(verifier); n < 43 || n > 128 {
				t.Fatalf("verifier of length %d accepted", n)
			}
			const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
			if strings.Trim(verifier, alphabet) != "" {
				t.Fatalf("verifier %q outside the RFC 7636 alphabet accepted", verifier)
			}
		}
		own := pkceS256(verifier)
		if !challengePattern.MatchString(own) {
			t.Fatalf("pkceS256(%q) = %q is not a valid challenge", verifier, own)
		}
		if pkceMatches(verifier, own) != valid {
			t.Fatalf("pkceMatches(%q, own challenge) = %v, want %v", verifier, !valid, valid)
		}
		if challenge != own && pkceMatches(verifier, challenge) {
			t.Fatalf("pkceMatches(%q, %q) accepted a foreign challenge", verifier, challenge)
		}
	})
}
