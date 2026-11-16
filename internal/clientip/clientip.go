// Package clientip works out the address of the client behind a request,
// for rate limiting and the operator's views. It never authenticates
// anyone: the result only decides whose budget a request spends.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// FromRequest returns the caller's address. When the peer is a reverse proxy
// on the same host or network (a loopback, private or Unix socket peer, as
// with Caddy in front or Docker's port proxy), the rightmost
// X-Forwarded-For entry, which that proxy appended, is used instead. A
// public peer's X-Forwarded-For is ignored, so a remote client cannot pick
// its own address. Unix socket peers without a forwarded address are
// "local".
func FromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	trusted := host == "" || host == "@" || (ip != nil && (ip.IsLoopback() || ip.IsPrivate()))
	if trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if last := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); last != nil {
				return last.String()
			}
		}
	}
	if ip != nil {
		return ip.String()
	}
	if host == "" || host == "@" {
		return "local"
	}
	return host
}
