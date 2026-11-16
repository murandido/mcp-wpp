package clientip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzFromRequest(f *testing.F) {
	f.Add("203.0.113.9:4000", "1.2.3.4")
	f.Add("127.0.0.1:1", "6.6.6.6, 198.51.100.7")
	f.Add("@", "")
	f.Add("garbage", "::1")
	f.Add("[fe80::1%eth0]:1", "x")
	f.Fuzz(func(t *testing.T, remote, xff string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		got := FromRequest(r)
		if got == "" {
			t.Fatalf("FromRequest(%q, %q) is empty", remote, xff)
		}
		// A public peer cannot choose its address through the header.
		host, _, err := net.SplitHostPort(remote)
		if err != nil {
			host = remote
		}
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && got != ip.String() {
			t.Fatalf("public peer %q with X-Forwarded-For %q became %q", remote, xff, got)
		}
	})
}
