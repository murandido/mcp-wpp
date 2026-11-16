package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFromRequest(t *testing.T) {
	for _, c := range []struct{ remote, xff, want string }{
		{"203.0.113.9:4000", "1.2.3.4", "203.0.113.9"},
		{"127.0.0.1:4000", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		{"172.17.0.1:4000", "198.51.100.7", "198.51.100.7"},
		{"127.0.0.1:4000", "", "127.0.0.1"},
		{"127.0.0.1:4000", "garbage", "127.0.0.1"},
		{"@", "", "local"},
		{"", "198.51.100.7", "198.51.100.7"},
		{"[::1]:9", "2001:db8::1", "2001:db8::1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := FromRequest(r); got != c.want {
			t.Errorf("FromRequest(%s, %q) = %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}
