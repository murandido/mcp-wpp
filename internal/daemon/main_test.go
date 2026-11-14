package daemon

import (
	"net/http"
	"os"
	"testing"
)

// testToken is the bearer token every test daemon is built with.
const testToken = "test-token-0123456789abcdef"

// rawClient never adds credentials; use it to assert that guards reject.
var rawClient = &http.Client{Transport: http.DefaultTransport}

// bearerTransport adds the test token to requests that carry no
// Authorization header, so tests written against plain http.Get keep
// exercising the handlers behind the auth guard.
type bearerTransport struct{ next http.RoundTripper }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("Authorization") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+testToken)
	}
	return b.next.RoundTrip(r)
}

func TestMain(m *testing.M) {
	http.DefaultTransport = bearerTransport{next: rawClient.Transport}
	os.Exit(m.Run())
}
