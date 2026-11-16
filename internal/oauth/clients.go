package oauth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/murandido/mcp-wpp/internal/store"
)

// Client identification. A client_id is either
//
//   - an https URL with a path: a Client ID Metadata Document, fetched with
//     SSRF protection and cached for an hour, or
//   - an ID minted by POST /oauth/register (RFC 7591), stored in
//     oauth_clients.
//
// Either way the client is public (token_endpoint_auth_method "none") and
// may only use redirect URIs that are also in the operator's allowlist.

const (
	cimdTimeout    = 5 * time.Second
	cimdMaxBody    = 64 << 10
	dcrIDPrefix    = "wppc_"
	maxClientName  = 64
	maxRedirectURI = 10
)

// errClient is shown on the error page; it never names internal details.
type errClient struct{ msg string }

func (e errClient) Error() string { return e.msg }

// client is a resolved, validated client.
type client struct {
	ID           string
	Name         string
	Kind         string
	RedirectURIs []string
}

// isCIMDClientID reports whether id looks like a metadata document URL.
func isCIMDClientID(id string) bool { return strings.HasPrefix(id, "https://") }

// validCIMDURL enforces the Client ID Metadata Document URL rules: https,
// a host, a non-root path without dot segments, no user info, query or
// fragment.
func validCIMDURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" {
		return nil, errClient{"client_id must be an https URL without user info, query or fragment"}
	}
	if u.Path == "" || u.Path == "/" {
		return nil, errClient{"client_id URL must have a path"}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return nil, errClient{"client_id URL must not contain dot segments"}
		}
	}
	return u, nil
}

// resolveClient returns the client for id, fetching its metadata document
// when needed.
func (s *Server) resolveClient(ctx context.Context, id string) (client, error) {
	if id == "" {
		return client{}, errClient{"client_id is missing"}
	}
	if isCIMDClientID(id) {
		return s.resolveCIMD(ctx, id)
	}
	if !strings.HasPrefix(id, dcrIDPrefix) {
		return client{}, errClient{"unknown client"}
	}
	c, err := s.st.GetOAuthClient(ctx, id)
	if err != nil || c.Kind != store.OAuthClientDCR {
		return client{}, errClient{"unknown client"}
	}
	return client{ID: c.ClientID, Name: c.ClientName, Kind: c.Kind, RedirectURIs: c.RedirectURIs}, nil
}

func (s *Server) resolveCIMD(ctx context.Context, id string) (client, error) {
	if _, err := validCIMDURL(id); err != nil {
		return client{}, err
	}
	now := s.now()
	if c, err := s.st.GetOAuthClient(ctx, id); err == nil && c.Kind == store.OAuthClientCIMD && c.FetchedAt != nil && now.Sub(*c.FetchedAt) < cimdCacheTTL {
		return client{ID: c.ClientID, Name: c.ClientName, Kind: c.Kind, RedirectURIs: c.RedirectURIs}, nil
	}
	doc, err := fetchCIMD(ctx, s.fetch, id)
	if err != nil {
		s.logf("oauth: client metadata document refused: %v", err)
		return client{}, errClient{"the client's metadata document could not be used"}
	}
	fetched := now.UTC()
	rec := store.OAuthClient{ClientID: id, Kind: store.OAuthClientCIMD, ClientName: doc.Name, RedirectURIs: doc.RedirectURIs, CreatedAt: fetched, FetchedAt: &fetched}
	if err := s.st.PutOAuthClient(ctx, rec, cimdCacheTTL); err != nil {
		// The cache is an optimisation; the document itself was valid.
		s.logf("oauth: cache client metadata: %v", err)
	}
	return client{ID: id, Name: doc.Name, Kind: store.OAuthClientCIMD, RedirectURIs: doc.RedirectURIs}, nil
}

type cimdDoc struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Name                    string   `json:"-"`
}

// fetchCIMD downloads and validates a Client ID Metadata Document. c must
// not follow redirects (NewFetchClient does not).
func fetchCIMD(ctx context.Context, c *http.Client, id string) (cimdDoc, error) {
	ctx, cancel := context.WithTimeout(ctx, cimdTimeout)
	defer cancel()
	// The URL passed validCIMDURL; c is NewFetchClient, which refuses
	// non-public addresses at dial time and follows no redirects.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil) //nolint:gosec // G704: see above; fetching the client's URL is the CIMD protocol
	if err != nil {
		return cimdDoc{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req) //nolint:gosec // G704: guarded client, see above
	if err != nil {
		return cimdDoc{}, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cimdDoc{}, fmt.Errorf("fetch: status %d (redirects are not followed)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBody+1))
	if err != nil {
		return cimdDoc{}, fmt.Errorf("read: %w", err)
	}
	if len(body) > cimdMaxBody {
		return cimdDoc{}, fmt.Errorf("document larger than %d bytes", cimdMaxBody)
	}
	var doc cimdDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return cimdDoc{}, fmt.Errorf("decode: %w", err)
	}
	if doc.ClientID != id {
		return cimdDoc{}, errors.New("document client_id does not equal its URL")
	}
	doc.Name = cleanName(doc.ClientName)
	if doc.Name == "" {
		return cimdDoc{}, errors.New("document has no client_name")
	}
	if len(doc.RedirectURIs) == 0 || len(doc.RedirectURIs) > 50 {
		return cimdDoc{}, errors.New("document has no usable redirect_uris")
	}
	if m := doc.TokenEndpointAuthMethod; m != "" && m != "none" {
		return cimdDoc{}, fmt.Errorf("token_endpoint_auth_method %q is not supported (public clients only)", m)
	}
	return doc, nil
}

// NewFetchClient returns the HTTP client used for metadata documents: no
// proxy, no redirects, a 5 s timeout, and a dialer that refuses private,
// loopback, link-local, unspecified and multicast addresses. The check runs
// on the address actually dialled, after DNS resolution, so a name that
// resolves (or rebinds) to an internal address is refused too.
func NewFetchClient() *http.Client { return newFetchClient(dialGuard, nil) }

func newFetchClient(control func(network, address string, c syscall.RawConn) error, roots *x509.CertPool) *http.Client {
	d := &net.Dialer{Timeout: cimdTimeout, Control: control}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    cimdTimeout,
		ResponseHeaderTimeout:  cimdTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       cimdTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// blockedPrefixes are non-public ranges beyond what netip's predicates
// cover.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach IPv4 internals
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// publicAddr reports whether ip is a global unicast address that is not
// private or reserved.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// dialGuard is a net.Dialer Control function: it runs for every connection
// attempt with the resolved address and refuses non-public ones.
func dialGuard(network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" && network != "tcp" {
		return fmt.Errorf("refusing to dial %s", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("refusing to dial %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("refusing to dial non-IP address %q", host)
	}
	if !publicAddr(ip) {
		return fmt.Errorf("refusing to dial non-public address %s", ip)
	}
	return nil
}

// cleanName keeps printable characters of a client-supplied name, collapses
// whitespace and truncates it, so it is safe on a page and in a terminal.
func cleanName(s string) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if !unicode.IsPrint(r) {
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
			n++
		}
		space = false
		if n >= maxClientName {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// --- Dynamic Client Registration (RFC 7591) ----------------------------------

type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.registerLimit.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "3600")
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations from this address")
		return
	}
	var in registerRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFormBytes))
	if err := dec.Decode(&in); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body must be a JSON client metadata document")
		return
	}
	if m := in.TokenEndpointAuthMethod; m != "" && m != "none" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only public clients (token_endpoint_auth_method none) are supported")
		return
	}
	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > maxRedirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, u := range in.RedirectURIs {
		if _, ok := s.allowedRedirect(u); !ok {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "a redirect URI is not allowed by this server")
			return
		}
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant type")
			return
		}
	}
	for _, rt := range in.ResponseTypes {
		if rt != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response type")
			return
		}
	}
	name := cleanName(in.ClientName)
	if name == "" {
		name = "unnamed client"
	}
	ctx := r.Context()
	if n, err := s.st.CountOAuthClients(ctx, store.OAuthClientDCR); err != nil || n >= maxDCRClients {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "client registration is full")
		return
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	now := s.now().UTC()
	c := store.OAuthClient{ClientID: dcrIDPrefix + hex.EncodeToString(b), Kind: store.OAuthClientDCR, ClientName: name, RedirectURIs: slices.Clone(in.RedirectURIs), CreatedAt: now}
	if err := s.st.PutOAuthClient(ctx, c, cimdCacheTTL); err != nil {
		if errors.Is(err, store.ErrOAuthLimit) {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "client registration is full")
			return
		}
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.logf("oauth: registered client %q (%s)", name, c.ClientID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  c.ClientID,
		"client_id_issued_at":        now.Unix(),
		"client_name":                name,
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}
