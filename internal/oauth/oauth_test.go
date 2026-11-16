package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

const testPublic = "https://wpp.test"

// fixture is an OAuth server over a real store with a controllable clock.
type fixture struct {
	t   *testing.T
	srv *Server
	st  *store.Store
	ts  *httptest.Server
	mu  sync.Mutex
	at  time.Time
}

func newFixture(t *testing.T, mutate ...func(*Config)) *fixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{t: t, st: st, at: time.Now()}
	cfg := Config{PublicURL: testPublic, Store: st, Now: f.now}
	for _, m := range mutate {
		m(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	mux := http.NewServeMux()
	srv.Mount(mux)
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.at
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.at = f.at.Add(d)
	f.mu.Unlock()
}

// noRedirect never follows redirects, so tests see every Location.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (f *fixture) get(path string) (*http.Response, string) {
	f.t.Helper()
	resp, err := noRedirect.Get(f.ts.URL + path)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (f *fixture) postForm(path string, v url.Values) (int, map[string]any) {
	f.t.Helper()
	resp, err := noRedirect.PostForm(f.ts.URL+path, v)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Cache-Control") != "no-store" {
		f.t.Errorf("%s: Cache-Control %q", path, resp.Header.Get("Cache-Control"))
	}
	return resp.StatusCode, out
}

func (f *fixture) register(redirects ...string) string {
	f.t.Helper()
	if len(redirects) == 0 {
		redirects = []string{DefaultRedirectURI}
	}
	body, _ := json.Marshal(map[string]any{"client_name": "Claude", "redirect_uris": redirects, "token_endpoint_auth_method": "none"})
	resp, err := http.Post(f.ts.URL+PathRegister, "application/json", strings.NewReader(string(body)))
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusCreated {
		f.t.Fatalf("register: %d %v", resp.StatusCode, out)
	}
	return out["client_id"].(string)
}

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-padding"

func challengeFor(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func authParams(clientID string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {DefaultRedirectURI},
		"state":                 {"st-123"},
		"code_challenge":        {challengeFor(testVerifier)},
		"code_challenge_method": {"S256"},
		"resource":              {testPublic + "/mcp"},
		"scope":                 {"read"},
	}
}

var (
	pageCodeRE = regexp.MustCompile(`<code class="big">([A-Z0-9]{4}-[A-Z0-9]{4})</code>`)
	pageIDRE   = regexp.MustCompile(`encodeURIComponent\("([0-9a-f]{32})"\)`)
)

// startAuthorize opens the authorization page and returns its short code
// and opaque request ID.
func (f *fixture) startAuthorize(p url.Values) (code, id string) {
	f.t.Helper()
	resp, body := f.get(PathAuthorize + "?" + p.Encode())
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("authorize: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	c, i := pageCodeRE.FindStringSubmatch(body), pageIDRE.FindStringSubmatch(body)
	if c == nil || i == nil {
		f.t.Fatalf("authorize page lacks code or id: %s", body)
	}
	if strings.Contains(body, "wpp-mcp oauth approve "+c[1]) == false {
		f.t.Fatalf("page lacks the approve command")
	}
	return c[1], i[1]
}

func (f *fixture) status(id string) statusResponse {
	f.t.Helper()
	_, body := f.get(PathAuthorizeStatus + "?req=" + id)
	var s statusResponse
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		f.t.Fatalf("status: %v %s", err, body)
	}
	return s
}

// approvedCode runs the flow up to the authorization code.
func (f *fixture) approvedCode(clientID string, approve ApproveRequest) string {
	f.t.Helper()
	code, id := f.startAuthorize(authParams(clientID))
	approve.Code = code
	if _, err := f.srv.Approve(approve); err != nil {
		f.t.Fatal(err)
	}
	st := f.status(id)
	u, err := url.Parse(st.Redirect)
	if err != nil || st.Status != "approved" {
		f.t.Fatalf("status after approval: %+v", st)
	}
	if !strings.HasPrefix(st.Redirect, DefaultRedirectURI+"?") || u.Query().Get("state") != "st-123" || u.Query().Get("iss") != testPublic {
		f.t.Fatalf("redirect: %s", st.Redirect)
	}
	return u.Query().Get("code")
}

func (f *fixture) exchange(clientID, code, verifier string) (int, map[string]any) {
	return f.postForm(PathToken, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {DefaultRedirectURI}, "code_verifier": {verifier}, "resource": {testPublic + "/mcp"},
	})
}

func TestMetadataDocuments(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{PathResourceMetadata, PathResourceMetadataMCP} {
		resp, body := f.get(p)
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", p, resp.StatusCode, body)
		}
		if m["resource"] != testPublic+"/mcp" || len(m["authorization_servers"].([]any)) != 1 || m["authorization_servers"].([]any)[0] != testPublic {
			t.Fatalf("%s: %v", p, m)
		}
		if strings.Join(toStrings(m["scopes_supported"]), ",") != "read,send" || strings.Join(toStrings(m["bearer_methods_supported"]), ",") != "header" {
			t.Fatalf("%s: %v", p, m)
		}
	}
	_, body := f.get(PathAuthServerMetadata)
	var as map[string]any
	if err := json.Unmarshal([]byte(body), &as); err != nil {
		t.Fatal(err)
	}
	// The issuer equals the URL the well-known document was derived from.
	if as["issuer"] != testPublic || f.srv.ResourceMetadataURL() != testPublic+PathResourceMetadataMCP {
		t.Fatalf("issuer: %v", as["issuer"])
	}
	want := map[string]string{
		"authorization_endpoint":                testPublic + "/oauth/authorize",
		"token_endpoint":                        testPublic + "/oauth/token",
		"registration_endpoint":                 testPublic + "/oauth/register",
		"revocation_endpoint":                   testPublic + "/oauth/revoke",
		"response_types_supported":              "code",
		"grant_types_supported":                 "authorization_code,refresh_token",
		"code_challenge_methods_supported":      "S256",
		"token_endpoint_auth_methods_supported": "none",
		"scopes_supported":                      "read,send",
	}
	for k, v := range want {
		got := as[k]
		if arr, ok := got.([]any); ok {
			got = strings.Join(toStrings(arr), ",")
		}
		if got != v {
			t.Errorf("%s = %v, want %s", k, got, v)
		}
	}
	for _, k := range []string{"client_id_metadata_document_supported", "authorization_response_iss_parameter_supported"} {
		if as[k] != true {
			t.Errorf("%s = %v", k, as[k])
		}
	}
}

func toStrings(v any) []string {
	var out []string
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			out = append(out, x.(string))
		}
	}
	return out
}

func TestParsePublicURLAndResource(t *testing.T) {
	for in, want := range map[string]string{
		"https://WPP.Example.com":      "https://wpp.example.com",
		"https://wpp.example.com/":     "https://wpp.example.com",
		"https://wpp.example.com:443":  "https://wpp.example.com",
		"https://wpp.example.com:8443": "https://wpp.example.com:8443",
	} {
		if got, err := ParsePublicURL(in); err != nil || got != want {
			t.Errorf("ParsePublicURL(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "http://wpp.example.com", "https://wpp.example.com/mcp", "https://u@wpp.example.com", "https://wpp.example.com?x=1", "wpp.example.com", "HTTPS://:443", "https://:8443"} {
		if _, err := ParsePublicURL(bad); err == nil {
			t.Errorf("ParsePublicURL(%q) accepted", bad)
		}
	}
	for in, want := range map[string]string{
		"https://WPP.test/mcp":     "https://wpp.test/mcp",
		"https://wpp.test/mcp/":    "https://wpp.test/mcp",
		"https://wpp.test:443/mcp": "https://wpp.test/mcp",
	} {
		if got, ok := CanonicalResource(in); !ok || got != want {
			t.Errorf("CanonicalResource(%q) = %q", in, got)
		}
	}
	if _, ok := CanonicalResource("https://wpp.test/mcp#x"); ok {
		t.Error("fragment accepted")
	}
}

func TestFullFlowAndCodeSingleUse(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	code := f.approvedCode(cid, ApproveRequest{})
	status, tok := f.exchange(cid, code, testVerifier)
	if status != http.StatusOK || tok["token_type"] != "Bearer" || tok["scope"] != "read" || tok["expires_in"].(float64) != 3600 {
		t.Fatalf("exchange: %d %v", status, tok)
	}
	access := tok["access_token"].(string)
	at, err := f.st.VerifyAPIToken(context.Background(), access)
	if err != nil || at.Audience != testPublic+"/mcp" || at.GrantID == "" || !strings.HasPrefix(at.Name, "oauth:Claude#") {
		t.Fatalf("access token row: %+v %v", at, err)
	}
	if at.ExpiresAt == nil || time.Until(*at.ExpiresAt) > time.Hour+time.Minute {
		t.Fatalf("access token lifetime: %v", at.ExpiresAt)
	}
	// Replaying the code fails and revokes what it produced.
	if status, out := f.exchange(cid, code, testVerifier); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", status, out)
	}
	if _, err := f.st.VerifyAPIToken(context.Background(), access); err == nil {
		t.Fatal("code replay did not revoke the grant")
	}
}

func TestCodeExpires(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	code := f.approvedCode(cid, ApproveRequest{})
	f.advance(codeTTL + time.Second)
	if status, out := f.exchange(cid, code, testVerifier); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("expired code: %d %v", status, out)
	}
}

func TestPKCE(t *testing.T) {
	f := newFixture(t)
	cid := f.register()

	// Wrong verifier: refused, and the code is spent.
	code := f.approvedCode(cid, ApproveRequest{})
	wrong := strings.Repeat("a", 50)
	if status, out := f.exchange(cid, code, wrong); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %v", status, out)
	}
	if status, _ := f.exchange(cid, code, testVerifier); status != http.StatusBadRequest {
		t.Fatal("a code survived a failed exchange")
	}
	// Missing verifier.
	code = f.approvedCode(cid, ApproveRequest{})
	if status, _ := f.exchange(cid, code, ""); status != http.StatusBadRequest {
		t.Fatal("missing verifier accepted")
	}

	// plain and missing challenges are refused at the authorization
	// endpoint, by redirect (client and redirect URI are valid).
	for name, mutate := range map[string]func(url.Values){
		"plain":   func(v url.Values) { v.Set("code_challenge_method", "plain"); v.Set("code_challenge", testVerifier) },
		"missing": func(v url.Values) { v.Del("code_challenge"); v.Del("code_challenge_method") },
		"nomethod": func(v url.Values) {
			v.Del("code_challenge_method")
		},
	} {
		p := authParams(cid)
		mutate(p)
		resp, _ := f.get(PathAuthorize + "?" + p.Encode())
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("iss") != testPublic ||
			loc.Query().Get("state") != "st-123" || !strings.HasPrefix(resp.Header.Get("Location"), DefaultRedirectURI+"?") {
			t.Errorf("%s challenge: %d %s", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestAuthorizeValidation(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	for name, c := range map[string]struct {
		mutate func(url.Values)
		err    string
	}{
		"response_type": {func(v url.Values) { v.Set("response_type", "token") }, "unsupported_response_type"},
		"resource":      {func(v url.Values) { v.Set("resource", "https://evil.test/mcp") }, "invalid_target"},
		"scope":         {func(v url.Values) { v.Set("scope", "admin") }, "invalid_scope"},
	} {
		p := authParams(cid)
		c.mutate(p)
		resp, _ := f.get(PathAuthorize + "?" + p.Encode())
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != c.err {
			t.Errorf("%s: %d %s", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// Default resource and scope, send implies read.
	p := authParams(cid)
	p.Del("resource")
	p.Set("scope", "send offline_access")
	f.startAuthorize(p)
	if pend := f.srv.Pending(); len(pend) != 1 || strings.Join(pend[0].Scopes, ",") != "read,send" {
		t.Fatalf("pending: %+v", pend)
	}
}

// A redirect URI outside the allowlist never produces a redirect.
func TestRedirectOutsideAllowlistNeverRedirects(t *testing.T) {
	f := newFixture(t)
	// DCR refuses it.
	body := `{"client_name":"x","redirect_uris":["https://evil.test/cb"]}`
	resp, err := http.Post(f.ts.URL+PathRegister, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DCR with a foreign redirect: %d", resp.StatusCode)
	}
	// Confidential clients are refused too.
	resp, _ = http.Post(f.ts.URL+PathRegister, "application/json", strings.NewReader(`{"redirect_uris":["`+DefaultRedirectURI+`"],"token_endpoint_auth_method":"client_secret_basic"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DCR confidential client: %d", resp.StatusCode)
	}

	cid := f.register()
	for name, mutate := range map[string]func(url.Values){
		"foreign redirect": func(v url.Values) { v.Set("redirect_uri", "https://evil.test/cb") },
		"prefix match":     func(v url.Values) { v.Set("redirect_uri", DefaultRedirectURI+"/x") },
		"no redirect":      func(v url.Values) { v.Del("redirect_uri") },
		"unknown client":   func(v url.Values) { v.Set("client_id", "wppc_00") },
		"no client":        func(v url.Values) { v.Del("client_id") },
		"bad and foreign": func(v url.Values) {
			v.Set("redirect_uri", "https://evil.test/cb")
			v.Set("response_type", "token")
		},
	} {
		p := authParams(cid)
		mutate(p)
		resp, body := f.get(PathAuthorize + "?" + p.Encode())
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || !strings.Contains(body, "not redirected") {
			t.Errorf("%s: %d Location=%q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if len(f.srv.Pending()) != 0 {
		t.Fatal("an invalid request became pending")
	}
}

func TestStatusNeverLeaksCodeBeforeApproval(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	code, id := f.startAuthorize(authParams(cid))
	for i := 0; i < 3; i++ {
		st := f.status(id)
		if st.Status != "pending" || st.Redirect != "" {
			t.Fatalf("unapproved status: %+v", st)
		}
	}
	// The short code is not a request ID.
	if st := f.status(strings.ReplaceAll(code, "-", "")); st.Status != "unknown" || st.Redirect != "" {
		t.Fatalf("short code as id: %+v", st)
	}
	if st := f.status(""); st.Status != "unknown" {
		t.Fatalf("empty id: %+v", st)
	}
	if len(f.srv.codes) != 0 {
		t.Fatal("a code exists before approval")
	}
	// Deny: the page is sent back with access_denied and no code.
	if _, err := f.srv.Deny(strings.ToLower(code)); err != nil {
		t.Fatal(err)
	}
	st := f.status(id)
	u, _ := url.Parse(st.Redirect)
	if st.Status != "denied" || u.Query().Get("error") != "access_denied" || u.Query().Get("code") != "" || u.Query().Get("iss") != testPublic || u.Query().Get("state") != "st-123" {
		t.Fatalf("denied status: %+v", st)
	}
	if _, err := f.srv.Approve(ApproveRequest{Code: code}); err == nil {
		t.Fatal("a denied request was approved")
	}
	// Expiry also ends in access_denied.
	_, id2 := f.startAuthorize(authParams(cid))
	f.advance(pendingTTL + time.Second)
	if st := f.status(id2); st.Status != "denied" || strings.Contains(st.Redirect, "code=") {
		t.Fatalf("expired status: %+v", st)
	}
}

func TestApproveNarrowsScopesAndChats(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	p := authParams(cid)
	p.Set("scope", "read send")
	code, id := f.startAuthorize(p)
	if _, err := f.srv.Approve(ApproveRequest{Code: code, Scopes: []string{"read"}, Chats: []string{"447700000001"}, Days: 7}); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.status(id).Redirect)
	status, tok := f.exchange(cid, u.Query().Get("code"), testVerifier)
	if status != http.StatusOK || tok["scope"] != "read" {
		t.Fatalf("exchange: %d %v", status, tok)
	}
	at, err := f.st.VerifyAPIToken(context.Background(), tok["access_token"].(string))
	if err != nil || at.Identity().Has("send") || len(at.Chats) != 1 || at.Chats[0] != "447700000001@s.whatsapp.net" {
		t.Fatalf("token: %+v %v", at, err)
	}
	grants, _ := f.st.ListOAuthGrants(context.Background())
	if len(grants) != 1 || grants[0].RefreshTTL != int64(7*24*3600) {
		t.Fatalf("grants: %+v", grants)
	}
	if _, err := f.srv.Approve(ApproveRequest{Code: "ZZZZ-ZZZZ"}); err == nil {
		t.Fatal("unknown code approved")
	}
}

func TestRefreshRotationAndReuse(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	code := f.approvedCode(cid, ApproveRequest{})
	_, tok := f.exchange(cid, code, testVerifier)
	rt1, at1 := tok["refresh_token"].(string), tok["access_token"].(string)

	refresh := func(rt, client string) (int, map[string]any) {
		return f.postForm(PathToken, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {client}})
	}
	// Another client cannot use it, and does not burn it.
	if status, out := refresh(rt1, "wppc_other"); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("foreign client refresh: %d %v", status, out)
	}
	status, tok2 := refresh(rt1, cid)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, tok2)
	}
	rt2, at2 := tok2["refresh_token"].(string), tok2["access_token"].(string)
	if rt2 == rt1 || at2 == at1 {
		t.Fatal("refresh did not rotate")
	}
	ctx := context.Background()
	if _, err := f.st.VerifyAPIToken(ctx, at2); err != nil {
		t.Fatalf("new access token: %v", err)
	}
	// Reusing the old refresh token revokes the grant and every token.
	if status, out := refresh(rt1, cid); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", status, out)
	}
	if _, err := f.st.VerifyAPIToken(ctx, at2); err == nil {
		t.Fatal("access token survived refresh token reuse")
	}
	if status, _ := refresh(rt2, cid); status != http.StatusBadRequest {
		t.Fatal("current refresh token survived reuse detection")
	}
	grants, _ := f.st.ListOAuthGrants(ctx)
	if len(grants) != 1 || grants[0].Status(time.Now()) != "revoked" || grants[0].RevokeReason != "refresh token reuse" {
		t.Fatalf("grant: %+v", grants)
	}
}

func TestRevokeEndpoint(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	_, tok := f.exchange(cid, f.approvedCode(cid, ApproveRequest{}), testVerifier)
	ctx := context.Background()
	// Unknown tokens and other clients: 200, nothing happens.
	for _, v := range []url.Values{
		{"token": {"wppmcpr_" + strings.Repeat("0", 64)}},
		{"token": {tok["refresh_token"].(string)}, "client_id": {"wppc_other"}},
	} {
		if status, _ := f.postForm(PathRevoke, v); status != http.StatusOK {
			t.Fatalf("revoke %v: %d", v, status)
		}
	}
	if _, err := f.st.VerifyAPIToken(ctx, tok["access_token"].(string)); err != nil {
		t.Fatal("revoked by a foreign client")
	}
	if status, _ := f.postForm(PathRevoke, url.Values{"token": {tok["refresh_token"].(string)}, "client_id": {cid}}); status != http.StatusOK {
		t.Fatal("revoke")
	}
	if _, err := f.st.VerifyAPIToken(ctx, tok["access_token"].(string)); err == nil {
		t.Fatal("refresh token revocation left the access token valid")
	}
}

func TestTokenEndpointErrors(t *testing.T) {
	f := newFixture(t)
	for name, c := range map[string]struct {
		v    url.Values
		code int
		err  string
	}{
		"no grant type":   {url.Values{"client_id": {"x"}}, 400, "invalid_request"},
		"bad grant type":  {url.Values{"client_id": {"x"}, "grant_type": {"password"}}, 400, "unsupported_grant_type"},
		"no client":       {url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}, 400, "invalid_request"},
		"foreign target":  {url.Values{"client_id": {"x"}, "grant_type": {"refresh_token"}, "refresh_token": {"x"}, "resource": {"https://evil.test/mcp"}}, 400, "invalid_target"},
		"garbage refresh": {url.Values{"client_id": {"x"}, "grant_type": {"refresh_token"}, "refresh_token": {"x"}}, 400, "invalid_grant"},
		"garbage code":    {url.Values{"client_id": {"x"}, "grant_type": {"authorization_code"}, "code": {"x"}, "redirect_uri": {DefaultRedirectURI}, "code_verifier": {testVerifier}}, 400, "invalid_grant"},
	} {
		status, out := f.postForm(PathToken, c.v)
		if status != c.code || out["error"] != c.err {
			t.Errorf("%s: %d %v", name, status, out)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+PathToken, strings.NewReader(`{"grant_type":"refresh_token"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("JSON body: %d", resp.StatusCode)
	}
}

func TestPendingCapAndRateLimit(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	ok := 0
	for i := 0; i < authorizePerIP+2; i++ {
		resp, _ := f.get(PathAuthorize + "?" + authParams(cid).Encode())
		if resp.StatusCode == http.StatusOK {
			ok++
		} else if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("unexpected %d", resp.StatusCode)
		}
	}
	if ok != authorizePerIP {
		t.Fatalf("per-IP limit let %d through", ok)
	}
	// The global cap holds even across addresses.
	f.srv.authorizeLimit = newIPLimiter(1000, time.Minute)
	for i := 0; i < maxPending; i++ {
		resp, _ := f.get(PathAuthorize + "?" + authParams(cid).Encode())
		_ = resp
	}
	if n := len(f.srv.Pending()); n != maxPending {
		t.Fatalf("pending = %d, want cap %d", n, maxPending)
	}
	resp, _ := f.get(PathAuthorize + "?" + authParams(cid).Encode())
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.Contains(loc, "temporarily_unavailable") {
		t.Fatalf("over cap: %d %s", resp.StatusCode, loc)
	}
}

func TestTokenEndpointClientAuth(t *testing.T) {
	f := newFixture(t)
	cid := f.register()
	code := f.approvedCode(cid, ApproveRequest{})
	send := func(user, pass string) (int, map[string]any) {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {DefaultRedirectURI}, "code_verifier": {testVerifier}}
		req, _ := http.NewRequest(http.MethodPost, f.ts.URL+PathToken, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(user, pass)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	// A secret is refused (and does not spend the code).
	if status, out := send(cid, "secret"); status != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Fatalf("basic with secret: %d %v", status, out)
	}
	// The client_id as Basic with an empty secret is accepted.
	if status, out := send(cid, ""); status != http.StatusOK {
		t.Fatalf("basic without secret: %d %v", status, out)
	}
}

func TestClientIP(t *testing.T) {
	for _, c := range []struct{ remote, xff, want string }{
		{"203.0.113.9:4000", "1.2.3.4", "203.0.113.9"},
		{"127.0.0.1:4000", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		{"172.17.0.1:4000", "198.51.100.7", "198.51.100.7"},
		{"127.0.0.1:4000", "", "127.0.0.1"},
		{"127.0.0.1:4000", "garbage", "127.0.0.1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("clientIP(%s, %q) = %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestShortCodeFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := newShortCode()
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`).MatchString(c) || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	if len(codeAlphabet) != 32 || strings.ContainsAny(codeAlphabet, "01IO") {
		t.Fatal("alphabet")
	}
	if NormalizeCode(" abcd efgh ") != "ABCD-EFGH" || NormalizeCode("abcd-efgh") != "ABCD-EFGH" {
		t.Fatal("NormalizeCode")
	}
}

func TestCleanName(t *testing.T) {
	if got := cleanName("  Claude\x1b[31m\n  evil\u202e "); got != "Claude[31m evil" {
		t.Fatalf("cleanName = %q", got)
	}
	if got := cleanName(strings.Repeat("x", 200)); len(got) != maxClientName {
		t.Fatalf("len = %d", len(got))
	}
}
