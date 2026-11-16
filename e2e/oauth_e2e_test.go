//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	oauthHost     = "wpp.test"
	oauthPublic   = "https://" + oauthHost
	oauthCallback = "https://claude.ai/api/mcp/auth_callback"
)

var (
	oauthCodeRE = regexp.MustCompile(`<code class="big">([A-Z0-9]{4}-[A-Z0-9]{4})</code>`)
	oauthIDRE   = regexp.MustCompile(`encodeURIComponent\("([0-9a-f]{32})"\)`)
)

// oauthClient talks to the daemon as if through the reverse proxy: every
// request carries Host wpp.test, and redirects are never followed.
type oauthClient struct {
	t *testing.T
	h *harness
	c *http.Client
}

func (o *oauthClient) send(method, path, contentType, body string, hdr map[string]string) (*http.Response, []byte) {
	o.t.Helper()
	req, err := http.NewRequest(method, "http://"+o.h.addr+path, strings.NewReader(body))
	if err != nil {
		o.t.Fatal(err)
	}
	req.Host = oauthHost
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := o.c.Do(req)
	if err != nil {
		o.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func (o *oauthClient) token(form url.Values) (int, map[string]any) {
	o.t.Helper()
	resp, raw := o.send(http.MethodPost, "/oauth/token", "application/x-www-form-urlencoded", form.Encode(), nil)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (o *oauthClient) mcp(token string) int {
	o.t.Helper()
	resp, _ := o.send(http.MethodPost, "/mcp", "application/json", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		map[string]string{"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream"})
	return resp.StatusCode
}

// connect runs register → authorize → CLI approve → status → token and
// returns the client ID and token response.
func (o *oauthClient) connect(approveArgs ...string) (string, map[string]any) {
	t := o.t
	t.Helper()
	resp, raw := o.send(http.MethodPost, "/oauth/register", "application/json",
		`{"client_name":"Claude","redirect_uris":["`+oauthCallback+`"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}`, nil)
	var reg map[string]any
	if err := json.Unmarshal(raw, &reg); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.StatusCode, raw)
	}
	clientID := reg["client_id"].(string)

	verifier := strings.Repeat("v3rifier-", 6)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {oauthCallback}, "state": {"xyz"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"resource": {oauthPublic + "/mcp"}, "scope": {"read"},
	}
	resp, raw = o.send(http.MethodGet, "/oauth/authorize?"+q.Encode(), "", "", nil)
	page := string(raw)
	code, id := oauthCodeRE.FindStringSubmatch(page), oauthIDRE.FindStringSubmatch(page)
	if resp.StatusCode != http.StatusOK || code == nil || id == nil {
		t.Fatalf("authorize: %d %s", resp.StatusCode, page)
	}
	if strings.Contains(page, id[1][:8]+"-") || strings.Contains(strings.ReplaceAll(code[1], "-", ""), id[1]) {
		t.Fatal("short code and request ID are related")
	}

	out, err := o.h.cli(t, "oauth", "pending")
	if err != nil || !strings.Contains(out, code[1]) || !strings.Contains(out, "claude.ai") || !strings.Contains(out, "Claude") {
		t.Fatalf("oauth pending: %s %v", out, err)
	}
	// Before approval the status endpoint returns no code.
	resp, raw = o.send(http.MethodGet, "/oauth/authorize/status?req="+id[1], "", "", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"pending"`) || strings.Contains(string(raw), "code=") {
		t.Fatalf("status before approval: %d %s", resp.StatusCode, raw)
	}
	if out, err := o.h.cli(t, append([]string{"oauth", "approve", code[1]}, approveArgs...)...); err != nil || !strings.Contains(out, "Approved") {
		t.Fatalf("oauth approve: %s %v", out, err)
	}
	resp, raw = o.send(http.MethodGet, "/oauth/authorize/status?req="+id[1], "", "", nil)
	var st struct {
		Status   string `json:"status"`
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(raw, &st); err != nil || st.Status != "approved" || !strings.HasPrefix(st.Redirect, oauthCallback+"?") {
		t.Fatalf("status after approval: %s", raw)
	}
	u, _ := url.Parse(st.Redirect)
	if u.Query().Get("state") != "xyz" || u.Query().Get("iss") != oauthPublic || u.Query().Get("code") == "" {
		t.Fatalf("redirect: %s", st.Redirect)
	}
	status, tok := o.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "client_id": {clientID},
		"redirect_uri": {oauthCallback}, "code_verifier": {verifier}, "resource": {oauthPublic + "/mcp"},
	})
	if status != http.StatusOK || tok["token_type"] != "Bearer" || tok["refresh_token"] == nil {
		t.Fatalf("token exchange: %d %v", status, tok)
	}
	return clientID, tok
}

func TestOAuth_ConnectRefreshRevoke(t *testing.T) {
	h := newHarness(t, "-oauth", "-public-url", oauthPublic, "-allowed-host", oauthHost)
	o := &oauthClient{t: t, h: h, c: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}

	// Discovery: the 401 points at the metadata, which points at the issuer.
	resp, _ := o.send(http.MethodPost, "/mcp", "application/json", `{}`, nil)
	if want := `Bearer realm="wpp-mcp", resource_metadata="` + oauthPublic + `/.well-known/oauth-protected-resource/mcp", scope="read"`; resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != want {
		t.Fatalf("challenge: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	_, raw := o.send(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", "", "", nil)
	if !strings.Contains(string(raw), `"authorization_servers":["`+oauthPublic+`"]`) {
		t.Fatalf("resource metadata: %s", raw)
	}
	_, raw = o.send(http.MethodGet, "/.well-known/oauth-authorization-server", "", "", nil)
	if !strings.Contains(string(raw), `"issuer":"`+oauthPublic+`"`) || !strings.Contains(string(raw), `"code_challenge_methods_supported":["S256"]`) {
		t.Fatalf("authorization server metadata: %s", raw)
	}

	clientID, tok := o.connect()
	access, refresh := tok["access_token"].(string), tok["refresh_token"].(string)
	if code := o.mcp(access); code != http.StatusOK {
		t.Fatalf("/mcp with the access token: %d", code)
	}
	if res := h.as(access).callTool("get_status", map[string]any{}); res.IsError {
		t.Fatalf("get_status with the access token: %s", res.Text)
	}

	// Refresh rotates; the new access token works.
	status, tok2 := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
	if status != http.StatusOK || tok2["refresh_token"] == refresh {
		t.Fatalf("refresh: %d %v", status, tok2)
	}
	access2 := tok2["access_token"].(string)
	if code := o.mcp(access2); code != http.StatusOK {
		t.Fatalf("/mcp after refresh: %d", code)
	}
	// Reusing the old refresh token is refused and revokes the grant.
	if status, out := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}}); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("refresh reuse: %d %v", status, out)
	}
	if code := o.mcp(access2); code != http.StatusUnauthorized {
		t.Fatalf("access token after refresh reuse: %d", code)
	}

	// A second connection, revoked by the operator through the CLI.
	_, tok3 := o.connect("-scope", "read")
	access3 := tok3["access_token"].(string)
	if code := o.mcp(access3); code != http.StatusOK {
		t.Fatalf("/mcp with the second grant: %d", code)
	}
	out, err := h.cli(t, "oauth", "grants")
	if err != nil {
		t.Fatalf("oauth grants: %s %v", out, err)
	}
	var active string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " active ") {
			active = strings.Fields(line)[0]
		}
		if strings.Contains(line, access3) || strings.Contains(line, refresh) {
			t.Fatal("grants output leaks a token")
		}
	}
	if active == "" || !strings.Contains(out, "refresh token reuse") {
		t.Fatalf("oauth grants: %s", out)
	}
	if out, err := h.cli(t, "oauth", "revoke", active); err != nil {
		t.Fatalf("oauth revoke: %s %v", out, err)
	}
	if code := o.mcp(access3); code != http.StatusUnauthorized {
		t.Fatalf("access token after operator revoke: %d", code)
	}

	// The operator's decisions are in the audit log; tokens are not.
	out, err = h.cli(t, "audit", "-since", "1h")
	if err != nil || !strings.Contains(out, "POST /admin/oauth/approve") || !strings.Contains(out, "POST /admin/oauth/grants/{id}/revoke") {
		t.Fatalf("audit: %s %v", out, err)
	}
	if strings.Contains(out, access) || strings.Contains(out, refresh) {
		t.Fatal("audit leaks a token")
	}
}

func TestOAuth_ServeRefusesWithoutPublicURL(t *testing.T) {
	bin := binPath(t)
	store := t.TempDir()
	key := keygen(t, bin)
	for _, args := range [][]string{
		{"-oauth"},
		{"-oauth", "-public-url", "http://wpp.test"},
		{"-oauth", "-public-url", "https://wpp.test/mcp"},
		{"-oauth", "-public-url", "https://wpp.test", "-oauth-redirect-uris", "http://evil.test/cb"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, bin, append([]string{"-store", store, "-key-file", key, "serve", "-addr", fmt.Sprintf("127.0.0.1:%d", freePort(t))}, args...)...)
		cmd.Env = append(os.Environ(), "WPP_MCP_KEY_FILE=")
		out, err := cmd.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "public URL") && !strings.Contains(string(out), "redirect URI") && !strings.Contains(string(out), "-public-url") {
			t.Fatalf("serve %v: %v %s", args, err, out)
		}
	}
}
