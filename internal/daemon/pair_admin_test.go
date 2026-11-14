package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func postCode(t *testing.T, c *http.Client, base, body string) (int, pairCodeResponse) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/admin/pair/code", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out pairCodeResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAdminPairCode(t *testing.T) {
	s, drv, _, base := startFlowServer(t, false)
	waitFor(t, func() bool { return drv.starts.Load() == 1 }, "boot started pairing")
	drv.qrCh <- "qr-1"
	waitFor(t, func() bool { return s.Cache().QR() == "qr-1" }, "session ready")

	if code, _ := postCode(t, rawClient, base, `{"phone":"+5511999999999"}`); code != http.StatusUnauthorized {
		t.Fatalf("without token: %d", code)
	}
	if code, out := postCode(t, http.DefaultClient, base, `{"phone":"abc"}`); code != http.StatusBadRequest || out.Error == "" {
		t.Fatalf("invalid phone: %d %+v", code, out)
	}
	code, out := postCode(t, http.DefaultClient, base, `{"phone":"+55 11 99999-9999"}`)
	if code != http.StatusOK || out.Code != "ABCD-1234" {
		t.Fatalf("code request: %d %+v", code, out)
	}
	// The short-term limiter allows one request per burst.
	if code, _ := postCode(t, http.DefaultClient, base, `{"phone":"+5511999999999"}`); code != http.StatusTooManyRequests {
		t.Fatalf("second immediate request: %d, want 429", code)
	}
}

func TestAdminPairStatus(t *testing.T) {
	s, drv, _, base := startFlowServer(t, false)
	waitFor(t, func() bool { return drv.starts.Load() == 1 }, "boot started pairing")
	drv.qrCh <- "qr-xyz"
	waitFor(t, func() bool { return s.Cache().QR() == "qr-xyz" }, "QR cached")

	req, _ := http.NewRequest(http.MethodGet, base+"/admin/pair/status", nil)
	if got := status(t, rawClient, req); got != http.StatusUnauthorized {
		t.Fatalf("status without token: %d", got)
	}
	resp, err := http.Get(base + "/admin/pair/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st pairStatusResponse
	_ = json.NewDecoder(resp.Body).Decode(&st)
	if st.Paired || st.QR != "qr-xyz" {
		t.Fatalf("status: %+v", st)
	}
}

func TestAdminPairCode_AlreadyPaired(t *testing.T) {
	_, _, _, base := startFlowServer(t, true)
	if code, _ := postCode(t, http.DefaultClient, base, `{"phone":"+5511999999999"}`); code != http.StatusConflict {
		t.Fatalf("paired daemon: %d, want 409", code)
	}
}

func TestPairCode_HourlyCap(t *testing.T) {
	h := newPairHandlers(NewPairCache(), nil, nil)
	h.pairCodeLimiter = NewLimiter(1000, 1000) // isolate the hourly cap
	allowed := 0
	for i := 0; i < 10; i++ {
		if ok, _ := h.allowCode(); ok {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("hourly cap allowed %d requests, want 5", allowed)
	}
}

func TestMaskPhone(t *testing.T) {
	if got := maskPhone("5511999991234"); got != "*********1234" {
		t.Fatalf("maskPhone = %q", got)
	}
	if got := maskPhone("12"); got != "****" {
		t.Fatalf("maskPhone short = %q", got)
	}
}
