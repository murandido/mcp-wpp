package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/murandido/mcp-wpp/internal/client"
)

// Operator pairing endpoints for `wpp-mcp pair`. They live under /admin, so
// they accept only the bearer token (never a browser cookie) and need no
// CSRF token. The model never sees them: pairing_status exposes neither the
// QR payload nor a pairing code.

type pairStatusResponse struct {
	Paired  bool   `json:"paired"`
	Expired bool   `json:"expired,omitempty"`
	QR      string `json:"qr,omitempty"`
	RetryIn int    `json:"retry_in,omitempty"`
}

type pairCodeRequest struct {
	Phone string `json:"phone"`
}

type pairCodeResponse struct {
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// allowCode applies both pairing-code limits: a short-term burst limit and
// an hourly cap. WhatsApp throttles code requests server-side as well, and
// repeated requests can get the number temporarily blocked from linking.
func (h *pairHandlers) allowCode() (bool, int) {
	if !h.pairCodeLimiter.Allow() {
		return false, 20
	}
	if h.pairCodeHourLimiter != nil && !h.pairCodeHourLimiter.Allow() {
		return false, 15 * 60
	}
	return true, 0
}

func (h *pairHandlers) mountAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/pair/status", h.handleAdminPairStatus)
	mux.HandleFunc("POST /admin/pair/code", h.handleAdminPairCode)
}

// handleAdminPairStatus reports the pairing state. With ?start=1 it starts a
// new pairing session when the previous one expired, as opening /pair does.
func (h *pairHandlers) handleAdminPairStatus(w http.ResponseWriter, r *http.Request) {
	resp := pairStatusResponse{Paired: h.cache.Paired()}
	if !resp.Paired {
		if h.flow != nil && r.URL.Query().Get("start") == "1" {
			var backoff *pairBackoffError
			if _, err := h.flow.ensure(); errors.As(err, &backoff) {
				resp.RetryIn = backoff.seconds()
			}
		}
		resp.Expired = h.cache.Expired()
		resp.QR = h.cache.QR()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *pairHandlers) handleAdminPairCode(w http.ResponseWriter, r *http.Request) {
	if h.cache.Paired() {
		writeJSON(w, http.StatusConflict, pairCodeResponse{Error: "already paired; unlink from the phone or reset /pair first"})
		return
	}
	if h.coder == nil {
		writeJSON(w, http.StatusNotImplemented, pairCodeResponse{Error: "phone-number pairing not supported by this driver"})
		return
	}
	var req pairCodeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, pairCodeResponse{Error: "body must be JSON {\"phone\": \"+<international number>\"}"})
		return
	}
	phone := normalizePairingPhone(req.Phone)
	if phone == "" {
		writeJSON(w, http.StatusBadRequest, pairCodeResponse{Error: "enter a valid international phone number (country code first)"})
		return
	}
	if ok, retry := h.allowCode(); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests, pairCodeResponse{Error: "too many pairing-code requests; wait before trying again"})
		return
	}
	code, err := h.requestCode(r.Context(), phone)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, pairCodeResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, pairCodeResponse{Code: client.FormatPairingCode(code)})
}

// autoPair requests one pairing code at startup and prints it. The code is
// single-use and expires within minutes, but it still lands in logs, so
// prefer `wpp-mcp pair -phone` where a terminal is available.
func autoPair(ctx context.Context, h *pairHandlers, rawPhone string) {
	phone := normalizePairingPhone(rawPhone)
	if phone == "" {
		fmt.Fprintln(os.Stderr, "WPP_MCP_PAIR_PHONE is not a valid international number; skipping automatic pairing code")
		return
	}
	if h.coder == nil {
		return
	}
	if ok, _ := h.allowCode(); !ok {
		return
	}
	code, err := h.requestCode(ctx, phone)
	if err != nil {
		fmt.Fprintf(os.Stderr, "automatic pairing code for %s failed: %v (run `wpp-mcp pair -phone ...` to retry)\n", maskPhone(phone), err)
		return
	}
	fmt.Fprintf(os.Stderr, "\nPairing code for %s: %s\nOn your phone: WhatsApp → Settings → Linked devices → Link a device → Link with phone number instead. Expires in about 3 minutes.\n\n", maskPhone(phone), client.FormatPairingCode(code))
}

// maskPhone keeps only the last four digits for logs.
func maskPhone(p string) string {
	if len(p) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(p)-4) + p[len(p)-4:]
}
