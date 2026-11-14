package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mdp/qrterminal"

	"github.com/murandido/mcp-wpp/internal/security"
)

const linkWithPhoneHint = "On your phone: WhatsApp → Settings → Linked devices → Link a device → Link with phone number instead, then type the code."

// pairTimeout bounds how long `pair` waits for the phone to finish linking.
const pairTimeout = 4 * time.Minute

// runPair links this daemon to a WhatsApp account. With a running daemon it
// talks to /admin/pair/*; otherwise it pairs directly (the `login` flow).
func runPair(storeDir string, redactor *security.Redactor, args []string) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "wpp-mcp pair: link WhatsApp with a pairing code (-phone) or a QR code in the terminal.")
		fmt.Fprintln(os.Stderr, "Works whether or not `wpp-mcp serve` is running.")
		fmt.Fprintln(os.Stderr, "\nUsage: wpp-mcp [-store DIR] pair [-phone +<international number>] [-addr ADDR] [-full-history]")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	phone := fs.String("phone", "", "pair with an 8-character code instead of a QR (international format, e.g. +5511999999999)")
	addr := fs.String("addr", "", "daemon address (default 127.0.0.1:8765, env WPP_MCP_ADDR)")
	fullHistory := fs.Bool("full-history", false, "without a running daemon: ask the phone for a full history sync")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dc, err := newDaemonClient(storeDir, *addr)
	if err == nil && daemonUp(dc) {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		ctx, cancelT := context.WithTimeout(ctx, pairTimeout)
		defer cancelT()
		if *phone != "" {
			return pairWithCode(ctx, dc, *phone)
		}
		return pairWithQR(ctx, dc)
	}

	fmt.Fprintln(os.Stderr, "No running daemon found; pairing directly (stop with Ctrl-C).")
	loginArgs := []string{}
	if *phone != "" {
		loginArgs = append(loginArgs, "-phone", *phone)
	}
	if *fullHistory {
		loginArgs = append(loginArgs, "-full-history")
	}
	return runLogin(storeDir, redactor, loginArgs)
}

func daemonUp(dc *daemonClient) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := dc.do(ctx, http.MethodGet, "/healthz", nil, "")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type pairStatus struct {
	Paired  bool   `json:"paired"`
	Expired bool   `json:"expired"`
	QR      string `json:"qr"`
	RetryIn int    `json:"retry_in"`
}

func fetchPairStatus(ctx context.Context, dc *daemonClient, start bool) (pairStatus, error) {
	path := "/admin/pair/status"
	if start {
		path += "?start=1"
	}
	var st pairStatus
	resp, err := dc.do(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("daemon returned %s", resp.Status)
	}
	return st, json.NewDecoder(resp.Body).Decode(&st)
}

func pairWithCode(ctx context.Context, dc *daemonClient, phone string) int {
	if st, err := fetchPairStatus(ctx, dc, false); err == nil && st.Paired {
		fmt.Fprintln(os.Stderr, "Already paired.")
		return 0
	}
	body, _ := json.Marshal(map[string]string{"phone": phone})
	resp, err := dc.do(ctx, http.MethodPost, "/admin/pair/code", bytes.NewReader(body), "application/json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pair: %v\n", err)
		return 1
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	var out struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK || out.Code == "" {
		msg := out.Error
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			msg += fmt.Sprintf(" (retry after %ss)", ra)
		}
		fmt.Fprintf(os.Stderr, "pair: %s\n", msg)
		return 1
	}
	printCode(os.Stdout, out.Code)
	fmt.Fprintln(os.Stderr, linkWithPhoneHint)
	fmt.Fprintln(os.Stderr, "The code expires in about 3 minutes. Waiting for the phone…")
	return waitPaired(ctx, dc)
}

func printCode(w io.Writer, code string) {
	pad := strings.Repeat("─", len(code)+6)
	fmt.Fprintf(w, "\n  ┌%s┐\n  │   %s   │\n  └%s┘\n\n", pad, code, pad)
}

func pairWithQR(ctx context.Context, dc *daemonClient) int {
	last := ""
	start := true
	for {
		st, err := fetchPairStatus(ctx, dc, start)
		start = false
		if err != nil {
			fmt.Fprintf(os.Stderr, "pair: %v\n", err)
			return 1
		}
		switch {
		case st.Paired:
			fmt.Fprintln(os.Stderr, "Paired. The daemon is now syncing your chats.")
			return 0
		case st.RetryIn > 0:
			fmt.Fprintf(os.Stderr, "WhatsApp asked us to slow down; retrying in %ds…\n", st.RetryIn)
		case st.Expired:
			// The QR codes ran out; ask for a fresh session on the next poll.
			start = true
		case st.QR != "" && st.QR != last:
			last = st.QR
			fmt.Fprintln(os.Stderr, "\nScan with WhatsApp → Settings → Linked devices → Link a device:")
			qrterminal.GenerateHalfBlock(st.QR, qrterminal.L, os.Stdout)
		}
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "pair: timed out or cancelled")
			return 1
		case <-time.After(2 * time.Second):
		}
	}
}

func waitPaired(ctx context.Context, dc *daemonClient) int {
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "pair: timed out waiting for the phone; request a new code and try again")
			return 1
		case <-time.After(2 * time.Second):
		}
		st, err := fetchPairStatus(ctx, dc, false)
		if err != nil {
			continue
		}
		if st.Paired {
			fmt.Fprintln(os.Stderr, "Paired. The daemon is now syncing your chats.")
			return 0
		}
	}
}
