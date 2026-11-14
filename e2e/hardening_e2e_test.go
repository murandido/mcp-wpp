//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestHardening_MCPRequiresToken(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost, "http://"+h.addr+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/mcp without token: got %d, want 401", resp.StatusCode)
	}
}

func TestHardening_RejectsRebindingHost(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct{ host, origin string }{
		{"attacker.example:8765", ""},
		{"", "http://attacker.example"},
	} {
		req, _ := http.NewRequest(http.MethodPost, "http://"+h.addr+"/mcp", strings.NewReader(`{}`))
		if tc.host != "" {
			req.Host = tc.host
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		resp, err := h.do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("host=%q origin=%q: got %d, want 403", tc.host, tc.origin, resp.StatusCode)
		}
	}
}

func TestStdioProxy_RoundTrip(t *testing.T) {
	h := newHarness(t)
	cmd := exec.Command(h.bin, "-store", h.store, "stdio", "-addr", h.addr)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	lines := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	next := func() string {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("stdio closed early; stderr: %s", stderr.String())
			}
			return l
		case <-time.After(10 * time.Second):
			t.Fatalf("timeout waiting for stdio response; stderr: %s", stderr.String())
		}
		return ""
	}

	_, _ = stdin.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}` + "\n"))
	if got := next(); !strings.Contains(got, `"serverInfo"`) || !strings.Contains(got, `"id":1`) {
		t.Fatalf("initialize via stdio: %s", got)
	}
	_, _ = stdin.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))
	_, _ = stdin.Write([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"))
	got := next()
	if !strings.Contains(got, `"id":2`) || !strings.Contains(got, `"list_chats"`) {
		t.Fatalf("tools/list via stdio: %s", got)
	}
	if strings.Contains(got, `"send_message"`) {
		t.Fatal("default daemon is read-only but stdio listed send_message")
	}
}
