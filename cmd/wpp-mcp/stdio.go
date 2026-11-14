package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// runStdio bridges an MCP client that speaks stdio (newline-delimited
// JSON-RPC) to the running daemon's Streamable HTTP endpoint. The client
// config then holds only a command, never a port or a token: the token is
// read from the store directory, which only the owner can read.
func runStdio(storeDir string, args []string) int {
	fs := flag.NewFlagSet("stdio", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "", "daemon address: host:port or unix:/path.sock (default 127.0.0.1:8765, env WPP_MCP_ADDR)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dc, err := newDaemonClient(storeDir, *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wpp-mcp stdio: %v\n", err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := proxyStdio(ctx, dc, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "wpp-mcp stdio: %v\n", err)
		return 1
	}
	return 0
}

// lockedWriter serialises whole lines so concurrent responses never interleave.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) writeLine(b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(bytes.TrimSpace(b), '\n'))
}

func proxyStdio(ctx context.Context, dc *daemonClient, in io.Reader, out io.Writer) error {
	w := &lockedWriter{w: out}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 64*1024*1024)
	var wg sync.WaitGroup
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		msg := append([]byte(nil), line...)
		wg.Add(1)
		// Requests run concurrently: a slow media download must not block a
		// quick list_chats issued after it.
		go func() {
			defer wg.Done()
			forward(ctx, dc, msg, w)
		}()
	}
	wg.Wait()
	return sc.Err()
}

func forward(ctx context.Context, dc *daemonClient, msg []byte, w *lockedWriter) {
	resp, err := dc.do(ctx, http.MethodPost, "/mcp", bytes.NewReader(msg), "application/json")
	if err != nil {
		replyError(msg, w, fmt.Sprintf("wpp-mcp daemon unreachable (is `wpp-mcp serve` running?): %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		return // notification or response acknowledged
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		replyError(msg, w, fmt.Sprintf("wpp-mcp daemon returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body))))
		return
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mt == "text/event-stream" {
		relaySSE(resp.Body, w)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		replyError(msg, w, fmt.Sprintf("read daemon response: %v", err))
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		w.writeLine(compactJSON(body))
	}
}

// relaySSE writes each SSE event's data payload as one line.
func relaySSE(r io.Reader, w *lockedWriter) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024*1024)
	var data bytes.Buffer
	flush := func() {
		if data.Len() > 0 {
			w.writeLine(compactJSON(data.Bytes()))
			data.Reset()
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
}

func compactJSON(b []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return bytes.ReplaceAll(b, []byte("\n"), nil)
	}
	return buf.Bytes()
}

// replyError answers a request with a JSON-RPC error so the client does not
// hang. Notifications (no id) are only logged.
func replyError(msg []byte, w *lockedWriter, text string) {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(msg, &probe) != nil || len(probe.ID) == 0 || string(probe.ID) == "null" {
		fmt.Fprintln(os.Stderr, "wpp-mcp stdio:", text)
		return
	}
	resp, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      probe.ID,
		"error":   map[string]any{"code": -32603, "message": text},
	})
	w.writeLine(resp)
}
