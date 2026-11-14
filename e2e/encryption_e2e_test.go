//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// daemonRun starts `serve` on store with the given global flags and waits
// until /healthz answers, or returns the process output if it exits first.
type daemonRun struct {
	cmd *exec.Cmd
	out *bytes.Buffer
}

func startServe(t *testing.T, bin, store string, global []string) (*daemonRun, error) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	args := append(append([]string{"-store", store}, global...), "serve", "-addr", addr)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "WPP_MCP_KEY_FILE=") // only -key-file counts here
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			return nil, fmt.Errorf("serve exited (%v): %s", err, out.String())
		default:
		}
		if resp, err := http.Get("http://" + addr + "/healthz"); err == nil {
			resp.Body.Close()
			d := &daemonRun{cmd: cmd, out: &out}
			t.Cleanup(func() { d.stop() })
			return d, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return nil, fmt.Errorf("serve not ready: %s", out.String())
}

func (d *daemonRun) stop() {
	if d.cmd.ProcessState != nil {
		return
	}
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = d.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = d.cmd.Process.Kill()
	}
}

func binPath(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(repoRoot(t), "bin", "wpp-mcp")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("binary missing (run make e2e): %v", err)
	}
	return bin
}

func keygen(t *testing.T, bin string) string {
	t.Helper()
	key := filepath.Join(t.TempDir(), "key")
	if out, err := exec.Command(bin, "-key-file", key, "keygen").CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	return key
}

func assertEncrypted(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3")) {
		t.Fatalf("%s is plaintext SQLite", path)
	}
}

func TestEncryption_RestartReopensStore(t *testing.T) {
	bin := binPath(t)
	store := t.TempDir()
	key := keygen(t, bin)
	for i := 0; i < 2; i++ {
		d, err := startServe(t, bin, store, []string{"-key-file", key})
		if err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		d.stop()
	}
	assertEncrypted(t, filepath.Join(store, "messages.db"))
	assertEncrypted(t, filepath.Join(store, "whatsapp.db"))
}

func TestEncryption_WrongKeyRefused(t *testing.T) {
	bin := binPath(t)
	store := t.TempDir()
	d, err := startServe(t, bin, store, []string{"-key-file", keygen(t, bin)})
	if err != nil {
		t.Fatal(err)
	}
	d.stop()
	_, err = startServe(t, bin, store, []string{"-key-file", keygen(t, bin)})
	if err == nil || !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("wrong key must be refused with a clear error, got: %v", err)
	}
	_, err = startServe(t, bin, store, []string{"-no-encryption"})
	if err == nil || !strings.Contains(err.Error(), "is encrypted") {
		t.Fatalf("-no-encryption on an encrypted store must be refused, got: %v", err)
	}
}

func TestEncryption_MigratePlaintextStore(t *testing.T) {
	bin := binPath(t)
	store := t.TempDir()
	d, err := startServe(t, bin, store, []string{"-no-encryption"})
	if err != nil {
		t.Fatal(err)
	}
	d.stop()
	key := keygen(t, bin)
	if _, err := startServe(t, bin, store, []string{"-key-file", key}); err == nil || !strings.Contains(err.Error(), "wpp-mcp encrypt") {
		t.Fatalf("plaintext store with a key must point at `wpp-mcp encrypt`, got: %v", err)
	}
	if out, err := exec.Command(bin, "-store", store, "-key-file", key, "encrypt").CombinedOutput(); err != nil {
		t.Fatalf("encrypt: %v %s", err, out)
	}
	assertEncrypted(t, filepath.Join(store, "messages.db"))
	assertEncrypted(t, filepath.Join(store, "whatsapp.db"))
	if d, err = startServe(t, bin, store, []string{"-key-file", key}); err != nil {
		t.Fatalf("serve after migration: %v", err)
	}
	d.stop()
}
