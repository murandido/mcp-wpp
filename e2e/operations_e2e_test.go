//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// wpp runs the binary with -store and -key-file and returns its output.
func wpp(t *testing.T, bin, store, key string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"-store", store, "-key-file", key}, args...)
	cmd := exec.Command(bin, full...)
	cmd.Env = append(os.Environ(), "WPP_MCP_KEY_FILE=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestOperations_BackupRestoreRekey(t *testing.T) {
	bin := binPath(t)
	src := t.TempDir()
	key := keygen(t, bin)

	// Back up the store of a running daemon, and read its metrics.
	d, err := startServe(t, bin, src, []string{"-key-file", key})
	if err != nil {
		t.Fatal(err)
	}
	addr := regexp.MustCompile(`listening on (?:http://)?([^\s/]+)`).FindStringSubmatch(d.out.String())
	if addr == nil {
		t.Fatalf("no listen address in: %s", d.out.String())
	}
	token, err := os.ReadFile(filepath.Join(src, "token"))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr[1]+"/admin/metrics", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("metrics without a token must be refused: %v %v", resp, err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "wpp_mcp_uptime_seconds") || !strings.Contains(string(body), "wpp_mcp_whatsapp_paired 0") {
		t.Fatalf("metrics: %d %s", resp.StatusCode, body)
	}

	archive := filepath.Join(t.TempDir(), "store.tar")
	if out, err := wpp(t, bin, src, key, "backup", "-out", archive); err != nil {
		t.Fatalf("backup of a running daemon: %v %s", err, out)
	}
	fi, err := os.Stat(archive)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive: %v %v", fi, err)
	}
	if out, err := wpp(t, bin, src, key, "backup", "verify", archive); err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("verify: %v %s", err, out)
	}
	if out, err := wpp(t, bin, src, keygen(t, bin), "backup", "verify", archive); err == nil || !strings.Contains(out, "different key") {
		t.Fatalf("verify with a wrong key must fail clearly: %v %s", err, out)
	}
	d.stop()

	// Restore into a fresh directory.
	dst := filepath.Join(t.TempDir(), "restored")
	if out, err := wpp(t, bin, dst, key, "restore", "-in", archive); err != nil {
		t.Fatalf("restore: %v %s", err, out)
	}
	assertEncrypted(t, filepath.Join(dst, "messages.db"))
	assertEncrypted(t, filepath.Join(dst, "whatsapp.db"))
	if out, err := wpp(t, bin, dst, key, "restore", "-in", archive); err == nil || !strings.Contains(out, "-force") {
		t.Fatalf("restore over data must need -force: %v %s", err, out)
	}

	// Restore and rekey refuse a store a daemon is using.
	d, err = startServe(t, bin, dst, []string{"-key-file", key})
	if err != nil {
		t.Fatalf("serve the restored store: %v", err)
	}
	if out, err := wpp(t, bin, dst, key, "restore", "-force", "-in", archive); err == nil || !strings.Contains(out, "already running") {
		t.Fatalf("restore with the daemon running: %v %s", err, out)
	}
	newKey := keygen(t, bin)
	if out, err := wpp(t, bin, dst, key, "rekey", "-new-key-file", newKey); err == nil || !strings.Contains(out, "already running") {
		t.Fatalf("rekey with the daemon running: %v %s", err, out)
	}
	d.stop()

	// Rotate the key; serve must start with the new key only.
	if out, err := wpp(t, bin, dst, key, "rekey", "-new-key-file", newKey); err != nil {
		t.Fatalf("rekey: %v %s", err, out)
	}
	if _, err := startServe(t, bin, dst, []string{"-key-file", key}); err == nil || !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("the old key must no longer open the store: %v", err)
	}
	d, err = startServe(t, bin, dst, []string{"-key-file", newKey})
	if err != nil {
		t.Fatalf("serve with the new key: %v", err)
	}
	d.stop()

	// The old backup still needs the old key.
	if out, err := wpp(t, bin, dst, newKey, "backup", "verify", archive); err == nil {
		t.Fatalf("an old backup must not verify with the new key: %s", out)
	}
}
