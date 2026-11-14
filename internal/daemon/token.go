package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// TokenFileName is the default token file name inside the store directory.
const TokenFileName = "token"

// ResolveToken returns the bearer token for the daemon and its clients.
// WPP_MCP_TOKEN wins when set (envToken). Otherwise the token is read from
// path; when create is true and the file does not exist, a new random token
// is written there with mode 0600.
func ResolveToken(envToken, path string, create bool) (string, error) {
	if t := strings.TrimSpace(envToken); t != "" {
		if len(t) < 16 {
			return "", errors.New("WPP_MCP_TOKEN must be at least 16 characters")
		}
		return t, nil
	}
	tok, err := readTokenFile(path)
	if err == nil {
		return tok, nil
	}
	if !errors.Is(err, fs.ErrNotExist) || !create {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create token dir: %w", err)
	}
	tok = randomToken()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create token file: %w", err)
	}
	if _, err := f.WriteString(tok + "\n"); err != nil {
		f.Close()
		return "", fmt.Errorf("write token file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("write token file: %w", err)
	}
	return tok, nil
}

func readTokenFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file %s is accessible by other users (mode %04o); run: chmod 600 %s", path, fi.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if len(tok) < 16 {
		return "", fmt.Errorf("token file %s is empty or too short", path)
	}
	return tok, nil
}
