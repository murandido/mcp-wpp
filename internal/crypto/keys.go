// Package crypto implements encryption at rest for the wpp-mcp store: a
// master key read from a key file, per-purpose sub-keys derived with
// HKDF-SHA256, SQLCipher-encrypted SQLite databases and AES-256-GCM sealed
// media files.
package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// KeySize is the length in bytes of the master key and every sub-key.
const KeySize = 32

// Keys are the sub-keys derived from the master key, one per purpose, so a
// leak of one (for example through a SQLCipher bug) says nothing about the
// others.
type Keys struct {
	Messages []byte // messages.db (SQLCipher)
	WhatsApp []byte // whatsapp.db: session and Signal keys (SQLCipher)
	Media    []byte // cached media files (AES-256-GCM)
}

// DeriveKeys expands master into the per-purpose sub-keys.
func DeriveKeys(master []byte) (*Keys, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(master))
	}
	derive := func(info string) ([]byte, error) {
		return hkdf.Key(sha256.New, master, nil, "wpp-mcp/v1/"+info, KeySize)
	}
	var k Keys
	var err error
	if k.Messages, err = derive("messages.db"); err != nil {
		return nil, err
	}
	if k.WhatsApp, err = derive("whatsapp.db"); err != nil {
		return nil, err
	}
	if k.Media, err = derive("media"); err != nil {
		return nil, err
	}
	return &k, nil
}

// LoadKeyFile reads a hex-encoded master key and derives the sub-keys. The
// file must not be readable or writable by group or others.
func LoadKeyFile(path string) (*Keys, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("key file %s not found; create one with `wpp-mcp keygen -out %s` (and back it up: without it the store cannot be read)", path, path)
		}
		return nil, fmt.Errorf("key file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 && !isMountedSecret(path) {
		return nil, fmt.Errorf("key file %s is accessible by other users (mode %04o); run: chmod 600 %s", path, fi.Mode().Perm(), path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	master, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(master) != KeySize {
		return nil, fmt.Errorf("key file %s must hold %d hex characters (a %d-byte key)", path, KeySize*2, KeySize)
	}
	return DeriveKeys(master)
}

// isMountedSecret reports whether path is a Docker/Compose or systemd
// credential mount. Those are owned by root with group/other read bits that
// the container user cannot change, but the directory itself is private to
// the container or service.
func isMountedSecret(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if strings.HasPrefix(abs, "/run/secrets/") {
		return true
	}
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" && strings.HasPrefix(abs, filepath.Clean(cd)+string(filepath.Separator)) {
		return true
	}
	return false
}

// NewKeyHex returns a new random master key, hex-encoded.
func NewKeyHex() (string, error) {
	master := make([]byte, KeySize)
	if _, err := rand.Read(master); err != nil {
		return "", err
	}
	return hex.EncodeToString(master), nil
}

// GenerateKeyFile writes a new random master key to path with mode 0600. It
// never overwrites an existing file: losing the old key loses the store.
func GenerateKeyFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	key, err := NewKeyHex()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite a key", path)
		}
		return err
	}
	if _, err := f.WriteString(key + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// DefaultKeyPath picks the key file location: WPP_MCP_KEY_FILE, then a
// Docker secret, then a systemd credential, then the user config directory.
func DefaultKeyPath() string {
	if p := os.Getenv("WPP_MCP_KEY_FILE"); p != "" {
		return p
	}
	if _, err := os.Stat("/run/secrets/wpp_mcp_key"); err == nil {
		return "/run/secrets/wpp_mcp_key"
	}
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
		p := filepath.Join(cd, "wpp_mcp_key")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "wpp-mcp", "key")
	}
	return "wpp-mcp.key"
}
