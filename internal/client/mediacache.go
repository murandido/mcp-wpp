package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/murandido/mcp-wpp/internal/crypto"
)

// The media cache lives under the store directory. With encryption at rest
// every cache file is sealed (crypto.MediaCipher) and bound to its path
// relative to the store; files outside the store (output_path exports and
// outbound attachments) are always plaintext, because the operator asked
// for a usable copy there.

// storeRel returns path relative to the store directory, and whether path
// lives inside it.
func (c *Client) storeRel(path string) (string, bool) {
	root, err := filepath.Abs(c.store.Dir())
	if err != nil {
		return "", false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(filepath.Clean(root), abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// writeCacheFile atomically stores data at path (inside the store), sealed
// when encryption is on.
func (c *Client) writeCacheFile(dir, path string, data []byte) error {
	if c.media != nil {
		rel, ok := c.storeRel(path)
		if !ok {
			return fmt.Errorf("cache path %s is outside the store", path)
		}
		sealed, err := c.media.Seal(data, rel)
		if err != nil {
			return err
		}
		data = sealed
	}
	return replaceCacheFile(dir, path, data)
}

// readCacheFile returns the plaintext of a cache file.
func (c *Client) readCacheFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if c.media == nil {
		if crypto.IsSealed(raw) {
			return nil, errors.New("cached media is encrypted but no key is configured")
		}
		return raw, nil
	}
	rel, ok := c.storeRel(path)
	if !ok {
		return nil, fmt.Errorf("cache path %s is outside the store", path)
	}
	return c.media.Open(raw, rel)
}

// ReadMedia returns the plaintext bytes of a path returned by Download:
// decrypted from the cache, or read as-is from an output_path export.
func (c *Client) ReadMedia(path string) ([]byte, error) {
	if _, inStore := c.storeRel(path); inStore {
		return c.readCacheFile(path)
	}
	return os.ReadFile(path)
}

// validateCacheFile checks a cache file's plaintext against the recorded
// size and SHA-256.
func (c *Client) validateCacheFile(path string, fileLength uint64, fileSHA256 []byte) error {
	data, err := c.readCacheFile(path)
	if err != nil {
		return err
	}
	return validateMediaPayload(data, fileLength, fileSHA256)
}

// SealExistingCache encrypts every plaintext file in the media cache in
// place. It is used by `wpp-mcp encrypt` and is idempotent: sealed files are
// skipped. Databases, the token, the lock and the uploads root are left
// alone.
func (c *Client) SealExistingCache() (int, error) {
	if c.media == nil {
		return 0, errors.New("no media key configured")
	}
	root, err := filepath.Abs(c.store.Dir())
	if err != nil {
		return 0, err
	}
	// Read through an os.Root so a symlink swapped in during the walk cannot
	// make us read (and seal a copy of) a file outside the store.
	rooted, err := os.OpenRoot(root)
	if err != nil {
		return 0, err
	}
	defer rooted.Close()
	sealed := 0
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel == "uploads" {
				return filepath.SkipDir
			}
			return nil
		}
		// Cache files live at <chat>/<hex(message id)>/<name>.
		if strings.Count(filepath.ToSlash(rel), "/") != 2 || !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".download-") {
			return nil
		}
		raw, err := rooted.ReadFile(rel)
		if err != nil {
			return err
		}
		if crypto.IsSealed(raw) {
			return nil
		}
		if err := c.writeCacheFile(filepath.Dir(path), path, raw); err != nil {
			return fmt.Errorf("seal %s: %w", rel, err)
		}
		sealed++
		return nil
	})
	return sealed, err
}
