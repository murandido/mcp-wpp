// Package backup implements store maintenance that runs outside the MCP
// surface: encrypted backups (Create, Verify), restore (Restore) and master
// key rotation (Rekey).
//
// It handles the media cache as sealed bytes. Backup and restore copy sealed
// files verbatim; rekey opens each one with the old media key and seals it
// with the new one in memory. Nothing here ever writes plaintext to disk.
package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Database files in the store, with the sub-key that opens each.
const (
	MessagesDB = "messages.db"
	WhatsAppDB = "whatsapp.db"
)

// Hidden names this package uses inside the store directory.
const (
	restoreStaging = ".restore-staging"
	preRestore     = ".pre-restore"
	rekeyMarker    = ".rekey-state"
	rekeyNew       = ".rekey"  // suffix (databases) or prefix (media) of a re-encrypted copy
	rekeyOld       = ".prekey" // suffix (databases) or prefix (media) of a superseded original
)

// isMediaRel reports whether rel (slash-separated, relative to the store) is
// a media cache file: <chat>/<hex(message id)>/<name>, outside uploads/ and
// outside the hidden directories this package and the daemon use.
func isMediaRel(rel string) bool {
	parts := strings.Split(rel, "/")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	if parts[0] == "uploads" || strings.HasPrefix(parts[0], ".") {
		return false
	}
	name := parts[2]
	return !strings.HasPrefix(name, ".download-") && !strings.HasPrefix(name, rekeyNew+"-") && !strings.HasPrefix(name, rekeyOld+"-")
}

// walkMedia calls fn for every media cache file under storeDir, with its
// slash-separated path relative to the store. Symlinks are skipped, so the
// walk never leaves the store.
func walkMedia(storeDir string, fn func(rel string) error) error {
	root, err := filepath.Abs(storeDir)
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if depth := strings.Count(rel, "/"); depth >= 2 || rel == "uploads" || (depth == 0 && strings.HasPrefix(rel, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isMediaRel(rel) {
			return nil
		}
		return fn(rel)
	})
}

// storeHasData reports whether storeDir holds a database or any media.
func storeHasData(storeDir string) (bool, error) {
	for _, name := range []string{MessagesDB, WhatsAppDB} {
		fi, err := os.Stat(filepath.Join(storeDir, name))
		if err == nil && fi.Size() > 0 {
			return true, nil
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	found := false
	errStop := errors.New("stop")
	err := walkMedia(storeDir, func(string) error { found = true; return errStop })
	if err != nil && !errors.Is(err, errStop) {
		return false, err
	}
	return found, nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// syncDir flushes a directory entry change (rename, create) to disk.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}

// writeFileSync writes data to path atomically (temp file, fsync, rename)
// with mode 0600.
func writeFileSync(path string, data []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close() // the write error is what matters; the file is removed
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close() // the sync error is what matters; the file is removed
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}
