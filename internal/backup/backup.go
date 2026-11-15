package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/crypto"
)

// Archive format (FormatVersion 1): an uncompressed tar whose entries are
//
//	messages.db              SQLCipher snapshot, keyed like the store
//	whatsapp.db              SQLCipher snapshot (absent before the first pairing)
//	media/<chat>/<id>/<name> sealed media files, byte for byte
//	manifest.json            written last: format, version, key fingerprint,
//	                         schema summary and the SHA-256 of every entry
//
// Every entry stays encrypted with the store's current key; the tar is not
// compressed because ciphertext does not compress. The key file and the
// bearer token are deliberately left out: an archive that carried its own
// key would protect nothing, so the key must be backed up separately, and
// the token is a credential that serve regenerates when it is missing.
// uploads/ (the operator's outbound attachments, plaintext by design) is
// not part of the store's encrypted state and is not archived either.
const (
	Format        = "wpp-mcp-backup"
	FormatVersion = 1
	manifestName  = "manifest.json"
	mediaPrefix   = "media/"
)

// Manifest describes an archive.
type Manifest struct {
	Format         string    `json:"format"`
	FormatVersion  int       `json:"format_version"`
	CreatedAt      time.Time `json:"created_at"`
	Version        string    `json:"wpp_mcp_version"`
	KeyFingerprint string    `json:"key_fingerprint"`
	// Databases maps a database file name to its schema summary.
	Databases map[string]*crypto.DBInfo `json:"databases"`
	Files     []FileEntry               `json:"files"`
}

// FileEntry is one archived file.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// MediaCount returns how many media files the manifest lists.
func (m *Manifest) MediaCount() int {
	n := 0
	for _, f := range m.Files {
		if strings.HasPrefix(f.Path, mediaPrefix) {
			n++
		}
	}
	return n
}

// CreateOptions configures Create.
type CreateOptions struct {
	StoreDir string
	Keys     *crypto.Keys
	// TempDir holds the database snapshots while the archive is written
	// (they are encrypted). Empty uses os.TempDir.
	TempDir string
	// Version is recorded in the manifest.
	Version string
	// Now overrides the clock (tests).
	Now func() time.Time
}

func dbKey(keys *crypto.Keys, name string) []byte {
	if name == MessagesDB {
		return keys.Messages
	}
	return keys.WhatsApp
}

// ErrRekeyPending is returned when a key rotation must be finished first.
var ErrRekeyPending = errors.New("a key rotation is in progress in this store; finish it with `wpp-mcp rekey` (or abandon it with `wpp-mcp rekey -abort` if it never reached the commit phase)")

// Create writes an archive of the store to w. It is safe to run while the
// daemon serves from the same store: the databases are copied with
// SQLite's online backup API (see crypto.SnapshotDatabase) and media files
// are only ever replaced atomically by the daemon, so each one is read
// whole. Media written while the backup runs may or may not be included;
// either way the archive is self-consistent per file, and a message whose
// media is missing simply downloads it again.
func Create(ctx context.Context, opts CreateOptions, w io.Writer) (*Manifest, error) {
	if opts.Keys == nil {
		return nil, errors.New("backup requires encryption at rest: the archive must never hold plaintext (encrypt the store first with `wpp-mcp encrypt`)")
	}
	if exists(filepath.Join(opts.StoreDir, rekeyMarker)) {
		return nil, ErrRekeyPending
	}
	if !exists(filepath.Join(opts.StoreDir, MessagesDB)) {
		return nil, fmt.Errorf("no %s in %s: nothing to back up", MessagesDB, opts.StoreDir)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	tmp, err := os.MkdirTemp(opts.TempDir, ".wpp-backup-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	m := &Manifest{
		Format:         Format,
		FormatVersion:  FormatVersion,
		CreatedAt:      now().UTC().Truncate(time.Second),
		Version:        opts.Version,
		KeyFingerprint: opts.Keys.Fingerprint,
		Databases:      map[string]*crypto.DBInfo{},
	}
	tw := tar.NewWriter(w)
	for _, name := range []string{MessagesDB, WhatsAppDB} {
		src := filepath.Join(opts.StoreDir, name)
		if !exists(src) {
			continue
		}
		snap := filepath.Join(tmp, name)
		key := dbKey(opts.Keys, name)
		if err := crypto.SnapshotDatabase(ctx, src, key, snap, key); err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", name, err)
		}
		info, err := crypto.InspectDatabase(snap, key)
		if err != nil {
			return nil, fmt.Errorf("check snapshot of %s: %w", name, err)
		}
		m.Databases[name] = info
		f, err := os.Open(snap)
		if err != nil {
			return nil, err
		}
		entry, err := addFile(tw, name, f, m.CreatedAt)
		f.Close()
		if err != nil {
			return nil, err
		}
		m.Files = append(m.Files, entry)
	}

	root, err := os.OpenRoot(opts.StoreDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	err = walkMedia(opts.StoreDir, func(rel string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := root.Open(filepath.FromSlash(rel))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // removed by retention while we walked
			}
			return err
		}
		defer f.Close()
		head := make([]byte, 5)
		if n, _ := io.ReadFull(f, head); !crypto.IsSealed(head[:n]) {
			return fmt.Errorf("media file %s is not sealed; refusing to archive plaintext (run `wpp-mcp encrypt` with the daemon stopped)", rel)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		entry, err := addFile(tw, mediaPrefix+rel, f, m.CreatedAt)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, entry)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("archive media: %w", err)
	}

	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(raw)), ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(raw); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return m, nil
}

// addFile streams f into the archive as name and returns its entry. The
// size comes from the open descriptor: the daemon replaces cache files by
// rename, never in place, so an open file does not change under us.
func addFile(tw *tar.Writer, name string, f *os.File, mtime time.Time) (FileEntry, error) {
	fi, err := f.Stat()
	if err != nil {
		return FileEntry{}, err
	}
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), ModTime: mtime, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return FileEntry{}, err
	}
	h := sha256.New()
	n, err := io.Copy(tw, io.TeeReader(io.LimitReader(f, fi.Size()), h))
	if err != nil {
		return FileEntry{}, fmt.Errorf("archive %s: %w", name, err)
	}
	if n != fi.Size() {
		return FileEntry{}, fmt.Errorf("archive %s: file shrank while reading", name)
	}
	return FileEntry{Path: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// CreateFile writes an archive to path, which must not exist. The archive
// is written to path+".partial" with mode 0600, synced, and renamed into
// place only once complete.
func CreateFile(ctx context.Context, opts CreateOptions, path string) (*Manifest, error) {
	if exists(path) {
		return nil, fmt.Errorf("%s already exists; refusing to overwrite a backup", path)
	}
	partial := path + ".partial"
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if opts.TempDir == "" {
		opts.TempDir = filepath.Dir(path)
	}
	m, err := Create(ctx, opts, f)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(partial, path)
	}
	if err != nil {
		_ = os.Remove(partial)
		return nil, err
	}
	_ = syncDir(filepath.Dir(path))
	return m, nil
}
