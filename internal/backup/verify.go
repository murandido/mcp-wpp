package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/murandido/mcp-wpp/internal/crypto"
)

// ErrWrongArchiveKey means the archive was made with a different master key.
var ErrWrongArchiveKey = errors.New("the archive was made with a different key than the configured one")

const (
	maxManifestSize = 64 << 20
	// Media up to this size is decrypted to prove the key opens it; larger
	// files are checked against their SHA-256 and sealed header only, so
	// verification never holds a huge file in memory.
	maxAuthenticatedMedia = 256 << 20
)

// readArchive reads an archive from r, checks every entry against the
// manifest and every database and media file against keys, and writes the
// databases (and, with keepMedia, the media files under media/) into dir.
func readArchive(ctx context.Context, r io.Reader, keys *crypto.Keys, dir string, keepMedia bool) (*Manifest, error) {
	if keys == nil {
		return nil, errors.New("backups are encrypted: a key file is required")
	}
	media, err := crypto.NewMediaCipher(keys.Media)
	if err != nil {
		return nil, err
	}
	seen := map[string]FileEntry{}
	var manifest *Manifest
	var authFailed string
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		name := hdr.Name
		if hdr.Typeflag != tar.TypeReg || hdr.Size < 0 || !safeEntryName(name) {
			return nil, fmt.Errorf("archive entry %q is not a plain file with a safe relative path", name)
		}
		if _, dup := seen[name]; dup || (name == manifestName && manifest != nil) {
			return nil, fmt.Errorf("archive entry %q appears twice", name)
		}
		switch {
		case name == manifestName:
			raw, err := io.ReadAll(io.LimitReader(tr, maxManifestSize+1))
			if err != nil {
				return nil, err
			}
			if len(raw) > maxManifestSize {
				return nil, errors.New("manifest is too large")
			}
			manifest = &Manifest{}
			if err := json.Unmarshal(raw, manifest); err != nil {
				return nil, fmt.Errorf("manifest: %w", err)
			}
		case name == MessagesDB || name == WhatsAppDB:
			// Join a constant, not the header name.
			dbFile := MessagesDB
			if name == WhatsAppDB {
				dbFile = WhatsAppDB
			}
			entry, err := copyEntry(tr, hdr, filepath.Join(dir, dbFile))
			if err != nil {
				return nil, err
			}
			seen[name] = entry
		case strings.HasPrefix(name, mediaPrefix) && isMediaRel(strings.TrimPrefix(name, mediaPrefix)):
			rel := strings.TrimPrefix(name, mediaPrefix)
			dst := ""
			if keepMedia {
				var err error
				if dst, err = within(dir, name); err != nil {
					return nil, err
				}
				if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
					return nil, err
				}
			}
			entry, ok, err := checkMedia(tr, hdr, rel, media, dst)
			if err != nil {
				return nil, err
			}
			if !ok && authFailed == "" {
				authFailed = name
			}
			seen[name] = entry
		default:
			return nil, fmt.Errorf("unexpected archive entry %q", name)
		}
	}

	if manifest == nil {
		return nil, errors.New("archive has no manifest (truncated, or not a wpp-mcp backup)")
	}
	if manifest.Format != Format || manifest.FormatVersion < 1 || manifest.FormatVersion > FormatVersion {
		return nil, fmt.Errorf("unsupported archive format %q version %d", manifest.Format, manifest.FormatVersion)
	}
	if manifest.KeyFingerprint != keys.Fingerprint {
		return nil, fmt.Errorf("%w (archive key %s, configured key %s): restore with the key file that was in use when the backup was made", ErrWrongArchiveKey, manifest.KeyFingerprint, keys.Fingerprint)
	}
	listed := map[string]bool{}
	for _, f := range manifest.Files {
		got, ok := seen[f.Path]
		if !ok {
			return nil, fmt.Errorf("archive is missing %s listed in the manifest", f.Path)
		}
		if got.Size != f.Size || got.SHA256 != f.SHA256 {
			return nil, fmt.Errorf("%s does not match its manifest checksum (corrupted archive)", f.Path)
		}
		listed[f.Path] = true
	}
	for name := range seen {
		if !listed[name] {
			return nil, fmt.Errorf("archive entry %s is not in the manifest", name)
		}
	}
	if authFailed != "" {
		return nil, fmt.Errorf("%s does not open with the configured media key", authFailed)
	}
	if _, ok := seen[MessagesDB]; !ok {
		return nil, fmt.Errorf("archive has no %s", MessagesDB)
	}
	for name := range seen {
		if name != MessagesDB && name != WhatsAppDB {
			continue
		}
		info, err := crypto.InspectDatabase(filepath.Join(dir, name), dbKey(keys, name))
		if err != nil {
			return nil, fmt.Errorf("open %s from the archive: %w", name, err)
		}
		if want := manifest.Databases[name]; want == nil || !want.SameSchema(info) {
			return nil, fmt.Errorf("%s schema does not match the manifest", name)
		}
	}
	return manifest, nil
}

// copyEntry streams the current entry into a new 0600 file at dst.
func copyEntry(tr io.Reader, hdr *tar.Header, dst string) (FileEntry, error) {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return FileEntry{}, err
	}
	h := sha256.New()
	n, err := io.Copy(f, io.TeeReader(io.LimitReader(tr, hdr.Size), h))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return FileEntry{}, fmt.Errorf("extract %s: %w", hdr.Name, err)
	}
	return FileEntry{Path: hdr.Name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// checkMedia hashes a media entry, checks it is sealed and, when small
// enough, that the media key opens it for its path. With dst set, the
// sealed bytes are written there. ok is false when authentication failed.
func checkMedia(tr io.Reader, hdr *tar.Header, rel string, media *crypto.MediaCipher, dst string) (FileEntry, bool, error) {
	if hdr.Size > maxAuthenticatedMedia {
		w := io.Discard
		var f *os.File
		if dst != "" {
			var err error
			if f, err = os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
				return FileEntry{}, false, err
			}
			w = f
		}
		// fail closes and removes a partial destination; the original error
		// is what the caller sees.
		fail := func(err error) (FileEntry, bool, error) {
			if f != nil {
				_ = f.Close()
				_ = os.Remove(dst)
			}
			return FileEntry{}, false, err
		}
		h := sha256.New()
		head := &bytes.Buffer{}
		n, err := io.Copy(io.MultiWriter(w, h, &prefixWriter{buf: head, max: 5}), io.LimitReader(tr, hdr.Size))
		if err != nil {
			return fail(err)
		}
		if f != nil {
			if err := f.Sync(); err != nil {
				return fail(err)
			}
			if err := f.Close(); err != nil {
				_ = os.Remove(dst)
				return FileEntry{}, false, err
			}
		}
		return FileEntry{Path: hdr.Name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, crypto.IsSealed(head.Bytes()), nil
	}
	data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
	if err != nil {
		return FileEntry{}, false, err
	}
	sum := sha256.Sum256(data)
	entry := FileEntry{Path: hdr.Name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	_, openErr := media.Open(data, rel)
	if dst != "" {
		if err := writeNew(dst, data); err != nil {
			return FileEntry{}, false, err
		}
	}
	return entry, openErr == nil, nil
}

// prefixWriter keeps the first max bytes written to it.
type prefixWriter struct {
	buf *bytes.Buffer
	max int
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	if room := p.max - p.buf.Len(); room > 0 {
		if len(b) < room {
			room = len(b)
		}
		p.buf.Write(b[:room])
	}
	return len(b), nil
}

// writeNew creates path (0600, must not exist) with data and syncs it.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Verify checks an archive without touching any store: every entry against
// the manifest checksums, the key fingerprint, each database opened (and
// quick-checked) with the configured key, and each media file authenticated
// with the media key. tempDir holds the extracted databases briefly; they
// stay encrypted.
func Verify(ctx context.Context, archive string, keys *crypto.Keys, tempDir string) (*Manifest, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tmp, err := os.MkdirTemp(tempDir, ".wpp-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	return readArchive(ctx, f, keys, tmp, false)
}

// safeEntryName accepts only plain relative archive paths: no absolute
// paths, no ".." element, no backslashes and nothing that is not already
// clean, and never "." (the directory itself). A crafted archive must never
// write outside the staging directory ("zip slip").
func safeEntryName(name string) bool {
	return name != "" && name != "." &&
		!strings.Contains(name, "..") &&
		!strings.Contains(name, `\`) &&
		path.Clean(name) == name &&
		filepath.IsLocal(filepath.FromSlash(name))
}

// within joins name under dir and checks the result is still inside dir.
func within(dir, name string) (string, error) {
	if !safeEntryName(name) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	dst := filepath.Join(dir, filepath.FromSlash(name))
	rel, err := filepath.Rel(dir, dst)
	if err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("archive path %q escapes the restore directory", name)
	}
	return dst, nil
}
