package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/crypto"
	"github.com/murandido/mcp-wpp/internal/store"
	"go.mau.fi/whatsmeow"
)

// With a media key, the cache holds only ciphertext, while ReadMedia and
// output_path exports return the plaintext.
func TestDownload_SealsMediaCacheAtRest(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const jid = "447700000099@s.whatsapp.net"
	payload := []byte("\xff\xd8\xff\xe0 very private photo")
	digest := sha256.Sum256(payload)
	if err := s.StoreChat(jid, "test", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := s.StoreMessage(context.Background(), store.Message{
		ID: "M-SEAL", ChatJID: jid, Sender: jid, Content: "x", Timestamp: time.Now().UTC(),
		MediaType: "image", Filename: "p.jpg", URL: "https://example.invalid/media",
	}, []byte{1}, digest[:], []byte{2}, uint64(len(payload))); err != nil {
		t.Fatal(err)
	}

	keys, err := crypto.DeriveKeys(bytes.Repeat([]byte{9}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	mc, _ := crypto.NewMediaCipher(keys.Media)
	mediaRoot := t.TempDir()
	c := newClientWithStore(t, s)
	c.media = mc
	c.allowedMediaRoot = mediaRoot
	c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) { return payload, nil }

	res := c.Download(context.Background(), "M-SEAL", jid, "")
	if !res.Success {
		t.Fatalf("download: %+v", res)
	}
	onDisk, _ := os.ReadFile(res.Path)
	if !crypto.IsSealed(onDisk) || bytes.Contains(onDisk, []byte("private")) {
		t.Fatal("media cache file is not sealed")
	}
	got, err := c.ReadMedia(res.Path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ReadMedia: %v", err)
	}

	// A second call is a cache hit: it must validate the sealed file without
	// downloading again.
	c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) {
		t.Fatal("cache hit expected")
		return nil, nil
	}
	out := filepath.Join(mediaRoot, "export.jpg")
	res = c.Download(context.Background(), "M-SEAL", jid, out)
	if !res.Success || res.Path != out {
		t.Fatalf("export: %+v", res)
	}
	exported, _ := os.ReadFile(out)
	if !bytes.Equal(exported, payload) {
		t.Fatal("output_path export is not the plaintext")
	}

	// Without the key the sealed cache is unreadable.
	c.media = nil
	cachePath := filepath.Join(s.Dir(), jid, "4d2d5345414c", "p.jpg")
	if _, err := c.ReadMedia(cachePath); err == nil {
		t.Fatal("sealed cache read without a key")
	}
}

func TestSealExistingCache(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dir := filepath.Join(s.Dir(), "447700000099@s.whatsapp.net", "4d31")
	_ = os.MkdirAll(dir, 0o700)
	plain := []byte("legacy plaintext media")
	_ = os.WriteFile(filepath.Join(dir, "a.bin"), plain, 0o600)
	_ = os.MkdirAll(filepath.Join(s.Dir(), "uploads", "x", "y"), 0o700)
	_ = os.WriteFile(filepath.Join(s.Dir(), "uploads", "x", "y", "keep.txt"), []byte("outbound"), 0o600)

	keys, _ := crypto.DeriveKeys(bytes.Repeat([]byte{3}, crypto.KeySize))
	mc, _ := crypto.NewMediaCipher(keys.Media)
	c := newClientWithStore(t, s)
	c.media = mc
	n, err := c.SealExistingCache()
	if err != nil || n != 1 {
		t.Fatalf("sealed %d: %v", n, err)
	}
	if n, _ := c.SealExistingCache(); n != 0 {
		t.Fatal("second pass must be a no-op")
	}
	got, err := c.ReadMedia(filepath.Join(dir, "a.bin"))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("read back: %v", err)
	}
	if raw, _ := os.ReadFile(filepath.Join(s.Dir(), "uploads", "x", "y", "keep.txt")); string(raw) != "outbound" {
		t.Fatal("uploads root must not be sealed")
	}
}
