package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/murandido/mcp-wpp/internal/crypto"
)

// A crafted archive must never write outside the restore directory.
func TestReadArchive_RejectsUnsafeEntryNames(t *testing.T) {
	keys, err := crypto.DeriveKeys(bytes.Repeat([]byte{7}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"../evil",
		"media/../../evil",
		"media/chat/../../../evil",
		"/etc/evil",
		`media\..\evil`,
		"./media/x",
		"",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "staging")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			payload := []byte("not a real file")
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(payload)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			_, _ = tw.Write(payload)
			_ = tw.Close()

			_, err := readArchive(context.Background(), &buf, keys, dir, true)
			if err == nil {
				t.Fatalf("entry %q was accepted", name)
			}
			entries, _ := os.ReadDir(root)
			for _, e := range entries {
				if e.Name() != "staging" {
					t.Fatalf("entry %q wrote %s outside the staging directory", name, e.Name())
				}
			}
			if _, statErr := os.Stat(filepath.Join(root, "evil")); statErr == nil {
				t.Fatalf("entry %q escaped", name)
			}
		})
	}
}

func TestSafeEntryName(t *testing.T) {
	for _, ok := range []string{"messages.db", "whatsapp.db", "manifest.json", "media/123@g.us/4d31/photo.jpg"} {
		if !safeEntryName(ok) {
			t.Errorf("safeEntryName(%q) = false", ok)
		}
	}
}
