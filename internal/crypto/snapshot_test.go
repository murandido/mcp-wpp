package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFingerprint_StableAndDistinct(t *testing.T) {
	master := bytes.Repeat([]byte{7}, KeySize)
	a, _ := DeriveKeys(master)
	b, _ := DeriveKeys(master)
	c := testKeys(t)
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint || a.Fingerprint == c.Fingerprint || len(a.Fingerprint) != 16 {
		t.Fatalf("fingerprints %q %q %q", a.Fingerprint, b.Fingerprint, c.Fingerprint)
	}
	if strings.Contains(hex.EncodeToString(a.Messages)+hex.EncodeToString(a.WhatsApp)+hex.EncodeToString(a.Media), a.Fingerprint) {
		t.Fatal("the fingerprint must not reveal part of a sub-key")
	}
}

func TestSnapshotDatabase_SameAndNewKey(t *testing.T) {
	requireCipher(t)
	dir := t.TempDir()
	k1, k2 := testKeys(t), testKeys(t)
	src := filepath.Join(dir, "src.db")
	db, err := OpenSQLite("file:"+src+"?_journal_mode=WAL", k1.Messages)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t (x); INSERT INTO t VALUES (1), (2); PRAGMA user_version = 3"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		key, bad []byte
	}{{"same.db", k1.Messages, k2.Messages}, {"rekeyed.db", k2.Messages, k1.Messages}} {
		dst := filepath.Join(dir, tc.name)
		if err := SnapshotDatabase(ctx, src, k1.Messages, dst, tc.key); err != nil {
			t.Fatal(err)
		}
		if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %04o", tc.name, fi.Mode().Perm())
		}
		if st, _ := InspectFile(dst); st != FileEncrypted {
			t.Fatalf("%s is not encrypted", tc.name)
		}
		info, err := InspectDatabase(dst, tc.key)
		if err != nil || info.UserVersion != 3 || len(info.Tables) != 1 {
			t.Fatalf("%s: %+v %v", tc.name, info, err)
		}
		if _, err := InspectDatabase(dst, tc.bad); !errors.Is(err, ErrWrongKey) {
			t.Fatalf("%s opened with the wrong key: %v", tc.name, err)
		}
		if err := SnapshotDatabase(ctx, src, k1.Messages, dst, tc.key); err == nil {
			t.Fatal("snapshot must not overwrite an existing file")
		}
	}
	if err := SnapshotDatabase(ctx, src, k2.Messages, filepath.Join(dir, "x.db"), k2.Messages); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong source key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.db")); err == nil {
		t.Fatal("a failed snapshot must remove its destination")
	}
}
