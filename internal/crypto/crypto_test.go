package crypto

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireCipher skips tests that need SQLCipher when the test binary was
// built without it, unless the build asked for it (make sets
// WPP_MCP_REQUIRE_CIPHER=1), in which case a plain-SQLite build fails.
func requireCipher(t *testing.T) {
	t.Helper()
	if CipherAvailable() {
		return
	}
	if os.Getenv("WPP_MCP_REQUIRE_CIPHER") == "1" {
		t.Fatal("SQLCipher is required but this test binary links plain SQLite")
	}
	t.Skip("SQLCipher not linked; run through `make test`")
}

func testKeys(t *testing.T) *Keys {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := GenerateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	k, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyFile_GenerateLoadAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "key")
	if err := GenerateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %04o", fi.Mode().Perm())
	}
	if err := GenerateKeyFile(path); err == nil {
		t.Fatal("GenerateKeyFile overwrote an existing key")
	}
	k, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k.Messages, k.WhatsApp) || bytes.Equal(k.Messages, k.Media) || len(k.Media) != KeySize {
		t.Fatal("sub-keys must be distinct 32-byte keys")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
	if _, err := LoadKeyFile(filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "keygen") {
		t.Fatalf("missing key error should point at keygen: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad")
	_ = os.WriteFile(bad, []byte("not-hex"), 0o600)
	if _, err := LoadKeyFile(bad); err == nil {
		t.Fatal("malformed key accepted")
	}
}

func TestDeriveKeys_Deterministic(t *testing.T) {
	master := bytes.Repeat([]byte{7}, KeySize)
	a, _ := DeriveKeys(master)
	b, _ := DeriveKeys(master)
	if !bytes.Equal(a.Messages, b.Messages) {
		t.Fatal("derivation is not deterministic")
	}
	if _, err := DeriveKeys([]byte("short")); err == nil {
		t.Fatal("short master key accepted")
	}
}

func TestOpenSQLite_EncryptsAndRejectsWrongKey(t *testing.T) {
	requireCipher(t)
	k := testKeys(t)
	path := filepath.Join(t.TempDir(), "x.db")
	db, err := OpenSQLite("file:"+path, k.Messages)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('segredo pessoal')"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Reopening with the right key must work, also with the PRAGMAs the
	// store passes in its DSN (a key applied after them is too late).
	re, err := OpenSQLite("file:"+path+"?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000", k.Messages)
	if err != nil {
		t.Fatalf("reopen with the right key: %v", err)
	}
	var got string
	if err := re.QueryRow("SELECT v FROM t").Scan(&got); err != nil || got != "segredo pessoal" {
		t.Fatalf("reopen read: %q %v", got, err)
	}
	re.Close()

	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("segredo pessoal")) || bytes.HasPrefix(raw, sqliteHeader) {
		t.Fatal("database file holds plaintext")
	}
	if st, _ := InspectFile(path); st != FileEncrypted {
		t.Fatalf("InspectFile = %v, want encrypted", st)
	}
	if _, err := OpenSQLite("file:"+path, k.WhatsApp); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	plain := sql.OpenDB(connector{dsn: "file:" + path})
	defer plain.Close()
	var n int
	if err := plain.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&n); err == nil {
		t.Fatal("encrypted database opened without a key")
	}
	if err := CheckStoreFile(path, false); err == nil {
		t.Fatal("CheckStoreFile allowed an encrypted file without a key")
	}
}

func TestCheckStoreFile_PlaintextWithKeyRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	db := sql.OpenDB(connector{dsn: "file:" + path})
	if _, err := db.Exec("CREATE TABLE t(v)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := CheckStoreFile(path, true); err == nil || !strings.Contains(err.Error(), "wpp-mcp encrypt") {
		t.Fatalf("plaintext store with key: %v", err)
	}
	if err := CheckStoreFile(filepath.Join(t.TempDir(), "none.db"), true); err != nil {
		t.Fatalf("missing file must be allowed: %v", err)
	}
}

func TestEncryptDatabase_Migrates(t *testing.T) {
	requireCipher(t)
	k := testKeys(t)
	path := filepath.Join(t.TempDir(), "m.db")
	db := sql.OpenDB(connector{dsn: "file:" + path + "?_journal_mode=WAL"})
	if _, err := db.Exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('olá'); PRAGMA user_version = 7"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	done, err := EncryptDatabase(path, k.Messages)
	if err != nil || !done {
		t.Fatalf("EncryptDatabase: %v %v", done, err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("plaintext backup left behind")
	}
	enc, err := OpenSQLite("file:"+path, k.Messages)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	var v string
	var uv int
	if err := enc.QueryRow("SELECT v FROM t").Scan(&v); err != nil || v != "olá" {
		t.Fatalf("migrated row: %q %v", v, err)
	}
	if err := enc.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != 7 {
		t.Fatalf("user_version: %d %v", uv, err)
	}
	if again, err := EncryptDatabase(path, k.Messages); err != nil || again {
		t.Fatalf("second run must be a no-op: %v %v", again, err)
	}
}

func TestFTS5_AccentInsensitive(t *testing.T) {
	requireCipher(t)
	db, err := OpenSQLite("file:"+filepath.Join(t.TempDir(), "f.db"), testKeys(t).Messages)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE VIRTUAL TABLE f USING fts5(body, tokenize='unicode61 remove_diacritics 2'); INSERT INTO f VALUES('Não sei, amanhã eu vejo')`); err != nil {
		if os.Getenv("WPP_MCP_REQUIRE_FTS5") == "1" {
			t.Fatalf("fts5 unavailable: %v", err)
		}
		t.Skipf("this SQLCipher build lacks FTS5 (%v); search falls back to substring matching", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM f WHERE f MATCH 'nao AND amanha'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("accent-insensitive match: %d %v", n, err)
	}
}

func TestMediaCipher_SealOpenAndBinding(t *testing.T) {
	m, err := NewMediaCipher(testKeys(t).Media)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("\xff\xd8\xff\xe0 JPEG bytes")
	sealed, err := m.Seal(plain, "chat/abc/photo.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain[:4]) || !IsSealed(sealed) {
		t.Fatal("sealed output leaks plaintext or lacks magic")
	}
	got, err := m.Open(sealed, "chat/abc/photo.jpg")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := m.Open(sealed, "chat/other/photo.jpg"); err == nil {
		t.Fatal("sealed file opened under another path")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := m.Open(sealed, "chat/abc/photo.jpg"); err == nil {
		t.Fatal("tampered file opened")
	}
	if _, err := m.Open(plain, "x"); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("plaintext input: %v", err)
	}
}

// TestConnector_RegistersUnaccentLower checks that every connection, keyed
// or not, has the folding function the store's LIKE fallback uses.
func TestConnector_RegistersUnaccentLower(t *testing.T) {
	keys := [][]byte{nil}
	if CipherAvailable() {
		keys = append(keys, testKeys(t).Messages)
	}
	for _, key := range keys {
		db, err := OpenSQLite("file:"+filepath.Join(t.TempDir(), "f.db"), key)
		if err != nil {
			t.Fatal(err)
		}
		var got string
		var null sql.NullString
		if err := db.QueryRow("SELECT unaccent_lower('JOÃO Cauê'), unaccent_lower(NULL)").Scan(&got, &null); err != nil {
			t.Fatal(err)
		}
		db.Close()
		// mattn/go-sqlite3 hands a Go function NULL as an empty value, so
		// NULL may fold to ''; either way it never matches a search pattern.
		if got != "joao caue" || null.String != "" {
			t.Fatalf("keyed=%v: got %q, %v", key != nil, got, null)
		}
	}
}
