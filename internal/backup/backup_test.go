package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/murandido/mcp-wpp/internal/crypto"
	"github.com/murandido/mcp-wpp/internal/store"
)

const (
	plainMarker = "plaintext-marker-7f3a"
	mediaMarker = "media-plaintext-marker-91bc"
)

func requireCipher(t *testing.T) {
	t.Helper()
	if crypto.CipherAvailable() {
		return
	}
	if os.Getenv("WPP_MCP_REQUIRE_CIPHER") == "1" {
		t.Fatal("SQLCipher is required but this test binary links plain SQLite")
	}
	t.Skip("SQLCipher not linked; run through `make test`")
}

func newKeys(t *testing.T) *crypto.Keys {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := crypto.GenerateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	k, err := crypto.LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var mediaFiles = []string{
	"111@s.whatsapp.net/a1b2/photo.jpg",
	"111@s.whatsapp.net/c3d4/voice.ogg",
	"222@g.us/e5f6/doc.pdf",
}

// seedStore creates an encrypted store with one message, a whatsapp.db and
// sealed media files.
func seedStore(t *testing.T, dir string, keys *crypto.Keys) {
	t.Helper()
	st, err := store.OpenWithKeys(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO chats (jid, name, last_message_time) VALUES ('111@s.whatsapp.net', ?, ?)`, plainMarker, time.Now()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	wa, err := crypto.OpenSQLite("file:"+filepath.Join(dir, WhatsAppDB)+"?_foreign_keys=on", keys.WhatsApp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wa.Exec(`CREATE TABLE session (k TEXT); INSERT INTO session VALUES ('` + plainMarker + `')`); err != nil {
		t.Fatal(err)
	}
	wa.Close()
	mc, err := crypto.NewMediaCipher(keys.Media)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range mediaFiles {
		sealed, err := mc.Seal([]byte(mediaMarker+rel), rel)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, sealed, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Files a backup must leave out.
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("secret-token-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "uploads"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uploads", "out.txt"), []byte("upload"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func chatName(t *testing.T, dir string, keys *crypto.Keys) string {
	t.Helper()
	db, err := crypto.OpenSQLite("file:"+filepath.Join(dir, MessagesDB), keys.Messages)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err := db.QueryRow(`SELECT name FROM chats WHERE jid = '111@s.whatsapp.net'`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

func assertMedia(t *testing.T, dir string, keys *crypto.Keys) {
	t.Helper()
	mc, _ := crypto.NewMediaCipher(keys.Media)
	for _, rel := range mediaFiles {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := mc.Open(raw, rel)
		if err != nil || string(plain) != mediaMarker+rel {
			t.Fatalf("media %s: %v", rel, err)
		}
	}
}

func makeBackup(t *testing.T, dir string, keys *crypto.Keys) (string, *Manifest) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "backup.tar")
	m, err := CreateFile(context.Background(), CreateOptions{StoreDir: dir, Keys: keys, Version: "test"}, out)
	if err != nil {
		t.Fatal(err)
	}
	return out, m
}

func TestBackup_ManifestModeAndNoPlaintext(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	dir, keys := t.TempDir(), newKeys(t)
	seedStore(t, dir, keys)
	out, m := makeBackup(t, dir, keys)

	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode %04o, want 0600", fi.Mode().Perm())
	}
	if m.Format != Format || m.FormatVersion != FormatVersion || m.KeyFingerprint != keys.Fingerprint || m.Version != "test" {
		t.Fatalf("manifest header: %+v", m)
	}
	if m.MediaCount() != len(mediaFiles) || len(m.Files) != len(mediaFiles)+2 {
		t.Fatalf("manifest files: %+v", m.Files)
	}
	if info := m.Databases[MessagesDB]; info == nil || info.SchemaObjects == 0 {
		t.Fatalf("messages.db schema info missing: %+v", m.Databases)
	}

	raw, _ := os.ReadFile(out)
	for _, leak := range []string{plainMarker, mediaMarker, "secret-token-value", "SQLite format 3"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("archive contains %q in the clear", leak)
		}
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	var names []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	if names[len(names)-1] != manifestName {
		t.Fatalf("manifest must be the last entry: %v", names)
	}
	for _, n := range names {
		if strings.Contains(n, "token") || strings.Contains(n, "uploads") || strings.Contains(n, ".lock") {
			t.Fatalf("archive must not include %s", n)
		}
	}
	if _, err := Verify(context.Background(), out, keys, t.TempDir()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBackup_RequiresEncryption(t *testing.T) {
	if _, err := Create(context.Background(), CreateOptions{StoreDir: t.TempDir()}, io.Discard); err == nil {
		t.Fatal("backup without keys must be refused")
	}
}

func TestBackup_RefusesUnsealedMedia(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	dir, keys := t.TempDir(), newKeys(t)
	seedStore(t, dir, keys)
	p := filepath.Join(dir, "333@s.whatsapp.net", "ff", "plain.jpg")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte("plaintext"), 0o600)
	out := filepath.Join(t.TempDir(), "b.tar")
	if _, err := CreateFile(context.Background(), CreateOptions{StoreDir: dir, Keys: keys}, out); err == nil || !strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("unsealed media must be refused, got %v", err)
	}
	if exists(out) || exists(out+".partial") {
		t.Fatal("a failed backup must not leave an archive behind")
	}
}

// TestBackup_ConsistentWhileWriting backs up while another connection keeps
// committing pairs of rows: a consistent snapshot always holds an even count.
func TestBackup_ConsistentWhileWriting(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	dir, keys := t.TempDir(), newKeys(t)
	seedStore(t, dir, keys)
	st, err := store.OpenWithKeys(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db := st.DB()
	if _, err := db.Exec(`CREATE TABLE pairs (n INTEGER, pad TEXT)`); err != nil {
		t.Fatal(err)
	}
	var written atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pad := strings.Repeat("x", 2000)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			tx, err := db.Begin()
			if err != nil {
				continue
			}
			_, e1 := tx.Exec(`INSERT INTO pairs VALUES (?, ?)`, i, pad)
			_, e2 := tx.Exec(`INSERT INTO pairs VALUES (?, ?)`, i, pad)
			if e1 != nil || e2 != nil {
				_ = tx.Rollback()
				continue
			}
			if tx.Commit() == nil {
				written.Add(2)
			}
		}
	}()
	for written.Load() < 200 {
		time.Sleep(time.Millisecond)
	}
	before := written.Load()
	out, _ := makeBackup(t, dir, keys)
	after := written.Load()
	close(stop)
	wg.Wait()
	if after == before {
		t.Log("writer made no progress during the backup; consistency still checked")
	}

	restored := t.TempDir()
	if _, err := Restore(context.Background(), out, RestoreOptions{StoreDir: restored, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	rdb, err := crypto.OpenSQLite("file:"+filepath.Join(restored, MessagesDB), keys.Messages)
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	var n int64
	var ok string
	if err := rdb.QueryRow(`PRAGMA integrity_check`).Scan(&ok); err != nil || ok != "ok" {
		t.Fatalf("integrity: %q %v", ok, err)
	}
	if err := rdb.QueryRow(`SELECT count(*) FROM pairs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n%2 != 0 || n < before {
		t.Fatalf("snapshot holds %d rows (written before backup: %d): not a consistent snapshot", n, before)
	}
	// The daemon's connection is still usable after the backup.
	if _, err := db.Exec(`INSERT INTO pairs VALUES (-1, '')`); err != nil {
		t.Fatalf("writer blocked after backup: %v", err)
	}
}

func TestVerify_WrongKeyAndCorruption(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	dir, keys := t.TempDir(), newKeys(t)
	seedStore(t, dir, keys)
	out, _ := makeBackup(t, dir, keys)

	if _, err := Verify(context.Background(), out, newKeys(t), t.TempDir()); !errors.Is(err, ErrWrongArchiveKey) {
		t.Fatalf("wrong key: got %v", err)
	}

	raw, _ := os.ReadFile(out)
	idx := bytes.Index(raw, []byte("WPPM\x01")) // first sealed media file
	if idx < 0 {
		t.Fatal("no sealed media in archive")
	}
	raw[idx+40] ^= 0xff
	bad := filepath.Join(t.TempDir(), "bad.tar")
	_ = os.WriteFile(bad, raw, 0o600)
	if _, err := Verify(context.Background(), bad, keys, t.TempDir()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corruption: got %v", err)
	}

	trunc := filepath.Join(t.TempDir(), "trunc.tar")
	_ = os.WriteFile(trunc, raw[:len(raw)/2], 0o600)
	if _, err := Verify(context.Background(), trunc, keys, t.TempDir()); err == nil {
		t.Fatal("a truncated archive must fail verification")
	}
}

func TestRestore_FreshStore(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	dir, keys := t.TempDir(), newKeys(t)
	seedStore(t, dir, keys)
	out, _ := makeBackup(t, dir, keys)

	fresh := filepath.Join(t.TempDir(), "store")
	if _, err := Restore(context.Background(), out, RestoreOptions{StoreDir: fresh, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	if got := chatName(t, fresh, keys); got != plainMarker {
		t.Fatalf("restored chat name %q", got)
	}
	assertMedia(t, fresh, keys)
	for _, leftover := range []string{preRestore, restoreStaging, "token"} {
		if exists(filepath.Join(fresh, leftover)) {
			t.Fatalf("%s must not exist after restore", leftover)
		}
	}
	if err := OpenCheck(fresh, keys); err != nil {
		t.Fatal(err)
	}
}

func TestRestore_LockNonEmptyAndRollback(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	keys := newKeys(t)
	src := t.TempDir()
	seedStore(t, src, keys)
	out, _ := makeBackup(t, src, keys)

	// A different store with its own data.
	dst := t.TempDir()
	seedStore(t, dst, keys)
	db, _ := crypto.OpenSQLite("file:"+filepath.Join(dst, MessagesDB), keys.Messages)
	_, _ = db.Exec(`UPDATE chats SET name = 'current-store'`)
	db.Close()

	if _, err := Restore(context.Background(), out, RestoreOptions{StoreDir: dst, Keys: keys}); !errors.Is(err, ErrStoreNotEmpty) {
		t.Fatalf("non-empty store: got %v", err)
	}

	lock, err := store.TryLock(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), out, RestoreOptions{StoreDir: dst, Keys: keys, Force: true}); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("locked store: got %v", err)
	}
	lock.Release()

	failing := func(string, *crypto.Keys) error { return errors.New("simulated open failure") }
	if _, err := Restore(context.Background(), out, RestoreOptions{StoreDir: dst, Keys: keys, Force: true, Check: failing}); err == nil || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("failing check must roll back, got %v", err)
	}
	if got := chatName(t, dst, keys); got != "current-store" {
		t.Fatalf("rollback left chat name %q", got)
	}
	assertMedia(t, dst, keys)
	if exists(filepath.Join(dst, preRestore)) || exists(filepath.Join(dst, restoreStaging)) {
		t.Fatal("rollback must clean up")
	}

	if _, err := Restore(context.Background(), out, RestoreOptions{StoreDir: dst, Keys: keys, Force: true}); err != nil {
		t.Fatal(err)
	}
	if got := chatName(t, dst, keys); got != plainMarker {
		t.Fatalf("forced restore left chat name %q", got)
	}
	if !exists(filepath.Join(dst, "token")) || !exists(filepath.Join(dst, "uploads", "out.txt")) {
		t.Fatal("restore must keep the token and uploads/")
	}
	if exists(filepath.Join(dst, preRestore)) {
		t.Fatal(".pre-restore must be deleted once the restored store opens")
	}
}

func TestRestore_WrongKeyTouchesNothing(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	keys := newKeys(t)
	src := t.TempDir()
	seedStore(t, src, keys)
	out, _ := makeBackup(t, src, keys)
	dst := t.TempDir()
	if _, err := Restore(context.Background(), out, RestoreOptions{StoreDir: dst, Keys: newKeys(t)}); !errors.Is(err, ErrWrongArchiveKey) {
		t.Fatalf("got %v", err)
	}
	if has, _ := storeHasData(dst); has {
		t.Fatal("a refused restore must not write store files")
	}
}

func openFails(t *testing.T, path string, key []byte) {
	t.Helper()
	db, err := crypto.OpenSQLite("file:"+path, key)
	if err == nil {
		db.Close()
		t.Fatalf("%s still opens with the old key", path)
	}
}

func assertRekeyed(t *testing.T, dir string, oldKeys, newKeys *crypto.Keys) {
	t.Helper()
	if got := chatName(t, dir, newKeys); got != plainMarker {
		t.Fatalf("chat name after rekey %q", got)
	}
	if _, err := crypto.InspectDatabase(filepath.Join(dir, WhatsAppDB), newKeys.WhatsApp); err != nil {
		t.Fatal(err)
	}
	openFails(t, filepath.Join(dir, MessagesDB), oldKeys.Messages)
	openFails(t, filepath.Join(dir, WhatsAppDB), oldKeys.WhatsApp)
	assertMedia(t, dir, newKeys)
	old, _ := crypto.NewMediaCipher(oldKeys.Media)
	raw, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(mediaFiles[0])))
	if _, err := old.Open(raw, mediaFiles[0]); err == nil {
		t.Fatal("media still opens with the old key")
	}
	if RekeyPending(dir) {
		t.Fatal("marker left behind")
	}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && (strings.Contains(d.Name(), rekeyNew) || strings.Contains(d.Name(), rekeyOld)) {
			t.Errorf("leftover %s", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := OpenCheck(dir, newKeys); err != nil {
		t.Fatal(err)
	}
}

func TestRekey_RotatesEverything(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	dir, oldKeys, nk := t.TempDir(), newKeys(t), newKeys(t)
	seedStore(t, dir, oldKeys)
	res, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: nk})
	if err != nil {
		t.Fatal(err)
	}
	if res.Databases != 2 || res.Media != len(mediaFiles) || res.Resumed {
		t.Fatalf("result %+v", res)
	}
	assertRekeyed(t, dir, oldKeys, nk)

	if _, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: nk, New: nk}); err == nil {
		t.Fatal("rekeying to the same key must be refused")
	}
	if _, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: newKeys(t)}); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("a wrong current key must be refused, got %v", err)
	}
	if RekeyPending(dir) {
		t.Fatal("a refused rekey must not leave a marker")
	}
}

func TestRekey_LockHeld(t *testing.T) {
	requireCipher(t)
	t.Parallel()
	dir, oldKeys := t.TempDir(), newKeys(t)
	seedStore(t, dir, oldKeys)
	lock, err := store.TryLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if _, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: newKeys(t)}); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("got %v", err)
	}
}

// withFault makes Rekey fail at the given step after `after` passes. Tests
// that use it must not call t.Parallel: parallel tests only start once the
// serial ones are done, so they never see a fault.
func withFault(t *testing.T, step string, after int) {
	t.Helper()
	n := 0
	rekeyFault = func(s string) error {
		if s == step {
			n++
			if n > after {
				return errors.New("simulated crash at " + s)
			}
		}
		return nil
	}
	t.Cleanup(func() { rekeyFault = func(string) error { return nil } })
}

func TestRekey_InterruptedBeforeCommit(t *testing.T) {
	requireCipher(t)
	dir, oldKeys, nk := t.TempDir(), newKeys(t), newKeys(t)
	seedStore(t, dir, oldKeys)
	withFault(t, "prepared", 0)
	if _, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: nk}); err == nil {
		t.Fatal("expected the simulated crash")
	}
	// Still entirely on the old key, with the marker blocking serve.
	if got := chatName(t, dir, oldKeys); got != plainMarker {
		t.Fatal("old key no longer opens the store")
	}
	assertMedia(t, dir, oldKeys)
	if !RekeyPending(dir) {
		t.Fatal("marker missing")
	}
	if _, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: newKeys(t)}); err == nil {
		t.Fatal("resuming with a different new key must be refused")
	}
	if _, err := CreateFile(context.Background(), CreateOptions{StoreDir: dir, Keys: oldKeys}, filepath.Join(t.TempDir(), "b.tar")); !errors.Is(err, ErrRekeyPending) {
		t.Fatalf("backup during a pending rekey: %v", err)
	}

	// Abort restores the plain old-key store.
	if err := AbortRekey(dir); err != nil {
		t.Fatal(err)
	}
	if RekeyPending(dir) || exists(filepath.Join(dir, MessagesDB+rekeyNew)) {
		t.Fatal("abort must remove the marker and the copies")
	}

	// Interrupt again and resume this time.
	if _, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: nk}); err == nil {
		t.Fatal("expected the simulated crash")
	}
	rekeyFault = func(string) error { return nil }
	res, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: nk})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resumed {
		t.Fatal("expected a resumed rotation")
	}
	assertRekeyed(t, dir, oldKeys, nk)
}

func TestRekey_InterruptedDuringCommit(t *testing.T) {
	requireCipher(t)
	dir, oldKeys, nk := t.TempDir(), newKeys(t), newKeys(t)
	seedStore(t, dir, oldKeys)
	withFault(t, "commit:media", 1) // crash after the first media file moved
	if _, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: nk}); err == nil {
		t.Fatal("expected the simulated crash")
	}
	// Mixed state: databases on the new key, the old ones kept aside.
	if got := chatName(t, dir, nk); got != plainMarker {
		t.Fatal("committed database does not open with the new key")
	}
	if _, err := crypto.InspectDatabase(filepath.Join(dir, MessagesDB+rekeyOld), oldKeys.Messages); err != nil {
		t.Fatalf("old copy must stay readable with the old key: %v", err)
	}
	if err := AbortRekey(dir); err == nil {
		t.Fatal("abort must be refused after the commit point")
	}
	rekeyFault = func(string) error { return nil }
	// Resuming needs only the new key (the operator may already have
	// switched the configured key).
	res, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: nk, New: nk})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resumed {
		t.Fatal("expected a resumed rotation")
	}
	assertRekeyed(t, dir, oldKeys, nk)
}

func TestRekey_InterruptedBetweenRenames(t *testing.T) {
	requireCipher(t)
	dir, oldKeys, nk := t.TempDir(), newKeys(t), newKeys(t)
	seedStore(t, dir, oldKeys)
	withFault(t, "prepared", 0)
	_, _ = Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: nk})
	rekeyFault = func(string) error { return nil }
	// Simulate a crash between the two renames of messages.db: the
	// original moved aside, the copy not yet in place, marker committed.
	st, _ := readRekeyState(dir)
	st.Phase = phaseCommit
	if err := writeRekeyState(dir, st); err != nil {
		t.Fatal(err)
	}
	orig := filepath.Join(dir, MessagesDB)
	if err := os.Rename(orig, orig+rekeyOld); err != nil {
		t.Fatal(err)
	}
	if _, err := Rekey(context.Background(), RekeyOptions{StoreDir: dir, Old: oldKeys, New: nk}); err != nil {
		t.Fatal(err)
	}
	assertRekeyed(t, dir, oldKeys, nk)
}
