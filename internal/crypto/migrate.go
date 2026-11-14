package crypto

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
)

// EncryptDatabase converts the plaintext SQLite database at path into a
// SQLCipher database keyed with key, in place. It is a no-op for a missing
// or already-encrypted file. The plaintext original is kept as path+".bak"
// until the encrypted copy has been verified, then removed.
//
// Removing the plaintext file does not scrub it from the disk: on SSDs and
// copy-on-write filesystems the old blocks may survive. Full-disk encryption
// is the only defence for data that was ever written in the clear.
func EncryptDatabase(path string, key []byte) (bool, error) {
	state, err := InspectFile(path)
	if err != nil {
		return false, err
	}
	if state != FilePlaintext {
		return false, nil
	}
	if !CipherAvailable() {
		return false, ErrNoSQLCipher
	}
	if strings.ContainsAny(path, "'\"") {
		return false, fmt.Errorf("refusing to migrate a path containing quotes: %s", path)
	}

	tmp := path + ".encrypting"
	_ = os.Remove(tmp)

	// Checkpoint the plaintext WAL so the export sees every committed page.
	plain := sql.OpenDB(connector{dsn: "file:" + path})
	if _, err := plain.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		plain.Close()
		return false, fmt.Errorf("checkpoint: %w", err)
	}
	var userVersion int
	err = plain.QueryRow("PRAGMA user_version").Scan(&userVersion)
	plain.Close()
	if err != nil {
		return false, err
	}

	// Open the destination through the keyed connector (the same key path
	// every later open uses), attach the plaintext source with an empty key
	// and export source -> main.
	enc := sql.OpenDB(connector{dsn: "file:" + tmp, key: key})
	enc.SetMaxOpenConns(1) // ATTACH is per-connection
	stmts := []string{
		fmt.Sprintf(`ATTACH DATABASE '%s' AS plain KEY ''`, path),
		"SELECT sqlcipher_export('main', 'plain')",
		"DETACH DATABASE plain",
		fmt.Sprintf("PRAGMA user_version = %d", userVersion),
	}
	for _, q := range stmts {
		if _, err := enc.Exec(q); err != nil {
			enc.Close()
			_ = os.Remove(tmp)
			return false, fmt.Errorf("export %s: %w", path, err)
		}
	}
	enc.Close()

	// Verify before swapping.
	var wantTables int
	src := sql.OpenDB(connector{dsn: "file:" + path + "?mode=ro"})
	err = src.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&wantTables)
	src.Close()
	if err != nil {
		return false, err
	}
	check, err := OpenSQLite("file:"+tmp, key)
	if err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("verify encrypted copy: %w", err)
	}
	var gotTables int
	err = check.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&gotTables)
	check.Close()
	if err != nil || gotTables != wantTables {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("verify encrypted copy: %d of %d schema objects (%v)", gotTables, wantTables, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return false, err
	}

	bak := path + ".bak"
	if err := os.Rename(path, bak); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Rename(bak, path)
		return false, err
	}
	for _, suffix := range []string{".bak", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	return true, nil
}
