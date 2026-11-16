package crypto

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	sqlite3 "github.com/mattn/go-sqlite3"

	"github.com/murandido/mcp-wpp/internal/textfold"
)

// ErrNoSQLCipher means the binary was linked against plain SQLite, where
// PRAGMA key is silently ignored. Encryption must never degrade to that.
var ErrNoSQLCipher = errors.New("this binary was built without SQLCipher, so it cannot encrypt the store; build with `make build` (needs SQLCipher, see README) or pass -no-encryption")

// ErrWrongKey means the database exists but the key does not open it.
var ErrWrongKey = errors.New("cannot decrypt database: wrong key, or the file is not an encrypted wpp-mcp store")

var sqliteHeader = []byte("SQLite format 3\x00")

// connector opens SQLite connections, keyed when key is set.
//
// The key travels as SQLCipher's `hexkey` URI parameter so it is applied
// inside sqlite3_open_v2, before mattn/go-sqlite3 runs its per-connection
// PRAGMAs (synchronous, locking_mode, journal_mode, ...). A `PRAGMA key`
// issued after those comes too late to open an existing encrypted file.
// SQLCipher treats the decoded hexkey bytes as a passphrase, so it still
// runs its PBKDF2 key derivation on every open (about 0.1-0.3 s per new
// connection). That is redundant, since the input is already a uniformly
// random 32-byte HKDF output, but harmless. Switching to SQLCipher's raw-key
// form would derive a different database key, so it would need
// `wpp-mcp rekey`-style migration of existing stores.
type connector struct {
	dsn string
	key []byte
}

func (c connector) keyedDSN() string {
	if len(c.key) == 0 {
		return c.dsn
	}
	sep := "?"
	if strings.Contains(c.dsn, "?") {
		sep = "&"
	}
	return c.dsn + sep + "hexkey=" + hex.EncodeToString(c.key)
}

func (c connector) Connect(context.Context) (driver.Conn, error) {
	d := &sqlite3.SQLiteDriver{}
	conn, err := d.Open(c.keyedDSN())
	if err != nil {
		return nil, err
	}
	sc := conn.(*sqlite3.SQLiteConn)
	// Accent- and case-insensitive matching for the LIKE fallback of search
	// (see internal/store). Pure, so SQLite may use it in indexes and
	// constant-fold it.
	if err := sc.RegisterFunc(textfold.SQLFunc, textfold.SQL, true); err != nil {
		sc.Close()
		return nil, err
	}
	if len(c.key) > 0 {
		// Keep temporary tables and sort spills off disk.
		if _, err := sc.Exec("PRAGMA temp_store = MEMORY", nil); err != nil {
			sc.Close()
			return nil, err
		}
	}
	return sc, nil
}

func (c connector) Driver() driver.Driver { return &sqlite3.SQLiteDriver{} }

// OpenSQLite opens dsn ("file:/path?params") with key, or unencrypted when
// key is empty. With a key it fails fast if SQLCipher is missing or the key
// does not open an existing file. Callers must not use sql.Open("sqlite3")
// directly for store databases.
func OpenSQLite(dsn string, key []byte) (*sql.DB, error) {
	db := sql.OpenDB(connector{dsn: dsn, key: key})
	if len(key) == 0 {
		return db, nil
	}
	if !CipherAvailable() {
		db.Close()
		return nil, ErrNoSQLCipher
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		db.Close()
		if isNotADatabase(err) {
			return nil, ErrWrongKey
		}
		return nil, err
	}
	return db, nil
}

func isNotADatabase(err error) bool {
	var se sqlite3.Error
	if errors.As(err, &se) {
		return se.Code == sqlite3.ErrNotADB
	}
	return false
}

// CipherAvailable reports whether the linked SQLite library is SQLCipher.
func CipherAvailable() bool {
	db := sql.OpenDB(connector{dsn: "file::memory:"})
	defer db.Close()
	var v sql.NullString
	if err := db.QueryRow("PRAGMA cipher_version").Scan(&v); err != nil {
		return false
	}
	return v.Valid && v.String != ""
}

// FileState describes a database file on disk.
type FileState int

const (
	FileMissing   FileState = iota // does not exist or is empty
	FilePlaintext                  // starts with the SQLite header
	FileEncrypted                  // anything else: SQLCipher output is indistinguishable from random
)

// InspectFile classifies the database at path without opening it.
func InspectFile(path string) (FileState, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FileMissing, nil
		}
		return 0, err
	}
	defer f.Close()
	head := make([]byte, len(sqliteHeader))
	n, err := io.ReadFull(f, head)
	if n == 0 && (err == io.EOF || err == io.ErrUnexpectedEOF) {
		return FileMissing, nil
	}
	if bytes.Equal(head[:n], sqliteHeader) {
		return FilePlaintext, nil
	}
	return FileEncrypted, nil
}

// CheckStoreFile refuses to mix modes: an encrypted file without a key, or a
// plaintext file when a key is configured (the key would be ignored and new
// data written in the clear).
func CheckStoreFile(path string, encrypted bool) error {
	state, err := InspectFile(path)
	if err != nil {
		return err
	}
	switch {
	case state == FileEncrypted && !encrypted:
		return fmt.Errorf("%s is encrypted; provide the key file (WPP_MCP_KEY_FILE or -key-file) instead of -no-encryption", path)
	case state == FilePlaintext && encrypted:
		return fmt.Errorf("%s is not encrypted; migrate it with `wpp-mcp encrypt`, or pass -no-encryption", path)
	}
	return nil
}

// ReadOnlyConnector returns a keyed connector without the fail-fast checks
// of OpenSQLite, for handles opened before the file is known to exist.
func ReadOnlyConnector(dsn string, key []byte) driver.Connector {
	return connector{dsn: dsn, key: key}
}
