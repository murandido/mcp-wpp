package crypto

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// SnapshotDatabase copies the database at srcPath (opened with srcKey) into
// a new file at dstPath encrypted with dstKey, using SQLite's online backup
// API. It serves both backups (dstKey == srcKey) and key rotation (a new
// dstKey): SQLCipher decrypts each page with the source key and encrypts it
// with the destination key, and the destination goes through the same keyed
// connector as every other open, so the result opens with OpenSQLite.
//
// The copy is a single sqlite3_backup_step(-1), which runs inside one read
// transaction on the source: the snapshot is consistent even while another
// process writes. In WAL mode (messages.db) readers never block writers, so
// a running daemon keeps writing during the copy. In rollback-journal mode
// (whatsapp.db) the daemon's writers wait on their busy timeout while the
// copy holds its shared lock, which takes milliseconds for that small file.
// When the source is locked, the step is retried until ctx ends.
//
// No plaintext ever reaches disk: both ends are keyed, and temp_store is
// MEMORY on keyed connections. dstPath must not exist; it is created 0600.
func SnapshotDatabase(ctx context.Context, srcPath string, srcKey []byte, dstPath string, dstKey []byte) error {
	if len(srcKey) == 0 || len(dstKey) == 0 {
		return errors.New("snapshot: both databases must be encrypted")
	}
	if !CipherAvailable() {
		return ErrNoSQLCipher
	}
	if state, err := InspectFile(srcPath); err != nil {
		return err
	} else if state != FileEncrypted {
		return fmt.Errorf("snapshot: %s is missing or not encrypted", srcPath)
	}
	// Reserve the destination with private permissions before SQLite opens
	// it (an empty file is treated as a new database).
	f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("snapshot: create %s: %w", dstPath, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := snapshot(ctx, srcPath, srcKey, dstPath, dstKey); err != nil {
		removeDB(dstPath)
		return err
	}
	return syncFile(dstPath)
}

func snapshot(ctx context.Context, srcPath string, srcKey []byte, dstPath string, dstKey []byte) error {
	src, err := OpenSQLite("file:"+srcPath+"?_busy_timeout=5000", srcKey)
	if err != nil {
		return fmt.Errorf("open %s: %w", srcPath, err)
	}
	defer src.Close()
	dst := sql.OpenDB(connector{dsn: "file:" + dstPath, key: dstKey})
	defer dst.Close()

	srcConn, err := src.Conn(ctx)
	if err != nil {
		return err
	}
	defer srcConn.Close()
	dstConn, err := dst.Conn(ctx)
	if err != nil {
		return err
	}
	defer dstConn.Close()

	return dstConn.Raw(func(d any) error {
		return srcConn.Raw(func(s any) error {
			dc, ok1 := d.(*sqlite3.SQLiteConn)
			sc, ok2 := s.(*sqlite3.SQLiteConn)
			if !ok1 || !ok2 {
				return errors.New("snapshot: unexpected driver connection type")
			}
			bk, err := dc.Backup("main", sc, "main")
			if err != nil {
				return fmt.Errorf("start backup: %w", err)
			}
			for {
				done, err := bk.Step(-1)
				if err != nil {
					_ = bk.Finish()
					return fmt.Errorf("backup step: %w", err)
				}
				if done {
					return bk.Finish()
				}
				// The source was busy or locked: wait and retry.
				select {
				case <-ctx.Done():
					_ = bk.Finish()
					return fmt.Errorf("backup: source stayed locked: %w", ctx.Err())
				case <-time.After(50 * time.Millisecond):
				}
			}
		})
	})
}

// DBInfo summarises a database for backup manifests and verification. It
// holds schema facts only, never row content.
type DBInfo struct {
	UserVersion   int      `json:"user_version"`
	SchemaObjects int      `json:"schema_objects"`
	Tables        []string `json:"tables"`
}

// InspectDatabase opens path with key, runs PRAGMA quick_check and returns
// its schema summary. A wrong key yields ErrWrongKey.
func InspectDatabase(path string, key []byte) (*DBInfo, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := OpenSQLite("file:"+path, key)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var check string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil {
		return nil, fmt.Errorf("quick_check: %w", err)
	}
	if check != "ok" {
		return nil, fmt.Errorf("database %s failed its integrity check", path)
	}
	info := &DBInfo{}
	if err := db.QueryRow("PRAGMA user_version").Scan(&info.UserVersion); err != nil {
		return nil, err
	}
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&info.SchemaObjects); err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		info.Tables = append(info.Tables, name)
	}
	sort.Strings(info.Tables)
	return info, rows.Err()
}

// SameSchema reports whether two summaries describe the same schema.
func (i *DBInfo) SameSchema(o *DBInfo) bool {
	return i.UserVersion == o.UserVersion && i.SchemaObjects == o.SchemaObjects &&
		strings.Join(i.Tables, ",") == strings.Join(o.Tables, ",")
}

// CheckpointDatabase folds a WAL back into the database file and truncates
// it, so the main file alone holds every committed page. Only meaningful
// while no other process has the database open.
func CheckpointDatabase(path string, key []byte) error {
	db, err := OpenSQLite("file:"+path, key)
	if err != nil {
		return err
	}
	defer db.Close()
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		return err
	}
	if mode != "wal" {
		return nil
	}
	_, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

// DBSidecars are the files SQLite keeps next to a database.
var DBSidecars = []string{"-wal", "-shm", "-journal"}

func removeDB(path string) {
	_ = os.Remove(path)
	for _, s := range DBSidecars {
		_ = os.Remove(path + s)
	}
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
