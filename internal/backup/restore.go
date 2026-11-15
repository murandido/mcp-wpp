package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/murandido/mcp-wpp/internal/crypto"
	"github.com/murandido/mcp-wpp/internal/store"
)

// ErrStoreNotEmpty is returned when restoring over existing data without Force.
var ErrStoreNotEmpty = errors.New("the store already holds data; pass -force to replace it (the current files are kept until the restored store opens)")

// RestoreOptions configures Restore.
type RestoreOptions struct {
	StoreDir string
	Keys     *crypto.Keys
	// Force replaces a store that already holds data.
	Force bool
	// Check opens the restored store; nil uses OpenCheck. Tests replace it
	// to simulate a restored store that fails to open.
	Check func(storeDir string, keys *crypto.Keys) error
}

// OpenCheck opens the store the way serve does (which also applies schema
// migrations) and the whatsmeow database, then closes both.
func OpenCheck(storeDir string, keys *crypto.Keys) error {
	st, err := store.OpenWithKeys(storeDir, keys)
	if err != nil {
		return err
	}
	if err := st.Close(); err != nil {
		return err
	}
	if wa := filepath.Join(storeDir, WhatsAppDB); exists(wa) {
		if _, err := crypto.InspectDatabase(wa, keys.WhatsApp); err != nil {
			return fmt.Errorf("%s: %w", WhatsAppDB, err)
		}
	}
	return nil
}

// Restore replaces the store's databases and media cache with an archive.
//
// It takes the store lock, so the daemon must be stopped. The archive is
// fully extracted into <store>/.restore-staging and verified (checksums,
// key, database integrity, media authentication) before anything in the
// store is touched. The current databases and media directories are then
// moved into <store>/.pre-restore, the staged files moved in, and the
// restored store opened. Only when that succeeds is .pre-restore deleted;
// otherwise the restored files are removed and the previous ones moved
// back. The token and uploads/ are left as they are.
func Restore(ctx context.Context, archive string, opts RestoreOptions) (*Manifest, error) {
	if opts.Keys == nil {
		return nil, errors.New("restore requires the key file the backup was made with")
	}
	check := opts.Check
	if check == nil {
		check = OpenCheck
	}
	dir := opts.StoreDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := store.TryLock(dir)
	if err != nil {
		return nil, fmt.Errorf("%w (stop `wpp-mcp serve` first)", err)
	}
	defer lock.Release()

	if exists(filepath.Join(dir, rekeyMarker)) {
		return nil, ErrRekeyPending
	}
	pre := filepath.Join(dir, preRestore)
	if exists(pre) {
		return nil, fmt.Errorf("a previous restore did not finish: %s holds the store as it was before; move its contents back or delete it, then retry", pre)
	}
	hasData, err := storeHasData(dir)
	if err != nil {
		return nil, err
	}
	if hasData && !opts.Force {
		return nil, ErrStoreNotEmpty
	}

	staging := filepath.Join(dir, restoreStaging)
	if err := os.RemoveAll(staging); err != nil {
		return nil, err
	}
	if err := os.Mkdir(staging, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	m, err := readArchive(ctx, f, opts.Keys, staging, true)
	f.Close()
	if err != nil {
		return nil, err
	}

	if err := os.Mkdir(pre, 0o700); err != nil {
		return nil, err
	}
	sw := &swap{dir: dir, pre: pre}
	if err := sw.moveAside(); err != nil {
		return nil, sw.rollback(fmt.Errorf("move the current store aside: %w", err))
	}
	if err := sw.install(staging); err != nil {
		return nil, sw.rollback(fmt.Errorf("install restored files: %w", err))
	}
	if err := syncDir(dir); err != nil {
		return nil, sw.rollback(err)
	}
	if err := check(dir, opts.Keys); err != nil {
		return nil, sw.rollback(fmt.Errorf("the restored store does not open: %w", err))
	}
	if err := os.RemoveAll(pre); err != nil {
		return m, fmt.Errorf("restored, but could not delete %s: %w", pre, err)
	}
	return m, nil
}

// swap tracks the moves Restore makes so it can undo them.
type swap struct {
	dir, pre  string
	aside     []string // names moved from dir into pre
	installed []string // names created in dir from the archive
}

// storeEntries lists what a restore replaces: the databases with their
// sidecars and every media chat directory. The token, the lock, uploads/
// and hidden entries stay.
func storeEntries(dir string) ([]string, error) {
	var names []string
	for _, db := range []string{MessagesDB, WhatsAppDB} {
		for _, suffix := range append([]string{""}, crypto.DBSidecars...) {
			if exists(filepath.Join(dir, db+suffix)) {
				names = append(names, db+suffix)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != "uploads" && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func (s *swap) moveAside() error {
	names, err := storeEntries(s.dir)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := os.Rename(filepath.Join(s.dir, name), filepath.Join(s.pre, name)); err != nil {
			return err
		}
		s.aside = append(s.aside, name)
	}
	return syncDir(s.dir)
}

func (s *swap) install(staging string) error {
	var moves [][2]string
	for _, db := range []string{MessagesDB, WhatsAppDB} {
		if exists(filepath.Join(staging, db)) {
			moves = append(moves, [2]string{filepath.Join(staging, db), db})
		}
	}
	chats, err := os.ReadDir(filepath.Join(staging, "media"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, c := range chats {
		moves = append(moves, [2]string{filepath.Join(staging, "media", c.Name()), c.Name()})
	}
	for _, mv := range moves {
		if err := os.Rename(mv[0], filepath.Join(s.dir, mv[1])); err != nil {
			return err
		}
		s.installed = append(s.installed, mv[1])
	}
	return nil
}

// rollback removes what install created and moves the previous files back.
func (s *swap) rollback(cause error) error {
	var errs []error
	for _, name := range s.installed {
		p := filepath.Join(s.dir, name)
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, err)
		}
		if name == MessagesDB || name == WhatsAppDB {
			for _, suffix := range crypto.DBSidecars {
				_ = os.Remove(p + suffix)
			}
		}
	}
	for _, name := range s.aside {
		if err := os.Rename(filepath.Join(s.pre, name), filepath.Join(s.dir, name)); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		_ = os.Remove(s.pre)
		_ = syncDir(s.dir)
		return fmt.Errorf("%w; the previous store was put back", cause)
	}
	return fmt.Errorf("%w; rolling back also failed (%v): the previous files are in %s", cause, errors.Join(errs...), s.pre)
}
