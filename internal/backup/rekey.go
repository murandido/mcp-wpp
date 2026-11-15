package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/crypto"
	"github.com/murandido/mcp-wpp/internal/store"
)

// Key rotation re-encrypts the store with sub-keys derived from a new master
// key. It runs with the daemon stopped (it takes the store lock) and is
// built so that an interruption at any point leaves every file readable
// with the old key or the new one, plus a marker that says which, and
// rerunning `wpp-mcp rekey` with the same new key finishes the job.
//
// Order of operations:
//
//  1. Write <store>/.rekey-state {phase: "prepare"} (fsynced, atomic).
//  2. Prepare, without touching any original: checkpoint each database's
//     WAL, copy it with the online backup API into <db>.rekey under the new
//     key (crypto.SnapshotDatabase, the same keyed connector every open
//     uses) and check the copy's schema; decrypt every media file with the
//     old media key and seal it with the new one into a sibling
//     .rekey-<name>, bound to the original's path. Each copy is fsynced.
//     An interruption here leaves the store entirely on the old key; a
//     rerun discards the partial copies and starts over, and `rekey -abort`
//     discards them and removes the marker.
//  3. Commit point: rewrite the marker with phase "commit". From here on
//     every new-key copy is complete, so recovery only ever rolls forward.
//  4. For each copy: move the original (and a database's -wal/-shm
//     sidecars) to <db>.prekey or .prekey-<name>, then rename the copy into
//     place. Both are renames within one directory. An interruption leaves
//     some files on the new key and the rest on the old key, with the old
//     versions kept as .prekey; serve refuses to start while the marker
//     exists, and a rerun finishes the renames.
//  5. Verify every database and media file opens with the new key, then
//     delete the .prekey files and the marker.
//
// Afterwards the operator must configure the new key file. Backups made
// before the rotation still need the old key.

// RekeyOptions configures Rekey.
type RekeyOptions struct {
	StoreDir string
	// Old is the configured (current) key. It may be nil only when resuming
	// a rotation that already reached the commit phase.
	Old *crypto.Keys
	New *crypto.Keys
}

// RekeyResult reports what Rekey did.
type RekeyResult struct {
	Databases int
	Media     int
	// Resumed is true when an interrupted rotation was finished.
	Resumed bool
}

type rekeyState struct {
	Phase     string    `json:"phase"` // "prepare" or "commit"
	OldKey    string    `json:"old_key"`
	NewKey    string    `json:"new_key"`
	StartedAt time.Time `json:"started_at"`
}

const (
	phasePrepare = "prepare"
	phaseCommit  = "commit"
)

// rekeyFault lets tests interrupt Rekey at a named step.
var rekeyFault = func(string) error { return nil }

// RekeyPending reports whether storeDir has an unfinished key rotation.
func RekeyPending(storeDir string) bool {
	return exists(filepath.Join(storeDir, rekeyMarker))
}

func readRekeyState(dir string) (*rekeyState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, rekeyMarker))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st rekeyState
	if err := json.Unmarshal(raw, &st); err != nil || (st.Phase != phasePrepare && st.Phase != phaseCommit) {
		return nil, fmt.Errorf("unreadable key rotation marker %s", filepath.Join(dir, rekeyMarker))
	}
	return &st, nil
}

func writeRekeyState(dir string, st *rekeyState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeFileSync(filepath.Join(dir, rekeyMarker), raw)
}

// Rekey rotates the store from opts.Old to opts.New (see the order of
// operations above), or finishes an interrupted rotation.
func Rekey(ctx context.Context, opts RekeyOptions) (*RekeyResult, error) {
	if opts.New == nil {
		return nil, errors.New("rekey: a new key is required")
	}
	dir := opts.StoreDir
	lock, err := store.TryLock(dir)
	if err != nil {
		return nil, fmt.Errorf("%w (stop `wpp-mcp serve` first)", err)
	}
	defer lock.Release()

	st, err := readRekeyState(dir)
	if err != nil {
		return nil, err
	}
	res := &RekeyResult{}
	if st != nil {
		if st.NewKey != opts.New.Fingerprint {
			return nil, fmt.Errorf("an interrupted key rotation to key %s is pending; rerun with that key as -new-key-file", st.NewKey)
		}
		res.Resumed = true
		if st.Phase == phaseCommit {
			return res, commitRekey(ctx, dir, opts.New, res)
		}
		if opts.Old == nil || st.OldKey != opts.Old.Fingerprint {
			return nil, fmt.Errorf("the interrupted key rotation started from key %s, which is not the configured key", st.OldKey)
		}
		if err := discardPrepared(dir); err != nil {
			return nil, err
		}
	} else {
		if opts.Old == nil {
			return nil, errors.New("rekey: the current key is required")
		}
		if opts.Old.Fingerprint == opts.New.Fingerprint {
			return nil, errors.New("the new key is the key already in use")
		}
		if pre := filepath.Join(dir, preRestore); exists(pre) {
			return nil, fmt.Errorf("a restore did not finish (%s exists); resolve it first", pre)
		}
		st = &rekeyState{Phase: phasePrepare, OldKey: opts.Old.Fingerprint, NewKey: opts.New.Fingerprint, StartedAt: time.Now().UTC()}
	}

	if err := writeRekeyState(dir, st); err != nil {
		return nil, err
	}
	if err := prepareRekey(ctx, dir, opts.Old, opts.New); err != nil {
		// Nothing original was touched: drop the partial copies and the
		// marker, so the store is exactly as before.
		if derr := discardPrepared(dir); derr == nil {
			_ = os.Remove(filepath.Join(dir, rekeyMarker))
		}
		return nil, err
	}
	if err := rekeyFault("prepared"); err != nil {
		return nil, err
	}
	st.Phase = phaseCommit
	if err := writeRekeyState(dir, st); err != nil {
		return nil, err
	}
	return res, commitRekey(ctx, dir, opts.New, res)
}

// AbortRekey abandons a rotation that has not reached the commit phase: it
// deletes the new-key copies and the marker, leaving the store on the old
// key. A rotation in the commit phase can only be finished.
func AbortRekey(storeDir string) error {
	lock, err := store.TryLock(storeDir)
	if err != nil {
		return fmt.Errorf("%w (stop `wpp-mcp serve` first)", err)
	}
	defer lock.Release()
	st, err := readRekeyState(storeDir)
	if err != nil {
		return err
	}
	if st == nil {
		return errors.New("no key rotation is in progress")
	}
	if st.Phase == phaseCommit {
		return errors.New("the key rotation already reached its commit phase and can only be finished: rerun `wpp-mcp rekey` with the new key")
	}
	if err := discardPrepared(storeDir); err != nil {
		return err
	}
	return os.Remove(filepath.Join(storeDir, rekeyMarker))
}

func presentDBs(dir string) []string {
	var out []string
	for _, name := range []string{MessagesDB, WhatsAppDB} {
		if exists(filepath.Join(dir, name)) {
			out = append(out, name)
		}
	}
	return out
}

func prepareRekey(ctx context.Context, dir string, oldKeys, newKeys *crypto.Keys) error {
	for _, name := range presentDBs(dir) {
		src := filepath.Join(dir, name)
		oldKey, newKey := dbKey(oldKeys, name), dbKey(newKeys, name)
		if err := crypto.CheckpointDatabase(src, oldKey); err != nil {
			return fmt.Errorf("open %s with the current key: %w", name, err)
		}
		want, err := crypto.InspectDatabase(src, oldKey)
		if err != nil {
			return fmt.Errorf("check %s: %w", name, err)
		}
		dst := src + rekeyNew
		if err := crypto.SnapshotDatabase(ctx, src, oldKey, dst, newKey); err != nil {
			return fmt.Errorf("re-encrypt %s: %w", name, err)
		}
		got, err := crypto.InspectDatabase(dst, newKey)
		if err != nil {
			return fmt.Errorf("check re-encrypted %s: %w", name, err)
		}
		if !want.SameSchema(got) {
			return fmt.Errorf("re-encrypted %s has a different schema", name)
		}
		if err := rekeyFault("db:" + name); err != nil {
			return err
		}
	}

	oldMedia, err := crypto.NewMediaCipher(oldKeys.Media)
	if err != nil {
		return err
	}
	newMedia, err := crypto.NewMediaCipher(newKeys.Media)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return walkMedia(dir, func(rel string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		sealed, err := root.ReadFile(filepath.FromSlash(rel))
		if err != nil {
			return err
		}
		plain, err := oldMedia.Open(sealed, rel)
		if err != nil {
			return fmt.Errorf("media file %s: %w", rel, err)
		}
		resealed, err := newMedia.Seal(plain, rel)
		clear(plain)
		if err != nil {
			return err
		}
		reldir, name := filepath.Split(filepath.FromSlash(rel))
		return writeNew(filepath.Join(dir, reldir, rekeyNew+"-"+name), resealed)
	})
}

// discardPrepared removes every new-key copy left by an interrupted prepare.
func discardPrepared(dir string) error {
	for _, name := range []string{MessagesDB, WhatsAppDB} {
		p := filepath.Join(dir, name+rekeyNew)
		for _, suffix := range append([]string{""}, crypto.DBSidecars...) {
			if err := os.Remove(p + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return walkPrefixed(dir, rekeyNew+"-", func(path, _ string) error { return os.Remove(path) })
}

// walkPrefixed calls fn for each file in a media message directory whose
// name starts with prefix, with its path and the name without the prefix.
func walkPrefixed(dir, prefix string, fn func(path, orig string) error) error {
	chats, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, c := range chats {
		if !c.IsDir() || c.Name() == "uploads" || strings.HasPrefix(c.Name(), ".") {
			continue
		}
		msgs, err := os.ReadDir(filepath.Join(dir, c.Name()))
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if !m.IsDir() {
				continue
			}
			mdir := filepath.Join(dir, c.Name(), m.Name())
			files, err := os.ReadDir(mdir)
			if err != nil {
				return err
			}
			for _, f := range files {
				if f.Type().IsRegular() && strings.HasPrefix(f.Name(), prefix) {
					if err := fn(filepath.Join(mdir, f.Name()), strings.TrimPrefix(f.Name(), prefix)); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// promote moves orig aside to old and copy into orig's place. It is
// idempotent across interruptions: a missing orig means the first rename
// already happened.
func promote(orig, copyPath, old string, sidecars bool) error {
	if exists(orig) {
		if exists(old) {
			return fmt.Errorf("both %s and %s exist; resolve by hand", orig, old)
		}
		if sidecars {
			for _, s := range crypto.DBSidecars {
				if exists(orig + s) {
					if err := os.Rename(orig+s, old+s); err != nil {
						return err
					}
				}
			}
		}
		if err := os.Rename(orig, old); err != nil {
			return err
		}
	}
	if err := os.Rename(copyPath, orig); err != nil {
		return err
	}
	return syncDir(filepath.Dir(orig))
}

func commitRekey(ctx context.Context, dir string, newKeys *crypto.Keys, res *RekeyResult) error {
	for _, name := range []string{MessagesDB, WhatsAppDB} {
		orig := filepath.Join(dir, name)
		if !exists(orig + rekeyNew) {
			continue
		}
		if err := promote(orig, orig+rekeyNew, orig+rekeyOld, true); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
		if err := rekeyFault("commit:" + name); err != nil {
			return err
		}
	}
	err := walkPrefixed(dir, rekeyNew+"-", func(path, orig string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		d := filepath.Dir(path)
		if err := promote(filepath.Join(d, orig), path, filepath.Join(d, rekeyOld+"-"+orig), false); err != nil {
			return err
		}
		return rekeyFault("commit:media")
	})
	if err != nil {
		return fmt.Errorf("commit media: %w", err)
	}

	// Everything is in place: prove it opens with the new key before the
	// old copies go.
	for _, name := range presentDBs(dir) {
		if _, err := crypto.InspectDatabase(filepath.Join(dir, name), dbKey(newKeys, name)); err != nil {
			return fmt.Errorf("verify %s with the new key: %w (the old files are kept as *%s)", name, err, rekeyOld)
		}
		res.Databases++
	}
	newMedia, err := crypto.NewMediaCipher(newKeys.Media)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	err = walkMedia(dir, func(rel string) error {
		sealed, err := root.ReadFile(filepath.FromSlash(rel))
		if err != nil {
			return err
		}
		plain, err := newMedia.Open(sealed, rel)
		if err != nil {
			return fmt.Errorf("verify media %s with the new key: %w", rel, err)
		}
		clear(plain)
		res.Media++
		return nil
	})
	if err != nil {
		return err
	}

	for _, name := range []string{MessagesDB, WhatsAppDB} {
		p := filepath.Join(dir, name+rekeyOld)
		for _, suffix := range append([]string{""}, crypto.DBSidecars...) {
			if err := os.Remove(p + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	if err := walkPrefixed(dir, rekeyOld+"-", func(path, _ string) error { return os.Remove(path) }); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, rekeyMarker)); err != nil {
		return err
	}
	return syncDir(dir)
}
