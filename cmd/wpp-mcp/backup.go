package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/murandido/mcp-wpp/internal/backup"
	"github.com/murandido/mcp-wpp/internal/crypto"
)

// requireKeys loads the configured key for commands that only make sense on
// an encrypted store.
func requireKeys(cmd string) (*crypto.Keys, int) {
	if encryption.disabled {
		fmt.Fprintf(os.Stderr, "%s: needs encryption at rest; it cannot run with -no-encryption (encrypt the store first with `wpp-mcp encrypt`)\n", cmd)
		return nil, 2
	}
	keys, err := crypto.LoadKeyFile(encryption.keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		return nil, 1
	}
	return keys, 0
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// runBackup writes an encrypted archive of the store, or with `backup
// verify <file>` checks one.
func runBackup(storeDir string, args []string) int {
	if len(args) > 0 && args[0] == "verify" {
		return runBackupVerify(args[1:])
	}
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "archive to write (must not exist; created with mode 0600); - writes to stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "backup: -out is required")
		return 2
	}
	keys, code := requireKeys("backup")
	if keys == nil {
		return code
	}
	ctx, cancel := signalContext()
	defer cancel()
	opts := backup.CreateOptions{StoreDir: storeDir, Keys: keys, Version: Version}
	var m *backup.Manifest
	var err error
	if *out == "-" {
		// The encrypted database snapshots wait in a hidden directory in
		// the store rather than /tmp, which is a small tmpfs in Docker.
		opts.TempDir = storeDir
		m, err = backup.Create(ctx, opts, os.Stdout)
	} else {
		m, err = backup.CreateFile(ctx, opts, *out)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "backup: %d database(s) and %d media file(s), encrypted with key %s\n", len(m.Databases), m.MediaCount(), m.KeyFingerprint)
	fmt.Fprintln(os.Stderr, "The key file and the token are not in the archive: keep a separate copy of the key, or the backup cannot be restored.")
	return 0
}

func runBackupVerify(args []string) int {
	fs := flag.NewFlagSet("backup verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "archive to verify (or pass it as the argument)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := *in
	if path == "" && fs.NArg() == 1 {
		path = fs.Arg(0)
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: wpp-mcp backup verify <file>")
		return 2
	}
	keys, code := requireKeys("backup verify")
	if keys == nil {
		return code
	}
	ctx, cancel := signalContext()
	defer cancel()
	// The extracted (still encrypted) databases go next to the archive,
	// not to /tmp, which is a small tmpfs in Docker.
	m, err := backup.Verify(ctx, path, keys, filepath.Dir(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup verify: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "backup verify: OK, made %s by wpp-mcp %s: %d database(s), %d media file(s), key %s\n",
		m.CreatedAt.Format("2006-01-02 15:04:05 MST"), m.Version, len(m.Databases), m.MediaCount(), m.KeyFingerprint)
	return 0
}

func runRestore(storeDir string, args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "archive to restore")
	force := fs.Bool("force", false, "replace a store that already holds data (the current files are kept until the restored store opens)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" {
		fmt.Fprintln(os.Stderr, "restore: -in is required")
		return 2
	}
	keys, code := requireKeys("restore")
	if keys == nil {
		return code
	}
	ctx, cancel := signalContext()
	defer cancel()
	m, err := backup.Restore(ctx, *in, backup.RestoreOptions{StoreDir: storeDir, Keys: keys, Force: *force})
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "restore: restored %d database(s) and %d media file(s) from a backup made %s\n",
		len(m.Databases), m.MediaCount(), m.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	return 0
}

func runRekey(storeDir string, args []string) int {
	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	newKeyFile := fs.String("new-key-file", "", "key file to rotate to (create it with `wpp-mcp keygen -out <path>`)")
	abort := fs.Bool("abort", false, "abandon an interrupted rotation that has not reached its commit phase")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if encryption.disabled {
		fmt.Fprintln(os.Stderr, "rekey: cannot run with -no-encryption")
		return 2
	}
	if *abort {
		if err := backup.AbortRekey(storeDir); err != nil {
			fmt.Fprintf(os.Stderr, "rekey -abort: %v\n", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "rekey: rotation abandoned; the store is still on the current key")
		return 0
	}
	if *newKeyFile == "" {
		fmt.Fprintln(os.Stderr, "rekey: -new-key-file is required")
		return 2
	}
	newKeys, err := crypto.LoadKeyFile(*newKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rekey: new key: %v\n", err)
		return 1
	}
	// The configured key may already be the new one when finishing an
	// interrupted rotation; Rekey checks it against the marker.
	oldKeys, err := crypto.LoadKeyFile(encryption.keyFile)
	if err != nil && !backup.RekeyPending(storeDir) {
		fmt.Fprintf(os.Stderr, "rekey: current key: %v\n", err)
		return 1
	}
	ctx, cancel := signalContext()
	defer cancel()
	res, err := backup.Rekey(ctx, backup.RekeyOptions{StoreDir: storeDir, Old: oldKeys, New: newKeys})
	if err != nil {
		fmt.Fprintf(os.Stderr, "rekey: %v\n", err)
		if backup.RekeyPending(storeDir) {
			fmt.Fprintln(os.Stderr, "The store is marked as mid-rotation and serve will not start; rerun the same command to finish.")
		}
		return 1
	}
	verb := "re-encrypted"
	if res.Resumed {
		verb = "finished an interrupted rotation:"
	}
	fmt.Fprintf(os.Stderr, "rekey: %s %d database(s) and %d media file(s) with key %s\n", verb, res.Databases, res.Media, newKeys.Fingerprint)
	fmt.Fprintf(os.Stderr, "Now configure the new key (-key-file %s, WPP_MCP_KEY_FILE or the Docker secret) before starting serve.\nKeep the old key: backups made before this rotation still need it.\n", *newKeyFile)
	return 0
}

// checkNoPendingRekey refuses to open a store with an unfinished key
// rotation: past its commit point some files are already on the new key.
func checkNoPendingRekey(storeDir string) error {
	if backup.RekeyPending(storeDir) {
		return backup.ErrRekeyPending
	}
	return nil
}
