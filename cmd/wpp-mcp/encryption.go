package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/crypto"
	"github.com/murandido/mcp-wpp/internal/security"
	"github.com/murandido/mcp-wpp/internal/store"
)

// encryption holds the global -key-file / -no-encryption settings.
var encryption struct {
	keyFile  string
	disabled bool
}

// loadKeys returns the store keys, or nil when encryption is disabled.
func loadKeys() (*crypto.Keys, error) {
	if encryption.disabled {
		return nil, nil
	}
	return crypto.LoadKeyFile(encryption.keyFile)
}

// openStore loads the keys and opens the message store with them.
func openStore(storeDir string) (*store.Store, *crypto.Keys, error) {
	keys, err := loadKeys()
	if err != nil {
		return nil, nil, err
	}
	st, err := store.OpenWithKeys(storeDir, keys)
	if err != nil {
		return nil, nil, err
	}
	return st, keys, nil
}

func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", encryption.keyFile, "where to write the new key (default: the -key-file location); - prints it to stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "-" {
		key, err := crypto.NewKeyHex()
		if err != nil {
			fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
			return 1
		}
		fmt.Println(key)
		fmt.Fprintln(os.Stderr, "Store this key with mode 0600 and back it up: without it the store cannot be read.")
		return 0
	}
	if err := crypto.GenerateKeyFile(*out); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote a new key to %s (mode 0600).\nBack it up somewhere safe: without it the store cannot be read, and nobody can recover it.\n", *out)
	return 0
}

// runEncrypt migrates a plaintext store to encryption at rest.
func runEncrypt(storeDir string, redactor *security.Redactor, args []string) int {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if encryption.disabled {
		fmt.Fprintln(os.Stderr, "encrypt: cannot run with -no-encryption")
		return 2
	}
	keys, err := crypto.LoadKeyFile(encryption.keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt: %v\n", err)
		return 1
	}
	lock, err := store.TryLock(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt: %v (stop `wpp-mcp serve` first)\n", err)
		return 1
	}
	defer lock.Release()

	for _, db := range []struct {
		name string
		key  []byte
	}{{"messages.db", keys.Messages}, {"whatsapp.db", keys.WhatsApp}} {
		done, err := crypto.EncryptDatabase(filepath.Join(storeDir, db.name), db.key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "encrypt %s: %v\n", db.name, err)
			return 1
		}
		if done {
			fmt.Fprintf(os.Stderr, "%s: encrypted\n", db.name)
		} else {
			fmt.Fprintf(os.Stderr, "%s: already encrypted or absent\n", db.name)
		}
	}

	st, err := store.OpenWithKeys(storeDir, keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt: reopen store: %v\n", err)
		return 1
	}
	defer st.Close()
	c, err := client.New(context.Background(), client.Config{
		StoreDir: storeDir,
		Store:    st,
		Logger:   client.NewStderrLogger("Encrypt", "WARN", false),
		Redactor: redactor,
		Keys:     keys,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt: %v\n", err)
		return 1
	}
	defer c.Disconnect()
	n, err := c.SealExistingCache()
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt media cache: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "media cache: sealed %d file(s)\n", n)
	fmt.Fprintln(os.Stderr, "Done. Plaintext copies were deleted, but SSDs and copy-on-write filesystems may retain old blocks; use full-disk encryption for data that was ever stored unencrypted.")
	return 0
}

// smokeKeys returns throwaway keys for the smoke test, which must exercise
// the encrypted code path without touching the operator's key.
func smokeKeys() (*crypto.Keys, error) {
	if encryption.disabled {
		return nil, nil
	}
	if !crypto.CipherAvailable() {
		return nil, crypto.ErrNoSQLCipher
	}
	master := make([]byte, crypto.KeySize)
	for i := range master {
		master[i] = byte(i)
	}
	return crypto.DeriveKeys(master)
}
