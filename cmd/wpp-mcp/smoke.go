package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/murandido/mcp-wpp/internal/client"
	mcpsrv "github.com/murandido/mcp-wpp/internal/mcp"
	"github.com/murandido/mcp-wpp/internal/security"
	"github.com/murandido/mcp-wpp/internal/store"
)

// runSmoke boots the store + client (without connecting to WhatsApp servers)
// and constructs the MCP server. Used by CI to catch wire-up regressions.
func runSmoke(storeDir string, redactor *security.Redactor, args []string) int {
	fs := flag.NewFlagSet("smoke", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "wpp-mcp smoke: (CI) construct MCP server without connecting to WhatsApp; fails fast on wiring regressions.")
		fmt.Fprintln(os.Stderr, "\nUsage: wpp-mcp [-store DIR] smoke")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx := context.Background()

	// Smoke never touches the operator's store or key: it opens a throwaway
	// store with throwaway keys, which also proves SQLCipher is linked.
	_ = storeDir
	tmpStore, err := os.MkdirTemp("", "wpp-mcp-smoke-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpStore)
	storeDir = tmpStore
	keys, err := smokeKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: %v\n", err)
		return 1
	}
	st, err := store.OpenWithKeys(storeDir, keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		return 1
	}
	defer st.Close()

	c, err := client.New(ctx, client.Config{
		StoreDir: storeDir,
		Store:    st,
		Logger:   client.NewStderrLogger("Smoke", "WARN", false),
		Redactor: redactor,
		Keys:     keys,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client: %v\n", err)
		return 1
	}
	defer c.Disconnect()

	srv := mcpsrv.NewServer(c, nil, false) // no pair cache or label sync in smoke mode
	_ = srv                                // construction is the smoke test; not starting the server here

	if keys != nil {
		fmt.Fprintln(os.Stderr, "smoke: OK — encrypted store opens, client initialises, MCP tools register.")
	} else {
		fmt.Fprintln(os.Stderr, "smoke: OK (unencrypted) — store opens, client initialises, MCP tools register.")
	}
	return 0
}
