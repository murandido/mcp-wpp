package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

const tokHelp = `wpp-mcp token: API tokens for MCP clients.

Usage:
  wpp-mcp token create <name> [-scope read|read,send] [-chats JID,...] [-expires 90d]
  wpp-mcp token list
  wpp-mcp token revoke <name|id>

A client token works on /mcp only (never on /admin or the operator pages).
  -scope read       read-only tools (default)
  -scope read,send  also tools that send or change the account; these still
                    need serve -write and, by default, your approval
  -chats J1,J2      only these chats, and only if the access policy allows
                    them (JIDs or phone digits); default: whatever it allows
  -expires D        expire after D (e.g. 90d, 720h); default: never

The token is printed once and only its hash is stored. Revoking takes effect
immediately. The operator token in <store>/token keeps full access and is
the one the local CLI uses. Works with or without a running daemon.
`

func runToken(storeDir string, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(os.Stderr, tokHelp)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "create":
		return tokenCreate(storeDir, rest)
	case "list", "ls":
		return tokenList(storeDir)
	case "revoke":
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: wpp-mcp token revoke <name|id>")
			return 2
		}
		return tokenRevoke(storeDir, rest[0])
	default:
		fmt.Fprintf(os.Stderr, "token: unknown command %q\n\n%s", cmd, tokHelp)
		return 2
	}
}

func tokenCreate(storeDir string, args []string) int {
	// Accept the name before or after the flags.
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, tokHelp) }
	scope := fs.String("scope", "read", "read or read,send")
	chats := fs.String("chats", "", "comma-separated chat JIDs or phone digits")
	expires := fs.String("expires", "", "lifetime, e.g. 90d or 720h")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if name == "" && len(rest) == 1 {
		name, rest = rest[0], nil
	}
	if name == "" || len(rest) > 0 {
		fmt.Fprintln(os.Stderr, "usage: wpp-mcp token create <name> [-scope read|read,send] [-chats JID,...] [-expires 90d]")
		return 2
	}
	in := store.NewAPIToken{Name: name, Scopes: splitList(*scope), Chats: splitList(*chats)}
	if *expires != "" {
		d, err := parseAge(*expires)
		if err != nil {
			fmt.Fprintf(os.Stderr, "token: -expires: %v\n", err)
			return 2
		}
		at := time.Now().Add(d).UTC()
		in.ExpiresAt = &at
	}
	be, err := openAdminBackend(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		return 1
	}
	defer be.close()
	ctx, cancel := quick()
	defer cancel()
	t, secret, err := be.createToken(ctx, in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Created token %q (id %d, scopes %s", t.Name, t.ID, strings.Join(t.Scopes, ","))
	if len(t.Chats) > 0 {
		fmt.Fprintf(os.Stderr, ", chats %s", strings.Join(t.Chats, ","))
	}
	if t.ExpiresAt != nil {
		fmt.Fprintf(os.Stderr, ", expires %s", t.ExpiresAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Fprintln(os.Stderr, ").")
	fmt.Fprintln(os.Stderr, "Copy it now: it is shown only once and cannot be recovered. Treat it like a password.")
	fmt.Println(secret)
	return 0
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func tokenList(storeDir string) int {
	be, err := openAdminBackend(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		return 1
	}
	defer be.close()
	ctx, cancel := quick()
	defer cancel()
	list, err := be.listTokens(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		return 1
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "no API tokens; create one with `wpp-mcp token create <name>`")
		return 0
	}
	printTokens(os.Stdout, list)
	return 0
}

func printTokens(w io.Writer, list []tokenRow) {
	when := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.Local().Format("2006-01-02 15:04")
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tSTATUS\tSCOPES\tCHATS\tCREATED\tEXPIRES\tLAST USED")
	for _, t := range list {
		chats := "policy"
		if len(t.Chats) > 0 {
			chats = strings.Join(t.Chats, ",")
		}
		created := t.CreatedAt
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Status, strings.Join(t.Scopes, ","), chats,
			when(&created), when(t.ExpiresAt), when(t.LastUsedAt))
	}
	tw.Flush()
}

func tokenRevoke(storeDir, ref string) int {
	be, err := openAdminBackend(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		return 1
	}
	defer be.close()
	ctx, cancel := quick()
	defer cancel()
	t, err := be.revokeToken(ctx, ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "token %q (id %d) revoked\n", t.Name, t.ID)
	return 0
}
