package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

const notesHelp = `wpp-mcp notes: see and manage the living notes MCP clients keep per chat.

Usage:
  wpp-mcp notes show <chat>
  wpp-mcp notes history <chat>
  wpp-mcp notes revert <chat> <version>
  wpp-mcp notes clear <chat>

<chat> is a JID or a name that matches one cached chat.

  show      the current notes, their version, author and the newest message
            they cover
  history   earlier versions (the last 10 are kept)
  revert    make an earlier version current again (saved as a new version)
  clear     delete the chat's notes and their history

Notes are written by MCP clients (update_chat_notes) from other people's
messages: read them as notes, not as fact. Denying or resetting a chat's
access deletes its notes too. Works with or without a running daemon;
changes are audited either way.
`

// notesBackend is implemented by both access backends.
type notesBackend interface {
	notes(ctx context.Context, jid string) (store.ChatNotes, []store.ChatNotesVersion, error)
	revertNotes(ctx context.Context, jid string, version int) (store.ChatNotes, error)
	clearNotes(ctx context.Context, jid string) error
}

func runNotes(storeDir string, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(os.Stderr, notesHelp)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	want := map[string]int{"show": 1, "history": 1, "revert": 2, "clear": 1}
	n, ok := want[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "notes: unknown command %q\n\n%s", cmd, notesHelp)
		return 2
	}
	if len(rest) != n {
		fmt.Fprintf(os.Stderr, "usage: wpp-mcp notes %s <chat>%s\n", cmd, map[bool]string{true: " <version>"}[cmd == "revert"])
		return 2
	}
	be, err := openAccessBackend(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "notes: %v\n", err)
		return 1
	}
	defer be.close()
	nb, ok := be.(notesBackend)
	if !ok {
		fmt.Fprintln(os.Stderr, "notes: this backend does not support notes")
		return 1
	}
	ctx, cancel := quick()
	defer cancel()
	jid := resolveChatRef(ctx, be, rest[0], "notes")
	if jid == "" {
		return 1
	}
	switch cmd {
	case "show", "history":
		cur, hist, err := nb.notes(ctx, jid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "notes: %v\n", err)
			return 1
		}
		if cmd == "show" {
			printNotes(cur)
			return 0
		}
		if len(hist) == 0 {
			fmt.Fprintf(os.Stderr, "%s has no earlier versions\n", jid)
			return 0
		}
		for _, v := range hist {
			fmt.Printf("--- version %d, %s by %s\n%s\n\n", v.Version, v.UpdatedAt.UTC().Format(time.RFC3339), termSafe(v.UpdatedBy), termSafeMultiline(v.Summary))
		}
	case "revert":
		v, err := strconv.Atoi(rest[1])
		if err != nil || v < 1 {
			fmt.Fprintln(os.Stderr, "notes: version must be a positive number (see `wpp-mcp notes history`)")
			return 2
		}
		cur, err := nb.revertNotes(ctx, jid, v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "notes: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "%s: version %d is current again, saved as version %d\n", jid, v, cur.Version)
	case "clear":
		if err := nb.clearNotes(ctx, jid); err != nil {
			fmt.Fprintf(os.Stderr, "notes: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "%s: notes cleared\n", jid)
	}
	return 0
}

func printNotes(n store.ChatNotes) {
	if n.Version == 0 {
		fmt.Fprintf(os.Stderr, "%s has no notes yet\n", n.ChatJID)
		return
	}
	fmt.Printf("%s, version %d, updated %s by %s", n.ChatJID, n.Version, n.UpdatedAt.UTC().Format(time.RFC3339), termSafe(n.UpdatedBy))
	if n.CoveredUntilID != "" {
		fmt.Printf(", covers messages through %s (%s)", termSafe(n.CoveredUntilID), n.CoveredUntil.UTC().Format(time.RFC3339))
	}
	fmt.Printf("\n\n%s\n", termSafeMultiline(n.Summary))
}

// termSafeMultiline strips control characters except newlines and tabs, so
// notes written from other people's messages cannot drive the terminal.
func termSafeMultiline(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = termSafe(l)
	}
	return strings.Join(lines, "\n")
}

// --- backends ------------------------------------------------------------------

func (d *directAccess) notes(ctx context.Context, jid string) (store.ChatNotes, []store.ChatNotesVersion, error) {
	n, err := d.st.GetChatNotes(ctx, jid)
	if err != nil {
		return n, nil, err
	}
	h, err := d.st.ChatNotesHistory(ctx, jid)
	return n, h, err
}

func (d *directAccess) revertNotes(ctx context.Context, jid string, version int) (store.ChatNotes, error) {
	start := time.Now()
	n, err := d.st.RevertChatNotes(store.WithCreator(ctx, store.CreatorOperatorCLI), jid, version)
	cliAudit(ctx, d.st, start, routeNotesRevert, nil, map[string]any{"jid": jid, "version": version}, err)
	return n, err
}

func (d *directAccess) clearNotes(ctx context.Context, jid string) error {
	start := time.Now()
	err := d.st.ClearChatNotes(ctx, jid)
	cliAudit(ctx, d.st, start, routeNotesClear, nil, map[string]string{"jid": jid}, err)
	return err
}

func (h *httpAccess) notes(ctx context.Context, jid string) (store.ChatNotes, []store.ChatNotesVersion, error) {
	var out struct {
		Notes   store.ChatNotes          `json:"notes"`
		History []store.ChatNotesVersion `json:"history"`
	}
	err := h.call(ctx, http.MethodGet, "/admin/notes?"+url.Values{"jid": {jid}}.Encode(), nil, &out)
	return out.Notes, out.History, err
}

func (h *httpAccess) revertNotes(ctx context.Context, jid string, version int) (store.ChatNotes, error) {
	var out store.ChatNotes
	err := h.call(ctx, http.MethodPost, "/admin/notes/revert", map[string]any{"jid": jid, "version": version}, &out)
	return out, err
}

func (h *httpAccess) clearNotes(ctx context.Context, jid string) error {
	return h.call(ctx, http.MethodPost, "/admin/notes/clear", map[string]string{"jid": jid}, nil)
}
