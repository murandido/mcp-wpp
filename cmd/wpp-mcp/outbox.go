package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/murandido/mcp-wpp/internal/store"
)

const outboxUsage = `wpp-mcp outbox: review what the AI wants to send.

Usage:
  wpp-mcp outbox              List proposals awaiting approval
  wpp-mcp outbox history      List recent proposals and their outcome
  wpp-mcp outbox approve <id> Send it now
  wpp-mcp outbox reject <id>  Discard it

Needs a running daemon started with -write (confirmation is on by default).
`

func runOutbox(storeDir string, args []string) int {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(os.Stderr, outboxUsage)
		return 0
	}
	dc, err := newDaemonClient(storeDir, "")
	if err != nil || !daemonUp(dc) {
		fmt.Fprintln(os.Stderr, "outbox: the daemon is not running; proposals are executed by `wpp-mcp serve -write`")
		return 1
	}
	api := &httpAccess{dc: dc}
	ctx, cancel := quick()
	defer cancel()

	if len(args) == 0 || args[0] == "list" || args[0] == "history" {
		status := "pending"
		if len(args) > 0 && args[0] == "history" {
			status = ""
		}
		var out struct {
			Proposals []store.Proposal `json:"proposals"`
		}
		if err := api.call(ctx, http.MethodGet, "/admin/outbox?status="+status, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "outbox: %v (is the daemon running with -write?)\n", err)
			return 1
		}
		if len(out.Proposals) == 0 {
			fmt.Fprintln(os.Stderr, "nothing awaiting approval")
			return 0
		}
		for _, p := range out.Proposals {
			fmt.Printf("#%d  [%s]  expires %s\n%s\n", p.ID, p.Status, p.ExpiresAt.Local().Format("15:04:05"), p.Summary)
			if p.Result != "" {
				fmt.Printf("  result: %s\n", p.Result)
			}
			fmt.Println()
		}
		if status == "pending" {
			fmt.Fprintln(os.Stderr, "Approve with `wpp-mcp outbox approve <id>` or reject with `wpp-mcp outbox reject <id>`.")
		}
		return 0
	}

	if len(args) < 2 || (args[0] != "approve" && args[0] != "reject") {
		fmt.Fprint(os.Stderr, outboxUsage)
		return 2
	}
	id, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "outbox: invalid id %q\n", args[1])
		return 2
	}
	var p store.Proposal
	if err := api.call(ctx, http.MethodPost, fmt.Sprintf("/admin/outbox/%d/%s", id, args[0]), nil, &p); err != nil {
		fmt.Fprintf(os.Stderr, "outbox: %v\n", err)
		return 1
	}
	if args[0] == "reject" {
		fmt.Fprintf(os.Stderr, "proposal %d rejected\n", id)
		return 0
	}
	fmt.Fprintf(os.Stderr, "proposal %d: %s\n%s\n", id, p.Status, p.Result)
	if p.Status == "failed" {
		return 1
	}
	return 0
}
