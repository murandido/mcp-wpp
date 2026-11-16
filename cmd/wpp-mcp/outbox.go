package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

const outboxUsage = `wpp-mcp outbox: review what the AI wants to send, and what is scheduled.

Usage:
  wpp-mcp outbox              List proposals awaiting approval and scheduled messages
  wpp-mcp outbox scheduled    List scheduled messages only
  wpp-mcp outbox history      List recent items and their outcome
  wpp-mcp outbox approve <id> Send it now (a proposed scheduled message is queued for its time)
  wpp-mcp outbox reject <id>  Discard a proposal
  wpp-mcp outbox cancel <id>  Withdraw a pending proposal or a scheduled message

Needs a running daemon started with -write. Schedule a message yourself with
` + "`wpp-mcp schedule`" + `.
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

	if len(args) == 0 || args[0] == "list" || args[0] == "history" || args[0] == "scheduled" {
		status := store.OutboxPending + "," + store.OutboxScheduled
		if len(args) > 0 {
			switch args[0] {
			case "history":
				status = ""
			case "scheduled":
				status = store.OutboxScheduled
			}
		}
		var out struct {
			Proposals []store.Proposal `json:"proposals"`
		}
		if err := api.call(ctx, http.MethodGet, "/admin/outbox?status="+status, nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "outbox: %v (is the daemon running with -write?)\n", err)
			return 1
		}
		if len(out.Proposals) == 0 {
			fmt.Fprintln(os.Stderr, "nothing awaiting approval or scheduled")
			return 0
		}
		for _, p := range out.Proposals {
			fmt.Printf("#%d  [%s]  %s  by %s\n%s\n", p.ID, p.Status, outboxWhen(p), creatorText(p), p.Summary)
			if p.Result != "" {
				fmt.Printf("  result: %s\n", p.Result)
			}
			fmt.Println()
		}
		if status != "" {
			fmt.Fprintln(os.Stderr, "Approve with `wpp-mcp outbox approve <id>`, reject with `wpp-mcp outbox reject <id>`, cancel a scheduled message with `wpp-mcp outbox cancel <id>`.")
		}
		return 0
	}

	if len(args) < 2 || (args[0] != "approve" && args[0] != "reject" && args[0] != "cancel") {
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
	switch args[0] {
	case "reject":
		fmt.Fprintf(os.Stderr, "proposal %d rejected\n", id)
		return 0
	case "cancel":
		fmt.Fprintf(os.Stderr, "%d cancelled\n", id)
		return 0
	}
	if p.Status == store.OutboxScheduled && p.SendAt != nil {
		fmt.Fprintf(os.Stderr, "proposal %d: scheduled for %s\n", id, localAndUTC(*p.SendAt))
		return 0
	}
	fmt.Fprintf(os.Stderr, "proposal %d: %s\n%s\n", id, p.Status, p.Result)
	if p.Status == store.OutboxFailed {
		return 1
	}
	return 0
}

// outboxWhen describes an item's timing for the listing.
func outboxWhen(p store.Proposal) string {
	switch {
	case p.SendAt != nil && p.Status == store.OutboxPending:
		return "needs approval; sends " + localAndUTC(*p.SendAt)
	case p.SendAt != nil && p.Status == store.OutboxScheduled:
		return "sends " + localAndUTC(*p.SendAt)
	case p.SendAt != nil:
		return "was due " + localAndUTC(*p.SendAt)
	case p.Status == store.OutboxPending:
		return "expires " + p.ExpiresAt.Local().Format("15:04:05")
	}
	return p.CreatedAt.Local().Format("2006-01-02 15:04")
}

// creatorText names who created an item for the listing.
func creatorText(p store.Proposal) string {
	if p.CreatedBy == "" {
		return "unknown"
	}
	return p.CreatedBy
}

// localAndUTC renders t in the local zone with its UTC time alongside.
func localAndUTC(t time.Time) string {
	return fmt.Sprintf("%s (%s UTC)", t.Local().Format("2006-01-02 15:04 MST"), t.UTC().Format("2006-01-02 15:04"))
}
