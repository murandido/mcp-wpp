package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

const accessUsage = `wpp-mcp access: decide which chats the AI can see.

Usage:
  wpp-mcp access list [search]          List chats and their access state
  wpp-mcp access allow <jid|name>       Let the AI see a chat
  wpp-mcp access deny <jid|name>        Hide a chat (also in mode "all")
  wpp-mcp access reset <jid|name>       Remove the decision (back to the mode's default)
  wpp-mcp access send <jid|name> none|confirm|direct|reset
                                        Set how the AI may write to a chat (with serve -write):
                                        refuse, wait for approval, or act at once
  wpp-mcp access window <jid|name> HH:MM-HH:MM|off
                                        Hours when the AI may write to a chat, in the
                                        daemon's -timezone (may wrap midnight, 22:00-06:00).
                                        Outside them messages wait for the next opening
                                        and other writes are refused
  wpp-mcp access mode [allowlist|all]   Show or set the mode (default: allowlist)
  wpp-mcp access requests               List pending requests from the AI
  wpp-mcp access approve <id> [jid...]  Approve a request (all matches, or only the given JIDs)
  wpp-mcp access reject <id>            Reject a request

A name must match exactly one chat; otherwise the matches are listed and
you can repeat the command with the JID. The send policy never makes a
hidden chat visible; chats without one use the daemon's default (confirm,
or direct with -confirm-sends=false). Works with or without a running
daemon (without one, the store is opened directly).
`

// accessBackend is implemented over the daemon's admin API and over a
// directly opened store.
type accessBackend interface {
	list(ctx context.Context, query string) (string, []store.AccessEntry, error)
	mode(ctx context.Context) (string, error)
	setMode(ctx context.Context, mode string) error
	setChat(ctx context.Context, jid, state string) error
	setSend(ctx context.Context, jid, policy string) error
	setWindow(ctx context.Context, jid, window string) error
	requests(ctx context.Context) ([]store.AccessRequest, error)
	decide(ctx context.Context, id int64, approve bool, jids []string) error
	close()
}

func runAccess(storeDir string, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(os.Stderr, accessUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	be, err := openAccessBackend(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "access: %v\n", err)
		return 1
	}
	defer be.close()
	ctx, cancel := quick()
	defer cancel()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "list", "ls":
		return accessList(ctx, be, strings.Join(rest, " "))
	case "allow", "deny", "reset":
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "usage: wpp-mcp access %s <jid|name>\n", cmd)
			return 2
		}
		state := map[string]string{"allow": store.AccessAllowed, "deny": store.AccessDenied, "reset": "reset"}[cmd]
		return accessSet(ctx, be, strings.Join(rest, " "), state)
	case "send":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: wpp-mcp access send <jid|name> none|confirm|direct|reset")
			return 2
		}
		policy := rest[len(rest)-1]
		if !store.ValidSendPolicy(policy) && policy != "reset" {
			fmt.Fprintf(os.Stderr, "access: send policy must be none, confirm, direct or reset, not %q\n", policy)
			return 2
		}
		return accessSend(ctx, be, strings.Join(rest[:len(rest)-1], " "), policy)
	case "window":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: wpp-mcp access window <jid|name> HH:MM-HH:MM|off")
			return 2
		}
		window := rest[len(rest)-1]
		if window != "off" && window != "reset" {
			if _, err := store.ParseSendWindow(window); err != nil {
				fmt.Fprintf(os.Stderr, "access: %v\n", err)
				return 2
			}
		}
		return accessWindow(ctx, be, strings.Join(rest[:len(rest)-1], " "), window)
	case "mode":
		if len(rest) == 0 {
			mode, err := be.mode(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "access: %v\n", err)
				return 1
			}
			fmt.Println(mode)
			return 0
		}
		if err := be.setMode(ctx, rest[0]); err != nil {
			fmt.Fprintf(os.Stderr, "access: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "mode set to %s\n", rest[0])
		return 0
	case "requests":
		return accessRequests(ctx, be)
	case "approve", "reject":
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "usage: wpp-mcp access %s <id>\n", cmd)
			return 2
		}
		id, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "access: invalid request id %q\n", rest[0])
			return 2
		}
		if err := be.decide(ctx, id, cmd == "approve", rest[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "access: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "request %d %sd\n", id, cmd)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "access: unknown command %q\n\n%s", cmd, accessUsage)
		return 2
	}
}

func stateText(e store.AccessEntry) string {
	switch e.State {
	case store.AccessAllowed:
		return "allowed"
	case store.AccessDenied:
		return "denied"
	}
	if e.Visible {
		return "visible"
	}
	return "hidden"
}

func printChats(w io.Writer, chats []store.AccessEntry) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATE\tSEND\tWINDOW\tNAME\tJID")
	for _, c := range chats {
		name := c.Name
		if c.IsGroup {
			name += " (group)"
		}
		send := c.Send
		if send == "" {
			send = "default"
		}
		window := c.Window
		if window == "" {
			window = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", stateText(c), send, window, name, c.JID)
	}
	tw.Flush()
}

func accessList(ctx context.Context, be accessBackend, query string) int {
	mode, chats, err := be.list(ctx, query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "access: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "mode: %s\n", mode)
	printChats(os.Stdout, chats)
	return 0
}

// resolveChatRef turns a JID or a unique chat name into a JID. It prints
// the problem and returns "" when the name matches no chat or several.
func resolveChatRef(ctx context.Context, be accessBackend, ref, prefix string) string {
	if strings.Contains(ref, "@") {
		return ref
	}
	_, matches, err := be.list(ctx, ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prefix, err)
		return ""
	}
	switch len(matches) {
	case 0:
		fmt.Fprintf(os.Stderr, "%s: no cached chat matches %q; pass a full JID (e.g. 5511999999999@s.whatsapp.net) to decide ahead of time\n", prefix, ref)
		return ""
	case 1:
		return matches[0].JID
	default:
		fmt.Fprintf(os.Stderr, "%s: %q matches %d chats; repeat with the JID:\n", prefix, ref, len(matches))
		printChats(os.Stderr, matches)
		return ""
	}
}

func accessSend(ctx context.Context, be accessBackend, ref, policy string) int {
	jid := resolveChatRef(ctx, be, ref, "access")
	if jid == "" {
		return 1
	}
	if err := be.setSend(ctx, jid, policy); err != nil {
		fmt.Fprintf(os.Stderr, "access: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "%s: send %s\n", jid, policy)
	return 0
}

func accessWindow(ctx context.Context, be accessBackend, ref, window string) int {
	jid := resolveChatRef(ctx, be, ref, "access")
	if jid == "" {
		return 1
	}
	if err := be.setWindow(ctx, jid, window); err != nil {
		fmt.Fprintf(os.Stderr, "access: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "%s: send window %s (daemon time zone)\n", jid, window)
	return 0
}

func accessSet(ctx context.Context, be accessBackend, ref, state string) int {
	jid := resolveChatRef(ctx, be, ref, "access")
	if jid == "" {
		return 1
	}
	if err := be.setChat(ctx, jid, state); err != nil {
		fmt.Fprintf(os.Stderr, "access: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", jid, state)
	return 0
}

func accessRequests(ctx context.Context, be accessBackend) int {
	reqs, err := be.requests(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "access: %v\n", err)
		return 1
	}
	if len(reqs) == 0 {
		fmt.Fprintln(os.Stderr, "no pending requests")
		return 0
	}
	for _, r := range reqs {
		fmt.Printf("#%d  %q  (%s)\n", r.ID, r.Query, r.CreatedAt.Local().Format("2006-01-02 15:04"))
		if r.Reason != "" {
			fmt.Printf("    reason: %s\n", r.Reason)
		}
		if len(r.Matches) == 0 {
			fmt.Println("    no chat matched; allow one directly with `wpp-mcp access allow <jid>`")
		}
		for _, m := range r.Matches {
			fmt.Printf("    - %s  %s\n", m.Name, m.JID)
		}
	}
	fmt.Fprintln(os.Stderr, "\nApprove with `wpp-mcp access approve <id> [jid...]` or reject with `wpp-mcp access reject <id>`.")
	return 0
}

func openAccessBackend(storeDir string) (accessBackend, error) {
	if dc, err := newDaemonClient(storeDir, ""); err == nil && daemonUp(dc) {
		return &httpAccess{dc: dc}, nil
	}
	lock, err := store.TryLock(storeDir)
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable and the store is locked: %w", err)
	}
	st, _, err := openStore(storeDir)
	if err != nil {
		lock.Release()
		return nil, err
	}
	return &directAccess{st: st, release: lock.Release}, nil
}

// --- direct (no daemon) ------------------------------------------------------

type directAccess struct {
	st      *store.Store
	release func()
}

func (d *directAccess) list(ctx context.Context, q string) (string, []store.AccessEntry, error) {
	mode, err := d.st.AccessMode(ctx)
	if err != nil {
		return "", nil, err
	}
	chats, err := d.st.ListAccess(ctx, q, 1000)
	return mode, chats, err
}
func (d *directAccess) mode(ctx context.Context) (string, error) { return d.st.AccessMode(ctx) }
func (d *directAccess) setMode(ctx context.Context, m string) error {
	start := time.Now()
	err := d.st.SetAccessMode(ctx, m)
	cliAudit(ctx, d.st, start, routeAccessMode, nil, accessModeBody(m), err)
	return err
}
func (d *directAccess) setChat(ctx context.Context, jid, state string) error {
	start := time.Now()
	stored := state
	if stored == "reset" {
		stored = store.AccessDefault
	}
	err := d.st.SetChatAccess(ctx, jid, stored, "set with wpp-mcp access")
	cliAudit(ctx, d.st, start, routeAccessChat, nil, accessChatBody(jid, state), err)
	return err
}
func (d *directAccess) setSend(ctx context.Context, jid, policy string) error {
	start := time.Now()
	err := d.st.SetChatSendPolicy(ctx, jid, policy)
	cliAudit(ctx, d.st, start, routeAccessSend, nil, accessSendBody(jid, policy), err)
	return err
}
func (d *directAccess) setWindow(ctx context.Context, jid, window string) error {
	return d.st.SetChatSendWindow(ctx, jid, window)
}
func (d *directAccess) requests(ctx context.Context) ([]store.AccessRequest, error) {
	return d.st.ListAccessRequests(ctx, "pending")
}
func (d *directAccess) decide(ctx context.Context, id int64, approve bool, jids []string) error {
	start := time.Now()
	err := d.st.DecideAccessRequest(ctx, id, approve, jids)
	cliAudit(ctx, d.st, start, routeAccessDecide, idPath("id", id), accessDecideBody(approve, jids), err)
	return err
}
func (d *directAccess) close() { d.st.Close(); d.release() }

// --- over the daemon's admin API ---------------------------------------------

type httpAccess struct{ dc *daemonClient }

func (h *httpAccess) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	ct := ""
	if in != nil {
		b, _ := json.Marshal(in)
		body, ct = bytes.NewReader(b), "application/json"
	}
	resp, err := h.dc.do(ctx, method, path, body, ct)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (h *httpAccess) list(ctx context.Context, q string) (string, []store.AccessEntry, error) {
	var out struct {
		Mode  string              `json:"mode"`
		Chats []store.AccessEntry `json:"chats"`
	}
	err := h.call(ctx, http.MethodGet, "/admin/access?limit=1000&query="+url.QueryEscape(q), nil, &out)
	return out.Mode, out.Chats, err
}
func (h *httpAccess) mode(ctx context.Context) (string, error) {
	var out struct {
		Mode string `json:"mode"`
	}
	err := h.call(ctx, http.MethodGet, "/admin/access?limit=1", nil, &out)
	return out.Mode, err
}
func (h *httpAccess) setMode(ctx context.Context, m string) error {
	return h.call(ctx, http.MethodPost, "/admin/access/mode", accessModeBody(m), nil)
}
func (h *httpAccess) setChat(ctx context.Context, jid, state string) error {
	return h.call(ctx, http.MethodPost, "/admin/access/chat", accessChatBody(jid, state), nil)
}
func (h *httpAccess) setSend(ctx context.Context, jid, policy string) error {
	return h.call(ctx, http.MethodPost, "/admin/access/send", accessSendBody(jid, policy), nil)
}
func (h *httpAccess) setWindow(ctx context.Context, jid, window string) error {
	return h.call(ctx, http.MethodPost, "/admin/access/window", map[string]string{"jid": jid, "window": window}, nil)
}
func (h *httpAccess) requests(ctx context.Context) ([]store.AccessRequest, error) {
	var out struct {
		Requests []store.AccessRequest `json:"requests"`
	}
	err := h.call(ctx, http.MethodGet, "/admin/access/requests?status=pending", nil, &out)
	return out.Requests, err
}
func (h *httpAccess) decide(ctx context.Context, id int64, approve bool, jids []string) error {
	return h.call(ctx, http.MethodPost, fmt.Sprintf("/admin/access/requests/%d", id), accessDecideBody(approve, jids), nil)
}
func (h *httpAccess) close() {}
