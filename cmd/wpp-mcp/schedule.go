package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/murandido/mcp-wpp/internal/store"
)

const scheduleUsage = `wpp-mcp schedule: have the daemon send a text message later.

Usage:
  wpp-mcp schedule [-tz ZONE] <jid|name> <time> <message...>

<time> is RFC 3339 (2026-11-16T06:00:00-03:00) or "YYYY-MM-DD HH:MM" (quoted
or as two words), read in -tz, else $TZ, else the system time zone. It must
be in the future and at most 30 days ahead. Your own schedules need no
approval, but the chat must be visible to the AI and its send policy must not
be "none": the daemon checks both again when it sends.

Needs a running daemon started with -write. See and cancel scheduled messages
with ` + "`wpp-mcp outbox`" + ` and ` + "`wpp-mcp outbox cancel <id>`" + `.
`

var (
	dateOnly = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	timeOnly = regexp.MustCompile(`^\d{1,2}:\d{2}(:\d{2})?$`)
)

// localLayouts are the zone-less forms `schedule` accepts.
var localLayouts = []string{"2006-01-02 15:04", "2006-01-02 15:04:05", "2006-01-02T15:04", "2006-01-02T15:04:05"}

// scheduleLocation resolves -tz, then $TZ, then the system zone.
func scheduleLocation(tz string, getenv func(string) string) (*time.Location, error) {
	if tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("unknown time zone %q", tz)
		}
		return loc, nil
	}
	if env := getenv("TZ"); env != "" {
		if loc, err := time.LoadLocation(strings.TrimPrefix(env, ":")); err == nil {
			return loc, nil
		}
	}
	return time.Local, nil
}

// parseScheduleTime reads the send time from the start of args and returns
// it with the remaining arguments (the message). "YYYY-MM-DD HH:MM" may be one
// argument or two.
func parseScheduleTime(args []string, loc *time.Location) (time.Time, []string, error) {
	if len(args) == 0 {
		return time.Time{}, nil, errors.New("missing send time")
	}
	if t, err := time.Parse(time.RFC3339, args[0]); err == nil {
		return t, args[1:], nil
	}
	raw, rest := args[0], args[1:]
	if dateOnly.MatchString(raw) && len(rest) > 0 && timeOnly.MatchString(rest[0]) {
		raw, rest = raw+" "+rest[0], rest[1:]
	}
	// Accept a one-digit hour, as in "2026-11-16 6:00".
	if date, clock, ok := strings.Cut(raw, " "); ok && len(clock) > 1 && clock[1] == ':' {
		raw = date + " 0" + clock
	}
	for _, layout := range localLayouts {
		if t, err := time.ParseInLocation(layout, raw, loc); err == nil {
			return t, rest, nil
		}
	}
	return time.Time{}, nil, fmt.Errorf("cannot read send time %q: use RFC 3339 (2026-11-16T06:00:00-03:00) or \"YYYY-MM-DD HH:MM\"", raw)
}

func runSchedule(storeDir string, args []string) int {
	fs := flag.NewFlagSet("schedule", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tz := fs.String("tz", "", "time zone for a time without an offset, e.g. America/Sao_Paulo (default $TZ, then the system zone)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, scheduleUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	rest := fs.Args()
	if len(rest) < 3 {
		fmt.Fprint(os.Stderr, scheduleUsage)
		return 2
	}
	loc, err := scheduleLocation(*tz, os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "schedule: %v\n", err)
		return 2
	}
	ref := rest[0]
	sendAt, msgArgs, err := parseScheduleTime(rest[1:], loc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "schedule: %v\n", err)
		return 2
	}
	message := strings.Join(msgArgs, " ")
	if strings.TrimSpace(message) == "" {
		fmt.Fprintln(os.Stderr, "schedule: the message is empty")
		return 2
	}
	if err := store.ValidateSendAt(sendAt, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "schedule: %v\n", err)
		return 2
	}

	dc, err := newDaemonClient(storeDir, "")
	if err != nil || !daemonUp(dc) {
		fmt.Fprintln(os.Stderr, "schedule: the daemon is not running; scheduled messages are sent by `wpp-mcp serve -write`")
		return 1
	}
	api := &httpAccess{dc: dc}
	ctx, cancel := quick()
	defer cancel()
	jid := resolveChatRef(ctx, api, ref, "schedule")
	if jid == "" {
		return 1
	}
	var p store.Proposal
	body := map[string]string{"chat": jid, "message": message, "send_at": sendAt.Format(time.RFC3339)}
	if err := api.call(ctx, http.MethodPost, "/admin/outbox/schedule", body, &p); err != nil {
		fmt.Fprintf(os.Stderr, "schedule: %v (is the daemon running with -write?)\n", err)
		return 1
	}
	fmt.Printf("scheduled #%d for %s (%s UTC)\n", p.ID, sendAt.In(loc).Format("2006-01-02 15:04 MST"), sendAt.UTC().Format("2006-01-02 15:04"))
	fmt.Fprintf(os.Stderr, "Cancel with `wpp-mcp outbox cancel %d`.\n", p.ID)
	return 0
}
