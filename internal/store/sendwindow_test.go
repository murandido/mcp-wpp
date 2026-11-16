package store

import (
	"context"
	"testing"
	"time"
)

func TestParseSendWindow(t *testing.T) {
	for in, want := range map[string]SendWindow{
		"08:00-22:00":   {8 * 60, 22 * 60},
		"8:00-22:30":    {8 * 60, 22*60 + 30},
		" 22:00-06:00 ": {22 * 60, 6 * 60},
		"00:00-23:59":   {0, 23*60 + 59},
	} {
		got, err := ParseSendWindow(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	if w, _ := ParseSendWindow("8:00-6:05"); w.String() != "08:00-06:05" {
		t.Errorf("canonical form: %s", w)
	}
	for _, bad := range []string{"", "08:00", "08:00-08:00", "24:00-06:00", "08:60-09:00", "8-22", "08:00-22:0", "123:00-01:00", "a:bc-01:00"} {
		if _, err := ParseSendWindow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSendWindow_ContainsAndWrap(t *testing.T) {
	utc := time.UTC
	day := func(h, m int) time.Time { return time.Date(2026, 11, 16, h, m, 0, 0, utc) }
	day9 := SendWindow{8 * 60, 22 * 60}
	night := SendWindow{22 * 60, 6 * 60}
	for _, c := range []struct {
		w    SendWindow
		at   time.Time
		want bool
	}{
		{day9, day(8, 0), true}, {day9, day(21, 59), true}, {day9, day(22, 0), false}, {day9, day(7, 59), false},
		{night, day(22, 0), true}, {night, day(23, 30), true}, {night, day(0, 0), true}, {night, day(5, 59), true},
		{night, day(6, 0), false}, {night, day(12, 0), false},
	} {
		if got := c.w.Contains(c.at, utc); got != c.want {
			t.Errorf("%s at %s: %v", c.w, c.at.Format("15:04"), got)
		}
	}
	// Next opening: later today, tomorrow, and across midnight.
	if got := day9.NextOpening(day(23, 0), utc); !got.Equal(time.Date(2026, 11, 17, 8, 0, 0, 0, utc)) {
		t.Errorf("after closing: %s", got)
	}
	if got := day9.NextOpening(day(7, 59).Add(30*time.Second), utc); !got.Equal(day(8, 0)) {
		t.Errorf("just before opening: %s", got)
	}
	if at := day(10, 0); !day9.NextOpening(at, utc).Equal(at) {
		t.Error("inside the window, the next opening is now")
	}
	if got := night.NextOpening(day(12, 0), utc); !got.Equal(day(22, 0)) {
		t.Errorf("wrapping window: %s", got)
	}
}

func TestSendWindow_DSTSafe(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no zone database")
	}
	// 2026-03-08: 02:00 EST jumps to 03:00 EDT. A window opening at 02:30
	// opens at the first real minute after the gap, 03:00 EDT.
	w := SendWindow{2*60 + 30, 6 * 60}
	from := time.Date(2026, 3, 8, 1, 0, 0, 0, ny)
	got := w.NextOpening(from, ny)
	if want := time.Date(2026, 3, 8, 3, 0, 0, 0, ny); !got.Equal(want) {
		t.Errorf("spring forward: %s, want %s", got, want)
	}
	// 2026-11-01: 02:00 EDT falls back to 01:00 EST, so the night from
	// 23:00 Oct 31 to 08:00 Nov 1 lasts ten real hours, not nine.
	day := SendWindow{8 * 60, 22 * 60}
	got = day.NextOpening(time.Date(2026, 10, 31, 23, 0, 0, 0, ny), ny)
	if want := time.Date(2026, 11, 1, 8, 0, 0, 0, ny); !got.Equal(want) {
		t.Errorf("fall back: %s, want %s", got, want)
	}
	if d := got.Sub(time.Date(2026, 10, 31, 23, 0, 0, 0, ny)); d != 10*time.Hour {
		t.Errorf("fall back night lasts %s, want 10h", d)
	}
	// The repeated 01:00-02:00 hour never opens a 01:30-05:00 window twice.
	early := SendWindow{60 + 30, 5 * 60}
	first := early.NextOpening(time.Date(2026, 11, 1, 0, 0, 0, 0, ny), ny)
	if want := time.Date(2026, 11, 1, 1, 30, 0, 0, ny); !first.Equal(want) {
		t.Errorf("first 01:30: %s", first)
	}
	if !early.Contains(first.Add(time.Hour), ny) {
		t.Error("the repeated hour is inside the window")
	}
}

func TestSendWindow_StoredWithPolicy(t *testing.T) {
	s := openFileStore(t)
	ctx := context.Background()
	const jid = "447700000001@s.whatsapp.net"
	if err := s.StoreChat(jid, "Alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if w, err := s.ChatSendWindow(ctx, jid); err != nil || w != nil {
		t.Fatalf("no window yet: %v %v", w, err)
	}
	if err := s.SetChatSendWindow(ctx, jid, "8:00-22:00"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.ChatSendPolicy(ctx, jid); p != SendDefault {
		t.Fatalf("a window alone sets no policy: %q", p)
	}
	if err := s.SetChatSendPolicy(ctx, jid, SendDirect); err != nil {
		t.Fatal(err)
	}
	// Resetting the policy keeps the window, and the reverse.
	if err := s.SetChatSendPolicy(ctx, jid, "reset"); err != nil {
		t.Fatal(err)
	}
	w, err := s.ChatSendWindow(ctx, jid)
	if err != nil || w == nil || w.String() != "08:00-22:00" {
		t.Fatalf("window after policy reset: %v %v", w, err)
	}
	entries, _ := s.ListAccess(ctx, "", 10)
	if len(entries) != 1 || entries[0].Window != "08:00-22:00" || entries[0].Send != "" {
		t.Fatalf("list: %+v", entries)
	}
	_ = s.SetChatSendPolicy(ctx, jid, SendNone)
	if err := s.SetChatSendWindow(ctx, jid, "off"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.ChatSendPolicy(ctx, jid); p != SendNone {
		t.Fatalf("policy after window off: %q", p)
	}
	if err := s.SetChatSendWindow(ctx, jid, "25:00-01:00"); err == nil {
		t.Fatal("invalid window accepted")
	}
	_ = s.SetChatSendPolicy(ctx, jid, "reset")
	var n int
	_ = s.db.QueryRow("SELECT count(*) FROM chat_send_policy").Scan(&n)
	if n != 0 {
		t.Fatalf("an empty row was kept: %d", n)
	}
}

func TestSendWindow_MigratesOldPolicyTable(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"DROP TABLE chat_send_policy",
		`CREATE TABLE chat_send_policy (jid TEXT PRIMARY KEY, policy TEXT NOT NULL CHECK (policy IN ('none', 'confirm', 'direct')), decided_at TIMESTAMP NOT NULL)`,
		"INSERT INTO chat_send_policy VALUES ('a@s.whatsapp.net', 'direct', '2026-01-01 10:00:00+00:00')",
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	if p, _ := s.ChatSendPolicy(ctx, "a@s.whatsapp.net"); p != SendDirect {
		t.Fatalf("policy lost in migration: %q", p)
	}
	if err := s.SetChatSendWindow(ctx, "b@s.whatsapp.net", "22:00-06:00"); err != nil {
		t.Fatalf("window after migration: %v", err)
	}
	if err := migrateSendPolicy(s.db); err != nil {
		t.Fatal(err)
	}
}
