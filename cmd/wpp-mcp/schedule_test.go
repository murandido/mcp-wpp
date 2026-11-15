package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseScheduleTime(t *testing.T) {
	sp, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		t.Skip("no tzdata")
	}
	want := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC) // 06:00 in São Paulo (UTC-3)
	for _, tc := range []struct {
		args []string
		rest string
	}{
		{[]string{"2026-11-16T06:00:00-03:00", "bom", "dia"}, "bom dia"},
		{[]string{"2026-11-16T09:00:00Z", "bom dia"}, "bom dia"},
		{[]string{"2026-11-16 06:00", "bom", "dia"}, "bom dia"},
		{[]string{"2026-11-16", "06:00", "bom", "dia"}, "bom dia"},
		{[]string{"2026-11-16", "6:00", "bom", "dia"}, "bom dia"},
		{[]string{"2026-11-16T06:00", "bom dia"}, "bom dia"},
		{[]string{"2026-11-16 06:00:00", "bom dia"}, "bom dia"},
	} {
		got, rest, err := parseScheduleTime(tc.args, sp)
		if err != nil {
			t.Errorf("%q: %v", tc.args, err)
			continue
		}
		if !got.Equal(want) || strings.Join(rest, " ") != tc.rest {
			t.Errorf("%q = %s, %q; want %s, %q", tc.args, got, rest, want, tc.rest)
		}
	}
	// An explicit offset wins over the zone.
	got, _, _ := parseScheduleTime([]string{"2026-11-16T06:00:00+01:00", "x"}, sp)
	if !got.Equal(time.Date(2026, 11, 16, 5, 0, 0, 0, time.UTC)) {
		t.Errorf("offset ignored: %s", got)
	}
	for _, bad := range [][]string{{}, {"tomorrow", "x"}, {"16/11/2026 06:00", "x"}, {"2026-11-16", "x"}} {
		if _, _, err := parseScheduleTime(bad, sp); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestScheduleLocation(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	if loc, err := scheduleLocation("Europe/London", env("America/Sao_Paulo")); err != nil || loc.String() != "Europe/London" {
		t.Fatalf("-tz must win: %v %v", loc, err)
	}
	if loc, err := scheduleLocation("", env("America/Sao_Paulo")); err != nil || loc.String() != "America/Sao_Paulo" {
		t.Fatalf("$TZ: %v %v", loc, err)
	}
	if loc, _ := scheduleLocation("", env("")); loc != time.Local {
		t.Fatalf("system zone: %v", loc)
	}
	if loc, _ := scheduleLocation("", env("Not/AZone")); loc != time.Local {
		t.Fatalf("a bad $TZ falls back to the system zone: %v", loc)
	}
	if _, err := scheduleLocation("Not/AZone", env("")); err == nil {
		t.Fatal("a bad -tz must fail")
	}
}
