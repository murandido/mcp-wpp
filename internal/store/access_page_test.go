package store

import (
	"context"
	"testing"
)

func TestListAccessPage_FiltersAndPages(t *testing.T) {
	s := openAccessStore(t)
	ctx := context.Background()
	if err := s.SetChatAccess(ctx, aliceJID, AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChatAccess(ctx, bobJID, AccessDenied, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAccessRequest(ctx, "Project", ""); err != nil {
		t.Fatal(err)
	}
	count := func(o AccessListOptions) (int, []string) {
		t.Helper()
		p, err := s.ListAccessPage(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		var jids []string
		for _, c := range p.Chats {
			jids = append(jids, c.JID)
		}
		return p.Total, jids
	}
	for _, tc := range []struct {
		opts  AccessListOptions
		total int
	}{
		{AccessListOptions{}, 4},
		{AccessListOptions{Filter: AccessFilterAllowed}, 1},
		{AccessListOptions{Filter: AccessFilterDenied}, 1},
		{AccessListOptions{Filter: AccessFilterGroups}, 1},
		{AccessListOptions{Filter: AccessFilterDirect}, 3},
		{AccessListOptions{Filter: AccessFilterPending}, 1},
		{AccessListOptions{Query: "ÁLÍCE"}, 1},
		{AccessListOptions{Query: "+44 7700-000002"}, 1},
		{AccessListOptions{Query: "nobody"}, 0},
	} {
		if got, _ := count(tc.opts); got != tc.total {
			t.Errorf("%+v: total %d, want %d", tc.opts, got, tc.total)
		}
	}
	total, first := count(AccessListOptions{Limit: 3})
	_, rest := count(AccessListOptions{Offset: 3, Limit: 3})
	if total != 4 || len(first) != 3 || len(rest) != 1 || rest[0] == first[0] {
		t.Fatalf("paging: total %d, %v then %v", total, first, rest)
	}
}

func TestChatsExist(t *testing.T) {
	s := openAccessStore(t)
	got, err := s.ChatsExist(context.Background(), []string{aliceJID, "nope@s.whatsapp.net"})
	if err != nil || !got[aliceJID] || got["nope@s.whatsapp.net"] {
		t.Fatalf("ChatsExist: %v %v", got, err)
	}
}

func TestPhoneQuery(t *testing.T) {
	for in, want := range map[string]string{"+55 (11) 9-8765": "551198765", "Ana 2": "Ana 2", "  ": "", "Team": "Team"} {
		if got := phoneQuery(in); got != want {
			t.Errorf("phoneQuery(%q) = %q, want %q", in, got, want)
		}
	}
}
