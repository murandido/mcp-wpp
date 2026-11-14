package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

const (
	aliceJID = "447700000001@s.whatsapp.net"
	bobJID   = "447700000002@s.whatsapp.net"
	teamJID  = "123456789@g.us"
)

func openAccessStore(t *testing.T) *Store {
	t.Helper()
	s := openTestStore(t)
	if _, err := s.db.Exec(accessSchema); err != nil {
		t.Fatalf("access schema: %v", err)
	}
	return s
}

func chatJIDs(t *testing.T, s *Store) []string {
	t.Helper()
	chats, err := s.ListChats(context.Background(), "", 100, 0, false, "name")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, c := range chats {
		out = append(out, c.JID)
	}
	return out
}

func TestAccess_DefaultAllowlistHidesEverything(t *testing.T) {
	s := openAccessStore(t)
	ctx := context.Background()
	if got := chatJIDs(t, s.Scoped()); len(got) != 0 {
		t.Fatalf("default allowlist must hide every chat, got %v", got)
	}
	if got := chatJIDs(t, s); len(got) != 4 {
		t.Fatalf("unscoped store must see every chat, got %v", got)
	}
	msgs, err := s.Scoped().ListMessages(ctx, ListMessagesParams{Limit: 100})
	if err != nil || len(msgs) != 0 {
		t.Fatalf("scoped messages: %d %v", len(msgs), err)
	}
}

func TestAccess_AllowOneChat(t *testing.T) {
	s := openAccessStore(t)
	ctx := context.Background()
	if err := s.SetChatAccess(ctx, aliceJID, AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	sc := s.Scoped()

	if got := chatJIDs(t, sc); len(got) != 1 || got[0] != aliceJID {
		t.Fatalf("list_chats: %v", got)
	}
	msgs, err := sc.ListMessages(ctx, ListMessagesParams{Limit: 100, IncludeContext: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.ChatJID != aliceJID {
			t.Fatalf("message from hidden chat %s leaked", m.ChatJID)
		}
	}
	// Explicitly asking for a hidden chat returns nothing.
	if msgs, _ := sc.ListMessages(ctx, ListMessagesParams{ChatJID: bobJID, Limit: 100}); len(msgs) != 0 {
		t.Fatalf("filter by hidden chat returned %d messages", len(msgs))
	}
	// A search hit in a hidden chat stays hidden.
	if msgs, _ := sc.ListMessages(ctx, ListMessagesParams{Query: "bob", Limit: 100}); len(msgs) != 0 {
		t.Fatalf("search leaked hidden messages: %+v", msgs)
	}
	if c, err := sc.GetChat(ctx, bobJID, true); err != nil || c != nil {
		t.Fatalf("GetChat(hidden) = %+v, %v; want nil", c, err)
	}
	if c, _ := sc.GetChat(ctx, aliceJID, false); c == nil {
		t.Fatal("GetChat(allowed) = nil")
	}

	// Context around a hidden message errors exactly like a missing one.
	_, hiddenErr := sc.GetMessageContext(ctx, "b1", 2, 2)
	_, missingErr := sc.GetMessageContext(ctx, "nope", 2, 2)
	if hiddenErr == nil || missingErr == nil {
		t.Fatalf("context: hidden=%v missing=%v", hiddenErr, missingErr)
	}
	if strings.Replace(hiddenErr.Error(), "b1", "X", 1) != strings.Replace(missingErr.Error(), "nope", "X", 1) {
		t.Fatalf("hidden and missing messages are distinguishable: %q vs %q", hiddenErr, missingErr)
	}

	contacts, err := sc.SearchContacts(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range contacts {
		if c.JID != aliceJID {
			t.Fatalf("search_contacts leaked %s", c.JID)
		}
	}
}

func TestAccess_ModeAllWithDenial(t *testing.T) {
	s := openAccessStore(t)
	ctx := context.Background()
	if err := s.SetAccessMode(ctx, AccessAll); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChatAccess(ctx, teamJID, AccessDenied, "work"); err != nil {
		t.Fatal(err)
	}
	got := chatJIDs(t, s.Scoped())
	if len(got) != 3 {
		t.Fatalf("mode all with one denial: %v", got)
	}
	for _, j := range got {
		if j == teamJID {
			t.Fatal("denied chat visible in mode all")
		}
	}
	if ok, _ := s.ChatAllowed(ctx, "999@s.whatsapp.net"); !ok {
		t.Fatal("mode all must allow chats without a decision")
	}
	// Clearing the denial restores the default.
	_ = s.SetChatAccess(ctx, teamJID, AccessDefault, "")
	if ok, _ := s.ChatAllowed(ctx, teamJID); !ok {
		t.Fatal("cleared denial still hides the chat")
	}
	if err := s.SetAccessMode(ctx, "everything"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestAccess_RequestsRevealNothingAndNeedApproval(t *testing.T) {
	s := openAccessStore(t)
	ctx := context.Background()
	id, err := s.CreateAccessRequest(ctx, "projéct", "user asked for the teamJID agenda")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ChatAllowed(ctx, teamJID); ok {
		t.Fatal("a request must not grant access")
	}
	reqs, err := s.ListAccessRequests(ctx, "pending")
	if err != nil || len(reqs) != 1 || reqs[0].ID != id {
		t.Fatalf("pending: %+v %v", reqs, err)
	}
	if len(reqs[0].Matches) != 1 || reqs[0].Matches[0].JID != teamJID {
		t.Fatalf("accent-insensitive match failed: %+v", reqs[0].Matches)
	}
	if err := s.DecideAccessRequest(ctx, id, true, []string{bobJID}); err == nil {
		t.Fatal("approving a chat outside the request's matches must fail")
	}
	if err := s.DecideAccessRequest(ctx, id, true, nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ChatAllowed(ctx, teamJID); !ok {
		t.Fatal("approved request did not allow the chat")
	}
	if err := s.DecideAccessRequest(ctx, id, false, nil); err == nil {
		t.Fatal("a decided request must not be decided again")
	}
}

func TestAccess_PendingRequestsAreCapped(t *testing.T) {
	s := openAccessStore(t)
	ctx := context.Background()
	for i := 0; i < maxPendingRequests; i++ {
		if _, err := s.CreateAccessRequest(ctx, "someone", "r"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if _, err := s.CreateAccessRequest(ctx, "someone", "r"); err == nil {
		t.Fatal("request queue is not capped")
	}
}

func TestResolveChats(t *testing.T) {
	s := openAccessStore(t)
	ctx := context.Background()
	got, err := s.ResolveChats(ctx, aliceJID, 10)
	if err != nil || len(got) != 1 || got[0].Name != "Alice" {
		t.Fatalf("by JID: %+v %v", got, err)
	}
	got, _ = s.ResolveChats(ctx, "ALICE", 10)
	if len(got) != 1 {
		t.Fatalf("by name: %+v", got)
	}
	if foldText(" João Ávila ") != "joao avila" {
		t.Fatalf("foldText = %q", foldText(" João Ávila "))
	}
}

// 1:1 chats are usually cached under the bare number; the address book has
// the name people search for.
func TestAddressBookNamesForNumberChats(t *testing.T) {
	s := openAccessStore(t)
	ctx := context.Background()
	const jid = "5564990000001@s.whatsapp.net"
	if err := s.StoreChat(jid, "5564990000001", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO whatsmeow_contacts (our_jid, their_jid, full_name, push_name) VALUES ('me', ?, 'Cauéca', 'Caue')`, jid); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"caueca", "Cauéca", "CAUE"} {
		got, err := s.ListAccess(ctx, q, 10)
		if err != nil || len(got) != 1 || got[0].JID != jid || got[0].Name != "Cauéca" {
			t.Fatalf("ListAccess(%q) = %+v, %v", q, got, err)
		}
	}
	if err := s.SetChatAccess(ctx, jid, AccessAllowed, ""); err != nil {
		t.Fatal(err)
	}
	chats, err := s.Scoped().ListChats(ctx, "Cauéca", 10, 0, false, "name")
	if err != nil || len(chats) != 1 || chats[0].Name != "Cauéca" {
		t.Fatalf("list_chats by address-book name: %+v, %v", chats, err)
	}
	if !isNumberName("+55 64 99000-0001", jid) || isNumberName("Cauéca", jid) {
		t.Fatal("isNumberName misclassifies")
	}
}
