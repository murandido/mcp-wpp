package client

import (
	"context"
	"testing"
	"time"

	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/proto/waSyncAction"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"github.com/murandido/mcp-wpp/internal/store"
)

const (
	rsDM    = "447700000001@s.whatsapp.net"
	rsGroup = "120363000000000001@g.us"
)

func rsClient(t *testing.T) (*Client, *store.Store) {
	t.Helper()
	s := newTestStoreWithLIDMap(t, map[string]string{"99887766": "447700000001"})
	c := newHistoryTestClient(t, s)
	for jid, name := range map[string]string{rsDM: "Alice", rsGroup: "Team", types.StatusBroadcastJID.String(): "Status"} {
		if err := s.StoreChat(jid, name, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return c, s
}

func liveMessage(chat, sender types.JID, id string, ts time.Time, fromMe bool, m *waProto.Message) *events.Message {
	return &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: chat, Sender: sender, IsFromMe: fromMe, IsGroup: chat.Server == types.GroupServer},
			ID:            id,
			Timestamp:     ts,
			PushName:      "Alice A.",
		},
		Message: m,
	}
}

func mentionsMeRow(t *testing.T, s *store.Store, id string) bool {
	t.Helper()
	var v bool
	if err := s.DB().QueryRow("SELECT mentions_me FROM messages WHERE id = ?", id).Scan(&v); err != nil {
		t.Fatalf("read mentions_me for %s: %v", id, err)
	}
	return v
}

func TestReadSelfReceiptRecordsReadMark(t *testing.T) {
	c, s := rsClient(t)
	ctx := context.Background()
	dm := types.NewJID("447700000001", types.DefaultUserServer)
	t1 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	c.handleMessage(liveMessage(dm, dm, "r1", t1, false, text("first")))
	c.handleMessage(liveMessage(dm, dm, "r2", t1.Add(time.Minute), false, text("second")))
	c.handleMessage(liveMessage(dm, dm, "r3", t1.Add(2*time.Minute), false, text("third")))

	own := types.NewADJID(historyOwnPhone, 0, 2)
	for _, r := range []*events.Receipt{
		// Someone else reading our message is not our read.
		{MessageSource: types.MessageSource{Chat: dm, Sender: dm}, MessageIDs: []string{"r3"}, Type: types.ReceiptTypeRead, Timestamp: t1.Add(time.Hour)},
		// Delivery receipts from our own devices are not reads.
		{MessageSource: types.MessageSource{Chat: dm, Sender: own, IsFromMe: true}, MessageIDs: []string{"r3"}, Type: types.ReceiptTypeDelivered, Timestamp: t1.Add(time.Hour)},
	} {
		c.handleReceipt(r)
	}
	if _, ok, _ := s.ChatLastRead(ctx, rsDM); ok {
		t.Fatal("a non-own or non-read receipt set the read mark")
	}

	// The phone read r1 and r2 with read receipts disabled: "read-self".
	c.handleReceipt(&events.Receipt{
		MessageSource: types.MessageSource{Chat: dm, Sender: own, IsFromMe: true},
		MessageIDs:    []string{"r1", "r2"},
		Type:          types.ReceiptTypeReadSelf,
		Timestamp:     t1.Add(10 * time.Minute),
	})
	at, ok, err := s.ChatLastRead(ctx, rsDM)
	if err != nil || !ok || !at.Equal(t1.Add(time.Minute)) {
		t.Fatalf("read mark = %v %v %v, want the newest read message (%v)", at, ok, err, t1.Add(time.Minute))
	}

	// A "read" receipt from our own device (read receipts on) moves it forward.
	c.handleReceipt(&events.Receipt{
		MessageSource: types.MessageSource{Chat: dm, Sender: own, IsFromMe: true},
		MessageIDs:    []string{"r3"}, Type: types.ReceiptTypeRead,
	})
	if at, _, _ := s.ChatLastRead(ctx, rsDM); !at.Equal(t1.Add(2 * time.Minute)) {
		t.Fatalf("read mark = %v after reading r3", at)
	}

	// A late receipt for an older message never moves it back.
	c.handleReceipt(&events.Receipt{
		MessageSource: types.MessageSource{Chat: dm, Sender: own, IsFromMe: true},
		MessageIDs:    []string{"r1"}, Type: types.ReceiptTypeRead,
	})
	if at, _, _ := s.ChatLastRead(ctx, rsDM); !at.Equal(t1.Add(2 * time.Minute)) {
		t.Fatalf("read mark moved back to %v", at)
	}
}

func TestReadReceiptForUncachedMessageUsesReceiptTime(t *testing.T) {
	c, s := rsClient(t)
	// A LID-addressed DM resolves to the phone-number chat.
	lidChat := types.NewJID("99887766", types.HiddenUserServer)
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	c.handleReceipt(&events.Receipt{
		MessageSource: types.MessageSource{Chat: lidChat, Sender: types.NewJID(historyOwnPhone, types.DefaultUserServer), IsFromMe: true},
		MessageIDs:    []string{"not-cached"}, Type: types.ReceiptTypeRead, Timestamp: at,
	})
	got, ok, _ := s.ChatLastRead(context.Background(), rsDM)
	if !ok || !got.Equal(at) {
		t.Fatalf("read mark = %v %v, want the receipt time", got, ok)
	}
}

func TestGroupReadReceiptAndMarkChatAsRead(t *testing.T) {
	c, s := rsClient(t)
	ctx := context.Background()
	group := types.NewJID("120363000000000001", types.GroupServer)
	alice := types.NewJID("447700000001", types.DefaultUserServer)
	ts := time.Date(2026, 3, 3, 8, 0, 0, 0, time.UTC)
	c.handleMessage(liveMessage(group, alice, "g1", ts, false, text("hi team")))
	c.handleReceipt(&events.Receipt{
		MessageSource: types.MessageSource{Chat: group, Sender: types.NewJID(historyOwnPhone, types.DefaultUserServer), IsFromMe: true, IsGroup: true},
		MessageIDs:    []string{"g1"}, Type: types.ReceiptTypeRead, MessageSender: alice,
	})
	if at, ok, _ := s.ChatLastRead(ctx, rsGroup); !ok || !at.Equal(ts) {
		t.Fatalf("group read mark = %v %v", at, ok)
	}

	later := ts.Add(time.Hour)
	c.handleMarkChatAsRead(&events.MarkChatAsRead{JID: group, Timestamp: later.Add(time.Minute), Action: &waSyncAction.MarkChatAsReadAction{
		Read:         proto.Bool(true),
		MessageRange: &waSyncAction.SyncActionMessageRange{LastMessageTimestamp: proto.Int64(later.Unix())},
	}})
	if at, _, _ := s.ChatLastRead(ctx, rsGroup); !at.Equal(later) {
		t.Fatalf("mark-as-read app state: read mark = %v, want %v", at, later)
	}
	// Marking unread keeps the mark.
	c.handleMarkChatAsRead(&events.MarkChatAsRead{JID: group, Timestamp: later.Add(time.Hour), Action: &waSyncAction.MarkChatAsReadAction{Read: proto.Bool(false)}})
	if at, _, _ := s.ChatLastRead(ctx, rsGroup); !at.Equal(later) {
		t.Fatalf("mark unread changed the read mark to %v", at)
	}
}

func TestMentionsMeLive(t *testing.T) {
	c, s := rsClient(t)
	group := types.NewJID("120363000000000001", types.GroupServer)
	alice := types.NewJID("447700000001", types.DefaultUserServer)
	ts := time.Date(2026, 3, 4, 8, 0, 0, 0, time.UTC)
	mention := func(jids ...string) *waProto.Message {
		return &waProto.Message{ExtendedTextMessage: &waProto.ExtendedTextMessage{
			Text:        proto.String("@you look"),
			ContextInfo: &waProto.ContextInfo{MentionedJID: jids},
		}}
	}
	c.handleMessage(liveMessage(group, alice, "m-pn", ts, false, mention(historyOwnPhone+"@s.whatsapp.net")))
	c.handleMessage(liveMessage(group, alice, "m-lid", ts, false, mention("447700000005@s.whatsapp.net", historyOwnLID+"@lid")))
	c.handleMessage(liveMessage(group, alice, "m-other", ts, false, mention("447700000005@s.whatsapp.net")))
	c.handleMessage(liveMessage(group, alice, "m-caption", ts, false, &waProto.Message{ImageMessage: &waProto.ImageMessage{
		Caption: proto.String("photo"), Mimetype: proto.String("image/jpeg"),
		ContextInfo: &waProto.ContextInfo{MentionedJID: []string{historyOwnPhone + "@s.whatsapp.net"}},
	}}))
	c.handleMessage(liveMessage(group, alice, "m-plain", ts, false, text("no mention")))
	// Our own message mentioning ourselves is not a mention of interest.
	c.handleMessage(liveMessage(group, types.NewJID(historyOwnPhone, types.DefaultUserServer), "m-self", ts, true, mention(historyOwnPhone+"@s.whatsapp.net")))

	for id, want := range map[string]bool{"m-pn": true, "m-lid": true, "m-caption": true, "m-other": false, "m-plain": false, "m-self": false} {
		if got := mentionsMeRow(t, s, id); got != want {
			t.Errorf("%s: mentions_me = %v, want %v", id, got, want)
		}
	}
}

func TestMentionsMeHistory(t *testing.T) {
	c, s := rsClient(t)
	runHistorySync(c, rsGroup,
		historyMsg(historyKey(rsGroup, "h-mention", false, "447700000001@s.whatsapp.net"), &waProto.Message{
			ExtendedTextMessage: &waProto.ExtendedTextMessage{
				Text:        proto.String("@me please"),
				ContextInfo: &waProto.ContextInfo{MentionedJID: []string{historyOwnLID + "@lid"}},
			},
		}),
		historyMsg(historyKey(rsGroup, "h-plain", false, "447700000001@s.whatsapp.net"), text("hello")),
	)
	if !mentionsMeRow(t, s, "h-mention") {
		t.Error("history mention not flagged")
	}
	if mentionsMeRow(t, s, "h-plain") {
		t.Error("plain history message flagged")
	}
}
