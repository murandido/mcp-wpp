package client

import (
	"testing"
	"time"

	waProto "go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

func TestSelfCommandOf(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	own := &types.JID{User: "447700000009", Server: types.DefaultUserServer, Device: 7} // this daemon
	ownLID := types.JID{User: "112233445566", Server: types.HiddenUserServer, Device: 7}
	phone := types.JID{User: own.User, Server: types.DefaultUserServer}       // the phone, device 0
	phoneLID := types.JID{User: ownLID.User, Server: types.HiddenUserServer}  // same, as LID
	other := types.JID{User: "447700000001", Server: types.DefaultUserServer} // someone else
	thisDevice := types.JID{User: own.User, Server: types.DefaultUserServer, Device: 7}
	laptop := types.JID{User: own.User, Server: types.DefaultUserServer, Device: 12} // another linked device

	msg := func(mod func(*events.Message)) *events.Message {
		m := &events.Message{
			Info: types.MessageInfo{
				MessageSource: types.MessageSource{Chat: phone, Sender: phone, IsFromMe: true},
				ID:            "3EB0SELF",
				Timestamp:     now.Add(-time.Minute),
			},
			Message: &waProto.Message{Conversation: proto.String(" approve 3 ")},
		}
		if mod != nil {
			mod(m)
		}
		return m
	}
	cases := []struct {
		name     string
		m        *events.Message
		ok       bool
		rejected string
	}{
		{"phone in own chat", msg(nil), true, ""},
		{"LID own chat", msg(func(m *events.Message) { m.Info.Chat, m.Info.Sender = phoneLID, phoneLID }), true, ""},
		{"another linked device", msg(func(m *events.Message) { m.Info.Sender = laptop }), true, ""},
		{"extended text", msg(func(m *events.Message) {
			m.Message = &waProto.Message{ExtendedTextMessage: &waProto.ExtendedTextMessage{Text: proto.String("outbox")}}
		}), true, ""},
		{"sent by this daemon", msg(func(m *events.Message) { m.Info.Sender = thisDevice }), true, SelfRejectOwnDevice},
		{"sent by this daemon as LID", msg(func(m *events.Message) {
			m.Info.Chat, m.Info.Sender = phoneLID, types.JID{User: ownLID.User, Server: types.HiddenUserServer, Device: 7}
		}), true, SelfRejectOwnDevice},
		{"too old", msg(func(m *events.Message) { m.Info.Timestamp = now.Add(-6 * time.Minute) }), true, SelfRejectTooOld},
		{"from the future", msg(func(m *events.Message) { m.Info.Timestamp = now.Add(10 * time.Minute) }), true, SelfRejectTooOld},
		{"not from me", msg(func(m *events.Message) { m.Info.IsFromMe = false }), false, ""},
		{"other chat", msg(func(m *events.Message) { m.Info.Chat = other }), false, ""},
		{"my message in another chat", msg(func(m *events.Message) { m.Info.Chat = other; m.Info.Sender = phone }), false, ""},
		{"other sender in own chat", msg(func(m *events.Message) { m.Info.Sender = other }), false, ""},
		{"group", msg(func(m *events.Message) { m.Info.Chat = types.JID{User: "1203630", Server: types.GroupServer} }), false, ""},
		{"history sync", msg(func(m *events.Message) { m.SourceWebMsg = &waWeb.WebMessageInfo{} }), false, ""},
		{"unavailable request", msg(func(m *events.Message) { m.UnavailableRequestID = "req" }), false, ""},
		{"edit", msg(func(m *events.Message) { m.IsEdit = true }), false, ""},
		{"edit attribute", msg(func(m *events.Message) { m.Info.Edit = types.EditAttributeMessageEdit }), false, ""},
		{"no text", msg(func(m *events.Message) { m.Message = &waProto.Message{} }), false, ""},
	}
	for _, c := range cases {
		cmd, ok := selfCommandOf(c.m, own, ownLID, now)
		if ok != c.ok || cmd.Rejected != c.rejected {
			t.Errorf("%s: ok=%v rejected=%q, want ok=%v rejected=%q", c.name, ok, cmd.Rejected, c.ok, c.rejected)
		}
	}
	if cmd, _ := selfCommandOf(msg(nil), own, ownLID, now); cmd.Text != "approve 3" || cmd.ChatJID != phone.String() {
		t.Errorf("accepted command: %+v", cmd)
	}
	if _, ok := selfCommandOf(msg(nil), nil, ownLID, now); ok {
		t.Error("an unpaired client accepts nothing")
	}
}
