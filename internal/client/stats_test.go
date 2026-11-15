package client

import (
	"testing"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

func TestStats_CountsAndLoggedOutHook(t *testing.T) {
	c := &Client{}
	called := 0
	c.OnLoggedOut(func() { called++ })

	in := &events.Message{Info: types.MessageInfo{MessageSource: types.MessageSource{IsFromMe: false}}}
	own := &events.Message{Info: types.MessageInfo{MessageSource: types.MessageSource{IsFromMe: true}}}
	c.trackConnectionEvent(in)
	c.trackConnectionEvent(in)
	c.trackConnectionEvent(own)
	c.countSent()
	c.trackConnectionEvent(&events.LoggedOut{})

	s := c.Stats()
	if s.MessagesReceived != 2 || s.MessagesSent != 1 {
		t.Fatalf("counters: %+v", s)
	}
	if s.LastReceived.IsZero() {
		t.Fatal("last received time not recorded")
	}
	if s.State != "logged_out" || s.Paired || s.Authenticated || s.Connected {
		t.Fatalf("state: %+v", s)
	}
	if called != 1 {
		t.Fatalf("logged-out hook called %d times", called)
	}
	if c.IsAuthenticated() {
		t.Fatal("a client without whatsmeow is not authenticated")
	}
}
