package client

import (
	"context"
	"testing"

	"go.mau.fi/whatsmeow/types"

	"github.com/murandido/mcp-wpp/internal/store"
)

// After a pairing session stores the device identity, the startup client
// must be rebuilt: whatsmeow fixes a client's paired state at construction.
func TestAdoptPairedDevice(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c, err := New(context.Background(), Config{StoreDir: dir, Store: st, Logger: NewStderrLogger("test", "ERROR", false)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()

	unpaired := c.wa
	c.AdoptPairedDevice()
	if c.wa != unpaired {
		t.Fatal("AdoptPairedDevice must be a no-op while unpaired")
	}

	c.StartEventHandler()
	unpaired.Store.ID = &types.JID{User: "5511999999999", Device: 84, Server: types.DefaultUserServer}
	c.AdoptPairedDevice()
	if c.wa == unpaired {
		t.Fatal("the whatsmeow client was not rebuilt after pairing")
	}
	if c.wa.Store != unpaired.Store {
		t.Fatal("the rebuilt client must keep the paired device store")
	}
	if c.handlerInstalled {
		t.Fatal("event handlers must be reinstalled on the new client")
	}
	c.StartEventHandler()
	if !c.handlerInstalled {
		t.Fatal("StartEventHandler did not install handlers on the rebuilt client")
	}
	if c.IsConnected() {
		t.Fatal("rebuilt client should start disconnected")
	}
}
