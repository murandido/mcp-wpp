package client

import (
	"strings"
	"time"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// Self-chat commands. With serve -self-approve, the operator approves outbox
// proposals by typing into their own "Message yourself" chat on the phone.
// This file decides which messages may count as such a command; what a
// command does is up to the hook (internal/mcp/selfapprove.go).

// SelfCommandMaxAge is how old a self-chat message may be and still count
// as a command. Older ones (offline delivery after a restart) are ignored.
const SelfCommandMaxAge = 5 * time.Minute

// selfCommandMaxSkew tolerates a phone clock slightly ahead of ours.
const selfCommandMaxSkew = time.Minute

// SelfCommand is a text the account wrote to its own chat from another of
// its devices.
type SelfCommand struct {
	ID        string
	Text      string
	Timestamp time.Time
	// ChatJID is the self chat as the phone addressed it (phone or LID
	// JID); replies go there.
	ChatJID string
	// Rejected is set when the text was written to the own chat but may not
	// act: "own device" (this daemon sent it) or "too old". The hook only
	// audits such commands; it must never act on them.
	Rejected string
}

// Reasons a self-chat message is not accepted as a command.
const (
	SelfRejectOwnDevice = "own device"
	SelfRejectTooOld    = "too old"
)

// OnSelfCommand installs fn as the hook for self-chat commands. fn runs on
// whatsmeow's event goroutine and must not block.
func (c *Client) OnSelfCommand(fn func(SelfCommand)) {
	c.selfHookMu.Lock()
	c.selfHook = fn
	c.selfHookMu.Unlock()
}

// notifySelfCommand hands msg to the self-command hook when it qualifies.
func (c *Client) notifySelfCommand(msg *events.Message) {
	c.selfHookMu.RLock()
	fn := c.selfHook
	c.selfHookMu.RUnlock()
	if fn == nil || c.wa == nil || c.wa.Store == nil {
		return
	}
	if cmd, ok := selfCommandOf(msg, c.wa.Store.ID, c.wa.Store.LID, time.Now()); ok {
		fn(cmd)
	}
}

// selfCommandOf applies the acceptance rules. It returns ok for a text in
// the account's own chat, with Rejected set unless the message may act. A
// message may act only when it is all of:
//
//   - a live, plain message: not from history sync or an unavailable-message
//     request, not an edit, and with text;
//   - in the account's own chat (its phone JID or its LID);
//   - from the account (IsFromMe, sender user is the account);
//   - sent from a device other than this daemon's linked device. This is
//     the key protection: anything this daemon sends, including messages an
//     MCP client asked it to send, can never approve anything;
//   - recent: at most SelfCommandMaxAge old.
//
// own is this daemon's device JID (with its device number); ownLID the
// account's LID.
func selfCommandOf(msg *events.Message, own *types.JID, ownLID types.JID, now time.Time) (SelfCommand, bool) {
	if msg == nil || own == nil || own.User == "" || msg.Message == nil {
		return SelfCommand{}, false
	}
	info := msg.Info
	if !info.IsFromMe || msg.IsEdit || info.Edit != "" || msg.SourceWebMsg != nil || msg.UnavailableRequestID != "" {
		return SelfCommand{}, false
	}
	isOwn := func(j types.JID) bool {
		switch j.Server {
		case types.DefaultUserServer:
			return j.User == own.User
		case types.HiddenUserServer:
			return ownLID.User != "" && j.User == ownLID.User
		}
		return false
	}
	if !isOwn(info.Chat) || !isOwn(info.Sender) {
		return SelfCommand{}, false
	}
	text := strings.TrimSpace(extractTextContent(msg.Message))
	if text == "" {
		return SelfCommand{}, false
	}
	cmd := SelfCommand{ID: info.ID, Text: text, Timestamp: info.Timestamp, ChatJID: info.Chat.ToNonAD().String()}
	if info.Sender.Device == own.Device {
		cmd.Rejected = SelfRejectOwnDevice
	} else if age := now.Sub(info.Timestamp); age > SelfCommandMaxAge || age < -selfCommandMaxSkew {
		cmd.Rejected = SelfRejectTooOld
	}
	return cmd, true
}

// OwnChatJIDs returns the account's own chat JIDs (phone and LID), or nil
// when unpaired.
func (c *Client) OwnChatJIDs() []string {
	if c.wa == nil || c.wa.Store == nil || c.wa.Store.ID == nil {
		return nil
	}
	out := []string{c.wa.Store.ID.ToNonAD().String()}
	if lid := c.wa.Store.LID; lid.User != "" {
		out = append(out, lid.ToNonAD().String())
	}
	return out
}
