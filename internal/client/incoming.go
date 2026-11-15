package client

import (
	"time"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// IncomingMessage is a live message from someone else, as handed to the hook
// set with OnIncomingMessage. It is called after the message is cached.
type IncomingMessage struct {
	ChatJID    string
	ChatName   string
	IsGroup    bool
	ID         string
	Timestamp  time.Time
	SenderJID  string
	SenderName string
	Text       string // message text or media caption
	MediaType  string // "" when the message has no media
}

// OnIncomingMessage installs fn as the hook for live incoming messages. It is
// not called for history sync, for the account's own messages, for status
// broadcasts, or for poll votes, edits and deletes. fn runs on whatsmeow's
// event goroutine and must not block. Call it before StartEventHandler.
func (c *Client) OnIncomingMessage(fn func(IncomingMessage)) {
	c.incomingHook = fn
}

// notifyIncoming hands a stored live message to the incoming hook.
func (c *Client) notifyIncoming(msg *events.Message, nm normalizedMessage, chatName string) {
	fn := c.incomingHook
	if fn == nil || msg == nil || msg.Info.IsFromMe {
		return
	}
	if msg.Info.Chat.Server == types.BroadcastServer || msg.Info.Chat.Server == types.NewsletterServer {
		return
	}
	sender := nm.senderFullJID
	if jid, err := types.ParseJID(sender); err == nil {
		sender = jid.ToNonAD().String()
	}
	isGroup := msg.Info.Chat.Server == types.GroupServer
	senderName := msg.Info.PushName
	if senderName == "" && !isGroup {
		senderName = chatName
	}
	fn(IncomingMessage{
		ChatJID:    nm.chatJID,
		ChatName:   chatName,
		IsGroup:    isGroup,
		ID:         nm.msg.ID,
		Timestamp:  nm.msg.Timestamp,
		SenderJID:  sender,
		SenderName: senderName,
		Text:       nm.msg.Content,
		MediaType:  nm.msg.MediaType,
	})
}
