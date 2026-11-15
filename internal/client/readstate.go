package client

import (
	"context"
	"time"

	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Read state and mentions feed the digest's only_unread and mentions_only
// filters.
//
// Read state: when the user reads a chat on another device, WhatsApp sends
// that device's read receipt to this linked device too. whatsmeow parses it
// as an events.Receipt whose source is the account itself (IsFromMe) with
// type "read", or "read-self" when read receipts are off in the privacy
// settings. Receipts from other people (IsFromMe false) are about messages we
// sent and are ignored. A chat marked as read in the app-state
// (events.MarkChatAsRead) and this daemon's own mark_read / mark_chat_read
// calls count too.

// isOwnReadReceipt reports whether r says the account read messages.
func isOwnReadReceipt(r *events.Receipt) bool {
	return r.IsFromMe && (r.Type == types.ReceiptTypeRead || r.Type == types.ReceiptTypeReadSelf)
}

// handleReceipt records the read mark carried by an own-device read receipt.
func (c *Client) handleReceipt(r *events.Receipt) {
	if r == nil || !isOwnReadReceipt(r) {
		return
	}
	chat := r.Chat.ToNonAD().String()
	if !r.IsGroup {
		chat = c.store.ResolveLIDToJID(chat)
	}
	c.recordRead(context.Background(), chat, r.MessageIDs, r.Timestamp)
}

// handleMarkChatAsRead records a chat marked as read from another device.
// Marking a chat unread leaves the read mark as it is.
func (c *Client) handleMarkChatAsRead(v *events.MarkChatAsRead) {
	if v == nil || v.Action == nil || !v.Action.GetRead() {
		return
	}
	at := v.Timestamp
	if ts := v.Action.GetMessageRange().GetLastMessageTimestamp(); ts > 0 {
		at = time.Unix(ts, 0)
	}
	chat := v.JID.ToNonAD().String()
	if v.JID.Server != types.GroupServer {
		chat = c.store.ResolveLIDToJID(chat)
	}
	c.recordRead(context.Background(), chat, nil, at)
}

// recordRead moves chat's read mark up to the newest cached message among
// ids, or to at when none is cached.
func (c *Client) recordRead(ctx context.Context, chat string, ids []string, at time.Time) {
	if err := c.store.MarkChatReadThrough(ctx, chat, ids, at); err != nil {
		c.log.Warnf("Failed to record read state for %s: %s", c.redactor.JID(chat), c.redactor.Err(err))
	}
}

// ownUsers returns the user parts of the account's phone-number and LID
// JIDs, or nil when no device is known (unpaired, or a test client).
func (c *Client) ownUsers() []string {
	if c.wa == nil || c.wa.Store == nil {
		return nil
	}
	var out []string
	if id := c.wa.Store.ID; id != nil && id.User != "" {
		out = append(out, id.User)
	}
	if lid := c.wa.Store.LID; lid.User != "" {
		out = append(out, lid.User)
	}
	return out
}

// mentionsAny reports whether any context info in m mentions one of users
// (phone or LID user parts).
func mentionsAny(m *waProto.Message, users []string) bool {
	if m == nil || len(users) == 0 {
		return false
	}
	for _, ci := range contextInfos(m) {
		for _, raw := range ci.GetMentionedJID() {
			jid, err := types.ParseJID(raw)
			if err != nil {
				continue
			}
			for _, u := range users {
				if jid.User == u {
					return true
				}
			}
		}
	}
	return false
}

// contextInfos collects the ContextInfo of every content message set in m
// (extended text, image, video, document, poll, ...). Each content type has
// its own contextInfo field, so they are found by reflection rather than by
// listing every type.
func contextInfos(m *waProto.Message) []*waProto.ContextInfo {
	var out []*waProto.ContextInfo
	m.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
			return true
		}
		sub := v.Message()
		cf := sub.Descriptor().Fields().ByName("contextInfo")
		if cf == nil || cf.Kind() != protoreflect.MessageKind || !sub.Has(cf) {
			return true
		}
		if ci, ok := sub.Get(cf).Message().Interface().(*waProto.ContextInfo); ok {
			out = append(out, ci)
		}
		return true
	})
	return out
}
