package mcp

import (
	"fmt"
	"sort"
	"strings"
)

// Tool groups let the operator expose a smaller tool surface. A smaller
// surface costs fewer tokens and gives a prompt-injected model fewer levers.
// Every registered tool must belong to exactly one group; a test enforces it.
const (
	groupCore       = "core"
	groupMessaging  = "messaging"
	groupTranscribe = "transcribe"
	groupLabels     = "labels"
	groupContacts   = "contacts"
	groupGroups     = "groups"
	groupPrivacy    = "privacy"
	groupPolls      = "polls"
	groupAccess     = "access"
)

var toolGroup = map[string]string{
	// core: read and search the cache, status, on-demand media.
	"get_status":          groupCore,
	"pairing_status":      groupCore,
	"list_chats":          groupCore,
	"get_chat":            groupCore,
	"list_messages":       groupCore,
	"get_message_context": groupCore,
	"search_contacts":     groupCore,
	"download_media":      groupCore,
	"request_sync":        groupCore,
	"get_poll_results":    groupCore,
	"digest":              groupCore,
	"mark_unread":         groupCore,

	// messaging: write tools (also gated by -write).
	"send_message":       groupMessaging,
	"send_reply":         groupMessaging,
	"send_file":          groupMessaging,
	"send_audio_message": groupMessaging,
	"send_reaction":      groupMessaging,
	"edit_message":       groupMessaging,
	"delete_message":     groupMessaging,
	"mark_read":          groupMessaging,
	"mark_chat_read":     groupMessaging,
	"schedule_message":   groupMessaging,

	"transcribe_audio":   groupTranscribe,
	"extract_image_text": groupTranscribe,

	"get_chat_labels":     groupLabels,
	"list_chats_by_label": groupLabels,
	"list_labels":         groupLabels,
	"resync_labels":       groupLabels,

	"is_on_whatsapp":    groupContacts,
	"send_contact_card": groupContacts,

	"create_group":              groupGroups,
	"leave_group":               groupGroups,
	"list_groups":               groupGroups,
	"get_group_info":            groupGroups,
	"get_group_invite_link":     groupGroups,
	"join_group_with_link":      groupGroups,
	"set_group_announce":        groupGroups,
	"set_group_locked":          groupGroups,
	"set_group_name":            groupGroups,
	"set_group_topic":           groupGroups,
	"update_group_participants": groupGroups,

	"get_blocklist":        groupPrivacy,
	"block_contact":        groupPrivacy,
	"unblock_contact":      groupPrivacy,
	"get_privacy_settings": groupPrivacy,
	"set_privacy_setting":  groupPrivacy,
	"set_status_message":   groupPrivacy,
	"send_presence":        groupPrivacy,
	"send_typing":          groupPrivacy,

	"send_poll":      groupPolls,
	"send_poll_vote": groupPolls,
}

// defaultGroups is the out-of-the-box profile. Groups, privacy, polls and
// contact lookups are opt-in via -tools.
var defaultGroups = []string{groupCore, groupMessaging, groupTranscribe, groupLabels, groupAccess}

func allGroups() []string {
	seen := map[string]bool{groupAccess: true}
	for _, g := range toolGroup {
		seen[g] = true
	}
	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// ToolSelection is the operator's choice of tool surface.
type ToolSelection struct {
	// Enable lists groups and/or tool names; empty means the default
	// profile. "default" and "all" are accepted as shorthands.
	Enable []string
	// Disable lists groups and/or tool names removed after Enable.
	Disable []string
}

// ParseToolList splits a comma-separated flag value.
func ParseToolList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolve returns the set of tool names the selection admits. Unknown names
// are an error so a typo never silently exposes or hides a tool.
func (sel ToolSelection) resolve() (map[string]bool, error) {
	groups := map[string]bool{}
	for _, g := range allGroups() {
		groups[g] = true
	}
	expand := func(items []string, into map[string]bool) error {
		for _, it := range items {
			switch {
			case it == "all":
				for _, g := range allGroups() {
					if err := expandGroup(g, into); err != nil {
						return err
					}
				}
			case it == "default":
				for _, g := range defaultGroups {
					if err := expandGroup(g, into); err != nil {
						return err
					}
				}
			case groups[it]:
				if err := expandGroup(it, into); err != nil {
					return err
				}
			case toolGroup[it] != "" || accessTools[it]:
				into[it] = true
			default:
				return fmt.Errorf("unknown tool or group %q (groups: %s)", it, strings.Join(allGroups(), ", "))
			}
		}
		return nil
	}
	enabled := map[string]bool{}
	enable := sel.Enable
	if len(enable) == 0 {
		enable = []string{"default"}
	}
	if err := expand(enable, enabled); err != nil {
		return nil, err
	}
	disabled := map[string]bool{}
	if err := expand(sel.Disable, disabled); err != nil {
		return nil, err
	}
	for name := range disabled {
		delete(enabled, name)
	}
	return enabled, nil
}

func expandGroup(g string, into map[string]bool) error {
	if g == groupAccess {
		for name := range accessTools {
			into[name] = true
		}
		return nil
	}
	for name, grp := range toolGroup {
		if grp == g {
			into[name] = true
		}
	}
	return nil
}

// accessTools are the consent-workflow tools. They are always kept when the
// access policy is active, but are listed here so -disable-tools can name
// them. Populated by the access feature.
var accessTools = map[string]bool{}
