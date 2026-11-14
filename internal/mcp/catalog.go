package mcp

import (
	"sort"
	"strings"
)

// ToolInfo describes a tool for documentation.
type ToolInfo struct {
	Name, Group, Access, Summary string
	ReadOnly, Confirm, Default   bool
}

// Catalog lists every tool the server can expose, from the live registry, so
// generated docs cannot drift from the code.
func Catalog() []ToolInfo {
	s := NewServer(nil, nil, true)
	def, _ := (&ToolSelection{}).resolve()
	var out []ToolInfo
	for name, t := range s.MCP().ListTools() {
		scope := toolAccessScope[name]
		access := "none (no chat content)"
		switch {
		case scope.chatArg != "":
			access = "chat in `" + scope.chatArg + "`"
		case scope.scopedRead:
			access = "authorised chats only"
		}
		group := toolGroup[name]
		if accessTools[name] {
			group = groupAccess
		}
		out = append(out, ToolInfo{
			Name: name, Group: group, Access: access,
			Summary:  firstSentence(t.Tool.Description),
			ReadOnly: readOnlyToolAccess[name],
			Confirm:  needsConfirmation(name),
			Default:  def[name],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return groupOrder(out[i].Group) < groupOrder(out[j].Group)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func groupOrder(g string) int {
	for i, x := range []string{groupCore, groupAccess, groupMessaging, groupTranscribe, groupLabels, groupContacts, groupGroups, groupPrivacy, groupPolls} {
		if x == g {
			return i
		}
	}
	return 99
}

func firstSentence(d string) string {
	d = strings.TrimPrefix(d, offlineSafePrefix)
	if i := strings.Index(d, ". "); i >= 0 {
		return d[:i+1]
	}
	return d
}
