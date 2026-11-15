package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every query that applies the access policy must also apply a client
// token's chat set. Use scopeClause, or pair accessFilter with tokenFilter.
// This guard fails when new code calls accessFilter on its own; extend the
// allowlist only for call sites that do not serve MCP reads.
func TestAccessFilterAlwaysPairedWithTokenFilter(t *testing.T) {
	allowed := []string{
		"func accessFilter(",                     // the definition
		`"SELECT "+accessFilter("?")`,            // ChatAllowed: checks tokenAllows first
		`accessFilter("c.jid")+`,                 // ListAccess: the operator's own view
		`accessFilter(col) + s.tokenFilter(col)`, // scopeClause
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, "accessFilter(") || strings.Contains(line, "tokenFilter(") {
				continue
			}
			ok := false
			for _, a := range allowed {
				if strings.Contains(line, a) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s:%d uses accessFilter without tokenFilter; use scopeClause or add s.tokenFilter: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
