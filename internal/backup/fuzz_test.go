package backup

import (
	"path/filepath"
	"strings"
	"testing"
)

func FuzzWithin(f *testing.F) {
	for _, s := range []string{
		"messages.db", "media/chat/abc/file.jpg", "../etc/passwd", "/etc/passwd", "a/../../b", `a\..\b`,
		"", ".", "./a", "a//b", "a/", "C:/x", "a/./b", "..", "a/..", "\x00",
	} {
		f.Add(s)
	}
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, name string) {
		dst, err := within(dir, name)
		if safeEntryName(name) != (err == nil) {
			t.Fatalf("within and safeEntryName disagree on %q: %v", name, err)
		}
		if err != nil {
			return
		}
		if strings.Contains(name, "..") || strings.Contains(name, `\`) || filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
			t.Fatalf("unsafe name %q accepted", name)
		}
		rel, rerr := filepath.Rel(dir, dst)
		if rerr != nil || !filepath.IsLocal(rel) || !strings.HasPrefix(dst, dir+string(filepath.Separator)) {
			t.Fatalf("within(%q) = %q escapes %q", name, dst, dir)
		}
	})
}
