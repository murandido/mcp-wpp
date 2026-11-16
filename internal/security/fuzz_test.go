package security

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var longDigitRun = regexp.MustCompile(`\d{10,}`)

func FuzzSafeFilename(f *testing.F) {
	for _, s := range []string{"report.pdf", "", ".", "..", "/", "../../etc/passwd", "a/b/c.txt", "x\x00y", `..\..\win.ini`, "///", "a/.."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := SafeFilename(raw)
		if got == "" || got == "." || got == ".." || strings.ContainsAny(got, "/\x00") {
			t.Fatalf("SafeFilename(%q) = %q", raw, got)
		}
		if filepath.Base(got) != got {
			t.Fatalf("SafeFilename(%q) = %q is not a single path element", raw, got)
		}
	})
}

// FuzzValidateOutputPath checks that an accepted output path always lands
// inside the root, whatever the input looks like.
func FuzzValidateOutputPath(f *testing.F) {
	for _, s := range []string{"out.bin", "sub/out.bin", "../out.bin", "/etc/passwd", "sub/../../x", "", ".", "link/x", "sub/./y"} {
		f.Add(s, true)
		f.Add(s, false)
	}
	root := f.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o700); err != nil {
		f.Fatal(err)
	}
	outside := f.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		f.Fatal(err)
	}
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, p string, join bool) {
		if join {
			p = filepath.Join(root, p)
		}
		for _, check := range []func(string, string) (string, error){ValidateOutputPath, ValidateMediaPath} {
			got, err := check(p, root)
			if err != nil || got == "" {
				continue
			}
			if got != rootResolved && !strings.HasPrefix(got, rootResolved+string(filepath.Separator)) {
				t.Fatalf("path %q accepted as %q outside %q", p, got, rootResolved)
			}
		}
	})
}

func FuzzRedactor(f *testing.F) {
	for _, s := range []string{
		"447700900123@s.whatsapp.net", "+447700900123", "1203630000000000@g.us", "", "@", "héllo wörld",
		"https://mmg.whatsapp.net/v/t62/abc?oh=secret", "call me on 5511999999999 or +5511888888888", "9+12345678901",
		"1234567890123456789012345", "/cmd 12345678901",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		quiet, debug := &Redactor{}, &Redactor{Debug: true}

		if j := quiet.JID(s); !strings.HasPrefix(j, "…") || utf8.RuneCountInString(j) > 5 {
			t.Fatalf("JID(%q) = %q", s, j)
		}
		if id := quiet.MsgID(s); !strings.HasPrefix(id, "…") || utf8.RuneCountInString(id) > 7 {
			t.Fatalf("MsgID(%q) = %q", s, id)
		}
		if b := quiet.Body(s); !regexp.MustCompile(`^\[\d+B: (text|url|command)\]$`).MatchString(b) {
			t.Fatalf("Body(%q) = %q", s, b)
		}
		if u := quiet.URL(s); u != "[url]" && (!strings.HasSuffix(u, "/…") || strings.ContainsAny(strings.TrimSuffix(u, "/…"), "?#")) {
			t.Fatalf("URL(%q) = %q keeps a path, query or fragment", s, u)
		}
		// Phone digit runs never survive, in either mode.
		for name, out := range map[string]string{
			"debug Body": debug.Body(s), "Line": quiet.Line(s), "Err": quiet.Err(errors.New(s)), "debug Err": debug.Err(errors.New(s)),
		} {
			if longDigitRun.MatchString(out) {
				t.Fatalf("%s(%q) = %q keeps a phone number", name, s, out)
			}
		}
		if j := debug.JID(s); longDigitRun.MatchString(strings.SplitN(j, "@", 2)[0]) {
			t.Fatalf("debug JID(%q) = %q keeps a phone number", s, j)
		}
	})
}
