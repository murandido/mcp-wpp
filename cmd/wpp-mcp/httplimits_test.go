package main

import (
	"flag"
	"io"
	"testing"

	"github.com/murandido/mcp-wpp/internal/daemon"
)

func TestHTTPLimitFlags(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f, err := registerHTTPLimitFlags(fs, env(nil))
	if err != nil || fs.Parse(nil) != nil {
		t.Fatal(err)
	}
	var cfg daemon.Config
	f.apply(&cfg)
	if cfg.MCPRate != daemon.DefaultMCPRate || cfg.AuthFailLimit != daemon.DefaultAuthFailLimit {
		t.Fatalf("defaults: %+v", f)
	}

	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	f, err = registerHTTPLimitFlags(fs, env(map[string]string{"WPP_MCP_RATE": "0", "WPP_MCP_AUTH_FAIL_LIMIT": "7"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"-auth-fail-limit", "9"}); err != nil {
		t.Fatal(err)
	}
	if f.mcpRate != 0 || f.authFailLimit != 9 || f.validate() != nil {
		t.Fatalf("env and flag: %+v", f)
	}

	for _, bad := range []string{"-1", "x"} {
		if _, err := registerHTTPLimitFlags(flag.NewFlagSet("t", flag.ContinueOnError), env(map[string]string{"WPP_MCP_RATE": bad})); err == nil {
			t.Fatalf("WPP_MCP_RATE=%s accepted", bad)
		}
	}
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f, _ = registerHTTPLimitFlags(fs, env(nil))
	_ = fs.Parse([]string{"-mcp-rate", "-5"})
	if f.validate() == nil {
		t.Fatal("negative -mcp-rate accepted")
	}
}
