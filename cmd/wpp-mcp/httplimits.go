package main

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/murandido/mcp-wpp/internal/daemon"
)

// httpLimitFlags are serve's HTTP rate limits.
type httpLimitFlags struct {
	mcpRate       int
	authFailLimit int
}

// registerHTTPLimitFlags adds -mcp-rate and -auth-fail-limit. Environment
// values are defaults the flags override.
func registerHTTPLimitFlags(fs *flag.FlagSet, getenv func(string) string) (*httpLimitFlags, error) {
	f := &httpLimitFlags{mcpRate: daemon.DefaultMCPRate, authFailLimit: daemon.DefaultAuthFailLimit}
	for _, e := range []struct {
		env string
		dst *int
	}{{"WPP_MCP_RATE", &f.mcpRate}, {"WPP_MCP_AUTH_FAIL_LIMIT", &f.authFailLimit}} {
		if v := getenv(e.env); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("%s must be a non-negative integer", e.env)
			}
			*e.dst = n
		}
	}
	fs.IntVar(&f.mcpRate, "mcp-rate", f.mcpRate, "per client token, the /mcp requests allowed per minute (burst of half that); the operator token is exempt; 0 disables (env WPP_MCP_RATE)")
	fs.IntVar(&f.authFailLimit, "auth-fail-limit", f.authFailLimit, "failed bearer attempts per client IP per minute before a 5-minute lock-out (429); 0 disables (env WPP_MCP_AUTH_FAIL_LIMIT)")
	return f, nil
}

func (f *httpLimitFlags) validate() error {
	if f.mcpRate < 0 {
		return fmt.Errorf("-mcp-rate must be 0 or more")
	}
	if f.authFailLimit < 0 {
		return fmt.Errorf("-auth-fail-limit must be 0 or more")
	}
	return nil
}

// apply copies the limits into the daemon configuration.
func (f *httpLimitFlags) apply(cfg *daemon.Config) {
	cfg.MCPRate = f.mcpRate
	cfg.AuthFailLimit = f.authFailLimit
}
