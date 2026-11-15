package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func TestWebhookFlags(t *testing.T) {
	env := map[string]string{
		"WPP_MCP_WEBHOOK_URL":          "https://hooks.example.com/wa",
		"WPP_MCP_WEBHOOK_SECRET":       "0123456789abcdef",
		"WPP_MCP_WEBHOOK_INCLUDE_TEXT": "1",
		"WPP_MCP_WEBHOOK_CHATS":        "447700000001@s.whatsapp.net, 123@g.us",
		"WPP_MCP_WEBHOOK_KEYWORDS":     "urgente,reunião",
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	w, err := registerWebhookFlags(fs, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"-webhook-keywords", "boleto"}); err != nil {
		t.Fatal(err)
	}
	cfg := w.config()
	if !cfg.Enabled() || !cfg.IncludeText || cfg.Secret != env["WPP_MCP_WEBHOOK_SECRET"] {
		t.Fatalf("config = %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.Chats, []string{"447700000001@s.whatsapp.net", "123@g.us"}) || !reflect.DeepEqual(cfg.Keywords, []string{"boleto"}) {
		t.Fatalf("lists = %v %v", cfg.Chats, cfg.Keywords)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	cfg.URL = "http://hooks.example.com/wa"
	if cfg.Validate() == nil {
		t.Error("plain HTTP to a public host accepted")
	}
	cfg.URL, cfg.Secret = "https://hooks.example.com/wa", ""
	if cfg.Validate() == nil {
		t.Error("a URL without a secret accepted")
	}

	fs = flag.NewFlagSet("serve", flag.ContinueOnError)
	if _, err := registerWebhookFlags(fs, func(k string) string {
		if k == "WPP_MCP_WEBHOOK_INCLUDE_TEXT" {
			return "maybe"
		}
		return ""
	}); err == nil {
		t.Error("a non-boolean WPP_MCP_WEBHOOK_INCLUDE_TEXT accepted")
	}
	if (&webhookFlags{}).config().Enabled() {
		t.Error("enabled without a URL")
	}
}
