package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/murandido/mcp-wpp/internal/client"
	"github.com/murandido/mcp-wpp/internal/security"
	"github.com/murandido/mcp-wpp/internal/store"
	"github.com/murandido/mcp-wpp/internal/webhook"
)

// webhookFlags holds the serve flags for outgoing event webhooks.
type webhookFlags struct {
	url         string
	secret      string
	includeText bool
	chats       string
	keywords    string
}

// registerWebhookFlags adds the -webhook-* flags to fs, defaulting to their
// environment variables. An invalid WPP_MCP_WEBHOOK_INCLUDE_TEXT is an error.
func registerWebhookFlags(fs *flag.FlagSet, getenv func(string) string) (*webhookFlags, error) {
	w := &webhookFlags{}
	if v := getenv("WPP_MCP_WEBHOOK_INCLUDE_TEXT"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("WPP_MCP_WEBHOOK_INCLUDE_TEXT must be a boolean (for example, 1 or 0)")
		}
		w.includeText = b
	}
	fs.StringVar(&w.url, "webhook-url", getenv("WPP_MCP_WEBHOOK_URL"), "POST live incoming messages from allowed chats to this URL; https unless the host is loopback or private (env WPP_MCP_WEBHOOK_URL)")
	fs.StringVar(&w.secret, "webhook-secret", getenv("WPP_MCP_WEBHOOK_SECRET"), "HMAC-SHA256 signing secret, required with -webhook-url (env WPP_MCP_WEBHOOK_SECRET)")
	fs.BoolVar(&w.includeText, "webhook-include-text", w.includeText, "include message text and captions in webhook payloads: they then leave this machine (env WPP_MCP_WEBHOOK_INCLUDE_TEXT)")
	fs.StringVar(&w.chats, "webhook-chats", getenv("WPP_MCP_WEBHOOK_CHATS"), "comma-separated chat JIDs or phone numbers to report (default: every allowed chat; env WPP_MCP_WEBHOOK_CHATS)")
	fs.StringVar(&w.keywords, "webhook-keywords", getenv("WPP_MCP_WEBHOOK_KEYWORDS"), "comma-separated words; report only messages containing one (case- and accent-insensitive; env WPP_MCP_WEBHOOK_KEYWORDS)")
	return w, nil
}

// config returns the webhook configuration; Enabled is false without a URL.
func (w *webhookFlags) config() webhook.Config {
	return webhook.Config{
		URL:         w.url,
		Secret:      w.secret,
		IncludeText: w.includeText,
		Chats:       webhook.ParseList(w.chats),
		Keywords:    webhook.ParseList(w.keywords),
	}
}

// startWebhook validates the configuration, hooks the dispatcher to c's live
// incoming messages and starts delivery. It is a no-op without a URL. Call it
// before the event handler is installed.
func startWebhook(ctx context.Context, cfg webhook.Config, c *client.Client, st *store.Store, redactor *security.Redactor) error {
	if !cfg.Enabled() {
		return nil
	}
	d, err := webhook.New(cfg, webhook.Options{
		Allowed:   st.ChatAllowed,
		Logger:    client.NewStderrLogger("Webhook", "INFO", false),
		RedactJID: redactor.JID,
	})
	if err != nil {
		return err
	}
	c.OnIncomingMessage(func(m client.IncomingMessage) {
		d.Enqueue(webhook.Message(m))
	})
	go d.Run(ctx)
	text := "without message text"
	if cfg.IncludeText {
		text = "WITH message text (it leaves this machine)"
	}
	fmt.Fprintf(os.Stderr, "webhooks: live incoming messages from allowed chats go to %s, %s\n", d.Host(), text)
	return nil
}
