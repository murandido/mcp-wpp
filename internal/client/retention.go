package client

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PurgeOlderThan deletes cached messages, transcripts and media older than
// age. It returns how many messages were removed.
func (c *Client) PurgeOlderThan(ctx context.Context, age time.Duration) (int, error) {
	purged, err := c.store.PurgeBefore(ctx, time.Now().UTC().Add(-age))
	if err != nil {
		return 0, err
	}
	root, err := filepath.Abs(c.store.Dir())
	if err != nil {
		return len(purged), err
	}
	for _, p := range purged {
		// Same layout as Download: <store>/<chat>/<hex(message id)>/.
		chatDir := filepath.Clean(filepath.Join(root, strings.ReplaceAll(p.ChatJID, ":", "_")))
		if !strings.HasPrefix(chatDir, root+string(filepath.Separator)) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(chatDir, hex.EncodeToString([]byte(p.ID))))
		_ = os.Remove(chatDir) // only succeeds once empty
	}
	return len(purged), nil
}

// RunRetention purges every hour until ctx ends, and vacuums after a purge
// at most once a day so deleted pages do not linger in the file.
func (c *Client) RunRetention(ctx context.Context, age time.Duration) {
	var lastVacuum time.Time
	run := func() {
		n, err := c.PurgeOlderThan(ctx, age)
		if err != nil {
			c.log.Warnf("retention: %s", c.redactor.Err(err))
			return
		}
		if n == 0 {
			return
		}
		c.log.Infof("retention: removed %d message(s) older than %s", n, age)
		if time.Since(lastVacuum) > 24*time.Hour {
			if err := c.store.Vacuum(ctx); err != nil {
				c.log.Warnf("retention: vacuum: %s", c.redactor.Err(err))
			}
			lastVacuum = time.Now()
		}
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
