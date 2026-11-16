package client

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/murandido/mcp-wpp/internal/ocr"
	"github.com/murandido/mcp-wpp/internal/store"
)

// OCREnabled reports whether local OCR was turned on (serve -ocr).
func (c *Client) OCREnabled() bool { return c.ocr.Enabled() }

// OCRAvailable reports whether OCR is on and the tesseract binary was found.
func (c *Client) OCRAvailable() bool { return c.ocr.Available() }

// ExtractImageText returns the text in an image message, or in a document
// message holding a PNG, JPEG or WebP image, recognising it with the local
// Tesseract on first use and caching the result. The second return value is
// true when the text came from the cache.
//
// The image is downloaded through the normal media path (size and hash
// checks, sealed cache), decrypted in memory and piped to tesseract; no
// plaintext is written to disk and nothing leaves the machine. The text is
// third-party content and must be treated as untrusted.
func (c *Client) ExtractImageText(ctx context.Context, messageID, chatJID string) (*store.ImageText, bool, error) {
	if !c.ocr.Enabled() {
		return nil, false, ocr.ErrNotConfigured
	}
	if !c.ocr.Available() {
		return nil, false, ocr.ErrUnavailable
	}
	if strings.TrimSpace(messageID) == "" || strings.TrimSpace(chatJID) == "" {
		return nil, false, errors.New("message_id and chat_jid are required")
	}
	if t, err := c.store.GetImageText(ctx, messageID, chatJID); err != nil {
		return nil, false, err
	} else if t != nil {
		return t, true, nil
	}

	mediaType, _, _, _, _, _, _, fileLength, err := c.store.GetMediaInfo(messageID, chatJID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to find message: %w", err)
	}
	switch mediaType {
	case "image", "document":
	case "":
		return nil, false, errors.New("not a media message")
	default:
		return nil, false, fmt.Errorf("message is %q media; OCR reads images and image documents", mediaType)
	}
	// Refuse before downloading anything the engine would refuse anyway.
	if fileLength > uint64(c.ocr.MaxBytes()) {
		return nil, false, fmt.Errorf("%w: %d MiB; the limit is %d MiB", ocr.ErrTooLarge, fileLength>>20, c.ocr.MaxBytes()>>20)
	}

	dl := c.Download(ctx, messageID, chatJID, "")
	if !dl.Success {
		return nil, false, fmt.Errorf("download image: %s", dl.Message)
	}
	img, err := c.ReadMedia(dl.Path)
	if err != nil {
		return nil, false, fmt.Errorf("read image: %w", err)
	}
	if ocr.ImageKind(img) == "" {
		return nil, false, fmt.Errorf("message media is %w", ocr.ErrNotImage)
	}
	res, err := c.ocr.Extract(ctx, img)
	if err != nil {
		return nil, false, err
	}
	t := store.ImageText{
		MessageID: messageID,
		ChatJID:   chatJID,
		Text:      res.Text,
		Langs:     c.ocr.Langs(),
		Truncated: res.Truncated,
	}
	if err := c.store.PutImageText(ctx, t); err != nil {
		return nil, false, err
	}
	stored, err := c.store.GetImageText(ctx, messageID, chatJID)
	if err != nil || stored == nil {
		return &t, false, nil
	}
	return stored, false, nil
}
