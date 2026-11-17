package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png" // decode PNG images and documents
	"strings"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp" // decode stickers and WebP images

	"github.com/murandido/mcp-wpp/internal/ocr"
	"github.com/murandido/mcp-wpp/internal/store"
)

// Media enrichment for chat notes: for each media message, what can be
// learned on this machine. Audio is transcribed only by a local or
// private-network service; images and stickers are downscaled for the MCP
// client to look at and, with -ocr, read by Tesseract; documents are read
// with pdftotext or directly. Everything is decrypted in memory and nothing
// leaves the machine except the result returned to the MCP client.

// NotesMediaLimits bounds the work one get_chat_notes call may do.
type NotesMediaLimits struct {
	Images     int // images and stickers downloaded and returned
	Transcribe int // audio transcribed now (cached transcripts are free)
	Documents  int // documents read now (cached text is free)
}

// DefaultNotesMediaLimits are the per-call limits.
var DefaultNotesMediaLimits = NotesMediaLimits{Images: 8, Transcribe: 10, Documents: 5}

// MaxNoteImageSide is the longest side of an image returned for notes.
const MaxNoteImageSide = 768

// maxNoteImageInput bounds the image decoded for a preview.
const maxNoteImageInput = 16 << 20

// NoteMedia is what is known about one media message.
type NoteMedia struct {
	// Text is a transcript, OCR text or document text; Label says which.
	Text  string
	Label string
	// Image is a JPEG preview for the MCP client to describe.
	Image []byte
	// Pending means the per-call budget ran out: the next call does it.
	Pending bool
	// Note explains a missing item ("expired on WhatsApp's servers", ...).
	Note string
}

// EnrichNotesMedia returns what can be learned about the media messages in
// msgs, keyed by message ID, within lim.
func (c *Client) EnrichNotesMedia(ctx context.Context, msgs []store.Message, lim NotesMediaLimits) map[string]NoteMedia {
	out := map[string]NoteMedia{}
	for _, m := range msgs {
		if ctx.Err() != nil {
			break
		}
		var nm NoteMedia
		switch m.MediaType {
		case "audio":
			nm = c.noteAudio(ctx, m, &lim)
		case "image", "sticker":
			nm = c.noteImage(ctx, m, &lim)
		case "document":
			nm = c.noteDocument(ctx, m, &lim)
		case "video":
			nm = NoteMedia{Note: "video: only its caption is available"}
		default:
			continue
		}
		out[m.ID] = nm
		if nm.Pending {
			// Stop at the first item over budget: the caller ends the page
			// before it, so the notes' watermark never skips it.
			break
		}
	}
	return out
}

// TranscriptionIsLocal reports whether transcription is configured and its
// service is on this machine or the private network (not a remote API), so
// it may run without an explicit request.
func (c *Client) TranscriptionIsLocal() bool {
	return c.transcribeCfg.Enabled() && !c.transcribeCfg.AllowRemote
}

func (c *Client) noteAudio(ctx context.Context, m store.Message, lim *NotesMediaLimits) NoteMedia {
	if t, err := c.store.GetTranscript(ctx, m.ID, m.ChatJID); err == nil && t != nil {
		return NoteMedia{Text: t.Text, Label: "transcript"}
	}
	if !c.TranscriptionIsLocal() {
		return NoteMedia{Note: "audio not transcribed (no local transcription service configured)"}
	}
	if lim.Transcribe <= 0 {
		return NoteMedia{Pending: true}
	}
	lim.Transcribe--
	t, _, err := c.TranscribeAudio(ctx, m.ID, m.ChatJID, "")
	if err != nil {
		return NoteMedia{Note: "audio not transcribed: " + shortReason(err)}
	}
	return NoteMedia{Text: t.Text, Label: "transcript"}
}

func (c *Client) noteImage(ctx context.Context, m store.Message, lim *NotesMediaLimits) NoteMedia {
	if lim.Images <= 0 {
		return NoteMedia{Pending: true}
	}
	lim.Images--
	data, _, err := c.mediaBytes(ctx, m, maxNoteImageInput)
	if err != nil {
		return NoteMedia{Note: m.MediaType + " unavailable: " + shortReason(err)}
	}
	nm := NoteMedia{}
	if prev, err := previewJPEG(data, MaxNoteImageSide); err == nil {
		nm.Image = prev
	} else {
		nm.Note = m.MediaType + " could not be decoded (animated stickers are not previewed)"
	}
	if c.OCRAvailable() && m.MediaType == "image" {
		if t, _, err := c.ExtractImageText(ctx, m.ID, m.ChatJID); err == nil && t.Text != "" {
			nm.Text, nm.Label = t.Text, "text in image"
		}
	}
	return nm
}

func (c *Client) noteDocument(ctx context.Context, m store.Message, lim *NotesMediaLimits) NoteMedia {
	if t, err := c.store.GetDocumentText(ctx, m.ID, m.ChatJID); err == nil && t != nil {
		return NoteMedia{Text: t.Text, Label: "document text"}
	}
	if lim.Documents <= 0 {
		return NoteMedia{Pending: true}
	}
	lim.Documents--
	data, filename, err := c.mediaBytes(ctx, m, c.docs.MaxBytes())
	if err != nil {
		return NoteMedia{Note: "document unavailable: " + shortReason(err)}
	}
	if ocr.ImageKind(data) != "" {
		// An image sent as a document: preview it like a photo.
		nm := NoteMedia{}
		if prev, err := previewJPEG(data, MaxNoteImageSide); err == nil {
			nm.Image = prev
		}
		return nm
	}
	res, err := c.docs.Extract(ctx, data, filename)
	if err != nil {
		return NoteMedia{Note: "document text not extracted: " + shortReason(err)}
	}
	if err := c.store.PutDocumentText(ctx, store.DocumentText{MessageID: m.ID, ChatJID: m.ChatJID, Text: res.Text, Kind: res.Kind, Truncated: res.Truncated}); err != nil {
		c.log.Warnf("cache document text: %v", err)
	}
	return NoteMedia{Text: res.Text, Label: "document text"}
}

// mediaBytes downloads (or reads from the sealed cache) a message's media
// and returns the plaintext in memory. It never asks the phone to re-upload
// expired media.
func (c *Client) mediaBytes(ctx context.Context, m store.Message, maxBytes int) ([]byte, string, error) {
	_, filename, _, _, _, _, _, fileLength, err := c.store.GetMediaInfo(m.ID, m.ChatJID)
	if err != nil {
		return nil, "", fmt.Errorf("find message: %w", err)
	}
	if maxBytes > 0 && fileLength > uint64(maxBytes) {
		return nil, "", fmt.Errorf("file is %d MiB; the limit is %d MiB", fileLength>>20, maxBytes>>20)
	}
	dl := c.Download(ctx, m.ID, m.ChatJID, "")
	if !dl.Success {
		return nil, "", errors.New(dl.Message)
	}
	data, err := c.ReadMedia(dl.Path)
	return data, filename, err
}

// previewJPEG decodes a JPEG, PNG or still WebP image and re-encodes it as a
// JPEG whose longest side is at most maxSide.
func previewJPEG(data []byte, maxSide int) ([]byte, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	// Refuse decompression bombs before allocating the pixels.
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > 50_000_000 {
		return nil, fmt.Errorf("image is %dx%d", cfg.Width, cfg.Height)
	}
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w > maxSide || h > maxSide {
		if w >= h {
			h = h * maxSide / w
			w = maxSide
		} else {
			w = w * maxSide / h
			h = maxSide
		}
	}
	dst := image.NewRGBA(image.Rect(0, 0, max(w, 1), max(h, 1)))
	// White background, so transparent stickers stay readable as JPEG.
	draw.Draw(dst, dst.Bounds(), image.White, image.Point{}, draw.Src)
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, b, draw.Over, nil)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 80}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// shortReason keeps the first line of an error, bounded, for a note.
func shortReason(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160]) + "…"
	}
	return s
}
