package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"

	"github.com/murandido/mcp-wpp/internal/crypto"
	"github.com/murandido/mcp-wpp/internal/doctext"
	"github.com/murandido/mcp-wpp/internal/store"
)

const notesJID = "447700000124@s.whatsapp.net"

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		img.Set(x, x%h, color.RGBA{200, 30, 30, 255})
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type notesMsg struct {
	id, mediaType, filename string
	payload                 []byte
}

// notesMediaFixture stores media messages a minute apart; downloads return
// each message's payload by its file hash, and pdftotext is stubbed.
func notesMediaFixture(t *testing.T, msgs []notesMsg) (*Client, *store.Store, []store.Message) {
	t.Helper()
	t.Chdir(t.TempDir())
	s, err := store.Open("./store")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if err := s.StoreChat(notesJID, "Test", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	byHash := map[string][]byte{}
	base := time.Now().UTC().Add(-time.Hour)
	var out []store.Message
	for i, m := range msgs {
		digest := sha256.Sum256(m.payload)
		byHash[string(digest[:])] = m.payload
		sm := store.Message{ID: m.id, ChatJID: notesJID, Sender: notesJID, Timestamp: base.Add(time.Duration(i) * time.Minute),
			MediaType: m.mediaType, Filename: m.filename, URL: "https://example.invalid/m", DirectPath: "/m"}
		if err := s.StoreMessage(ctx, sm, []byte{1}, digest[:], []byte{2}, uint64(len(m.payload))); err != nil {
			t.Fatal(err)
		}
		out = append(out, sm)
	}
	c := newClientWithStore(t, s)
	// Encryption at rest: the media cache is sealed, as in production.
	mc, err := crypto.NewMediaCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.media = mc
	c.downloadMedia = func(_ context.Context, d whatsmeow.DownloadableMessage) ([]byte, error) {
		if p, ok := byHash[string(d.GetFileSHA256())]; ok {
			return p, nil
		}
		return nil, fmt.Errorf("media expired")
	}
	c.docs = doctext.NewWithRunner("pdftotext", func(_ context.Context, _ string, _ []string, in io.Reader, out, _ io.Writer) error {
		b, _ := io.ReadAll(in)
		_, _ = fmt.Fprintf(out, "PDF with %d bytes: Contrato assinado", len(b))
		return nil
	})
	return c, s, out
}

func TestEnrichNotesMedia_ByKind(t *testing.T) {
	big := testPNG(t, 2000, 1000)
	pdf := []byte("%PDF-1.4 fake")
	c, s, msgs := notesMediaFixture(t, []notesMsg{
		{"img", "image", "", big},
		{"stk", "sticker", "", testPNG(t, 512, 512)},
		{"voice", "audio", "", []byte("OggS fake")},
		{"voice2", "audio", "", []byte("OggS other")},
		{"doc", "document", "contrato.pdf", pdf},
		{"txt", "document", "lista.txt", []byte("pão\nleite\n")},
		{"vid", "video", "", []byte("mp4")},
	})
	ctx := context.Background()
	if err := s.PutTranscript(ctx, store.Transcript{MessageID: "voice", ChatJID: notesJID, Text: "chego às 5"}); err != nil {
		t.Fatal(err)
	}
	got := c.EnrichNotesMedia(ctx, msgs, DefaultNotesMediaLimits)

	img := got["img"]
	cfg, format, err := image.DecodeConfig(bytes.NewReader(img.Image))
	if err != nil || format != "jpeg" || cfg.Width != MaxNoteImageSide || cfg.Height != MaxNoteImageSide/2 {
		t.Fatalf("image preview: %v %s %dx%d", err, format, cfg.Width, cfg.Height)
	}
	if got["stk"].Image == nil {
		t.Fatalf("sticker preview missing: %+v", got["stk"])
	}
	if v := got["voice"]; v.Text != "chego às 5" || v.Label != "transcript" {
		t.Fatalf("cached transcript: %+v", v)
	}
	// No local transcription service: a note, no upload anywhere.
	if v := got["voice2"]; v.Text != "" || !strings.Contains(v.Note, "no local transcription") {
		t.Fatalf("untranscribed audio: %+v", v)
	}
	if d := got["doc"]; d.Label != "document text" || !strings.Contains(d.Text, "Contrato assinado") || !strings.Contains(d.Text, fmt.Sprint(len(pdf))) {
		t.Fatalf("pdf: %+v", d)
	}
	if d := got["txt"]; d.Text != "pão\nleite" {
		t.Fatalf("text document: %+v", d)
	}
	if v := got["vid"]; !strings.Contains(v.Note, "caption") {
		t.Fatalf("video: %+v", v)
	}
	// Document text is cached in the encrypted store.
	if dt, _ := s.GetDocumentText(ctx, "doc", notesJID); dt == nil || dt.Kind != "pdf" {
		t.Fatalf("document text not cached: %+v", dt)
	}
	// Nothing decrypted reaches the disk: the PNG, PDF and text bytes appear
	// in no media file (the database's own encryption is tested elsewhere).
	sealed := 0
	_ = filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.Contains(filepath.Base(p), ".db") {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, big[:64]) || bytes.Contains(b, pdf) || bytes.Contains(b, []byte("pão\nleite")) {
			t.Errorf("plaintext media in %s", p)
		}
		if crypto.IsSealed(b) {
			sealed++
		}
		return nil
	})
	if sealed < 4 {
		t.Fatalf("only %d sealed media files", sealed)
	}
}

// When the budget runs out, enrichment stops at that item and marks it
// pending, so the caller can end the page before it.
func TestEnrichNotesMedia_StopsAtBudget(t *testing.T) {
	c, _, msgs := notesMediaFixture(t, []notesMsg{
		{"a", "image", "", testPNG(t, 10, 10)},
		{"b", "image", "", testPNG(t, 11, 10)},
		{"c", "image", "", testPNG(t, 12, 10)},
	})
	got := c.EnrichNotesMedia(context.Background(), msgs, NotesMediaLimits{Images: 1})
	if got["a"].Image == nil || !got["b"].Pending {
		t.Fatalf("budget: %+v", got)
	}
	if _, ok := got["c"]; ok {
		t.Fatal("enrichment continued past the first pending item")
	}
}

func TestEnrichNotesMedia_ExpiredMedia(t *testing.T) {
	c, _, msgs := notesMediaFixture(t, []notesMsg{{"x", "image", "", testPNG(t, 10, 10)}})
	c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) {
		return nil, whatsmeow.ErrMediaDownloadFailedWith404
	}
	got := c.EnrichNotesMedia(context.Background(), msgs, DefaultNotesMediaLimits)
	if got["x"].Image != nil || !strings.Contains(got["x"].Note, "unavailable") {
		t.Fatalf("expired: %+v", got["x"])
	}
}

func TestPreviewJPEG(t *testing.T) {
	out, err := previewJPEG(testPNG(t, 300, 900), 768)
	if err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(out))
	if err != nil || img.Bounds().Dx() != 256 || img.Bounds().Dy() != 768 {
		t.Fatalf("portrait: %v %v", img.Bounds(), err)
	}
	if out, _ := previewJPEG(testPNG(t, 40, 20), 768); out == nil {
		t.Fatal("small image not re-encoded")
	}
	if _, err := previewJPEG([]byte("not an image"), 768); err == nil {
		t.Fatal("garbage decoded")
	}
}
