package store

import (
	"context"
	"testing"
)

func TestImageTexts_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec(imageTextsSchema); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := s.GetImageText(ctx, "m1", "c1"); err != nil || got != nil {
		t.Fatalf("missing: %+v %v", got, err)
	}
	if err := s.PutImageText(ctx, ImageText{MessageID: "m1", ChatJID: "c1", Text: "PROMOÇÃO", Langs: "por+eng", Truncated: true}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetImageText(ctx, "m1", "c1")
	if err != nil || got == nil || got.Text != "PROMOÇÃO" || got.Langs != "por+eng" || !got.Truncated || got.CreatedAt.IsZero() {
		t.Fatalf("got %+v %v", got, err)
	}
	_ = s.PutImageText(ctx, ImageText{MessageID: "m1", ChatJID: "c1", Text: "novo"})
	_ = s.PutImageText(ctx, ImageText{MessageID: "m1", ChatJID: "c2", Text: "outro"})
	if g, _ := s.GetImageText(ctx, "m1", "c1"); g.Text != "novo" || g.Truncated {
		t.Fatalf("not replaced: %+v", g)
	}
	if g, _ := s.GetImageText(ctx, "m1", "c2"); g.Text != "outro" {
		t.Fatalf("chats not independent: %+v", g)
	}
}

func TestDocumentTexts_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec(documentTextsSchema); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := s.GetDocumentText(ctx, "m1", "c1"); err != nil || got != nil {
		t.Fatalf("missing: %+v %v", got, err)
	}
	if err := s.PutDocumentText(ctx, DocumentText{MessageID: "m1", ChatJID: "c1", Text: "Contrato", Kind: "pdf", Truncated: true}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDocumentText(ctx, "m1", "c1")
	if err != nil || got == nil || got.Text != "Contrato" || got.Kind != "pdf" || !got.Truncated || got.CreatedAt.IsZero() {
		t.Fatalf("got %+v %v", got, err)
	}
	_ = s.PutDocumentText(ctx, DocumentText{MessageID: "m1", ChatJID: "c1", Text: "novo", Kind: "text"})
	if g, _ := s.GetDocumentText(ctx, "m1", "c1"); g.Text != "novo" || g.Truncated || g.Kind != "text" {
		t.Fatalf("not replaced: %+v", g)
	}
}
