package doctext

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// minimalPDF builds a one-page PDF that shows text, with a correct xref
// table, so the real pdftotext can read it.
func minimalPDF(text string) []byte {
	stream := fmt.Sprintf("BT /F1 24 Tf 72 720 Td (%s) Tj ET", text)
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

func TestKind(t *testing.T) {
	for _, c := range []struct {
		data []byte
		name string
		want string
	}{
		{minimalPDF("x"), "anything.bin", "pdf"},
		{[]byte("a,b\n1,2\n"), "list.CSV", "text"},
		{[]byte("hello"), "notes.txt", "text"},
		{[]byte("hello"), "report.docx", ""},
		{[]byte{0xff, 0xfe, 0x00, 0x41}, "bad.txt", ""},
		{[]byte("MZ\x90\x00binary"), "x.txt", ""},
	} {
		if got := Kind(c.data, c.name); got != c.want {
			t.Errorf("Kind(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestExtract_PlainTextIsBounded(t *testing.T) {
	e := NewWithRunner("", nil)
	res, err := e.Extract(context.Background(), []byte("  olá mundo  "), "a.txt")
	if err != nil || res.Text != "olá mundo" || res.Kind != "text" || res.Truncated {
		t.Fatalf("small: %+v %v", res, err)
	}
	big := strings.Repeat("ã", DefaultMaxOutput) // 2 bytes each
	res, err = e.Extract(context.Background(), []byte(big), "a.txt")
	if err != nil || !res.Truncated || len(res.Text) > DefaultMaxOutput || !strings.HasPrefix(big, res.Text) {
		t.Fatalf("big: truncated=%v len=%d %v", res.Truncated, len(res.Text), err)
	}
	if _, err := e.Extract(context.Background(), []byte("x"), "a.docx"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("docx: %v", err)
	}
}

func TestExtract_PDFWithFakeRunner(t *testing.T) {
	var gotArgs []string
	var gotIn []byte
	run := func(_ context.Context, _ string, args []string, stdin io.Reader, stdout, _ io.Writer) error {
		gotArgs = args
		gotIn, _ = io.ReadAll(stdin)
		_, _ = stdout.Write([]byte("page one\fpage two\n"))
		return nil
	}
	pdf := minimalPDF("x")
	res, err := NewWithRunner("pdftotext", run).Extract(context.Background(), pdf, "doc.pdf")
	if err != nil || res.Text != "page one\npage two" || res.Kind != "pdf" {
		t.Fatalf("pdf: %+v %v", res, err)
	}
	if !bytes.Equal(gotIn, pdf) || strings.Join(gotArgs, " ") != "-q -enc UTF-8 -l 30 - -" {
		t.Fatalf("pdftotext got args %v and %d bytes on stdin", gotArgs, len(gotIn))
	}
}

func TestExtract_PDFLimits(t *testing.T) {
	if _, err := NewWithRunner("", nil).Extract(context.Background(), minimalPDF("x"), "a.pdf"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no binary: %v", err)
	}
	e := NewWithRunner("pdftotext", func(ctx context.Context, _ string, _ []string, _ io.Reader, _, _ io.Writer) error {
		<-ctx.Done()
		return ctx.Err()
	})
	e.timeout = 20 * time.Millisecond
	if _, err := e.Extract(context.Background(), minimalPDF("x"), "a.pdf"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("timeout: %v", err)
	}
	e.maxBytes = 10
	if _, err := e.Extract(context.Background(), minimalPDF("x"), "a.pdf"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size: %v", err)
	}
	out := NewWithRunner("pdftotext", func(_ context.Context, _ string, _ []string, _ io.Reader, stdout, _ io.Writer) error {
		_, _ = stdout.Write(bytes.Repeat([]byte("a"), DefaultMaxOutput*2))
		return nil
	})
	if res, err := out.Extract(context.Background(), minimalPDF("x"), "a.pdf"); err != nil || !res.Truncated || len(res.Text) != DefaultMaxOutput {
		t.Fatalf("output bound: %v %d %v", res.Truncated, len(res.Text), err)
	}
}

// The real pdftotext reads the PDF from stdin. Required in the container
// stage (WPP_MCP_REQUIRE_PDFTOTEXT=1), skipped elsewhere when missing.
func TestExtract_RealPDFToText(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		if os.Getenv("WPP_MCP_REQUIRE_PDFTOTEXT") == "1" {
			t.Fatal("pdftotext is required here (WPP_MCP_REQUIRE_PDFTOTEXT=1) but was not found")
		}
		t.Skip("pdftotext not installed")
	}
	res, err := New().Extract(context.Background(), minimalPDF("Contrato assinado em maio"), "c.pdf")
	if err != nil || !strings.Contains(res.Text, "Contrato assinado em maio") {
		t.Fatalf("real pdftotext: %+v %v", res, err)
	}
}
