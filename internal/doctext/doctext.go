// Package doctext extracts the text of document messages locally: PDFs with
// the pdftotext binary (poppler-utils) and plain-text formats directly.
//
// Nothing leaves the machine and nothing is written to disk: the decrypted
// document is piped to `pdftotext -q -enc UTF-8 -l <pages> - -` and the text
// is read back from its standard output. The subprocess runs without a
// shell, with a minimal environment, a timeout, an input size limit, a
// bounded output and one run at a time.
package doctext

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// DefaultTimeout bounds one extraction.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxBytes is the largest document handed to pdftotext.
	DefaultMaxBytes = 20 << 20
	// DefaultMaxOutput bounds the text kept; more is truncated.
	DefaultMaxOutput = 64 << 10
	// DefaultMaxPages bounds the PDF pages read.
	DefaultMaxPages = 30
	// maxPlainBytes is the largest plain-text document read directly.
	maxPlainBytes = 2 << 20
)

var (
	// ErrUnsupported means the document is neither a PDF nor plain text.
	ErrUnsupported = errors.New("document type is not supported for text extraction (PDF and plain-text formats are)")
	// ErrUnavailable means a PDF arrived but pdftotext is not installed.
	ErrUnavailable = errors.New("PDF text extraction is unavailable: the pdftotext binary (poppler-utils) was not found")
	// ErrTooLarge means the document exceeds the size limit.
	ErrTooLarge = errors.New("document is too large for text extraction")
	// ErrTimeout means pdftotext did not finish in time.
	ErrTimeout = errors.New("document text extraction timed out")
)

// Runner runs bin with args, feeding stdin and writing the process output
// to stdout and stderr. It is a seam for tests.
type Runner func(ctx context.Context, bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) error

// Engine extracts document text. The zero value is not usable; use New.
type Engine struct {
	bin       string
	run       Runner
	sema      chan struct{}
	timeout   time.Duration
	maxBytes  int
	maxOutput int
	maxPages  int
}

// New resolves pdftotext on PATH. A missing binary is not an error: plain
// text still works and PDFs return ErrUnavailable.
func New() *Engine {
	bin, _ := exec.LookPath("pdftotext")
	return newEngine(bin, execRunner)
}

// NewWithRunner takes bin as found and runs it with run. Tests use it.
func NewWithRunner(bin string, run Runner) *Engine { return newEngine(bin, run) }

func newEngine(bin string, run Runner) *Engine {
	return &Engine{bin: bin, run: run, sema: make(chan struct{}, 1), timeout: DefaultTimeout,
		maxBytes: DefaultMaxBytes, maxOutput: DefaultMaxOutput, maxPages: DefaultMaxPages}
}

// PDFAvailable reports whether pdftotext was found.
func (e *Engine) PDFAvailable() bool { return e != nil && e.bin != "" }

// MaxBytes returns the document size limit.
func (e *Engine) MaxBytes() int { return e.maxBytes }

// Result is extracted text.
type Result struct {
	Text      string
	Truncated bool
	Kind      string // "pdf" or "text"
}

// Kind classifies a document as "pdf", "text" or "" (unsupported) from its
// content and, for plain text, its file name.
func Kind(data []byte, filename string) string {
	if bytes.HasPrefix(data, []byte("%PDF-")) {
		return "pdf"
	}
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".txt", ".csv", ".tsv", ".md", ".json", ".log", ".xml", ".yaml", ".yml", ".ics", ".vcf", ".srt":
		if utf8.Valid(head(data, 4096)) && !bytes.ContainsRune(head(data, 4096), 0) {
			return "text"
		}
	}
	return ""
}

func head(b []byte, n int) []byte {
	if len(b) > n {
		b = b[:n]
		// Do not let a rune split at the cut make valid text look invalid.
		for i := 0; i < utf8.UTFMax && len(b) > 0 && !utf8.Valid(b); i++ {
			b = b[:len(b)-1]
		}
	}
	return b
}

// Extract returns the text of a PDF or plain-text document held in memory.
func (e *Engine) Extract(ctx context.Context, data []byte, filename string) (Result, error) {
	switch Kind(data, filename) {
	case "text":
		if len(data) > maxPlainBytes {
			return Result{}, fmt.Errorf("%w: %d MiB; the limit for plain text is %d MiB", ErrTooLarge, len(data)>>20, maxPlainBytes>>20)
		}
		text, truncated := bound(strings.ToValidUTF8(string(data), ""), e.maxOutput)
		return Result{Text: strings.TrimSpace(text), Truncated: truncated, Kind: "text"}, nil
	case "pdf":
		return e.extractPDF(ctx, data)
	}
	return Result{}, ErrUnsupported
}

func (e *Engine) extractPDF(ctx context.Context, data []byte) (Result, error) {
	if e.bin == "" {
		return Result{}, ErrUnavailable
	}
	if len(data) > e.maxBytes {
		return Result{}, fmt.Errorf("%w: %d MiB; the limit is %d MiB", ErrTooLarge, len(data)>>20, e.maxBytes>>20)
	}
	select {
	case e.sema <- struct{}{}:
		defer func() { <-e.sema }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	runCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	out := &boundedBuffer{max: e.maxOutput}
	errOut := &boundedBuffer{max: 4 << 10}
	args := []string{"-q", "-enc", "UTF-8", "-l", strconv.Itoa(e.maxPages), "-", "-"}
	err := e.run(runCtx, e.bin, args, bytes.NewReader(data), out, errOut)
	if runCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		return Result{}, fmt.Errorf("%w after %s", ErrTimeout, e.timeout)
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if err != nil {
		msg, _, _ := strings.Cut(strings.TrimSpace(errOut.String()), "\n")
		if msg != "" {
			return Result{}, fmt.Errorf("doctext: pdftotext failed: %v: %s", err, msg)
		}
		return Result{}, fmt.Errorf("doctext: pdftotext failed: %w", err)
	}
	text := strings.ReplaceAll(strings.ToValidUTF8(out.buf.String(), ""), "\f", "\n")
	return Result{Text: strings.TrimSpace(text), Truncated: out.truncated, Kind: "pdf"}, nil
}

// bound cuts s to at most n bytes on a rune boundary.
func bound(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s, true
}

// boundedBuffer keeps the first max bytes written and discards the rest
// without failing the write.
type boundedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room < len(p) {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) String() string { return b.buf.String() }

func execRunner(ctx context.Context, bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = []string{"LC_ALL=C.UTF-8"}
	cmd.Dir = os.TempDir() // a neutral working directory; nothing is written there
	cmd.WaitDelay = 2 * time.Second
	return cmd.Run()
}
