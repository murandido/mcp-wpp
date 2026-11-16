// Package ocr extracts text from images with a local Tesseract binary.
//
// Nothing leaves the machine and nothing is written to disk: the decrypted
// image is piped to `tesseract stdin stdout -l <langs>` and the text is read
// back from its standard output. The subprocess runs without a shell, with a
// minimal environment, a timeout, an input size limit, a bounded output and
// at most MaxConcurrent runs at a time.
//
// The feature is opt-in (serve -ocr, env WPP_MCP_OCR).
package ocr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultLangs is the Tesseract language list used when none is set.
	DefaultLangs = "por+eng"
	// DefaultTimeout bounds one recognition run.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxBytes is the largest image handed to Tesseract.
	DefaultMaxBytes = 20 << 20
	// DefaultMaxOutput bounds the text read back; more is truncated.
	DefaultMaxOutput = 256 << 10
	// DefaultMaxConcurrent is how many recognitions may run at once.
	DefaultMaxConcurrent = 2
	// maxStderr bounds the diagnostic output kept from a failed run.
	maxStderr = 4 << 10
)

var (
	// ErrNotConfigured means OCR was not enabled.
	ErrNotConfigured = errors.New("OCR is not enabled: start the daemon with -ocr (env WPP_MCP_OCR=1)")
	// ErrUnavailable means OCR is enabled but the tesseract binary is missing.
	ErrUnavailable = errors.New("OCR is unavailable: the tesseract binary was not found on this machine")
	// ErrTooLarge means the image exceeds the size limit.
	ErrTooLarge = errors.New("image is too large for OCR")
	// ErrTimeout means Tesseract did not finish in time.
	ErrTimeout = errors.New("OCR timed out")
	// ErrNotImage means the payload is not a PNG, JPEG or WebP image.
	ErrNotImage = errors.New("not a PNG, JPEG or WebP image")
)

// langsRE accepts Tesseract language codes joined by '+', e.g. por+eng or
// chi_sim. It keeps anything that looks like a flag off the command line.
var langsRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{1,31}(\+[A-Za-z][A-Za-z0-9_]{1,31}){0,7}$`)

// ValidLangs reports whether langs is a well-formed Tesseract language list.
func ValidLangs(langs string) bool { return langsRE.MatchString(langs) }

// Config configures an Engine. Zero values take the defaults.
type Config struct {
	Enabled       bool
	Langs         string
	Binary        string // name or path of the binary; default "tesseract"
	Timeout       time.Duration
	MaxBytes      int
	MaxOutput     int
	MaxConcurrent int
}

// Runner runs bin with args, feeding stdin and writing the process output
// to stdout and stderr. It is a seam for tests; the default is execRunner.
type Runner func(ctx context.Context, bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) error

// Engine runs OCR. A nil Engine is disabled.
type Engine struct {
	cfg  Config
	bin  string // resolved absolute path; empty when not found
	run  Runner
	sema chan struct{}
}

// New builds an Engine from cfg, resolving the binary on PATH. A missing
// binary is not an error: Available reports false and Extract returns
// ErrUnavailable, so the daemon still starts.
func New(cfg Config) (*Engine, error) {
	return newEngine(cfg, exec.LookPath, execRunner)
}

// NewWithRunner is New with an injected runner and a binary path that is
// taken as found. Tests use it instead of a real tesseract.
func NewWithRunner(cfg Config, run Runner) (*Engine, error) {
	return newEngine(cfg, func(name string) (string, error) { return name, nil }, run)
}

func newEngine(cfg Config, lookPath func(string) (string, error), run Runner) (*Engine, error) {
	if cfg.Langs == "" {
		cfg.Langs = DefaultLangs
	}
	if !ValidLangs(cfg.Langs) {
		return nil, fmt.Errorf("ocr: invalid language list %q (expected codes joined by '+', e.g. por+eng)", cfg.Langs)
	}
	if cfg.Binary == "" {
		cfg.Binary = "tesseract"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxOutput <= 0 {
		cfg.MaxOutput = DefaultMaxOutput
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = DefaultMaxConcurrent
	}
	e := &Engine{cfg: cfg, run: run, sema: make(chan struct{}, cfg.MaxConcurrent)}
	if cfg.Enabled {
		if p, err := lookPath(cfg.Binary); err == nil {
			e.bin = p
		}
	}
	return e, nil
}

// Enabled reports whether OCR was turned on.
func (e *Engine) Enabled() bool { return e != nil && e.cfg.Enabled }

// Available reports whether OCR is on and the binary was found.
func (e *Engine) Available() bool { return e.Enabled() && e.bin != "" }

// Langs returns the configured language list.
func (e *Engine) Langs() string {
	if e == nil {
		return ""
	}
	return e.cfg.Langs
}

// MaxBytes returns the image size limit.
func (e *Engine) MaxBytes() int {
	if e == nil {
		return DefaultMaxBytes
	}
	return e.cfg.MaxBytes
}

// Result is the outcome of one recognition.
type Result struct {
	Text      string
	Truncated bool
}

// Extract recognises the text in img. img must be a PNG, JPEG or WebP image
// held in memory; it is passed to Tesseract on standard input.
func (e *Engine) Extract(ctx context.Context, img []byte) (Result, error) {
	if !e.Enabled() {
		return Result{}, ErrNotConfigured
	}
	if e.bin == "" {
		return Result{}, ErrUnavailable
	}
	if len(img) > e.cfg.MaxBytes {
		return Result{}, fmt.Errorf("%w: %d MiB; the limit is %d MiB", ErrTooLarge, len(img)>>20, e.cfg.MaxBytes>>20)
	}
	if ImageKind(img) == "" {
		return Result{}, ErrNotImage
	}

	select {
	case e.sema <- struct{}{}:
		defer func() { <-e.sema }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}

	runCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	out := &boundedBuffer{max: e.cfg.MaxOutput}
	errOut := &boundedBuffer{max: maxStderr}
	args := []string{"stdin", "stdout", "-l", e.cfg.Langs}
	err := e.run(runCtx, e.bin, args, bytes.NewReader(img), out, errOut)
	if runCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		return Result{}, fmt.Errorf("%w after %s", ErrTimeout, e.cfg.Timeout)
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if err != nil {
		// Tesseract's diagnostics describe the image or the language data,
		// not its content, but keep only the first line and bound it.
		msg, _, _ := strings.Cut(strings.TrimSpace(errOut.String()), "\n")
		if msg != "" {
			return Result{}, fmt.Errorf("ocr: tesseract failed: %v: %s", err, msg)
		}
		return Result{}, fmt.Errorf("ocr: tesseract failed: %w", err)
	}
	return Result{Text: cleanText(out.Bytes()), Truncated: out.truncated}, nil
}

// ImageKind returns "png", "jpeg" or "webp" when data starts with that
// format's signature, and "" otherwise.
func ImageKind(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return "jpeg"
	case len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		return "webp"
	}
	return ""
}

// cleanText drops invalid UTF-8 (a truncated tail may split a rune), form
// feeds Tesseract puts between pages, and surrounding blank space.
func cleanText(b []byte) string {
	s := strings.ToValidUTF8(string(b), "")
	s = strings.ReplaceAll(s, "\f", "")
	return strings.TrimSpace(s)
}

// boundedBuffer keeps the first max bytes written and discards the rest, so
// a runaway process cannot grow memory without bound. It never fails a
// write, so the process is not killed by a broken pipe.
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

func (b *boundedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *boundedBuffer) String() string { return b.buf.String() }

// execRunner runs the binary directly (no shell) with a minimal environment:
// only what Tesseract needs to find its language data and to stay on one
// thread per run.
func execRunner(ctx context.Context, bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = subprocessEnv(os.Getenv)
	cmd.Dir = os.TempDir() // a neutral working directory; nothing is written there
	cmd.WaitDelay = 2 * time.Second
	return cmd.Run()
}

// subprocessEnv returns the environment for the tesseract process.
func subprocessEnv(getenv func(string) string) []string {
	env := []string{"LC_ALL=C.UTF-8", "OMP_THREAD_LIMIT=1"}
	if v := getenv("TESSDATA_PREFIX"); v != "" {
		env = append(env, "TESSDATA_PREFIX="+v)
	}
	return env
}
