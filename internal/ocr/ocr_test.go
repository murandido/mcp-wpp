package ocr

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

func fakeImage() []byte { return append(append([]byte{}, pngMagic...), "rest"...) }

func engineWith(t *testing.T, cfg Config, run Runner) *Engine {
	t.Helper()
	cfg.Enabled = true
	e, err := NewWithRunner(cfg, run)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestExtract_PassesImageOnStdinWithLangs(t *testing.T) {
	var gotBin string
	var gotArgs []string
	var gotIn []byte
	e := engineWith(t, Config{Binary: "/opt/tesseract", Langs: "por+eng"}, func(_ context.Context, bin string, args []string, in io.Reader, out, _ io.Writer) error {
		gotBin, gotArgs = bin, args
		gotIn, _ = io.ReadAll(in)
		_, _ = io.WriteString(out, "  Olá mundo\n\f")
		return nil
	})
	res, err := e.Extract(context.Background(), fakeImage())
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "Olá mundo" || res.Truncated {
		t.Fatalf("result %+v", res)
	}
	if gotBin != "/opt/tesseract" || strings.Join(gotArgs, " ") != "stdin stdout -l por+eng" {
		t.Fatalf("ran %s %v", gotBin, gotArgs)
	}
	if !bytes.Equal(gotIn, fakeImage()) {
		t.Fatal("image was not piped on stdin")
	}
}

func TestExtract_Disabled(t *testing.T) {
	var nilEngine *Engine
	if _, err := nilEngine.Extract(context.Background(), fakeImage()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil engine: %v", err)
	}
	e, _ := NewWithRunner(Config{}, nil)
	if _, err := e.Extract(context.Background(), fakeImage()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("disabled: %v", err)
	}
}

func TestNew_MissingBinary(t *testing.T) {
	e, err := New(Config{Enabled: true, Binary: "wpp-mcp-no-such-tesseract"})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Enabled() || e.Available() {
		t.Fatalf("enabled=%v available=%v", e.Enabled(), e.Available())
	}
	if _, err := e.Extract(context.Background(), fakeImage()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestNew_RejectsBadLangs(t *testing.T) {
	for _, l := range []string{"-c foo=bar", "por eng", "por+", "../eng", "p"} {
		if _, err := NewWithRunner(Config{Enabled: true, Langs: l}, nil); err == nil {
			t.Errorf("langs %q accepted", l)
		}
	}
	for _, l := range []string{"por+eng", "eng", "chi_sim+eng"} {
		if !ValidLangs(l) {
			t.Errorf("langs %q rejected", l)
		}
	}
}

func TestExtract_SizeLimit(t *testing.T) {
	ran := false
	e := engineWith(t, Config{MaxBytes: 16}, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
		ran = true
		return nil
	})
	big := append(fakeImage(), make([]byte, 32)...)
	if _, err := e.Extract(context.Background(), big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if ran {
		t.Fatal("tesseract ran on an oversized image")
	}
}

func TestExtract_RejectsNonImage(t *testing.T) {
	e := engineWith(t, Config{}, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("must not run")
		return nil
	})
	if _, err := e.Extract(context.Background(), []byte("%PDF-1.7 ...")); !errors.Is(err, ErrNotImage) {
		t.Fatalf("got %v", err)
	}
}

func TestExtract_Timeout(t *testing.T) {
	e := engineWith(t, Config{Timeout: 20 * time.Millisecond}, func(ctx context.Context, _ string, _ []string, _ io.Reader, _, _ io.Writer) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if _, err := e.Extract(context.Background(), fakeImage()); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestExtract_OutputBound(t *testing.T) {
	e := engineWith(t, Config{MaxOutput: 10}, func(_ context.Context, _ string, _ []string, _ io.Reader, out, _ io.Writer) error {
		_, _ = io.WriteString(out, "0123456789abcdef")
		_, _ = io.WriteString(out, "more")
		return nil
	})
	res, err := e.Extract(context.Background(), fakeImage())
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "0123456789" || !res.Truncated {
		t.Fatalf("result %+v", res)
	}
}

func TestExtract_TruncationDropsSplitRune(t *testing.T) {
	e := engineWith(t, Config{MaxOutput: 4}, func(_ context.Context, _ string, _ []string, _ io.Reader, out, _ io.Writer) error {
		_, _ = io.WriteString(out, "abcã") // 'ã' is two bytes; only one fits
		return nil
	})
	res, err := e.Extract(context.Background(), fakeImage())
	if err != nil || res.Text != "abc" {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestExtract_FailureKeepsFirstStderrLine(t *testing.T) {
	e := engineWith(t, Config{}, func(_ context.Context, _ string, _ []string, _ io.Reader, _, errOut io.Writer) error {
		_, _ = io.WriteString(errOut, "Error opening data file por.traineddata\nmore detail\n")
		return errors.New("exit status 1")
	})
	_, err := e.Extract(context.Background(), fakeImage())
	if err == nil || !strings.Contains(err.Error(), "por.traineddata") || strings.Contains(err.Error(), "more detail") {
		t.Fatalf("got %v", err)
	}
}

func TestExtract_ConcurrencyLimit(t *testing.T) {
	var running, peak atomic.Int32
	release := make(chan struct{})
	e := engineWith(t, Config{MaxConcurrent: 2}, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		running.Add(-1)
		return nil
	})
	done := make(chan struct{})
	for range 5 {
		go func() {
			_, _ = e.Extract(context.Background(), fakeImage())
			done <- struct{}{}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	for range 5 {
		<-done
	}
	if peak.Load() > 2 {
		t.Fatalf("%d runs at once, limit 2", peak.Load())
	}
}

func TestExtract_CancelledWhileWaiting(t *testing.T) {
	block := make(chan struct{})
	e := engineWith(t, Config{MaxConcurrent: 1}, func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
		<-block
		return nil
	})
	go func() { _, _ = e.Extract(context.Background(), fakeImage()) }()
	time.Sleep(10 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := e.Extract(ctx, fakeImage()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	close(block)
}

func TestImageKind(t *testing.T) {
	webp := append([]byte("RIFF\x00\x00\x00\x00WEBP"), "VP8 "...)
	for in, want := range map[string]string{
		string(pngMagic) + "x":     "png",
		"\xFF\xD8\xFF\xE0JFIF":     "jpeg",
		string(webp):               "webp",
		"GIF89a":                   "",
		"%PDF-1.4":                 "",
		"RIFF\x00\x00\x00\x00WAVE": "",
	} {
		if got := ImageKind([]byte(in)); got != want {
			t.Errorf("ImageKind(%q) = %q, want %q", in[:4], got, want)
		}
	}
}

func TestSubprocessEnv_IsMinimal(t *testing.T) {
	env := subprocessEnv(func(k string) string {
		return map[string]string{"TESSDATA_PREFIX": "/td", "WPP_MCP_TOKEN": "secret", "HOME": "/home/x"}[k]
	})
	joined := strings.Join(env, " ")
	if strings.Contains(joined, "secret") || strings.Contains(joined, "HOME") || !strings.Contains(joined, "TESSDATA_PREFIX=/td") {
		t.Fatalf("env %v", env)
	}
}

// TestExtract_RealTesseract runs the real binary on a generated image. It
// skips when tesseract is not installed, unless WPP_MCP_REQUIRE_TESSERACT=1
// (the container test stage), where a missing binary fails the test.
func TestExtract_RealTesseract(t *testing.T) {
	if _, err := exec.LookPath("tesseract"); err != nil {
		if os.Getenv("WPP_MCP_REQUIRE_TESSERACT") == "1" {
			t.Fatal("tesseract is required (WPP_MCP_REQUIRE_TESSERACT=1) but not installed")
		}
		t.Skip("tesseract not installed")
	}
	e, err := New(Config{Enabled: true, Langs: "eng"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Extract(context.Background(), RenderTextPNG("HELLO WORLD 42"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ToUpper(res.Text); !strings.Contains(got, "HELLO") || !strings.Contains(got, "WORLD") {
		t.Fatalf("tesseract read %q", res.Text)
	}
}

// RenderTextPNG draws text in a fixed 5x7 bitmap font, scaled up, black on
// white, and encodes it as PNG. It is deterministic, needs no font files and
// covers only the glyphs in glyphs5x7.
func RenderTextPNG(text string) []byte {
	const scale, pad = 8, 40
	cols := len(text) * 6
	img := image.NewGray(image.Rect(0, 0, cols*scale+2*pad, 7*scale+2*pad))
	for i := range img.Pix {
		img.Pix[i] = 0xFF
	}
	for ci, r := range text {
		g := glyphs5x7[r]
		for row, bits := range g {
			for col := range 5 {
				if bits&(1<<(4-col)) == 0 {
					continue
				}
				x0, y0 := pad+(ci*6+col)*scale, pad+row*scale
				for dy := range scale {
					for dx := range scale {
						img.SetGray(x0+dx, y0+dy, color.Gray{Y: 0})
					}
				}
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// glyphs5x7 holds rows of 5 bits, most significant bit leftmost.
var glyphs5x7 = map[rune][7]byte{
	' ': {},
	'D': {0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110},
	'E': {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111},
	'H': {0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001},
	'L': {0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111},
	'O': {0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110},
	'R': {0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001},
	'W': {0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b10101, 0b01010},
	'2': {0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111},
	'4': {0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010},
}
