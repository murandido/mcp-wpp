package main

import (
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/murandido/mcp-wpp/internal/ocr"
)

// ocrFlags holds the serve flags for local OCR.
type ocrFlags struct {
	enabled bool
	langs   string
}

// registerOCRFlags adds -ocr and -ocr-langs to fs, defaulting to their
// environment variables. An invalid WPP_MCP_OCR is an error.
func registerOCRFlags(fs *flag.FlagSet, getenv func(string) string) (*ocrFlags, error) {
	o := &ocrFlags{langs: ocr.DefaultLangs}
	if v := getenv("WPP_MCP_OCR"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("WPP_MCP_OCR must be a boolean (for example, 1 or 0)")
		}
		o.enabled = b
	}
	if v := getenv("WPP_MCP_OCR_LANGS"); v != "" {
		o.langs = v
	}
	fs.BoolVar(&o.enabled, "ocr", o.enabled, "extract text from images with the local tesseract binary (extract_image_text); nothing leaves this machine (env WPP_MCP_OCR)")
	fs.StringVar(&o.langs, "ocr-langs", o.langs, "Tesseract languages joined by '+'; their language data must be installed (env WPP_MCP_OCR_LANGS)")
	return o, nil
}

// engine builds the OCR engine, or nil when OCR is off. When the binary is
// missing it warns on w and returns an engine that reports OCR unavailable,
// so the daemon still starts.
func (o *ocrFlags) engine(w io.Writer) (*ocr.Engine, error) {
	if !o.enabled {
		return nil, nil
	}
	eng, err := ocr.New(ocr.Config{Enabled: true, Langs: o.langs})
	if err != nil {
		return nil, err
	}
	if !eng.Available() {
		fmt.Fprintln(w, "warn: -ocr is set but the tesseract binary was not found on PATH; extract_image_text will report OCR as unavailable (install tesseract-ocr and its language data, or use the Docker image)")
	} else {
		fmt.Fprintf(w, "ocr: local tesseract enabled for languages %s\n", eng.Langs())
	}
	return eng, nil
}
