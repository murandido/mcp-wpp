package main

import (
	"bytes"
	"flag"
	"io"
	"strings"
	"testing"
)

func parseOCRFlags(t *testing.T, env map[string]string, args ...string) (*ocrFlags, error) {
	t.Helper()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o, err := registerOCRFlags(fs, func(k string) string { return env[k] })
	if err != nil {
		return nil, err
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return o, nil
}

func TestOCRFlags_DefaultOff(t *testing.T) {
	o, err := parseOCRFlags(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.enabled || o.langs != "por+eng" {
		t.Fatalf("defaults %+v", o)
	}
	eng, err := o.engine(io.Discard)
	if err != nil || eng != nil {
		t.Fatalf("engine %v, %v", eng, err)
	}
}

func TestOCRFlags_EnvAndFlags(t *testing.T) {
	o, err := parseOCRFlags(t, map[string]string{"WPP_MCP_OCR": "1", "WPP_MCP_OCR_LANGS": "eng"}, "-ocr-langs", "deu+eng")
	if err != nil {
		t.Fatal(err)
	}
	if !o.enabled || o.langs != "deu+eng" {
		t.Fatalf("got %+v", o)
	}
	if _, err := parseOCRFlags(t, map[string]string{"WPP_MCP_OCR": "maybe"}); err == nil {
		t.Fatal("invalid WPP_MCP_OCR accepted")
	}
}

func TestOCRFlags_InvalidLangs(t *testing.T) {
	o, _ := parseOCRFlags(t, nil, "-ocr", "-ocr-langs", "-c x=y")
	if _, err := o.engine(io.Discard); err == nil {
		t.Fatal("flag-like language list accepted")
	}
}

func TestOCRFlags_MissingBinaryWarns(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	o, _ := parseOCRFlags(t, nil, "-ocr")
	var buf bytes.Buffer
	eng, err := o.engine(&buf)
	if err != nil || eng == nil || eng.Available() {
		t.Fatalf("engine %v available=%v err=%v", eng, eng != nil && eng.Available(), err)
	}
	if !strings.Contains(buf.String(), "tesseract binary was not found") {
		t.Fatalf("warning %q", buf.String())
	}
}
