package mcp

import (
	"encoding/base64"
	"strings"
	"testing"
)

// A cloud agent has no way to put a file under the media root, so send_file
// takes the bytes inline. The path branch is covered by the media root tests;
// these pin the inline one, which never touches the client or the disk.
func TestSendFileOptionsInlineContent(t *testing.T) {
	s := &Server{}
	content := []byte("PK\x03\x04 spreadsheet")
	encoded := base64.StdEncoding.EncodeToString(content)

	opts, err := s.sendFileOptions(sendFileArgs{
		Recipient: "120363000000000000@g.us", ContentBase64: encoded, FileName: "../report.xlsx", Caption: "hi",
	})
	if err != nil {
		t.Fatalf("inline content rejected: %v", err)
	}
	if string(opts.Content) != string(content) || opts.FileName != "../report.xlsx" || opts.MediaPath != "" || opts.Caption != "hi" {
		t.Errorf("options = %+v", opts)
	}
}

func TestSendFileOptionsRejects(t *testing.T) {
	s := &Server{}
	valid := base64.StdEncoding.EncodeToString([]byte("data"))
	tooLarge := base64.StdEncoding.EncodeToString(make([]byte, maxInlineFileBytes+1))
	cases := map[string]struct {
		args sendFileArgs
		want string
	}{
		"no recipient":    {sendFileArgs{ContentBase64: valid, FileName: "a.pdf"}, "recipient is required"},
		"nothing to send": {sendFileArgs{Recipient: "5511999999999"}, "media_path or content_base64 is required"},
		"both sources":    {sendFileArgs{Recipient: "5511999999999", MediaPath: "/tmp/a.pdf", ContentBase64: valid, FileName: "a.pdf"}, "not both"},
		"no file name":    {sendFileArgs{Recipient: "5511999999999", ContentBase64: valid}, "file_name is required"},
		"not base64":      {sendFileArgs{Recipient: "5511999999999", ContentBase64: "%%%", FileName: "a.pdf"}, "not valid base64"},
		"too large":       {sendFileArgs{Recipient: "5511999999999", ContentBase64: tooLarge, FileName: "a.pdf"}, "16 MiB"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := s.sendFileOptions(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
