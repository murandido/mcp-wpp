package textfold

import "testing"

func TestFold(t *testing.T) {
	for in, want := range map[string]string{
		"JOÃO":           "joao",
		"Cauê":           "caue",
		"Reunião às 10h": "reuniao as 10h",
		"ÇÉÜ ñ":          "ceu n",
		"100% _x":        "100% _x",
		"":               "",
	} {
		if got := Fold(in); got != want {
			t.Errorf("Fold(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSQL(t *testing.T) {
	if SQL(nil) != nil {
		t.Error("NULL must stay NULL")
	}
	if SQL("Ação") != "acao" || SQL([]byte("Ação")) != "acao" {
		t.Error("text and blobs must fold")
	}
	if SQL(int64(7)) != int64(7) {
		t.Error("numbers must pass through")
	}
}
