package util

import (
	"embed"
	"io/fs"
	"testing"
)

//go:embed *
var data embed.FS

func TestEscapeFS(t *testing.T) {
	efs := NewEscapeFS(data)
	f, _ := efs.Open("testdata/test:dir/test:0.txt")
	var content = make([]byte, 32)
	n, _ := f.Read(content)
	if string(content[0:n]) != "test" {
		t.Fatalf("expected 'test', got '%s'", string(content))
	}

	files, _ := efs.ReadDir("testdata/test:dir")
	if len(files) != 1 || files[0].Name() != "test:0.txt" {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	f, _ = efs.Open("testdata/test:dir")
	entries, _ := f.(fs.ReadDirFile).ReadDir(-1)
	if len(entries) != 1 {
		t.Fatalf("expected a directory of one")
	}
}
