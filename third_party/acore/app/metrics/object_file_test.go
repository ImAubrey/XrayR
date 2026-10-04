package metrics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadWriteObjectFile_YAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acore.ui.yaml")

	input := map[string]interface{}{
		"probeMode": "tcp",
		"n":         1,
		"nested": map[string]interface{}{
			"ok": true,
		},
	}
	if err := writeObjectFile(path, input); err != nil {
		t.Fatalf("writeObjectFile: %v", err)
	}

	got, format, found, err := readObjectFile(path)
	if err != nil {
		t.Fatalf("readObjectFile: %v", err)
	}
	if !found {
		t.Fatalf("expected found=true")
	}
	if format != "yaml" {
		t.Fatalf("expected format=yaml, got %q", format)
	}
	if got["probeMode"] != "tcp" {
		t.Fatalf("probeMode mismatch: %#v", got["probeMode"])
	}
	if got["n"] != 1 {
		t.Fatalf("n mismatch: %#v (%T)", got["n"], got["n"])
	}
	nested, ok := got["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested type mismatch: %#v (%T)", got["nested"], got["nested"])
	}
	if nested["ok"] != true {
		t.Fatalf("nested.ok mismatch: %#v", nested["ok"])
	}
}

func TestReadObjectFile_JSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.jsonc")
	if err := os.WriteFile(path, []byte("{\n  // comment\n  \"probeMode\": \"tcp\"\n}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, format, found, err := readObjectFile(path)
	if err != nil {
		t.Fatalf("readObjectFile: %v", err)
	}
	if !found {
		t.Fatalf("expected found=true")
	}
	if format != "jsonc" {
		t.Fatalf("expected format=jsonc, got %q", format)
	}
	if got["probeMode"] != "tcp" {
		t.Fatalf("probeMode mismatch: %#v", got["probeMode"])
	}
}
