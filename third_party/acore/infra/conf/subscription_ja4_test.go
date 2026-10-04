package conf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/platform"
)

const testJA4Fingerprint = "t13d1516h2_8daaf6152771_d8a2da3f94cd"

func mustCompileTestJA4DB(t *testing.T) []byte {
	t.Helper()

	raw := []byte(testJA4Fingerprint + ",app:test\n")
	compiled, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if !ja4db.IsBinary(compiled) {
		t.Fatal("compiled ja4 db should be binary")
	}
	return compiled
}

func TestApplyDatabaseSubscriptionAtLoadJA4AutoAcceptsBinary(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	want := mustCompileTestJA4DB(t)
	if err := os.WriteFile(sourcePath, want, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)

	err := applyDatabaseSubscriptionAtLoad(DatabaseSubscriptionConfig{
		Type: "ja4",
		URL:  sourcePath,
	}, []string{sourceDir})
	if err != nil {
		t.Fatalf("applyDatabaseSubscriptionAtLoad returned error: %v", err)
	}

	gotPath := filepath.Join(assetDir, "ja4.db")
	got, err := os.ReadFile(gotPath)
	if err != nil {
		t.Fatalf("read ja4 db: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("expected compiled payload passthrough, got len=%d want len=%d", len(got), len(want))
	}
}

func TestApplyDatabaseSubscriptionAtLoadJA4SourceTypeDBAcceptsBinary(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	want := mustCompileTestJA4DB(t)
	if err := os.WriteFile(sourcePath, want, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)

	err := applyDatabaseSubscriptionAtLoad(DatabaseSubscriptionConfig{
		Type:       "ja4",
		URL:        sourcePath,
		SourceType: "db",
	}, []string{sourceDir})
	if err != nil {
		t.Fatalf("applyDatabaseSubscriptionAtLoad returned error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(assetDir, "ja4.db"))
	if err != nil {
		t.Fatalf("read ja4 db: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("expected compiled payload passthrough with sourceType=db, got len=%d want len=%d", len(got), len(want))
	}
}

func TestApplyDatabaseSubscriptionAtLoadJA4SourceTypeDBRejectsNonBinary(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	payload := []byte("plain-text-payload\n")
	if err := os.WriteFile(sourcePath, payload, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)

	err := applyDatabaseSubscriptionAtLoad(DatabaseSubscriptionConfig{
		Type:       "ja4",
		URL:        sourcePath,
		SourceType: "db",
	}, []string{sourceDir})
	if err == nil {
		t.Fatal("expected error for non-binary payload with sourceType=db")
	}
}

func TestApplyDatabaseSubscriptionAtLoadJA4AutoRejectsNonBinary(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	payload := []byte("json-like-payload\n")
	if err := os.WriteFile(sourcePath, payload, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)

	err := applyDatabaseSubscriptionAtLoad(DatabaseSubscriptionConfig{
		Type: "ja4",
		URL:  sourcePath,
	}, []string{sourceDir})
	if err == nil {
		t.Fatal("expected error for non-binary payload with sourceType=auto")
	}
}

func TestApplyDatabaseSubscriptionAtLoadJA4RejectsSourceTypeJSON(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	payload := mustCompileTestJA4DB(t)
	if err := os.WriteFile(sourcePath, payload, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)

	err := applyDatabaseSubscriptionAtLoad(DatabaseSubscriptionConfig{
		Type:       "ja4",
		URL:        sourcePath,
		SourceType: "json",
	}, []string{sourceDir})
	if err == nil {
		t.Fatal("expected error for sourceType=json")
	}
}
