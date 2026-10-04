package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/platform"
)

const testRuntimeJA4Fingerprint = "t13d1516h2_8daaf6152771_d8a2da3f94cd"

func mustCompileRuntimeTestJA4DB(t *testing.T) []byte {
	t.Helper()

	raw := []byte(testRuntimeJA4Fingerprint + ",app:test\n")
	compiled, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if !ja4db.IsBinary(compiled) {
		t.Fatal("compiled ja4 db should be binary")
	}
	return compiled
}

func TestRefreshDatabaseSubscriptionJA4AutoAcceptsBinary(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	want := mustCompileRuntimeTestJA4DB(t)
	if err := os.WriteFile(sourcePath, want, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)

	s := &Instance{ctx: context.Background()}
	ok := s.refreshDatabaseSubscription(context.Background(), "", "ja4", SubscriptionDatabaseConfig{
		Type: "ja4",
		URL:  sourcePath,
	})
	if !ok {
		t.Fatal("refreshDatabaseSubscription returned false for binary ja4 payload")
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

func TestRefreshDatabaseSubscriptionJA4SourceTypeDBAcceptsBinary(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	want := mustCompileRuntimeTestJA4DB(t)
	if err := os.WriteFile(sourcePath, want, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)
	s := &Instance{ctx: context.Background()}
	ok := s.refreshDatabaseSubscription(context.Background(), "", "ja4", SubscriptionDatabaseConfig{
		Type:       "ja4",
		URL:        sourcePath,
		SourceType: "db",
	})
	if !ok {
		t.Fatal("refreshDatabaseSubscription returned false for sourceType=db")
	}
	got, err := os.ReadFile(filepath.Join(assetDir, "ja4.db"))
	if err != nil {
		t.Fatalf("read ja4 db: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("expected compiled payload passthrough, got len=%d want len=%d", len(got), len(want))
	}
}

func TestRefreshDatabaseSubscriptionJA4SourceTypeDBRejectsNonBinary(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	payload := []byte("plain-text-runtime-payload\n")
	if err := os.WriteFile(sourcePath, payload, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)
	s := &Instance{ctx: context.Background()}
	ok := s.refreshDatabaseSubscription(context.Background(), "", "ja4", SubscriptionDatabaseConfig{
		Type:       "ja4",
		URL:        sourcePath,
		SourceType: "db",
	})
	if ok {
		t.Fatal("expected sourceType=db non-binary payload to fail")
	}
}

func TestRefreshDatabaseSubscriptionJA4AutoRejectsNonBinary(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	payload := []byte("auto-runtime-payload\n")
	if err := os.WriteFile(sourcePath, payload, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)
	s := &Instance{ctx: context.Background()}
	ok := s.refreshDatabaseSubscription(context.Background(), "", "ja4", SubscriptionDatabaseConfig{
		Type: "ja4",
		URL:  sourcePath,
	})
	if ok {
		t.Fatal("expected sourceType=auto non-binary payload to fail")
	}
}

func TestRefreshDatabaseSubscriptionJA4RejectsSourceTypeJSON(t *testing.T) {
	assetDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "ja4-source.db")
	payload := mustCompileRuntimeTestJA4DB(t)
	if err := os.WriteFile(sourcePath, payload, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)
	s := &Instance{ctx: context.Background()}
	ok := s.refreshDatabaseSubscription(context.Background(), "", "ja4", SubscriptionDatabaseConfig{
		Type:       "ja4",
		URL:        sourcePath,
		SourceType: "json",
	})
	if ok {
		t.Fatal("expected sourceType=json to fail")
	}
}
