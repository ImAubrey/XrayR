package router_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	. "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/platform"
)

func TestLookupJA4TagFallsBackToDefaultSourceTag(t *testing.T) {
	assetDir := t.TempDir()
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	bin, err := ja4db.Compile([]byte(fp + ",source:ja4db\n"))
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	r := &Router{}
	cfg := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "sniffer-socket",
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init: %v", err)
	}

	got := r.LookupJA4Tag(fp)
	if got != "source:ja4db" {
		t.Fatalf("expected source:ja4db, got %q", got)
	}
}

func TestLookupJA4TagPrefersAppMajorLabel(t *testing.T) {
	assetDir := t.TempDir()
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	raw := []byte(
		fp + ",source:ja4db\n" +
			fp + ",app:chrome\n" +
			fp + ",app:chrome:major:124\n",
	)
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	r := &Router{}
	cfg := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "sniffer-socket",
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init: %v", err)
	}

	got := r.LookupJA4Tag(fp)
	if got != "app:chrome:major:124" {
		t.Fatalf("expected app:chrome:major:124, got %q", got)
	}
}

func TestLookupJA4TagPrefersUAFamilyOverAppMajorLabel(t *testing.T) {
	assetDir := t.TempDir()
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	raw := []byte(
		fp + ",source:ja4db\n" +
			fp + ",app:chrome:major:124\n" +
			fp + ",ua:family:chromium:major:124\n",
	)
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	r := &Router{}
	cfg := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "sniffer-socket",
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init: %v", err)
	}

	got := r.LookupJA4Tag(fp)
	if got != "ua:family:chromium:major:124" {
		t.Fatalf("expected ua:family:chromium:major:124, got %q", got)
	}
}

func TestLookupJA4TagPrefersAppMajorOverCoarseLabelFromJA4DB(t *testing.T) {
	assetDir := t.TempDir()
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	raw := []byte(
		fp + ",app:chrome:major:143\n" +
			fp + ",label:malware\n",
	)
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	r := &Router{}
	cfg := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "sniffer-socket",
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init: %v", err)
	}

	got := r.LookupJA4Tag(fp)
	if got != "app:chrome:major:143" {
		t.Fatalf("expected app:chrome:major:143, got %q", got)
	}
}

func TestLookupJA4TagPrefersAppMajorOverBareLabelFromJA4DB(t *testing.T) {
	assetDir := t.TempDir()
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	raw := []byte(
		fp + ",app:chrome:major:143\n" +
			fp + ",malware\n",
	)
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	r := &Router{}
	cfg := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "sniffer-socket",
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init: %v", err)
	}

	got := r.LookupJA4Tag(fp)
	if got != "app:chrome:major:143" {
		t.Fatalf("expected app:chrome:major:143, got %q", got)
	}
}

func TestLookupJA4TagUsesRawTagForCustomDB(t *testing.T) {
	assetDir := t.TempDir()
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	bin, err := ja4db.Compile([]byte(fp + ",malware\n"))
	if err != nil {
		t.Fatalf("compile ja4 custom db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4_custom.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 custom db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	r := &Router{}
	cfg := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "sniffer-socket",
				Attributes: map[string]string{
					"ja4": EncodeJA4DBAttributeValue("ja4_custom.db", "malware"),
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init: %v", err)
	}

	got := r.LookupJA4Tag(fp)
	if got != "malware" {
		t.Fatalf("expected malware, got %q", got)
	}
}

func TestLookupJA4TagAutoLookupUsesJA4DBOnly(t *testing.T) {
	assetDir := t.TempDir()
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"

	detailedBin, err := ja4db.Compile([]byte(fp + ",app:chrome:major:143\n"))
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), detailedBin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}

	customBin, err := ja4db.Compile([]byte(fp + ",malware\n"))
	if err != nil {
		t.Fatalf("compile ja4 custom db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4_custom.db"), customBin, 0o644); err != nil {
		t.Fatalf("write ja4 custom db: %v", err)
	}

	t.Setenv(platform.AssetLocation, assetDir)

	r := &Router{}
	cfg := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "sniffer-socket",
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init: %v", err)
	}

	got := r.LookupJA4Tag(fp)
	if got != "app:chrome:major:143" {
		t.Fatalf("expected app:chrome:major:143, got %q", got)
	}
}
