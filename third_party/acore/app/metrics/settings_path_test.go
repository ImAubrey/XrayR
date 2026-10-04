package metrics

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ImAubrey/acore/core"
)

func TestResolveSettingsPath_UsesYamlForYamlMainConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("log:\n  loglevel: info\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SETTINGS_FILE", "")
	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{cfg},
	})

	got := resolveSettingsPath()
	want := filepath.Join(dir, "acore.ui.yaml")
	if got != want {
		t.Fatalf("resolveSettingsPath mismatch\nwant: %s\ngot:  %s", want, got)
	}
}

func TestResolveSettingsPath_UsesYmlForYmlMainConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("log:\n  loglevel: info\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SETTINGS_FILE", "")
	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{cfg},
	})

	got := resolveSettingsPath()
	want := filepath.Join(dir, "acore.ui.yml")
	if got != want {
		t.Fatalf("resolveSettingsPath mismatch\nwant: %s\ngot:  %s", want, got)
	}
}

func TestResolveSettingsPath_UsesJsonForJsonMainConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte("{\"log\":{\"loglevel\":\"info\"}}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SETTINGS_FILE", "")
	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{cfg},
	})

	got := resolveSettingsPath()
	want := filepath.Join(dir, "acore.ui.json")
	if got != want {
		t.Fatalf("resolveSettingsPath mismatch\nwant: %s\ngot:  %s", want, got)
	}
}

func TestResolveSettingsPath_PicksFileWithLogAsMain(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(a, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile a: %v", err)
	}
	if err := os.WriteFile(b, []byte("log:\n  loglevel: info\n"), 0o644); err != nil {
		t.Fatalf("WriteFile b: %v", err)
	}
	t.Setenv("SETTINGS_FILE", "")
	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{a, b},
	})

	got := resolveSettingsPath()
	want := filepath.Join(dir, "acore.ui.yaml")
	if got != want {
		t.Fatalf("resolveSettingsPath mismatch\nwant: %s\ngot:  %s", want, got)
	}
}

func TestResolveSettingsPath_UsesConfDirWhenProvided(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "confs")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfg := filepath.Join(confDir, "main.yaml")
	if err := os.WriteFile(cfg, []byte("log:\n  loglevel: info\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SETTINGS_FILE", "")
	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfDir:     confDir,
		ConfigFiles: []string{cfg},
	})

	got := resolveSettingsPath()
	want := filepath.Join(confDir, "acore.ui.yaml")
	if got != want {
		t.Fatalf("resolveSettingsPath mismatch\nwant: %s\ngot:  %s", want, got)
	}
}

func TestLoadSettingsRaw_FallsBackToLegacyJsonWhenYamlMissing(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "acore.ui.json")
	if err := os.WriteFile(legacy, []byte("{\"probeMode\":\"tcp\",\"controller\":{\"uiState\":{\"version\":1}}}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile legacy: %v", err)
	}
	yamlPath := filepath.Join(dir, "acore.ui.yaml")

	got, err := loadSettingsRaw(yamlPath)
	if err != nil {
		t.Fatalf("loadSettingsRaw: %v", err)
	}
	if got["probeMode"] != "tcp" {
		t.Fatalf("probeMode mismatch: %#v", got["probeMode"])
	}
	if _, ok := got["controller"].(map[string]interface{}); !ok {
		t.Fatalf("controller missing/type mismatch: %#v (%T)", got["controller"], got["controller"])
	}
}
