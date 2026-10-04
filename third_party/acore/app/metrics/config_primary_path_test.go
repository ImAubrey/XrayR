package metrics

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ImAubrey/acore/core"
)

func TestFindPrimaryConfig_PrefersMainNamedFileInConfDir(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("MkdirAll conf: %v", err)
	}

	dnsPath := filepath.Join(confDir, "dns.yaml")
	inboundPath := filepath.Join(confDir, "inbound.yaml")
	mainPath := filepath.Join(confDir, "main.yaml")

	if err := os.WriteFile(dnsPath, []byte("dns: {}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile dns: %v", err)
	}
	if err := os.WriteFile(inboundPath, []byte("inbounds: []\n"), 0o644); err != nil {
		t.Fatalf("WriteFile inbound: %v", err)
	}
	if err := os.WriteFile(mainPath, []byte("log:\n  loglevel: info\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main: %v", err)
	}

	core.SetStartupInfo(core.StartupInfo{
		Cwd:          dir,
		ConfDir:      confDir,
		ConfigFormat: "yaml",
	})

	cfg, found, err := findPrimaryConfig("")
	if err != nil {
		t.Fatalf("findPrimaryConfig: %v", err)
	}
	if cfg == nil {
		t.Fatalf("findPrimaryConfig returned nil config")
	}
	if cfg.Path != mainPath {
		t.Fatalf("findPrimaryConfig picked wrong file\nwant: %s\ngot:  %s", mainPath, cfg.Path)
	}
	if !found {
		t.Fatalf("findPrimaryConfig should mark found=true for main file with log section")
	}
}

func TestFindPrimaryConfig_PrefersMainNamedFileEvenWhenSectionsMissing(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("MkdirAll conf: %v", err)
	}

	dnsPath := filepath.Join(confDir, "dns.yaml")
	outboundPath := filepath.Join(confDir, "outbound.yaml")
	mainPath := filepath.Join(confDir, "main.yaml")

	if err := os.WriteFile(dnsPath, []byte("dns: {}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile dns: %v", err)
	}
	if err := os.WriteFile(outboundPath, []byte("outbounds: []\n"), 0o644); err != nil {
		t.Fatalf("WriteFile outbound: %v", err)
	}
	if err := os.WriteFile(mainPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main: %v", err)
	}

	core.SetStartupInfo(core.StartupInfo{
		Cwd:          dir,
		ConfDir:      confDir,
		ConfigFormat: "yaml",
	})

	cfg, found, err := findPrimaryConfig("")
	if err != nil {
		t.Fatalf("findPrimaryConfig: %v", err)
	}
	if cfg == nil {
		t.Fatalf("findPrimaryConfig returned nil config")
	}
	if cfg.Path != mainPath {
		t.Fatalf("findPrimaryConfig picked wrong file\nwant: %s\ngot:  %s", mainPath, cfg.Path)
	}
	if found {
		t.Fatalf("findPrimaryConfig should mark found=false when main file has no primary sections")
	}
}

func TestFindRoutingConfig_RejectsPathOutsideActiveCandidates(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.json")
	externalPath := filepath.Join(dir, "external.json")

	if err := os.WriteFile(mainPath, []byte("{\"routing\":{\"rules\":[]}}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main: %v", err)
	}
	if err := os.WriteFile(externalPath, []byte("{\"routing\":{\"rules\":[{\"type\":\"field\"}]}}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile external: %v", err)
	}

	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{mainPath},
	})

	if _, _, err := findRoutingConfig(externalPath); err == nil {
		t.Fatalf("findRoutingConfig should reject preferred path outside active config candidates")
	}
}
