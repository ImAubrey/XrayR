package metrics

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ImAubrey/acore/core"
)

func TestMainConfigRead_AggregatesAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	dnsPath := filepath.Join(dir, "dns.yaml")
	metricsPath := filepath.Join(dir, "metrics.yaml")
	mainPath := filepath.Join(dir, "main.jsonc")
	statsPath := filepath.Join(dir, "stats.yaml")

	if err := os.WriteFile(dnsPath, []byte("dns:\n  servers:\n    - 1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile dns: %v", err)
	}
	if err := os.WriteFile(metricsPath, []byte("metrics:\n  listen: 127.0.0.1:14113\n"), 0o644); err != nil {
		t.Fatalf("WriteFile metrics: %v", err)
	}
	if err := os.WriteFile(mainPath, []byte("{\n  // comment\n  \"log\": {\"loglevel\": \"warning\"},\n  \"Observatory\": {\"interval\": \"600s\"}\n}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main: %v", err)
	}
	if err := os.WriteFile(statsPath, []byte("stats: {}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile stats: %v", err)
	}

	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{dnsPath, metricsPath, mainPath, statsPath},
	})

	req := httptest.NewRequest("GET", "http://example/config/main", nil)
	rec := httptest.NewRecorder()
	handleMainConfigRead(rec, req)
	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var resp mainConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal response: %v body=%s", err, rec.Body.String())
	}

	if resp.Path != mainPath {
		t.Fatalf("main config path mismatch\nwant: %s\ngot:  %s", mainPath, resp.Path)
	}
	if !resp.FoundMain {
		t.Fatalf("expected foundMain=true")
	}

	if _, ok := resp.Main["log"].(map[string]interface{}); !ok {
		t.Fatalf("missing/invalid log section: %#v", resp.Main["log"])
	}
	if _, ok := resp.Main["metrics"].(map[string]interface{}); !ok {
		t.Fatalf("missing/invalid metrics section: %#v", resp.Main["metrics"])
	}
	if _, ok := resp.Main["stats"].(map[string]interface{}); !ok {
		t.Fatalf("missing/invalid stats section: %#v", resp.Main["stats"])
	}
	if _, ok := resp.Main["Observatory"].(map[string]interface{}); !ok {
		t.Fatalf("missing/invalid Observatory section: %#v", resp.Main["Observatory"])
	}
}

func TestMainConfigWrite_SplitsSectionsToOwningFiles(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.jsonc")
	metricsPath := filepath.Join(dir, "metrics.yaml")
	statsPath := filepath.Join(dir, "stats.yaml")

	if err := os.WriteFile(mainPath, []byte("{\"log\":{\"loglevel\":\"info\"},\"routing\":{\"rules\":[]}}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main: %v", err)
	}
	if err := os.WriteFile(metricsPath, []byte("metrics:\n  listen: 127.0.0.1:1111\n"), 0o644); err != nil {
		t.Fatalf("WriteFile metrics: %v", err)
	}
	if err := os.WriteFile(statsPath, []byte("stats:\n  enabled: true\n"), 0o644); err != nil {
		t.Fatalf("WriteFile stats: %v", err)
	}

	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{mainPath, metricsPath, statsPath},
	})

	body := `{
	  "main": {
	    "Observatory": {"interval": "123s"},
	    "log": {"loglevel": "debug"},
	    "metrics": {"listen": "127.0.0.1:14113", "tag": "Metrics"},
	    "stats": {}
	  }
	}`

	req := httptest.NewRequest("POST", "http://example/config/main", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleMainConfigWrite(rec, req)
	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	mainData, _, _, err := readObjectFile(mainPath)
	if err != nil {
		t.Fatalf("readObjectFile main: %v", err)
	}
	metricsData, _, _, err := readObjectFile(metricsPath)
	if err != nil {
		t.Fatalf("readObjectFile metrics: %v", err)
	}
	statsData, _, _, err := readObjectFile(statsPath)
	if err != nil {
		t.Fatalf("readObjectFile stats: %v", err)
	}

	mainLog, _ := mainData["log"].(map[string]interface{})
	if got := strings.TrimSpace(toString(mainLog["loglevel"])); got != "debug" {
		t.Fatalf("main loglevel mismatch: %q", got)
	}
	obs, _ := mainData["Observatory"].(map[string]interface{})
	if got := strings.TrimSpace(toString(obs["interval"])); got != "123s" {
		t.Fatalf("main Observatory.interval mismatch: %q", got)
	}

	if _, hasLog := metricsData["log"]; hasLog {
		t.Fatalf("metrics file should not contain log section: %v", metricsData)
	}
	metricsSection, _ := metricsData["metrics"].(map[string]interface{})
	if got := strings.TrimSpace(toString(metricsSection["listen"])); got != "127.0.0.1:14113" {
		t.Fatalf("metrics.listen mismatch: %q", got)
	}

	if _, hasMetrics := statsData["metrics"]; hasMetrics {
		t.Fatalf("stats file should not contain metrics section: %v", statsData)
	}
	statsSection, ok := statsData["stats"].(map[string]interface{})
	if !ok {
		t.Fatalf("stats section missing after write: %v", statsData)
	}
	if len(statsSection) != 0 {
		t.Fatalf("stats section expected empty object, got: %v", statsSection)
	}
}
