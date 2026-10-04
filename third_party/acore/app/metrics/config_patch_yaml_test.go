package metrics

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ImAubrey/acore/core"
	"gopkg.in/yaml.v3"
)

func TestRoutingConfigWrite_YAMLConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("log:\n  loglevel: info\nrouting:\n  rules: []\noutbounds: []\n"), 0o644); err != nil {
		t.Fatalf("WriteFile config.yaml: %v", err)
	}
	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{cfg},
	})

	req := httptest.NewRequest("POST", "http://example/config/routing", strings.NewReader(`{"routing":{"rules":[{"type":"field","domain":["example.com"],"outboundTag":"direct"}]}}`))
	rec := httptest.NewRecorder()
	handleRoutingConfigWrite(rec, req)
	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("ReadFile config.yaml: %v", err)
	}
	var data map[string]interface{}
	if err := yaml.Unmarshal(raw, &data); err != nil {
		t.Fatalf("yaml.Unmarshal: %v\n%s", err, string(raw))
	}
	routing, _ := data["routing"].(map[string]interface{})
	if routing == nil {
		t.Fatalf("routing section missing after patch: %v", data)
	}
	rules, _ := routing["rules"].([]interface{})
	if len(rules) != 1 {
		t.Fatalf("expected 1 routing rule, got %d (routing=%v)", len(rules), routing)
	}
}

func TestFirewallConfigWrite_YAMLConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("log:\n  loglevel: info\nfirewall:\n  rule: []\noutbounds: []\n"), 0o644); err != nil {
		t.Fatalf("WriteFile config.yaml: %v", err)
	}
	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{cfg},
	})

	req := httptest.NewRequest("POST", "http://example/config/firewall", strings.NewReader(`{"firewall":{"rule":[{"match":{"ruleTag":"fw-block","domain":["example.com"]},"action":"block"}]}}`))
	rec := httptest.NewRecorder()
	handleFirewallConfigWrite(rec, req)
	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("ReadFile config.yaml: %v", err)
	}
	var data map[string]interface{}
	if err := yaml.Unmarshal(raw, &data); err != nil {
		t.Fatalf("yaml.Unmarshal: %v\n%s", err, string(raw))
	}
	firewall, _ := data["firewall"].(map[string]interface{})
	if firewall == nil {
		t.Fatalf("firewall section missing after patch: %v", data)
	}
	rules, _ := firewall["rule"].([]interface{})
	if len(rules) != 1 {
		t.Fatalf("expected 1 firewall rule, got %d (firewall=%v)", len(rules), firewall)
	}
}

func TestSubscriptionConfigWrite_YAMLConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("log:\n  loglevel: info\nsubscription: {}\noutbounds: []\n"), 0o644); err != nil {
		t.Fatalf("WriteFile config.yaml: %v", err)
	}
	core.SetStartupInfo(core.StartupInfo{
		Cwd:         dir,
		ConfigFiles: []string{cfg},
	})

	req := httptest.NewRequest("POST", "http://example/config/subscription", strings.NewReader(`{"subscription":{"subscription-inbound":"socks-in"}}`))
	rec := httptest.NewRecorder()
	handleSubscriptionConfigWrite(rec, req)
	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("ReadFile config.yaml: %v", err)
	}
	var data map[string]interface{}
	if err := yaml.Unmarshal(raw, &data); err != nil {
		t.Fatalf("yaml.Unmarshal: %v\n%s", err, string(raw))
	}
	subscription, _ := data["subscription"].(map[string]interface{})
	if subscription == nil {
		t.Fatalf("subscription section missing after patch: %v", data)
	}
	if got := strings.TrimSpace(toString(subscription["subscription-inbound"])); got != "socks-in" {
		t.Fatalf("unexpected subscription-inbound: %q (subscription=%v)", got, subscription)
	}
}
