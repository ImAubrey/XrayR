package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ImAubrey/acore/app/proxyman"
	core "github.com/ImAubrey/acore/core"
)

func TestConfigBuildExpandsSendThroughArray(t *testing.T) {
	var cfg Config
	raw := `{
		"outbounds": [
			{
				"protocol": "freedom",
				"sendThrough": [
					{
						"tag": "edge-a",
						"v4": "192.0.2.10/24",
						"v6": "2001:db8::10/64"
					},
					{
						"tag": "edge-b",
						"v4": "srcip"
					}
				],
				"settings": {}
			}
		]
	}`

	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(cfg.OutboundConfigs) != 2 {
		t.Fatalf("expected 2 expanded outbounds, got %d", len(cfg.OutboundConfigs))
	}
	if got := cfg.OutboundConfigs[0].Tag; got != "edge-a" {
		t.Fatalf("unexpected first expanded tag: %q", got)
	}
	if got := cfg.OutboundConfigs[1].Tag; got != "edge-b" {
		t.Fatalf("unexpected second expanded tag: %q", got)
	}

	if len(built.Outbound) != 2 {
		t.Fatalf("expected 2 built outbounds, got %d", len(built.Outbound))
	}

	first := senderConfigFromOutbound(t, built.Outbound[0])
	if got := first.Via.AsAddress().String(); got != "192.0.2.10" {
		t.Fatalf("unexpected first v4 sendThrough: %q", got)
	}
	if got := first.ViaCidr; got != "24" {
		t.Fatalf("unexpected first v4 cidr: %q", got)
	}
	if first.Via6 == nil {
		t.Fatal("expected first outbound to include v6 sendThrough")
	}
	if got := first.Via6.AsAddress().IP().String(); got != "2001:db8::10" {
		t.Fatalf("unexpected first v6 sendThrough: %q", got)
	}
	if got := first.Via6Cidr; got != "64" {
		t.Fatalf("unexpected first v6 cidr: %q", got)
	}

	second := senderConfigFromOutbound(t, built.Outbound[1])
	if got := second.Via.AsAddress().String(); got != "srcip" {
		t.Fatalf("unexpected second v4 sendThrough: %q", got)
	}
	if second.Via6 != nil {
		t.Fatal("expected second outbound to omit v6 sendThrough")
	}
}

func TestConfigBuildRejectsSendThroughArrayWithTopLevelSendThrough6(t *testing.T) {
	var cfg Config
	raw := `{
		"outbounds": [
			{
				"protocol": "freedom",
				"sendThrough": [
					{
						"tag": "edge-a",
						"v4": "192.0.2.10/24"
					}
				],
				"sendThrough6": "2001:db8::10/64",
				"settings": {}
			}
		]
	}`

	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if _, err := cfg.Build(); err == nil || !strings.Contains(err.Error(), "use v6 in each item") {
		t.Fatalf("expected sendThrough array + sendThrough6 error, got %v", err)
	}
}

func TestConfigBuildRejectsSendThroughArrayWithoutTag(t *testing.T) {
	var cfg Config
	raw := `{
		"outbounds": [
			{
				"protocol": "freedom",
				"sendThrough": [
					{
						"v4": "192.0.2.10/24"
					}
				],
				"settings": {}
			}
		]
	}`

	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if _, err := cfg.Build(); err == nil || !strings.Contains(err.Error(), "tag is required") {
		t.Fatalf("expected missing tag error, got %v", err)
	}
}

func TestConfigBuildRejectsSendThroughArrayV6WithoutV4(t *testing.T) {
	var cfg Config
	raw := `{
		"outbounds": [
			{
				"protocol": "freedom",
				"sendThrough": [
					{
						"tag": "edge-a",
						"v6": "2001:db8::10/64"
					}
				],
				"settings": {}
			}
		]
	}`

	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if _, err := cfg.Build(); err == nil || !strings.Contains(err.Error(), "v6 requires v4") {
		t.Fatalf("expected v6 requires v4 error, got %v", err)
	}
}

func TestConfigBuildKeepsParentTagAsFirstExpandedAlias(t *testing.T) {
	var cfg Config
	raw := `{
		"outbounds": [
			{
				"tag": "parent",
				"protocol": "freedom",
				"sendThrough": [
					{
						"tag": "edge-a",
						"v4": "192.0.2.10/24"
					},
					{
						"tag": "edge-b",
						"v4": "192.0.2.11/24"
					}
				],
				"settings": {}
			}
		]
	}`

	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(built.Outbound) != 3 {
		t.Fatalf("expected parent alias plus 2 expanded outbounds, got %d", len(built.Outbound))
	}
	if got := built.Outbound[0].Tag; got != "parent" {
		t.Fatalf("unexpected parent alias tag: %q", got)
	}
	if got := built.Outbound[1].Tag; got != "edge-a" {
		t.Fatalf("unexpected first expanded tag: %q", got)
	}
	if got := built.Outbound[2].Tag; got != "edge-b" {
		t.Fatalf("unexpected second expanded tag: %q", got)
	}

	parent := senderConfigFromOutbound(t, built.Outbound[0])
	first := senderConfigFromOutbound(t, built.Outbound[1])
	if got := parent.Via.AsAddress().String(); got != "192.0.2.10" {
		t.Fatalf("unexpected parent alias sendThrough: %q", got)
	}
	if got := first.Via.AsAddress().String(); got != "192.0.2.10" {
		t.Fatalf("unexpected first expanded sendThrough: %q", got)
	}
	if got := parent.ViaCidr; got != first.ViaCidr {
		t.Fatalf("expected parent alias cidr %q, got %q", first.ViaCidr, got)
	}
}

func senderConfigFromOutbound(t *testing.T, outbound *core.OutboundHandlerConfig) *proxyman.SenderConfig {
	t.Helper()

	raw, err := outbound.SenderSettings.GetInstance()
	if err != nil {
		t.Fatalf("SenderSettings.GetInstance() error = %v", err)
	}

	sender, ok := raw.(*proxyman.SenderConfig)
	if !ok {
		t.Fatalf("unexpected sender settings type %T", raw)
	}

	return sender
}
