package conf_test

import (
	"encoding/json"
	"testing"

	appfirewall "github.com/ImAubrey/acore/app/firewall"
	. "github.com/ImAubrey/acore/infra/conf"
)

func TestFirewallConfigBuildParsesRoutingLikeRule(t *testing.T) {
	rawRule := json.RawMessage(`{
		"ruleTag": "src-limit",
		"inboundTag": ["socks"],
		"action": "limit",
		"limit": {
			"key": "srcIp",
			"maxConnections": 3
		}
	}`)

	cfg := &FirewallConfig{
		RuleList: []json.RawMessage{rawRule},
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(built.Rule) != 1 {
		t.Fatalf("rule len = %d, want 1", len(built.Rule))
	}
	if built.Rule[0].Action != appfirewall.Rule_Limit {
		t.Fatalf("action = %v, want limit", built.Rule[0].Action)
	}
	if built.Rule[0].Limit == nil || built.Rule[0].Limit.Key != appfirewall.ConnectionLimit_SrcIp {
		t.Fatalf("limit = %#v, want src ip", built.Rule[0].Limit)
	}
	if built.Rule[0].Limit.GetMode() != appfirewall.ConnectionLimit_ActiveConnections {
		t.Fatalf("limit mode = %v, want active", built.Rule[0].Limit.GetMode())
	}
	if built.Rule[0].Match.GetRuleTag() != "src-limit" {
		t.Fatalf("ruleTag = %q, want src-limit", built.Rule[0].Match.GetRuleTag())
	}
}

func TestFirewallConfigRejectsRoutingDestination(t *testing.T) {
	rawRule := json.RawMessage(`{
		"ruleTag": "bad",
		"inboundTag": ["socks"],
		"destination": "direct",
		"action": "block"
	}`)
	cfg := &FirewallConfig{
		RuleList: []json.RawMessage{rawRule},
	}

	if _, err := cfg.Build(); err == nil {
		t.Fatal("expected destination-based firewall rule to be rejected")
	}
}

func TestFirewallConfigBuildAcceptsCountByAlias(t *testing.T) {
	rawRule := json.RawMessage(`{
		"ruleTag": "dst-limit",
		"action": "limit",
		"limit": {
			"countBy": "dstIp",
			"maxConnections": 2
		},
		"ip": ["198.51.100.7/32"]
	}`)

	cfg := &FirewallConfig{
		RuleList: []json.RawMessage{rawRule},
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(built.Rule) != 1 {
		t.Fatalf("rule len = %d, want 1", len(built.Rule))
	}
	if built.Rule[0].Limit == nil || built.Rule[0].Limit.Key != appfirewall.ConnectionLimit_DstIp {
		t.Fatalf("limit = %#v, want dst ip", built.Rule[0].Limit)
	}
}

func TestFirewallConfigBuildParsesNewConnectionLimit(t *testing.T) {
	rawRule := json.RawMessage(`{
		"ruleTag": "burst-limit",
		"action": "limit",
		"limit": {
			"key": "srcIp",
			"mode": "newConnections",
			"windowSeconds": 30,
			"maxConnections": 5
		},
		"inboundTag": ["socks"]
	}`)

	cfg := &FirewallConfig{
		RuleList: []json.RawMessage{rawRule},
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	limit := built.Rule[0].Limit
	if limit == nil {
		t.Fatal("limit is nil")
	}
	if limit.GetMode() != appfirewall.ConnectionLimit_NewConnections {
		t.Fatalf("limit mode = %v, want newConnections", limit.GetMode())
	}
	if limit.GetWindowSeconds() != 30 {
		t.Fatalf("windowSeconds = %d, want 30", limit.GetWindowSeconds())
	}
}

func TestFirewallConfigRejectsInvalidLimitWindowUsage(t *testing.T) {
	tests := []json.RawMessage{
		json.RawMessage(`{
			"ruleTag": "missing-window",
			"action": "limit",
			"limit": {
				"key": "srcIp",
				"mode": "newConnections",
				"maxConnections": 2
			},
			"inboundTag": ["socks"]
		}`),
		json.RawMessage(`{
			"ruleTag": "active-with-window",
			"action": "limit",
			"limit": {
				"key": "srcIp",
				"mode": "activeConnections",
				"windowSeconds": 10,
				"maxConnections": 2
			},
			"inboundTag": ["socks"]
		}`),
	}

	for _, rawRule := range tests {
		cfg := &FirewallConfig{RuleList: []json.RawMessage{rawRule}}
		if _, err := cfg.Build(); err == nil {
			t.Fatalf("expected Build() to fail for rule %s", string(rawRule))
		}
	}
}

func TestFirewallConfigBuildParsesSourcePrefixLimit(t *testing.T) {
	rawRule := json.RawMessage(`{
		"ruleTag": "src-prefix",
		"action": "limit",
		"limit": {
			"key": "srcPrefix",
			"maxConnections": 4
		},
		"sourceIP": ["203.0.113.0/24"]
	}`)

	cfg := &FirewallConfig{
		RuleList: []json.RawMessage{rawRule},
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if built.Rule[0].Limit == nil || built.Rule[0].Limit.Key != appfirewall.ConnectionLimit_SrcPrefix {
		t.Fatalf("limit = %#v, want src prefix", built.Rule[0].Limit)
	}
}

func TestFirewallConfigRejectsPrefixLimitWithoutExplicitCIDR(t *testing.T) {
	tests := []json.RawMessage{
		json.RawMessage(`{
			"ruleTag": "src-prefix-missing",
			"action": "limit",
			"limit": {
				"key": "srcPrefix",
				"maxConnections": 2
			},
			"inboundTag": ["socks"]
		}`),
		json.RawMessage(`{
			"ruleTag": "dst-prefix-missing",
			"action": "limit",
			"limit": {
				"key": "dstPrefix",
				"maxConnections": 2
			},
			"inboundTag": ["socks"]
		}`),
		json.RawMessage(`{
			"ruleTag": "src-prefix-reverse",
			"action": "limit",
			"limit": {
				"key": "srcPrefix",
				"maxConnections": 2
			},
			"sourceIP": ["!203.0.113.0/24"]
		}`),
	}

	for _, rawRule := range tests {
		cfg := &FirewallConfig{RuleList: []json.RawMessage{rawRule}}
		if _, err := cfg.Build(); err == nil {
			t.Fatalf("expected Build() to fail for rule %s", string(rawRule))
		}
	}
}
