package conf

import (
	"encoding/json"
	"strconv"
	"testing"
)

func TestManagedOutboundConfig_StringRoundtripAsObject(t *testing.T) {
	var managed ManagedOutboundConfig
	if err := json.Unmarshal([]byte(`"anet"`), &managed); err != nil {
		t.Fatalf("unmarshal managed string: %v", err)
	}
	if managed.Subscription != "anet" {
		t.Fatalf("expected subscription anet, got %q", managed.Subscription)
	}
	b, err := json.Marshal(managed)
	if err != nil {
		t.Fatalf("marshal managed: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatalf("unmarshal marshaled managed: %v", err)
	}
	if got := obj["subscription"]; got != "anet" {
		t.Fatalf("expected managed.subscription anet, got %v", got)
	}
	if _, exists := obj["rewrite"]; exists {
		t.Fatalf("did not expect rewrite in marshaled object")
	}
}

func TestManagedOutboundConfig_RewriteDropsTag(t *testing.T) {
	var managed ManagedOutboundConfig
	payload := `{
		"subscription":"anet",
		"rewrite":{
			"tag":"must-not-apply",
			"protocol":"freedom",
			"streamSettings":{"sockopt":{"dialerProxy":"nuro"}}
		}
	}`
	if err := json.Unmarshal([]byte(payload), &managed); err != nil {
		t.Fatalf("unmarshal managed object: %v", err)
	}
	if managed.Subscription != "anet" {
		t.Fatalf("expected subscription anet, got %q", managed.Subscription)
	}
	if managed.Rewrite == nil {
		t.Fatalf("expected rewrite not nil")
	}
	if _, exists := managed.Rewrite["tag"]; exists {
		t.Fatalf("rewrite.tag should be sanitized away")
	}
	if got := managed.Rewrite["protocol"]; got != "freedom" {
		t.Fatalf("expected rewrite.protocol=freedom, got %v", got)
	}
}

func TestApplyManagedOutboundRewrites_TagNotOverridden(t *testing.T) {
	outbounds := []OutboundDetourConfig{
		{
			Tag:      "anet-CN Datacenter",
			Protocol: "vless",
		},
	}
	rewrites := map[string]map[string]any{
		"anet-CN Datacenter": {
			"tag":      "override-not-allowed",
			"protocol": "freedom",
		},
	}

	rewritten := applyManagedOutboundRewrites(outbounds, rewrites)
	if len(rewritten) != 1 {
		t.Fatalf("expected one outbound, got %d", len(rewritten))
	}
	if rewritten[0].Tag != "anet-CN Datacenter" {
		t.Fatalf("tag should not be overridden, got %q", rewritten[0].Tag)
	}
	if rewritten[0].Protocol != "freedom" {
		t.Fatalf("protocol should be overridden by rewrite, got %q", rewritten[0].Protocol)
	}
}

func TestCollectManagedOutboundRewritesForSubscription(t *testing.T) {
	list := []OutboundDetourConfig{
		{
			Tag: "a-1",
			Managed: &ManagedOutboundConfig{
				Subscription: "a",
				Rewrite: map[string]any{
					"protocol": "freedom",
				},
			},
		},
		{
			Tag: "b-1",
			Managed: &ManagedOutboundConfig{
				Subscription: "b",
				Rewrite: map[string]any{
					"protocol": "blackhole",
				},
			},
		},
	}

	rewrites := collectManagedOutboundRewritesForSubscription(list, "a")
	if len(rewrites) != 1 {
		t.Fatalf("expected 1 rewrite for subscription a, got %d", len(rewrites))
	}
	if rewrites["a-1"]["protocol"] != "freedom" {
		t.Fatalf("expected rewrite for a-1 protocol freedom, got %v", rewrites["a-1"]["protocol"])
	}
	if _, exists := rewrites["b-1"]; exists {
		t.Fatalf("did not expect b-1 in rewrites for subscription a")
	}
}

func BenchmarkCollectManagedOutboundRewritesForSubscription(b *testing.B) {
	list := make([]OutboundDetourConfig, 0, 2000)
	for i := 0; i < 2000; i++ {
		sub := "other"
		if i%3 == 0 {
			sub = "anet"
		}
		list = append(list, OutboundDetourConfig{
			Tag: "tag-" + strconv.Itoa(i),
			Managed: &ManagedOutboundConfig{
				Subscription: sub,
				Rewrite: map[string]any{
					"protocol": "freedom",
					"settings": map[string]any{"domainStrategy": "UseIP"},
				},
			},
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = collectManagedOutboundRewritesForSubscription(list, "anet")
	}
}
