package core

import (
	"encoding/json"
	"testing"
)

func TestNormalizeManagedSubscriptionName_StringAndObject(t *testing.T) {
	if got := normalizeManagedSubscriptionName(map[string]any{
		"managed": "anet",
	}); got != "anet" {
		t.Fatalf("expected managed string subscription anet, got %q", got)
	}
	if got := normalizeManagedSubscriptionName(map[string]any{
		"managed": map[string]any{
			"subscription": "anet",
		},
	}); got != "anet" {
		t.Fatalf("expected managed object subscription anet, got %q", got)
	}
	if got := normalizeManagedSubscriptionName(map[string]any{
		"subscription": "anet",
		"managed":      "other",
	}); got != "anet" {
		t.Fatalf("expected top-level subscription takes precedence, got %q", got)
	}
}

func TestApplyRuntimeManagedOutboundRewrites_TagNotOverridden(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`{
			"tag":"anet-CN Datacenter",
			"protocol":"vless",
			"streamSettings":{"network":"tcp"}
		}`),
	}
	rewrites := map[string]map[string]any{
		"anet-CN Datacenter": {
			"tag":      "override-not-allowed",
			"protocol": "freedom",
			"streamSettings": map[string]any{
				"sockopt": map[string]any{
					"dialerProxy": "nuro",
				},
			},
		},
	}

	got := applyRuntimeManagedOutboundRewrites(raw, rewrites)
	if len(got) != 1 {
		t.Fatalf("expected 1 outbound raw message, got %d", len(got))
	}

	var ob map[string]any
	if err := json.Unmarshal(got[0], &ob); err != nil {
		t.Fatalf("unmarshal rewritten outbound: %v", err)
	}
	if ob["tag"] != "anet-CN Datacenter" {
		t.Fatalf("tag should not be overridden, got %v", ob["tag"])
	}
	if ob["protocol"] != "freedom" {
		t.Fatalf("protocol should be overridden, got %v", ob["protocol"])
	}
	stream, _ := ob["streamSettings"].(map[string]any)
	if stream == nil {
		t.Fatalf("expected streamSettings after rewrite")
	}
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt == nil {
		t.Fatalf("expected streamSettings.sockopt after rewrite")
	}
	if sockopt["dialerProxy"] != "nuro" {
		t.Fatalf("expected dialerProxy=nuro, got %v", sockopt["dialerProxy"])
	}
}
