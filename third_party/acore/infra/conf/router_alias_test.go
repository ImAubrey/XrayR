package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ImAubrey/acore/app/router"
	. "github.com/ImAubrey/acore/infra/conf"
)

func TestRoutingRuleTargetAliasConflicts(t *testing.T) {
	cases := []struct {
		name string
		rule string
	}{
		{
			name: "destination_outboundTag_conflict",
			rule: `{"type":"field","destination":"direct","outboundTag":"proxy","ruleTag":"r"}`,
		},
		{
			name: "destination_balancerTag_conflict",
			rule: `{"type":"field","destination":"direct","balancerTag":"round","ruleTag":"r"}`,
		},
		{
			name: "destination_object_outboundTag_conflict",
			rule: `{"type":"field","destination":{"tag":"direct","vlessRoute":"1"},"outboundTag":"proxy","ruleTag":"r"}`,
		},
		{
			name: "outboundTag_balancerTag_conflict",
			rule: `{"type":"field","outboundTag":"proxy","balancerTag":"round","ruleTag":"r"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRule(json.RawMessage(tc.rule))
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), "target conflict") {
				t.Fatalf("expected target conflict error, got: %v", err)
			}
		})
	}
}

func TestRoutingRuleTargetAliasAcceptsSameValue(t *testing.T) {
	rule, err := ParseRule(json.RawMessage(`{
		"type": "field",
		"destination": "direct",
		"outboundTag": "direct",
		"balancerTag": "direct",
		"ruleTag": "r"
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rule.GetTag(); got != "direct" {
		t.Fatalf("expected tag=direct, got: %q", got)
	}
	if got := rule.GetBalancingTag(); got != "" {
		t.Fatalf("expected balancingTag to be empty, got: %q", got)
	}
}

func TestRoutingRuleTargetAliasMapsBalancerTagToDestination(t *testing.T) {
	rule, err := ParseRule(json.RawMessage(`{
		"type": "field",
		"balancerTag": "round",
		"ruleTag": "r"
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rule.GetTag(); got != "round" {
		t.Fatalf("expected tag=round, got: %q", got)
	}
	if got := rule.GetBalancingTag(); got != "" {
		t.Fatalf("expected balancingTag to be empty, got: %q", got)
	}
}

func TestRoutingRuleDestinationObjectWithoutVlessRouteMatchesStringDestination(t *testing.T) {
	rule, err := ParseRule(json.RawMessage(`{
		"type":"field",
		"destination":{"tag":"direct"},
		"ruleTag":"r"
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rule.GetTag(); got != "direct" {
		t.Fatalf("expected tag=direct, got: %q", got)
	}
	if got := rule.GetAttributes()[router.InternalDestVlessRouteAttr]; got != "" {
		t.Fatalf("expected no %s, got %q", router.InternalDestVlessRouteAttr, got)
	}
}

func TestRoutingRuleDestinationObjectParsesVlessRouteDecimalAndHex(t *testing.T) {
	cases := []struct {
		name  string
		rule  string
		value string
	}{
		{
			name:  "decimal_number",
			rule:  `{"type":"field","destination":{"tag":"proxy","vlessRoute":4660},"ruleTag":"r"}`,
			value: "4660",
		},
		{
			name:  "hex_string",
			rule:  `{"type":"field","destination":{"tag":"proxy","vlessRoute":"0xffff"},"ruleTag":"r"}`,
			value: "65535",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := ParseRule(json.RawMessage(tc.rule))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := rule.GetAttributes()[router.InternalDestVlessRouteAttr]; got != tc.value {
				t.Fatalf("expected %s=%q, got %q", router.InternalDestVlessRouteAttr, tc.value, got)
			}
		})
	}
}

func TestRoutingRuleDestinationObjectRejectsOutOfRangeVlessRoute(t *testing.T) {
	_, err := ParseRule(json.RawMessage(`{"type":"field","destination":{"tag":"proxy","vlessRoute":"0x10000"},"ruleTag":"r"}`))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "destVlessRoute") {
		t.Fatalf("expected destVlessRoute error, got: %v", err)
	}
}

func TestRoutingRuleDestinationObjectRequiresTag(t *testing.T) {
	_, err := ParseRule(json.RawMessage(`{"type":"field","destination":{"vlessRoute":"1"},"ruleTag":"r"}`))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "invalid destination") {
		t.Fatalf("expected invalid destination error, got: %v", err)
	}
}
