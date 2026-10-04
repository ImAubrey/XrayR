package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/ImAubrey/acore/app/router"
	. "github.com/ImAubrey/acore/infra/conf"
)

func TestParseRuleJA4AttributeFromLabelUsesDefaultJA4DB(t *testing.T) {
	ruleJSON := json.RawMessage(`{
		"type": "field",
		"attrs": {
			"ja4": "threat:malware"
		},
		"outboundTag": "block"
	}`)
	rule, err := ParseRule(ruleJSON)
	if err != nil {
		t.Fatalf("ParseRule returned error: %v", err)
	}

	value := rule.Attributes["ja4"]
	file, tag, ok := router.DecodeJA4DBAttributeValue(value)
	if !ok {
		t.Fatalf("expected encoded ja4-db value, got: %q", value)
	}
	if file != "ja4.db" || tag != "threat:malware" {
		t.Fatalf("unexpected ja4 ref: file=%q tag=%q", file, tag)
	}
}

func TestParseRuleJA4AttributeDirectFingerprintPreserved(t *testing.T) {
	const fp = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	ruleJSON := json.RawMessage(`{
		"type": "field",
		"attrs": {
			"ja4": "` + fp + `"
		},
		"outboundTag": "block"
	}`)
	rule, err := ParseRule(ruleJSON)
	if err != nil {
		t.Fatalf("ParseRule returned error: %v", err)
	}

	if got := rule.Attributes["ja4"]; got != fp {
		t.Fatalf("expected direct ja4 fingerprint to be preserved, got %q", got)
	}
}

func TestParseRuleJA4AttributeLegacyPrefixNoLongerSpecial(t *testing.T) {
	ruleJSON := json.RawMessage(`{
		"type": "field",
		"attrs": {
			"ja4": "ja4:malware"
		},
		"outboundTag": "block"
	}`)
	rule, err := ParseRule(ruleJSON)
	if err != nil {
		t.Fatalf("ParseRule returned error: %v", err)
	}

	value := rule.Attributes["ja4"]
	file, tag, ok := router.DecodeJA4DBAttributeValue(value)
	if !ok {
		t.Fatalf("expected encoded ja4-db value, got: %q", value)
	}
	if file != "ja4.db" || tag != "ja4:malware" {
		t.Fatalf("unexpected ja4 ref: file=%q tag=%q", file, tag)
	}
}

func TestParseRuleJA4AttributeEmptyIsAllowedForSniffTrigger(t *testing.T) {
	ruleJSON := json.RawMessage(`{
		"type": "field",
		"attrs": {
			"ja4": ""
		},
		"outboundTag": "block"
	}`)
	rule, err := ParseRule(ruleJSON)
	if err != nil {
		t.Fatalf("ParseRule returned error: %v", err)
	}

	if got := rule.Attributes["ja4"]; got != "" {
		t.Fatalf("expected empty ja4 attr to be preserved, got %q", got)
	}
}
