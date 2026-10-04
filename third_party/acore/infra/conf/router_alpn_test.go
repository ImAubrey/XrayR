package conf_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	. "github.com/ImAubrey/acore/infra/conf"
)

func TestRoutingRuleALPNArrayIsParsedIntoProtocolMatchers(t *testing.T) {
	rule, err := ParseRule(json.RawMessage(`{
		"type": "field",
		"ruleTag": "r",
		"protocol": ["tls"],
		"alpn": ["!alpn:h2", "h3", "alpn=apns-security-v3"]
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := rule.GetProtocol()
	want := []string{"tls", "!alpn:h2", "alpn:h3", "alpn=apns-security-v3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected protocol matchers, got=%v want=%v", got, want)
	}
}

func TestRoutingRuleALPNArrayRejectsInvalidNegation(t *testing.T) {
	_, err := ParseRule(json.RawMessage(`{
		"type": "field",
		"ruleTag": "r",
		"alpn": ["!"]
	}`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid alpn rule") {
		t.Fatalf("expected invalid alpn rule error, got: %v", err)
	}
}
