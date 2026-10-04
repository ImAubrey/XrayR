package conf

import (
	"testing"

	approuter "github.com/ImAubrey/acore/app/router"
)

func TestParseDomainRuleMatchEmpty(t *testing.T) {
	rules, err := parseDomainRule("!")
	if err != nil {
		t.Fatalf("parseDomainRule(!) failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 domain rule, got %d", len(rules))
	}

	r := rules[0]
	if r.Type != approuter.Domain_Plain {
		t.Fatalf("expected Domain_Plain, got %v", r.Type)
	}
	if r.Value != "" {
		t.Fatalf("expected empty domain value, got %q", r.Value)
	}

	found := false
	for _, attr := range r.Attribute {
		if attr.GetKey() == approuter.DomainAttrMatchEmpty && attr.GetBoolValue() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q=true attribute", approuter.DomainAttrMatchEmpty)
	}
}
