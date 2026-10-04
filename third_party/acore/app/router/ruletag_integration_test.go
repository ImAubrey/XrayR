package router

import (
	"testing"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
)

// mock routing context with ruleTag storage.
type mockCtx struct {
	inTag    string
	domain   string
	skipDNS  bool
	ruleTags map[string]struct{}
}

func (m *mockCtx) GetInboundTag() string            { return m.inTag }
func (m *mockCtx) GetSourceIPs() []net.IP           { return nil }
func (m *mockCtx) GetSourcePort() net.Port          { return 0 }
func (m *mockCtx) GetTargetIPs() []net.IP           { return nil }
func (m *mockCtx) GetTargetPort() net.Port          { return 0 }
func (m *mockCtx) GetLocalIPs() []net.IP            { return nil }
func (m *mockCtx) GetLocalPort() net.Port           { return 0 }
func (m *mockCtx) GetTargetDomain() string          { return m.domain }
func (m *mockCtx) GetNetwork() net.Network          { return net.Network_Unknown }
func (m *mockCtx) GetProtocol() string              { return "" }
func (m *mockCtx) GetUser() string                  { return "" }
func (m *mockCtx) GetVlessRoute() net.Port          { return 0 }
func (m *mockCtx) GetAttributes() map[string]string { return nil }
func (m *mockCtx) GetSkipDNSResolve() bool          { return m.skipDNS }
func (m *mockCtx) AddRuleTag(tag string) {
	if tag == "" {
		return
	}
	if m.ruleTags == nil {
		m.ruleTags = map[string]struct{}{}
	}
	m.ruleTags[tag] = struct{}{}
}
func (m *mockCtx) HasRuleTag(tag string) bool { _, ok := m.ruleTags[tag]; return ok }

func newRule(cond Condition, tag, ruleTag string, hasTarget bool) *Rule {
	return &Rule{
		Condition: cond,
		Tag:       tag,
		RuleTag:   ruleTag,
		HasTarget: hasTarget,
	}
}

// Test that target-less rule writes ruleTag, and subsequent rule requiring it is matched.
func TestRuleTagAccumulateAndRequire(t *testing.T) {
	ctx := &mockCtx{inTag: "in"}

	cond1 := NewConditionChan()
	cond1.Add(NewInboundTagMatcher([]string{"in"}))
	r1 := newRule(cond1, "", "mark1", false)

	cond2 := NewConditionChan()
	cond2.Add(NewInboundTagMatcher([]string{"in"}))
	rtCond, _ := NewRuleTagCondition([]string{"mark1"})
	cond2.Add(rtCond)
	r2 := newRule(cond2, "out1", "route1", true)

	router := &Router{rules: []*Rule{r1, r2}}

	rule, _, err := router.pickRouteInternal(ctx)
	if err != nil {
		t.Fatalf("expected route, got err: %v", err)
	}
	if rule.RuleTag != "route1" || rule.Tag != "out1" {
		t.Fatalf("unexpected rule selected: %+v", rule)
	}
	if !ctx.HasRuleTag("mark1") {
		t.Fatalf("expected ruleTag mark1 to be recorded")
	}
}

// Test negative match with !tag.
func TestRuleTagExclude(t *testing.T) {
	ctx := &mockCtx{inTag: "in", ruleTags: map[string]struct{}{"blocked": {}}}

	cond := NewConditionChan()
	cond.Add(NewInboundTagMatcher([]string{"in"}))
	rtCond, _ := NewRuleTagCondition([]string{"!blocked"})
	cond.Add(rtCond)
	r := newRule(cond, "out1", "route1", true)

	router := &Router{rules: []*Rule{r}}
	_, _, err := router.pickRouteInternal(ctx)
	if err == nil {
		t.Fatalf("expected no route due to !blocked")
	}
	if err != common.ErrNoClue {
		t.Fatalf("expected ErrNoClue, got %v", err)
	}
}

// Test domain match with ruleTag recording.
func TestRuleTagDomainMatch(t *testing.T) {
	ctx := &mockCtx{domain: "example.com"}

	dm, _ := NewMphMatcherGroup([]*Domain{{Type: Domain_Domain, Value: "example.com"}})
	cond1 := NewConditionChan()
	cond1.Add(dm)
	r1 := newRule(cond1, "", "dom", false)

	cond2 := NewConditionChan()
	rtCond, _ := NewRuleTagCondition([]string{"dom"})
	cond2.Add(rtCond)
	r2 := newRule(cond2, "out2", "route2", true)

	router := &Router{rules: []*Rule{r1, r2}}
	rule, _, err := router.pickRouteInternal(ctx)
	if err != nil {
		t.Fatalf("expected route, got %v", err)
	}
	if rule.Tag != "out2" {
		t.Fatalf("expected out2, got %s", rule.Tag)
	}
}
