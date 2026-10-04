package metrics

import (
	"bytes"
	"net/http/httptest"
	"testing"

	dnscfg "github.com/ImAubrey/acore/app/dns"
	applog "github.com/ImAubrey/acore/app/log"
	observatorycfg "github.com/ImAubrey/acore/app/observatory"
	routercfg "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/routing"
)

type hotReloadRouterMock struct {
	lastConfig   *routercfg.Config
	lastAppend   bool
	addRuleCalls int
}

func (m *hotReloadRouterMock) Type() interface{} { return routing.RouterType() }
func (m *hotReloadRouterMock) Start() error      { return nil }
func (m *hotReloadRouterMock) Close() error      { return nil }
func (m *hotReloadRouterMock) PickRoute(routing.Context) (routing.Route, error) {
	return nil, nil
}
func (m *hotReloadRouterMock) AddRule(msg *serial.TypedMessage, shouldAppend bool) error {
	m.addRuleCalls++
	m.lastAppend = shouldAppend
	inst, err := msg.GetInstance()
	if err != nil {
		return err
	}
	cfg, ok := inst.(*routercfg.Config)
	if !ok {
		return nil
	}
	m.lastConfig = cfg
	return nil
}
func (m *hotReloadRouterMock) RemoveRule(string) error { return nil }

func TestExtractRouterConfigMessage_WithRouterConfig(t *testing.T) {
	wantRuleTag := "r1"
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dnscfg.Config{}),
			serial.ToTypedMessage(&routercfg.Config{
				Rule: []*routercfg.RoutingRule{{
					RuleTag:   wantRuleTag,
					TargetTag: &routercfg.RoutingRule_Tag{Tag: "direct"},
				}},
				BalancingRule: []*routercfg.BalancingRule{{
					Tag:              "b1",
					OutboundSelector: []string{"o_"},
				}},
			}),
		},
	}

	msg, err := extractRouterConfigMessage(cfg)
	if err != nil {
		t.Fatalf("extractRouterConfigMessage failed: %v", err)
	}
	inst, err := msg.GetInstance()
	if err != nil {
		t.Fatalf("typed message decode failed: %v", err)
	}
	routerCfg, ok := inst.(*routercfg.Config)
	if !ok {
		t.Fatalf("unexpected message type: %T", inst)
	}
	if len(routerCfg.Rule) != 1 || routerCfg.Rule[0].GetRuleTag() != wantRuleTag {
		t.Fatalf("unexpected rules: %#v", routerCfg.Rule)
	}
	if len(routerCfg.BalancingRule) != 1 || routerCfg.BalancingRule[0].GetTag() != "b1" {
		t.Fatalf("unexpected balancers: %#v", routerCfg.BalancingRule)
	}
}

func TestExtractRouterConfigMessage_WithoutRouterConfigReturnsEmptyRouter(t *testing.T) {
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dnscfg.Config{}),
		},
	}

	msg, err := extractRouterConfigMessage(cfg)
	if err != nil {
		t.Fatalf("extractRouterConfigMessage failed: %v", err)
	}
	inst, err := msg.GetInstance()
	if err != nil {
		t.Fatalf("typed message decode failed: %v", err)
	}
	routerCfg, ok := inst.(*routercfg.Config)
	if !ok {
		t.Fatalf("unexpected message type: %T", inst)
	}
	if len(routerCfg.Rule) != 0 || len(routerCfg.BalancingRule) != 0 {
		t.Fatalf("expected empty router config, got: %#v", routerCfg)
	}
}

func TestApplyHotReloadRules_ReloadsRouterRulesAndBalancers(t *testing.T) {
	mock := &hotReloadRouterMock{}
	setNodesDependencies(nil, mock, nil)
	t.Cleanup(func() { setNodesDependencies(nil, nil, nil) })

	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dnscfg.Config{}),
			serial.ToTypedMessage(&routercfg.Config{
				Rule: []*routercfg.RoutingRule{{
					RuleTag:   "r1",
					TargetTag: &routercfg.RoutingRule_Tag{Tag: "direct"},
				}},
				BalancingRule: []*routercfg.BalancingRule{{
					Tag:              "b1",
					OutboundSelector: []string{"o_"},
				}},
			}),
		},
	}

	if err := applyHotReloadRules(cfg); err != nil {
		t.Fatalf("applyHotReloadRules failed: %v", err)
	}
	if mock.addRuleCalls != 1 {
		t.Fatalf("expected AddRule called once, got %d", mock.addRuleCalls)
	}
	if mock.lastAppend {
		t.Fatalf("expected shouldAppend=false, got true")
	}
	if mock.lastConfig == nil {
		t.Fatalf("expected router config passed to AddRule")
	}
	if len(mock.lastConfig.Rule) != 1 || mock.lastConfig.Rule[0].GetRuleTag() != "r1" {
		t.Fatalf("unexpected rules in AddRule: %#v", mock.lastConfig.Rule)
	}
	if len(mock.lastConfig.BalancingRule) != 1 || mock.lastConfig.BalancingRule[0].GetTag() != "b1" {
		t.Fatalf("unexpected balancers in AddRule: %#v", mock.lastConfig.BalancingRule)
	}
}

func TestApplyHotReloadRules_NonRouterSectionsAreIgnored(t *testing.T) {
	mock := &hotReloadRouterMock{}
	setNodesDependencies(nil, mock, nil)
	t.Cleanup(func() { setNodesDependencies(nil, nil, nil) })

	cfg := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{Tag: "in1"}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "out1",
		}},
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dnscfg.Config{}),
		},
	}

	if err := applyHotReloadRules(cfg); err != nil {
		t.Fatalf("applyHotReloadRules failed: %v", err)
	}
	if mock.lastConfig == nil {
		t.Fatalf("expected router AddRule call")
	}
	if len(mock.lastConfig.Rule) != 0 || len(mock.lastConfig.BalancingRule) != 0 {
		t.Fatalf("expected empty router config for non-router hot reload, got: %#v", mock.lastConfig)
	}
}

func TestApplyHotReloadRules_RouterUnavailable(t *testing.T) {
	setNodesDependencies(nil, nil, nil)
	err := applyHotReloadRules(&core.Config{})
	if err == nil {
		t.Fatal("expected error when router is unavailable")
	}
}

func TestDecideHotReloadMode(t *testing.T) {
	if got := decideHotReloadMode([]string{"routing"}); got != "rulesOnly" {
		t.Fatalf("unexpected mode for routing-only hot reload: %q", got)
	}
	if got := decideHotReloadMode([]string{"routing", "outbounds"}); got != "dynamic" {
		t.Fatalf("unexpected mode for mixed targets: %q", got)
	}
	if got := decideHotReloadMode(nil); got != "rulesOnly" {
		t.Fatalf("unexpected mode for empty targets: %q", got)
	}
}

func TestNormalizeHotReloadTargets(t *testing.T) {
	got := normalizeHotReloadTargets([]string{" routing ", "DNS", "routing", "unknown", ""})
	want := []string{"routing", "dns"}
	if len(got) != len(want) {
		t.Fatalf("unexpected target count: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected targets: got=%v want=%v", got, want)
		}
	}
}

func TestDecodeHotReloadTargets(t *testing.T) {
	req := httptest.NewRequest("POST", "/core/hotreload", bytes.NewBufferString(`{"targets":["routing","outbounds","routing"]}`))
	got, err := decodeHotReloadTargets(req)
	if err != nil {
		t.Fatalf("decodeHotReloadTargets failed: %v", err)
	}
	want := []string{"routing", "outbounds"}
	if len(got) != len(want) {
		t.Fatalf("unexpected target count: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected targets: got=%v want=%v", got, want)
		}
	}
}

func TestDecodeHotReloadTargets_InvalidTarget(t *testing.T) {
	req := httptest.NewRequest("POST", "/core/hotreload", bytes.NewBufferString(`{"targets":["routing","invalid"]}`))
	if _, err := decodeHotReloadTargets(req); err == nil {
		t.Fatal("expected error for invalid targets")
	}
}

func TestDecodeHotReloadTargets_NoValidTarget(t *testing.T) {
	req := httptest.NewRequest("POST", "/core/hotreload", bytes.NewBufferString(`{"targets":[" ",""]}`))
	if _, err := decodeHotReloadTargets(req); err == nil {
		t.Fatal("expected error for empty target set")
	}
}

func TestExpandHotReloadTargets_All(t *testing.T) {
	got := expandHotReloadTargets([]string{"all"})
	want := []string{"outbounds", "inbounds", "routing", "subscription", "main"}
	if len(got) != len(want) {
		t.Fatalf("unexpected expanded target count: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected expanded targets: got=%v want=%v", got, want)
		}
	}
}

func TestBuildHotReloadPlan_DeduplicatesMainAndNestedTargets(t *testing.T) {
	plan, err := buildHotReloadPlan([]string{"dns", "main", "observatory"})
	if err != nil {
		t.Fatalf("buildHotReloadPlan failed: %v", err)
	}
	want := []hotReloadAction{
		hotReloadActionDNS,
		hotReloadActionObservatory,
		hotReloadActionLog,
	}
	if len(plan) != len(want) {
		t.Fatalf("unexpected plan length: got=%v want=%v", plan, want)
	}
	for i := range want {
		if plan[i] != want[i] {
			t.Fatalf("unexpected plan: got=%v want=%v", plan, want)
		}
	}
}

func TestBuildHotReloadPlan_All(t *testing.T) {
	plan, err := buildHotReloadPlan([]string{"all"})
	if err != nil {
		t.Fatalf("buildHotReloadPlan failed: %v", err)
	}
	want := []hotReloadAction{
		hotReloadActionOutbounds,
		hotReloadActionInbounds,
		hotReloadActionRouting,
		hotReloadActionSubscription,
		hotReloadActionDNS,
		hotReloadActionObservatory,
		hotReloadActionLog,
	}
	if len(plan) != len(want) {
		t.Fatalf("unexpected plan length: got=%v want=%v", plan, want)
	}
	for i := range want {
		if plan[i] != want[i] {
			t.Fatalf("unexpected plan: got=%v want=%v", plan, want)
		}
	}
}

func TestFindAppTypedMessage(t *testing.T) {
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dnscfg.Config{}),
			serial.ToTypedMessage(&applog.Config{}),
			serial.ToTypedMessage(&observatorycfg.Config{}),
		},
	}
	msg := findAppTypedMessage(cfg, serial.GetMessageType(&applog.Config{}))
	if msg == nil {
		t.Fatal("expected matched typed message for log config")
	}
	raw, err := msg.GetInstance()
	if err != nil {
		t.Fatalf("typed message decode failed: %v", err)
	}
	if _, ok := raw.(*applog.Config); !ok {
		t.Fatalf("unexpected decoded type: %T", raw)
	}
}
