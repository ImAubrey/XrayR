package metrics

import (
	"fmt"
	"testing"

	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/features/routing"
)

type testNodesRouter struct {
	tags      []string
	overrides map[string]string
	principle map[string][]string
	infos     map[string]routing.BalancerInfo
	resolved  map[string]string
}

func (r *testNodesRouter) Type() interface{} { return routing.RouterType() }
func (r *testNodesRouter) Start() error      { return nil }
func (r *testNodesRouter) Close() error      { return nil }
func (r *testNodesRouter) PickRoute(routing.Context) (routing.Route, error) {
	return nil, nil
}
func (r *testNodesRouter) AddRule(*serial.TypedMessage, bool) error { return nil }
func (r *testNodesRouter) RemoveRule(string) error                  { return nil }
func (r *testNodesRouter) ListBalancerTags() []string               { return append([]string{}, r.tags...) }
func (r *testNodesRouter) GetOverrideTarget(tag string) (string, error) {
	return r.overrides[tag], nil
}
func (r *testNodesRouter) SetOverrideTarget(string, string) error { return nil }
func (r *testNodesRouter) GetPrincipleTarget(tag string) ([]string, error) {
	return append([]string{}, r.principle[tag]...), nil
}
func (r *testNodesRouter) GetBalancerInfo(tag string) (routing.BalancerInfo, error) {
	info, ok := r.infos[tag]
	if !ok {
		return routing.BalancerInfo{}, fmt.Errorf("balancer %q not found", tag)
	}
	return info, nil
}
func (r *testNodesRouter) ResolveDestination(destination string) (string, error) {
	if value, ok := r.resolved[destination]; ok {
		return value, nil
	}
	return "", fmt.Errorf("cannot resolve %q", destination)
}

func TestFetchBalancerGroups_FallbackCurrentTarget(t *testing.T) {
	router := &testNodesRouter{
		tags:      []string{"auto"},
		overrides: map[string]string{},
		principle: map[string][]string{"auto": []string{"main-a", "backup-a"}},
		infos: map[string]routing.BalancerInfo{
			"auto": {Tag: "auto", Strategy: "fallback", FallbackTag: "backup-"},
		},
		resolved: map[string]string{"auto": "backup-a"},
	}

	groups, err := fetchBalancerGroups(router)
	if err != nil {
		t.Fatalf("fetchBalancerGroups failed: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("unexpected group count: %d", len(groups))
	}
	if groups[0].CurrentTarget != "backup-a" {
		t.Fatalf("unexpected current target: got=%q want=%q", groups[0].CurrentTarget, "backup-a")
	}
}

func TestFetchBalancerGroups_FallbackTagCurrentTargetForNonFallbackStrategy(t *testing.T) {
	router := &testNodesRouter{
		tags:      []string{"auto"},
		overrides: map[string]string{},
		principle: map[string][]string{"auto": []string{"main-a", "backup-a"}},
		infos: map[string]routing.BalancerInfo{
			"auto": {Tag: "auto", Strategy: "selector", FallbackTag: "backup-a"},
		},
		resolved: map[string]string{"auto": "backup-a"},
	}

	groups, err := fetchBalancerGroups(router)
	if err != nil {
		t.Fatalf("fetchBalancerGroups failed: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("unexpected group count: %d", len(groups))
	}
	if groups[0].CurrentTarget != "backup-a" {
		t.Fatalf("unexpected current target: got=%q want=%q", groups[0].CurrentTarget, "backup-a")
	}
}

func TestFetchBalancerGroups_SelectorCurrentTargetWithoutFallbackTag(t *testing.T) {
	router := &testNodesRouter{
		tags:      []string{"auto"},
		overrides: map[string]string{},
		principle: map[string][]string{"auto": []string{"main-a", "backup-a"}},
		infos: map[string]routing.BalancerInfo{
			"auto": {Tag: "auto", Strategy: "selector", FallbackTag: ""},
		},
		resolved: map[string]string{"auto": "main-a"},
	}

	groups, err := fetchBalancerGroups(router)
	if err != nil {
		t.Fatalf("fetchBalancerGroups failed: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("unexpected group count: %d", len(groups))
	}
	if groups[0].CurrentTarget != "main-a" {
		t.Fatalf("unexpected current target: got=%q want=%q", groups[0].CurrentTarget, "main-a")
	}
}

func TestEnrichBalancerStatuses_PassThroughCurrentTarget(t *testing.T) {
	groups := []balancerGroupView{
		{
			Tag:           "group-a",
			Strategy:      "leastping",
			CurrentTarget: "out-a",
		},
	}
	statuses := map[string]nodeStatusView{
		"out-a": {
			Alive:        true,
			Delay:        86,
			LastSeenTime: 101,
			LastTryTime:  102,
		},
	}

	enrichBalancerStatuses(groups, statuses)

	got, ok := statuses["group-a"]
	if !ok {
		t.Fatalf("missing status for group-a")
	}
	if !got.Alive || got.Delay != 86 {
		t.Fatalf("unexpected balancer status: %+v", got)
	}
	if got.LastSeenTime != 101 || got.LastTryTime != 102 {
		t.Fatalf("unexpected balancer status times: %+v", got)
	}
}

func TestEnrichBalancerStatuses_LoadBalancerUsesMedianDelay(t *testing.T) {
	groups := []balancerGroupView{
		{
			Tag:              "group-lb",
			Strategy:         "leastload",
			PrincipleTargets: []string{"out-a", "out-b", "out-c"},
		},
	}
	statuses := map[string]nodeStatusView{
		"out-a": {
			Alive:        true,
			Delay:        80,
			LastSeenTime: 100,
			LastTryTime:  110,
		},
		"out-b": {
			Alive:        true,
			Delay:        200,
			LastSeenTime: 120,
			LastTryTime:  130,
		},
		"out-c": {
			Alive:        false,
			Delay:        20,
			LastSeenTime: 140,
			LastTryTime:  150,
		},
	}

	enrichBalancerStatuses(groups, statuses)

	got, ok := statuses["group-lb"]
	if !ok {
		t.Fatalf("missing status for group-lb")
	}
	if !got.Alive {
		t.Fatalf("expected group-lb alive, got %+v", got)
	}
	if got.Delay != 140 {
		t.Fatalf("unexpected median delay: got=%d want=%d", got.Delay, 140)
	}
	if got.LastSeenTime != 120 || got.LastTryTime != 130 {
		t.Fatalf("unexpected balancer status times: %+v", got)
	}
}

func TestEnrichBalancerStatuses_LoadBalancerSupportsNestedBalancerMembers(t *testing.T) {
	groups := []balancerGroupView{
		{
			Tag:              "group-a",
			Strategy:         "leastload",
			PrincipleTargets: []string{"group-b", "out-a", "out-c"},
		},
		{
			Tag:           "group-b",
			Strategy:      "selector",
			CurrentTarget: "out-b",
		},
	}
	statuses := map[string]nodeStatusView{
		"out-a": {
			Alive:        true,
			Delay:        60,
			LastSeenTime: 210,
			LastTryTime:  220,
		},
		"out-b": {
			Alive:        true,
			Delay:        180,
			LastSeenTime: 230,
			LastTryTime:  240,
		},
		"out-c": {
			Alive:        false,
			Delay:        30,
			LastSeenTime: 250,
			LastTryTime:  260,
		},
	}

	enrichBalancerStatuses(groups, statuses)

	groupB, ok := statuses["group-b"]
	if !ok {
		t.Fatalf("missing status for group-b")
	}
	if !groupB.Alive || groupB.Delay != 180 {
		t.Fatalf("unexpected group-b status: %+v", groupB)
	}

	groupA, ok := statuses["group-a"]
	if !ok {
		t.Fatalf("missing status for group-a")
	}
	if !groupA.Alive {
		t.Fatalf("expected group-a alive, got %+v", groupA)
	}
	if groupA.Delay != 120 {
		t.Fatalf("unexpected nested median delay: got=%d want=%d", groupA.Delay, 120)
	}
	if groupA.LastSeenTime != 230 || groupA.LastTryTime != 240 {
		t.Fatalf("unexpected nested status times: %+v", groupA)
	}
}
