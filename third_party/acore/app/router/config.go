package router

import (
	"context"
	"strings"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
)

type Rule struct {
	Tag                 string
	RuleTag             string
	Balancer            *Balancer
	Condition           Condition
	ConditionNoProtocol Condition
	// Used by JA4 passive sniffing pre-check to avoid circular dependency on attrs.
	ConditionNoProtocolNoAttrs Condition
	Protocols                  []string
	HasJA4Attribute            bool
	HasTarget                  bool
	HasFixedTarget             bool
	HasRequire                 bool
	MarkOnMatch                bool
	ReLookup                   bool
	HasDestVlessRoute          bool
	DestVlessRoute             net.Port
	VlessRouteTargets          []vlessRouteTargetMatcher
}

type vlessRouteTargetMatcher struct {
	destination string
	port        net.MemoryPortList
}

func (r *Rule) GetTag() (string, error) {
	if r.Balancer != nil {
		return r.Balancer.PickOutbound()
	}
	return r.Tag, nil
}

func appendFallbackSelector(selectors []string, fallback string) []string {
	if fallback == "" {
		return append([]string{}, selectors...)
	}
	for _, selector := range selectors {
		if selector == fallback {
			return append([]string{}, selectors...)
		}
	}
	next := append([]string{}, selectors...)
	next = append(next, fallback)
	return next
}

func (r *Rule) applyMatched(ctx routing.Context) {
	if tmgr, ok := ctx.(routing.RuleTagManager); ok {
		if r.RuleTag != "" {
			tmgr.AddRuleTag(r.RuleTag)
		}
	}
	if marker, ok := ctx.(interface {
		MarkRuleMatched()
	}); ok && r.MarkOnMatch {
		marker.MarkRuleMatched()
	}
}

func (r *Rule) protocolMatches(protocol string) bool {
	if len(r.Protocols) == 0 {
		return true
	}
	return matchProtocolPatterns(r.Protocols, protocol, "")
}

func (r *Rule) protocolNeedsSniff(protocol string) bool {
	return protocolPatternsNeedSniffing(r.Protocols, protocol)
}

func (r *Rule) pickVlessRouteTarget(route net.Port) (string, bool) {
	for _, target := range r.VlessRouteTargets {
		if target.port.Contains(route) {
			return target.destination, true
		}
	}
	return "", false
}

func (r *Rule) resolveTarget(ctx routing.Context) (*Rule, bool) {
	if tag, ok := r.pickVlessRouteTarget(ctx.GetVlessRoute()); ok {
		cloned := *r
		cloned.Tag = tag
		cloned.Balancer = nil
		cloned.HasFixedTarget = true
		return &cloned, true
	}
	if r.HasFixedTarget || (r.HasTarget && len(r.VlessRouteTargets) == 0) {
		return r, true
	}
	return nil, false
}

// Apply checks rule matching of current routing context.
func (r *Rule) Apply(ctx routing.Context) bool {
	if !r.Condition.Apply(ctx) {
		return false
	}
	r.applyMatched(ctx)
	return true
}

type trueCondition struct{}

func (*trueCondition) Apply(routing.Context) bool { return true }

func (rr *RoutingRule) buildCondition(skipProtocol bool) (Condition, error) {
	conds := NewConditionChan()

	// Apply requireRuleTag as early as possible to short-circuit expensive matchers.
	if len(rr.RequireRuleTag) > 0 {
		c, err := NewRuleTagCondition(rr.RequireRuleTag)
		if err != nil {
			return nil, err
		}
		conds.Add(c)
	}

	if len(rr.InboundTag) > 0 {
		conds.Add(NewInboundTagMatcher(rr.InboundTag))
	}

	if len(rr.Networks) > 0 {
		conds.Add(NewNetworkMatcher(rr.Networks))
	}

	if rr.PortList != nil {
		conds.Add(NewPortMatcher(rr.PortList, MatcherAsType_Target))
	}

	if rr.SourcePortList != nil {
		conds.Add(NewPortMatcher(rr.SourcePortList, MatcherAsType_Source))
	}

	if rr.LocalPortList != nil {
		conds.Add(NewPortMatcher(rr.LocalPortList, MatcherAsType_Local))
	}

	if rr.VlessRouteList != nil {
		conds.Add(NewPortMatcher(rr.VlessRouteList, MatcherAsType_VlessRoute))
	}

	if len(rr.UserEmail) > 0 {
		conds.Add(NewUserMatcher(rr.UserEmail))
	}

	// Protocol match is cheap (string prefix / ALPN attribute) and helps prune early.
	// It does NOT trigger sniffing; sniffing is decided by dispatcher.
	if !skipProtocol && len(rr.Protocol) > 0 {
		conds.Add(NewProtocolMatcher(rr.Protocol))
	}

	if len(rr.Domain) > 0 {
		matcher, err := NewMphMatcherGroup(rr.Domain)
		if err != nil {
			return nil, errors.New("failed to build domain condition with MphDomainMatcher").Base(err)
		}
		errors.LogDebug(context.Background(), "MphDomainMatcher is enabled for ", len(rr.Domain), " domain rule(s)")
		conds.Add(matcher)
	}

	if len(rr.Attributes) > 0 {
		attrCond, err := NewAttributeMatcher(rr.Attributes)
		if err != nil {
			return nil, errors.New("failed to build attribute matcher").Base(err)
		}
		if attrCond != nil {
			conds.Add(attrCond)
		}
	}

	// IP matchers may trigger DNS resolve via ctx.GetTargetIPs() in IpOnDemand / IpIfNonMatch second pass.
	// Keep them after cheap string/regex matchers to avoid unnecessary DNS work.
	if len(rr.Geoip) > 0 {
		cond, err := NewIPMatcher(rr.Geoip, MatcherAsType_Target)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
	}

	if len(rr.SourceGeoip) > 0 {
		cond, err := NewIPMatcher(rr.SourceGeoip, MatcherAsType_Source)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
	}

	if len(rr.LocalGeoip) > 0 {
		cond, err := NewIPMatcher(rr.LocalGeoip, MatcherAsType_Local)
		if err != nil {
			return nil, err
		}
		conds.Add(cond)
		errors.LogWarning(context.Background(), "Due to some limitations, in UDP connections, localIP is always equal to listen interface IP, so \"localIP\" rule condition does not work properly on UDP inbound connections that listen on all interfaces")
	}

	if conds.Len() == 0 {
		if ruleHasInternalVlessRouteTarget(rr) {
			return &trueCondition{}, nil
		}
		if skipProtocol {
			return &trueCondition{}, nil
		}
		return nil, errors.New("this rule has no effective fields").AtWarning()
	}

	return conds, nil
}

func (rr *RoutingRule) BuildCondition() (Condition, error) {
	return rr.buildCondition(false)
}

func (rr *RoutingRule) BuildConditionWithoutProtocol() (Condition, error) {
	return rr.buildCondition(true)
}

// Build builds the balancing rule
func (br *BalancingRule) Build(ohm outbound.Manager, dispatcher routing.Dispatcher) (*Balancer, error) {
	strategy := strings.ToLower(strings.TrimSpace(br.Strategy))
	selectors := br.OutboundSelector
	switch strategy {
	case "selector":
		return &Balancer{
			tag:             br.Tag,
			selectors:       selectors,
			strategy:        &SelectorStrategy{},
			strategyName:    "selector",
			fallbackTag:     br.FallbackTag,
			orderedSelector: true,
			ohm:             ohm,
		}, nil
	case "fallback":
		selectors = appendFallbackSelector(br.OutboundSelector, br.FallbackTag)
		return &Balancer{
			tag:             br.Tag,
			selectors:       selectors,
			strategy:        &SelectorStrategy{},
			strategyName:    "fallback",
			fallbackTag:     br.FallbackTag,
			orderedSelector: true,
			ohm:             ohm,
		}, nil
	case "leastping":
		return &Balancer{
			tag:          br.Tag,
			selectors:    selectors,
			strategy:     &LeastPingStrategy{},
			strategyName: "leastping",
			fallbackTag:  br.FallbackTag,
			ohm:          ohm,
		}, nil
	case "roundrobin":
		return &Balancer{
			tag:          br.Tag,
			selectors:    selectors,
			strategy:     &RoundRobinStrategy{FallbackTag: br.FallbackTag},
			strategyName: "roundrobin",
			fallbackTag:  br.FallbackTag,
			ohm:          ohm,
		}, nil
	case "leastload":
		i, err := br.StrategySettings.GetInstance()
		if err != nil {
			return nil, err
		}
		s, ok := i.(*StrategyLeastLoadConfig)
		if !ok {
			return nil, errors.New("not a StrategyLeastLoadConfig").AtError()
		}
		leastLoadStrategy := NewLeastLoadStrategy(s)
		return &Balancer{
			tag:          br.Tag,
			selectors:    selectors,
			ohm:          ohm,
			fallbackTag:  br.FallbackTag,
			strategyName: "leastload",
			strategy:     leastLoadStrategy,
		}, nil
	case "random":
		fallthrough
	case "":
		return &Balancer{
			tag:          br.Tag,
			selectors:    selectors,
			ohm:          ohm,
			fallbackTag:  br.FallbackTag,
			strategyName: "random",
			strategy:     &RandomStrategy{FallbackTag: br.FallbackTag},
		}, nil
	default:
		return nil, errors.New("unrecognized balancer type")
	}
}
