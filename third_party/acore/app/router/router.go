package router

import (
	"context"
	"encoding/json"
	"strings"
	sync "sync"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	routing_dns "github.com/ImAubrey/acore/features/routing/dns"
	"google.golang.org/protobuf/proto"
)

func ruleHasInternalReLookup(rule *RoutingRule) bool {
	if rule == nil || len(rule.Attributes) == 0 {
		return false
	}
	if v, ok := rule.Attributes[InternalReLookupAttr]; ok && strings.EqualFold(v, "true") {
		return true
	}
	return false
}

func ruleDestVlessRoute(rule *RoutingRule) (net.Port, bool) {
	if rule == nil || len(rule.Attributes) == 0 {
		return 0, false
	}
	value, ok := lookupAttribute(rule.Attributes, InternalDestVlessRouteAttr)
	if !ok {
		return 0, false
	}
	port, err := net.PortFromString(strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	return port, true
}

func ruleHasInternalVlessRouteTarget(rule *RoutingRule) bool {
	if rule == nil || len(rule.Attributes) == 0 {
		return false
	}
	_, ok := lookupAttribute(rule.Attributes, InternalVlessRouteTargetAttr)
	return ok
}

func ruleVlessRouteTargets(rule *RoutingRule) ([]vlessRouteTargetMatcher, bool, error) {
	if rule == nil || len(rule.Attributes) == 0 {
		return nil, false, nil
	}

	value, ok := lookupAttribute(rule.Attributes, InternalVlessRouteTargetAttr)
	if !ok {
		return nil, false, nil
	}

	type rawPortRange struct {
		From uint32 `json:"from"`
		To   uint32 `json:"to"`
	}
	type rawTarget struct {
		Ranges      []rawPortRange `json:"ranges"`
		Destination string         `json:"destination"`
	}

	var rawTargets []rawTarget
	if err := json.Unmarshal([]byte(value), &rawTargets); err != nil {
		return nil, false, errors.New("invalid internal vlessRoute target").Base(err)
	}
	if len(rawTargets) == 0 {
		return nil, false, nil
	}

	targets := make([]vlessRouteTargetMatcher, 0, len(rawTargets))
	for _, rawTarget := range rawTargets {
		destination := strings.TrimSpace(rawTarget.Destination)
		if destination == "" {
			return nil, false, errors.New("invalid internal vlessRoute target: empty destination")
		}
		if len(rawTarget.Ranges) == 0 {
			return nil, false, errors.New("invalid internal vlessRoute target: empty ranges")
		}

		portList := &net.PortList{Range: make([]*net.PortRange, 0, len(rawTarget.Ranges))}
		for _, rawRange := range rawTarget.Ranges {
			from, err := net.PortFromInt(rawRange.From)
			if err != nil {
				return nil, false, errors.New("invalid internal vlessRoute target range").Base(err)
			}
			to, err := net.PortFromInt(rawRange.To)
			if err != nil {
				return nil, false, errors.New("invalid internal vlessRoute target range").Base(err)
			}
			if from > to {
				return nil, false, errors.New("invalid internal vlessRoute target range: ", rawRange.From, " -> ", rawRange.To)
			}
			portList.Range = append(portList.Range, &net.PortRange{
				From: rawRange.From,
				To:   rawRange.To,
			})
		}

		targets = append(targets, vlessRouteTargetMatcher{
			destination: destination,
			port:        net.PortListFromProto(portList),
		})
	}

	return targets, true, nil
}

func ruleHasJA4Attribute(rule *RoutingRule) bool {
	if rule == nil || len(rule.Attributes) == 0 {
		return false
	}
	for k := range rule.Attributes {
		if strings.EqualFold(k, "ja4") {
			return true
		}
	}
	return false
}

func hasJA4AttributeInRules(rules []*RoutingRule) bool {
	for _, rule := range rules {
		if ruleHasJA4Attribute(rule) {
			return true
		}
	}
	return false
}

func buildConditionWithoutProtocolAndAttrs(rule *RoutingRule) (Condition, error) {
	cloned := proto.Clone(rule).(*RoutingRule)
	cloned.Attributes = nil
	return cloned.BuildConditionWithoutProtocol()
}

// Router is an implementation of routing.Router.
type Router struct {
	domainStrategy Config_DomainStrategy
	domainRecover  DomainRecoverMode
	rules          []*Rule
	balancers      map[string]*Balancer
	balancerOrder  []string
	rawRules       []*RoutingRule
	rawBalancers   []*BalancingRule
	dns            dns.Client
	dnsSniffing    bool
	wireguardSniff bool
	mtprotoSniff   bool
	zerotierSniff  bool
	echSniffing    bool
	dotSniff       bool
	rdpSniffing    bool
	mqttSniffing   bool
	ntpSniffing    bool
	postgresSniff  bool
	ikeSniff       bool
	dtlsSniff      bool
	ja4Sniff       bool

	ctx        context.Context
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	mu         sync.Mutex
}

const defaultJA4AutoLabelTag = "source:ja4db"

type protocolEvalContext struct {
	routing.Context
	ruleTags map[string]struct{}
	marked   bool
}

func (c *protocolEvalContext) AddRuleTag(tag string) {
	if tag == "" {
		return
	}
	if c.ruleTags == nil {
		c.ruleTags = make(map[string]struct{})
	}
	c.ruleTags[tag] = struct{}{}
}

func (c *protocolEvalContext) HasRuleTag(tag string) bool {
	if c.ruleTags == nil {
		return false
	}
	_, ok := c.ruleTags[tag]
	return ok
}

func (c *protocolEvalContext) MarkRuleMatched() {
	c.marked = true
}

func (c *protocolEvalContext) HasRuleMark() bool {
	return c.marked
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
	ruleTag           string
	reLookup          bool
	hasDestVlessRoute bool
	destVlessRoute    net.Port
}

func ruleDestination(rule *RoutingRule) (string, bool) {
	if rule == nil {
		return "", false
	}
	if tag := rule.GetTag(); tag != "" {
		return tag, false
	}
	if tag := rule.GetBalancingTag(); tag != "" {
		return tag, true
	}
	return "", false
}

func (r *Router) assignBalancerRegistry() {
	for tag, balancer := range r.balancers {
		if balancer == nil {
			continue
		}
		balancer.setRegistry(tag, r.balancers)
	}
}

func (r *Router) checkBalancerTagConflicts() error {
	if r.ohm == nil || len(r.balancers) == 0 {
		return nil
	}
	handlers := r.ohm.ListHandlers(r.ctx)
	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		tag := handler.Tag()
		if tag == "" {
			continue
		}
		if _, ok := r.balancers[tag]; ok {
			return errors.New("balancer tag conflicts with outbound tag: ", tag)
		}
	}
	return nil
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	r.domainStrategy = config.DomainStrategy
	r.domainRecover = DomainRecoverOff
	r.dns = d
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher

	r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
	r.balancerOrder = make([]string, 0, len(config.BalancingRule))
	for _, rule := range config.BalancingRule {
		if rule != nil {
			r.rawBalancers = append(r.rawBalancers, proto.Clone(rule).(*BalancingRule))
		}
		balancer, err := rule.Build(ohm, dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(ctx)
		r.balancers[rule.Tag] = balancer
		r.balancerOrder = append(r.balancerOrder, rule.Tag)
	}
	r.assignBalancerRegistry()
	if err := detectBalancerLoop(r.balancers); err != nil {
		return err
	}
	if err := r.checkBalancerTagConflicts(); err != nil {
		return err
	}

	r.rules = make([]*Rule, 0, len(config.Rule))
	for _, rule := range config.Rule {
		if mode, ok := parseInternalDomainRecoverRule(rule); ok {
			r.domainRecover = mode
			continue
		}
		if rule != nil {
			r.rawRules = append(r.rawRules, proto.Clone(rule).(*RoutingRule))
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			return err
		}
		condNoProtocol, err := rule.BuildConditionWithoutProtocol()
		if err != nil {
			return err
		}
		hasJA4Attr := ruleHasJA4Attribute(rule)
		condNoProtocolNoAttrs := condNoProtocol
		if hasJA4Attr {
			condNoProtocolNoAttrs, err = buildConditionWithoutProtocolAndAttrs(rule)
			if err != nil {
				return err
			}
		}
		relookup := rule.GetReLookup()
		if !relookup && ruleHasInternalReLookup(rule) {
			relookup = true
		}
		destVlessRoute, hasDestVlessRoute := ruleDestVlessRoute(rule)
		vlessRouteTargets, hasVlessRouteTargets, err := ruleVlessRouteTargets(rule)
		if err != nil {
			return err
		}
		rt, mark := normalizeRuleTag(rule.GetRuleTag())
		dest, destIsBalancer := ruleDestination(rule)
		rr := &Rule{
			Condition:                  cond,
			ConditionNoProtocol:        condNoProtocol,
			ConditionNoProtocolNoAttrs: condNoProtocolNoAttrs,
			Protocols:                  append([]string(nil), rule.Protocol...),
			HasJA4Attribute:            hasJA4Attr,
			RuleTag:                    rt,
			HasTarget:                  dest != "" || hasVlessRouteTargets,
			HasFixedTarget:             dest != "",
			HasRequire:                 len(rule.RequireRuleTag) > 0,
			MarkOnMatch:                mark,
			ReLookup:                   relookup,
			HasDestVlessRoute:          hasDestVlessRoute,
			DestVlessRoute:             destVlessRoute,
			VlessRouteTargets:          vlessRouteTargets,
		}
		if dest != "" {
			if brule, found := r.balancers[dest]; found {
				rr.Balancer = brule
			} else if destIsBalancer {
				return errors.New("balancer ", dest, " not found")
			} else {
				rr.Tag = dest
			}
		}
		r.rules = append(r.rules, rr)
	}
	r.dnsSniffing = hasProtocolInRules(r.rawRules, "dns")
	r.wireguardSniff = hasProtocolInRules(r.rawRules, "wireguard")
	r.mtprotoSniff = hasProtocolInRules(r.rawRules, "mtproto")
	r.zerotierSniff = hasProtocolInRules(r.rawRules, "zerotier")
	r.echSniffing = hasProtocolInRules(r.rawRules, "ech")
	r.dotSniff = hasProtocolInRules(r.rawRules, "dot")
	r.rdpSniffing = hasProtocolInRules(r.rawRules, "rdp")
	r.mqttSniffing = hasProtocolInRules(r.rawRules, "mqtt")
	r.ntpSniffing = hasProtocolInRules(r.rawRules, "ntp")
	r.postgresSniff = hasProtocolInRules(r.rawRules, "postgres")
	r.ikeSniff = hasProtocolInRules(r.rawRules, "ikev2")
	r.dtlsSniff = hasProtocolInRules(r.rawRules, "dtls")
	r.ja4Sniff = hasJA4AttributeInRules(r.rawRules)

	return nil
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	rule, ctx, err := r.pickRouteInternal(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := rule.GetTag()
	if err != nil {
		return nil, err
	}
	return &Route{
		Context:           ctx,
		outboundTag:       tag,
		ruleTag:           rule.RuleTag,
		reLookup:          rule.ReLookup,
		hasDestVlessRoute: rule.HasDestVlessRoute,
		destVlessRoute:    rule.DestVlessRoute,
	}, nil
}

// AddRule implements routing.Router.
func (r *Router) AddRule(config *serial.TypedMessage, shouldAppend bool) error {

	inst, err := config.GetInstance()
	if err != nil {
		return err
	}
	if c, ok := inst.(*Config); ok {
		return r.ReloadRules(c, shouldAppend)
	}
	return errors.New("AddRule: config type error")
}

func (r *Router) ReloadRules(config *Config, shouldAppend bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !shouldAppend {
		r.balancers = make(map[string]*Balancer, len(config.BalancingRule))
		r.balancerOrder = make([]string, 0, len(config.BalancingRule))
		r.rules = make([]*Rule, 0, len(config.Rule))
		r.rawBalancers = nil
		r.rawRules = nil
		r.domainRecover = DomainRecoverOff
	}
	for _, rule := range config.BalancingRule {
		_, found := r.balancers[rule.Tag]
		if found {
			return errors.New("duplicate balancer tag")
		}
		if rule != nil {
			r.rawBalancers = append(r.rawBalancers, proto.Clone(rule).(*BalancingRule))
		}
		balancer, err := rule.Build(r.ohm, r.dispatcher)
		if err != nil {
			return err
		}
		balancer.InjectContext(r.ctx)
		r.balancers[rule.Tag] = balancer
		r.balancerOrder = append(r.balancerOrder, rule.Tag)
	}
	r.assignBalancerRegistry()
	if err := detectBalancerLoop(r.balancers); err != nil {
		return err
	}
	if err := r.checkBalancerTagConflicts(); err != nil {
		return err
	}

	for _, rule := range config.Rule {
		if mode, ok := parseInternalDomainRecoverRule(rule); ok {
			r.domainRecover = mode
			continue
		}
		if r.RuleExists(rule.GetRuleTag()) {
			return errors.New("duplicate ruleTag ", rule.GetRuleTag())
		}
		if rule != nil {
			r.rawRules = append(r.rawRules, proto.Clone(rule).(*RoutingRule))
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			return err
		}
		condNoProtocol, err := rule.BuildConditionWithoutProtocol()
		if err != nil {
			return err
		}
		hasJA4Attr := ruleHasJA4Attribute(rule)
		condNoProtocolNoAttrs := condNoProtocol
		if hasJA4Attr {
			condNoProtocolNoAttrs, err = buildConditionWithoutProtocolAndAttrs(rule)
			if err != nil {
				return err
			}
		}
		relookup := rule.GetReLookup()
		if !relookup && ruleHasInternalReLookup(rule) {
			relookup = true
		}
		destVlessRoute, hasDestVlessRoute := ruleDestVlessRoute(rule)
		vlessRouteTargets, hasVlessRouteTargets, err := ruleVlessRouteTargets(rule)
		if err != nil {
			return err
		}
		rt, mark := normalizeRuleTag(rule.GetRuleTag())
		dest, destIsBalancer := ruleDestination(rule)
		rr := &Rule{
			Condition:                  cond,
			ConditionNoProtocol:        condNoProtocol,
			ConditionNoProtocolNoAttrs: condNoProtocolNoAttrs,
			Protocols:                  append([]string(nil), rule.Protocol...),
			HasJA4Attribute:            hasJA4Attr,
			RuleTag:                    rt,
			HasTarget:                  dest != "" || hasVlessRouteTargets,
			HasFixedTarget:             dest != "",
			HasRequire:                 len(rule.RequireRuleTag) > 0,
			MarkOnMatch:                mark,
			ReLookup:                   relookup,
			HasDestVlessRoute:          hasDestVlessRoute,
			DestVlessRoute:             destVlessRoute,
			VlessRouteTargets:          vlessRouteTargets,
		}
		if dest != "" {
			if brule, found := r.balancers[dest]; found {
				rr.Balancer = brule
			} else if destIsBalancer {
				return errors.New("balancer ", dest, " not found")
			} else {
				rr.Tag = dest
			}
		}
		r.rules = append(r.rules, rr)
	}
	r.dnsSniffing = hasProtocolInRules(r.rawRules, "dns")
	r.wireguardSniff = hasProtocolInRules(r.rawRules, "wireguard")
	r.mtprotoSniff = hasProtocolInRules(r.rawRules, "mtproto")
	r.zerotierSniff = hasProtocolInRules(r.rawRules, "zerotier")
	r.echSniffing = hasProtocolInRules(r.rawRules, "ech")
	r.dotSniff = hasProtocolInRules(r.rawRules, "dot")
	r.rdpSniffing = hasProtocolInRules(r.rawRules, "rdp")
	r.mqttSniffing = hasProtocolInRules(r.rawRules, "mqtt")
	r.ntpSniffing = hasProtocolInRules(r.rawRules, "ntp")
	r.postgresSniff = hasProtocolInRules(r.rawRules, "postgres")
	r.ikeSniff = hasProtocolInRules(r.rawRules, "ikev2")
	r.dtlsSniff = hasProtocolInRules(r.rawRules, "dtls")
	r.ja4Sniff = hasJA4AttributeInRules(r.rawRules)

	return nil
}

func (r *Router) RuleExists(tag string) bool {
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag == tag {
				return true
			}
		}
	}
	return false
}

func normalizeRuleTag(tag string) (string, bool) {
	if strings.HasPrefix(tag, "+") {
		return strings.TrimPrefix(tag, "+"), true
	}
	return tag, false
}

func hasProtocolInRules(rules []*RoutingRule, protocol string) bool {
	if protocol == "" {
		return false
	}
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		if protocolPatternsNeedSniffing(rule.Protocol, protocol) {
			return true
		}
	}
	return false
}

// ShouldSniffProtocol reports whether sniffing should be enabled for a protocol
// based on routing rules.
func (r *Router) ShouldSniffProtocol(protocol string) bool {
	switch {
	case strings.EqualFold(protocol, "dns"):
		return r.dnsSniffing
	case strings.EqualFold(protocol, "wireguard"):
		return r.wireguardSniff
	case strings.EqualFold(protocol, "mtproto"):
		return r.mtprotoSniff
	case strings.EqualFold(protocol, "zerotier"):
		return r.zerotierSniff
	case strings.EqualFold(protocol, "ech"):
		return r.echSniffing
	case strings.EqualFold(protocol, "dot"):
		return r.dotSniff
	case strings.EqualFold(protocol, "rdp"):
		return r.rdpSniffing
	case strings.EqualFold(protocol, "mqtt"):
		return r.mqttSniffing
	case strings.EqualFold(protocol, "ntp"):
		return r.ntpSniffing
	case strings.EqualFold(protocol, "postgres"):
		return r.postgresSniff
	case strings.EqualFold(protocol, "ikev2"):
		return r.ikeSniff
	case strings.EqualFold(protocol, "dtls"):
		return r.dtlsSniff
	case strings.EqualFold(protocol, "ja4"):
		return r.ja4Sniff
	default:
		return false
	}
}

func (r *Router) shouldSniffProtocolWithContext(protocol string, ctx routing.Context) bool {
	if ctx == nil || !r.ShouldSniffProtocol(protocol) {
		return false
	}
	skipDNSResolve := ctx.GetSkipDNSResolve()
	pe := &protocolEvalContext{Context: ctx}
	if marker, ok := ctx.(interface{ HasRuleMark() bool }); ok && marker.HasRuleMark() {
		pe.marked = true
	}
	evalCtx := routing.Context(pe)
	if r.domainStrategy == Config_IpOnDemand && !skipDNSResolve {
		evalCtx = routing_dns.ContextWithDNSClient(evalCtx, r.dns)
	}
	for _, rule := range r.rules {
		if pe.marked && !rule.HasRequire {
			continue
		}
		if strings.EqualFold(protocol, "ja4") {
			if !rule.HasJA4Attribute {
				continue
			}
		} else if !rule.protocolNeedsSniff(protocol) {
			continue
		}
		cond := rule.Condition
		switch {
		case strings.EqualFold(protocol, "ja4") && rule.ConditionNoProtocolNoAttrs != nil:
			cond = rule.ConditionNoProtocolNoAttrs
		case rule.ConditionNoProtocol != nil:
			cond = rule.ConditionNoProtocol
		}
		if cond == nil {
			rule.applyMatched(evalCtx)
			if strings.EqualFold(protocol, "ja4") {
				if rule.HasJA4Attribute {
					return true
				}
			} else if len(rule.Protocols) > 0 && rule.HasTarget {
				return true
			}
			continue
		}
		if !cond.Apply(evalCtx) {
			continue
		}
		rule.applyMatched(evalCtx)
		if strings.EqualFold(protocol, "ja4") {
			if rule.HasJA4Attribute {
				return true
			}
		} else if len(rule.Protocols) > 0 && rule.HasTarget {
			return true
		}
	}

	if r.domainStrategy != Config_IpIfNonMatch || len(evalCtx.GetTargetDomain()) == 0 || skipDNSResolve {
		return false
	}
	evalCtx = routing_dns.ContextWithDNSClient(evalCtx, r.dns)
	for _, rule := range r.rules {
		if pe.marked && !rule.HasRequire {
			continue
		}
		if strings.EqualFold(protocol, "ja4") {
			if !rule.HasJA4Attribute {
				continue
			}
		} else if !rule.protocolNeedsSniff(protocol) {
			continue
		}
		cond := rule.Condition
		switch {
		case strings.EqualFold(protocol, "ja4") && rule.ConditionNoProtocolNoAttrs != nil:
			cond = rule.ConditionNoProtocolNoAttrs
		case rule.ConditionNoProtocol != nil:
			cond = rule.ConditionNoProtocol
		}
		if cond == nil {
			rule.applyMatched(evalCtx)
			if strings.EqualFold(protocol, "ja4") {
				if rule.HasJA4Attribute {
					return true
				}
			} else if len(rule.Protocols) > 0 && rule.HasTarget {
				return true
			}
			continue
		}
		if !cond.Apply(evalCtx) {
			continue
		}
		rule.applyMatched(evalCtx)
		if strings.EqualFold(protocol, "ja4") {
			if rule.HasJA4Attribute {
				return true
			}
		} else if len(rule.Protocols) > 0 && rule.HasTarget {
			return true
		}
	}
	return false
}

// ShouldSniffProtocolForContext reports whether protocol sniffing should be enabled
// for the current routing context.
func (r *Router) ShouldSniffProtocolForContext(protocol string, ctx routing.Context) bool {
	return r.shouldSniffProtocolWithContext(protocol, ctx)
}

// LookupJA4Tag tries to resolve a JA4 fingerprint to a JA4 DB tag for
// observability display. It first checks tags explicitly referenced by routing
// rules, then auto-selects a preferred label from ja4.db (for example
// app:*:major:* / app:*), and finally falls back to source:ja4db.
func (r *Router) LookupJA4Tag(fingerprint string) string {
	fp, ok := normalizeJA4FingerprintFast(fingerprint)
	if !ok {
		return ""
	}

	r.mu.Lock()
	rawRules := append([]*RoutingRule(nil), r.rawRules...)
	r.mu.Unlock()

	seen := make(map[string]struct{}, 8)
	try := func(file, tag string) string {
		file = strings.TrimSpace(file)
		tag = strings.TrimSpace(tag)
		if file == "" || tag == "" {
			return ""
		}
		key := strings.ToLower(file) + "|" + strings.ToLower(tag)
		if _, done := seen[key]; done {
			return ""
		}
		seen[key] = struct{}{}

		set, err := getJA4TagSet(file, tag)
		if err != nil || set == nil {
			return ""
		}
		if set.ContainsNormalized(fp) {
			return normalizeJA4MatchedTag(file, tag)
		}
		return ""
	}

	for _, rule := range rawRules {
		if rule == nil || len(rule.Attributes) == 0 {
			continue
		}
		for key, value := range rule.Attributes {
			if !strings.EqualFold(key, "ja4") {
				continue
			}
			file, tag, decoded := DecodeJA4DBAttributeValue(value)
			if !decoded {
				continue
			}
			if resolved := try(file, tag); resolved != "" {
				return resolved
			}
		}
	}

	bestResolved := ""
	if tags, err := preferredJA4AutoTags("ja4.db"); err == nil {
		for _, tag := range tags {
			if resolved := try("ja4.db", tag); resolved != "" {
				bestResolved = resolved
				break
			}
		}
	}
	if bestResolved != "" {
		return bestResolved
	}

	return try("ja4.db", defaultJA4AutoLabelTag)
}

func (r *Router) DomainRecoverMode() string {
	return r.domainRecover.String()
}

// RemoveRule implements routing.Router.
func (r *Router) RemoveRule(tag string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	newRules := []*Rule{}
	newRawRules := []*RoutingRule{}
	if tag != "" {
		for _, rule := range r.rules {
			if rule.RuleTag != tag {
				newRules = append(newRules, rule)
			}
		}
		for _, rule := range r.rawRules {
			if rule == nil {
				continue
			}
			rt, _ := normalizeRuleTag(rule.GetRuleTag())
			if rt != tag {
				newRawRules = append(newRawRules, rule)
			}
		}
		r.rules = newRules
		r.rawRules = newRawRules
		r.dnsSniffing = hasProtocolInRules(r.rawRules, "dns")
		r.wireguardSniff = hasProtocolInRules(r.rawRules, "wireguard")
		r.mtprotoSniff = hasProtocolInRules(r.rawRules, "mtproto")
		r.zerotierSniff = hasProtocolInRules(r.rawRules, "zerotier")
		r.echSniffing = hasProtocolInRules(r.rawRules, "ech")
		r.dotSniff = hasProtocolInRules(r.rawRules, "dot")
		r.rdpSniffing = hasProtocolInRules(r.rawRules, "rdp")
		r.mqttSniffing = hasProtocolInRules(r.rawRules, "mqtt")
		r.ntpSniffing = hasProtocolInRules(r.rawRules, "ntp")
		r.postgresSniff = hasProtocolInRules(r.rawRules, "postgres")
		r.ikeSniff = hasProtocolInRules(r.rawRules, "ikev2")
		r.dtlsSniff = hasProtocolInRules(r.rawRules, "dtls")
		r.ja4Sniff = hasJA4AttributeInRules(r.rawRules)
		return nil
	}
	return errors.New("empty tag name!")

}

// ListRuleConfigs returns a snapshot of routing rules as configs.
func (r *Router) ListRuleConfigs() []*RoutingRule {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]*RoutingRule, 0, len(r.rawRules))
	for _, rule := range r.rawRules {
		if rule == nil {
			continue
		}
		out = append(out, proto.Clone(rule).(*RoutingRule))
	}
	return out
}

// ListBalancerConfigs returns a snapshot of balancing rules as configs.
func (r *Router) ListBalancerConfigs() []*BalancingRule {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]*BalancingRule, 0, len(r.rawBalancers))
	for _, rule := range r.rawBalancers {
		if rule == nil {
			continue
		}
		out = append(out, proto.Clone(rule).(*BalancingRule))
	}
	return out
}
func (r *Router) pickRouteInternal(ctx routing.Context) (*Rule, routing.Context, error) {
	// SkipDNSResolve is set from DNS module.
	// the DOH remote server maybe a domain name,
	// this prevents cycle resolving dead loop
	skipDNSResolve := ctx.GetSkipDNSResolve()

	marked := false
	if marker, ok := ctx.(interface{ HasRuleMark() bool }); ok {
		marked = marker.HasRuleMark()
	}
	_, canMark := ctx.(interface{ MarkRuleMatched() })

	if r.domainStrategy == Config_IpOnDemand && !skipDNSResolve {
		ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
	}

	for _, rule := range r.rules {
		if marked && !rule.HasRequire {
			// already marked by previous +rule; skip rules without requireRuleTag
			continue
		}
		if rule.Apply(ctx) {
			if canMark && rule.MarkOnMatch {
				marked = true
			}
			if resolved, ok := rule.resolveTarget(ctx); ok {
				return resolved, ctx, nil
			}
			// no target: just accumulate ruleTag then continue
		}
	}

	if r.domainStrategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || skipDNSResolve {
		return nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)

	// Try applying rules again if we have IPs.
	for _, rule := range r.rules {
		if marked && !rule.HasRequire {
			continue
		}
		if rule.Apply(ctx) {
			if canMark && rule.MarkOnMatch {
				marked = true
			}
			if resolved, ok := rule.resolveTarget(ctx); ok {
				return resolved, ctx, nil
			}
		}
	}

	return nil, ctx, common.ErrNoClue
}

// Start implements common.Runnable.
func (r *Router) Start() error {
	return nil
}

// Close implements common.Closable.
func (r *Router) Close() error {
	return nil
}

// Type implements common.HasType.
func (*Router) Type() interface{} {
	return routing.RouterType()
}

// GetOutboundGroupTags implements routing.Route.
func (r *Route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

// GetOutboundTag implements routing.Route.
func (r *Route) GetOutboundTag() string {
	return r.outboundTag
}

func (r *Route) GetRuleTag() string {
	return r.ruleTag
}

func (r *Route) ReLookup() bool {
	return r.reLookup
}

func (r *Route) DestVlessRoute() (net.Port, bool) {
	return r.destVlessRoute, r.hasDestVlessRoute
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
			return r.Init(ctx, config.(*Config), d, ohm, dispatcher)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}
