package firewall

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/core"
	feature_conntrack "github.com/ImAubrey/acore/features/conntrack"
	feature_firewall "github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/routing"
	"google.golang.org/protobuf/proto"
)

type compiledRule struct {
	Match               *router.Rule
	Action              Rule_Action
	Limit               *ConnectionLimit
	SourceLimitPrefixes []limitPrefix
	TargetLimitPrefixes []limitPrefix
}

type limitPrefix struct {
	Prefix  netip.Prefix
	Literal string
}

// Firewall is the runtime firewall feature.
type Firewall struct {
	rules []*compiledRule
	ct    feature_conntrack.Manager

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
}

func ruleHasJA4Attribute(rule *router.RoutingRule) bool {
	if rule == nil || len(rule.Attributes) == 0 {
		return false
	}
	for key := range rule.Attributes {
		if strings.EqualFold(key, "ja4") {
			return true
		}
	}
	return false
}

func buildConditionWithoutProtocolAndAttrs(rule *router.RoutingRule) (router.Condition, error) {
	cloned := proto.Clone(rule).(*router.RoutingRule)
	cloned.Attributes = nil
	return cloned.BuildConditionWithoutProtocol()
}

func normalizeRuleTag(tag string) (string, bool) {
	if strings.HasPrefix(tag, "+") {
		return strings.TrimPrefix(tag, "+"), true
	}
	return tag, false
}

func hasProtocolInRules(rules []*router.RoutingRule, protocol string) bool {
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

func parseProtocolPattern(pattern string) (bool, string, bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false, "", false
	}
	neg := false
	if strings.HasPrefix(pattern, "!") {
		neg = true
		pattern = strings.TrimSpace(strings.TrimPrefix(pattern, "!"))
	}
	if pattern == "" {
		return false, "", false
	}
	return neg, pattern, true
}

func protocolPatternMentionsCandidate(pattern string, candidate string) bool {
	if pattern == "" || candidate == "" {
		return false
	}
	lp := strings.ToLower(pattern)
	lc := strings.ToLower(candidate)
	if lp == "alpn" || strings.HasPrefix(lp, "alpn:") || strings.HasPrefix(lp, "alpn=") {
		return lc == "alpn"
	}
	return strings.HasPrefix(lc, lp) || strings.HasPrefix(lp, lc)
}

func protocolPatternsNeedSniffing(patterns []string, protocol string) bool {
	hasValidPattern := false
	hasInclude := false
	includeMentioned := false
	excludeMentioned := false

	for _, pattern := range patterns {
		neg, parsed, ok := parseProtocolPattern(pattern)
		if !ok {
			continue
		}
		hasValidPattern = true
		if !neg {
			hasInclude = true
		}
		if !protocolPatternMentionsCandidate(parsed, protocol) {
			continue
		}
		if neg {
			excludeMentioned = true
		} else {
			includeMentioned = true
		}
	}

	if !hasValidPattern {
		return false
	}
	if hasInclude {
		return includeMentioned
	}
	return excludeMentioned
}

func hasJA4AttributeInRules(rules []*router.RoutingRule) bool {
	for _, rule := range rules {
		if ruleHasJA4Attribute(rule) {
			return true
		}
	}
	return false
}

// Init initializes firewall feature.
func (f *Firewall) Init(config *Config, counter feature_conntrack.Manager) error {
	f.ct = counter

	rawRules := make([]*router.RoutingRule, 0, len(config.Rule))
	f.rules = make([]*compiledRule, 0, len(config.Rule))
	for _, rule := range config.Rule {
		if rule == nil || rule.Match == nil {
			return errors.New("firewall rule is missing match block")
		}
		match := rule.Match
		cond, err := match.BuildCondition()
		if err != nil {
			return err
		}
		condNoProtocol, err := match.BuildConditionWithoutProtocol()
		if err != nil {
			return err
		}
		hasJA4Attr := ruleHasJA4Attribute(match)
		condNoProtocolNoAttrs := condNoProtocol
		if hasJA4Attr {
			condNoProtocolNoAttrs, err = buildConditionWithoutProtocolAndAttrs(match)
			if err != nil {
				return err
			}
		}
		rt, mark := normalizeRuleTag(match.GetRuleTag())
		compiled := &compiledRule{
			Match: &router.Rule{
				Condition:                  cond,
				ConditionNoProtocol:        condNoProtocol,
				ConditionNoProtocolNoAttrs: condNoProtocolNoAttrs,
				Protocols:                  append([]string(nil), match.Protocol...),
				HasJA4Attribute:            hasJA4Attr,
				RuleTag:                    rt,
				HasRequire:                 len(match.RequireRuleTag) > 0,
				MarkOnMatch:                mark,
			},
			Action: rule.Action,
			Limit:  rule.Limit,
		}
		if err := compileRuleLimitPrefixes(compiled, match); err != nil {
			return err
		}
		f.rules = append(f.rules, compiled)
		rawRules = append(rawRules, proto.Clone(match).(*router.RoutingRule))
	}

	f.dnsSniffing = hasProtocolInRules(rawRules, "dns")
	f.wireguardSniff = hasProtocolInRules(rawRules, "wireguard")
	f.mtprotoSniff = hasProtocolInRules(rawRules, "mtproto")
	f.zerotierSniff = hasProtocolInRules(rawRules, "zerotier")
	f.echSniffing = hasProtocolInRules(rawRules, "ech")
	f.dotSniff = hasProtocolInRules(rawRules, "dot")
	f.rdpSniffing = hasProtocolInRules(rawRules, "rdp")
	f.mqttSniffing = hasProtocolInRules(rawRules, "mqtt")
	f.ntpSniffing = hasProtocolInRules(rawRules, "ntp")
	f.postgresSniff = hasProtocolInRules(rawRules, "postgres")
	f.ikeSniff = hasProtocolInRules(rawRules, "ikev2")
	f.dtlsSniff = hasProtocolInRules(rawRules, "dtls")
	f.ja4Sniff = hasJA4AttributeInRules(rawRules)
	return nil
}

// Type implements common.HasType.
func (*Firewall) Type() interface{} {
	return feature_firewall.ManagerType()
}

// Start implements common.Runnable.
func (*Firewall) Start() error { return nil }

// Close implements common.Closable.
func (*Firewall) Close() error { return nil }

// ShouldSniffProtocol reports whether a protocol sniffer may be needed by firewall rules.
func (f *Firewall) ShouldSniffProtocol(protocol string) bool {
	switch {
	case strings.EqualFold(protocol, "dns"):
		return f.dnsSniffing
	case strings.EqualFold(protocol, "wireguard"):
		return f.wireguardSniff
	case strings.EqualFold(protocol, "mtproto"):
		return f.mtprotoSniff
	case strings.EqualFold(protocol, "zerotier"):
		return f.zerotierSniff
	case strings.EqualFold(protocol, "ech"):
		return f.echSniffing
	case strings.EqualFold(protocol, "dot"):
		return f.dotSniff
	case strings.EqualFold(protocol, "rdp"):
		return f.rdpSniffing
	case strings.EqualFold(protocol, "mqtt"):
		return f.mqttSniffing
	case strings.EqualFold(protocol, "ntp"):
		return f.ntpSniffing
	case strings.EqualFold(protocol, "postgres"):
		return f.postgresSniff
	case strings.EqualFold(protocol, "ikev2"):
		return f.ikeSniff
	case strings.EqualFold(protocol, "dtls"):
		return f.dtlsSniff
	case strings.EqualFold(protocol, "ja4"):
		return f.ja4Sniff
	default:
		return false
	}
}

func (f *Firewall) shouldSniffProtocolWithContext(protocol string, ctx routing.Context) bool {
	if ctx == nil || !f.ShouldSniffProtocol(protocol) {
		return false
	}
	return f.ruleNeedsSniff(protocol, ctx)
}

func (f *Firewall) ruleNeedsSniff(protocol string, ctx routing.Context) bool {
	marked := false
	if marker, ok := ctx.(interface{ HasRuleMark() bool }); ok {
		marked = marker.HasRuleMark()
	}
	for _, rule := range f.rules {
		if marked && !rule.Match.HasRequire {
			continue
		}
		if strings.EqualFold(protocol, "ja4") {
			if !rule.Match.HasJA4Attribute {
				continue
			}
		} else if !protocolPatternsNeedSniffing(rule.Match.Protocols, protocol) {
			continue
		}

		cond := rule.Match.Condition
		switch {
		case strings.EqualFold(protocol, "ja4") && rule.Match.ConditionNoProtocolNoAttrs != nil:
			cond = rule.Match.ConditionNoProtocolNoAttrs
		case rule.Match.ConditionNoProtocol != nil:
			cond = rule.Match.ConditionNoProtocol
		}
		if cond == nil {
			if rule.Match.MarkOnMatch {
				marked = true
			}
			return true
		}
		if !cond.Apply(ctx) {
			continue
		}
		if rule.Match.MarkOnMatch {
			marked = true
		}
		return true
	}
	return false
}

// ShouldSniffProtocolForContext reports whether firewall needs protocol sniffing for this connection.
func (f *Firewall) ShouldSniffProtocolForContext(protocol string, ctx routing.Context) bool {
	return f.shouldSniffProtocolWithContext(protocol, ctx)
}

// Evaluate applies firewall rules and returns the terminal decision.
func (f *Firewall) Evaluate(ctx context.Context, routingCtx routing.Context) feature_firewall.Decision {
	if routingCtx == nil {
		return feature_firewall.Decision{Action: feature_firewall.ActionAllow}
	}
	if decision, terminal := f.evaluatePass(ctx, routingCtx); terminal {
		return decision
	}
	return feature_firewall.Decision{Action: feature_firewall.ActionAllow}
}

func (f *Firewall) evaluatePass(ctx context.Context, routingCtx routing.Context) (feature_firewall.Decision, bool) {
	if routingCtx == nil {
		return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
	}

	marked := false
	if marker, ok := routingCtx.(interface{ HasRuleMark() bool }); ok {
		marked = marker.HasRuleMark()
	}

	for _, rule := range f.rules {
		if marked && !rule.Match.HasRequire {
			continue
		}
		if !rule.Match.Apply(routingCtx) {
			continue
		}
		if rule.Match.MarkOnMatch {
			marked = true
		}

		switch rule.Action {
		case Rule_Mark:
			continue
		case Rule_Allow:
			return feature_firewall.Decision{
				Action:  feature_firewall.ActionAllow,
				RuleTag: rule.Match.RuleTag,
			}, true
		case Rule_Block:
			return feature_firewall.Decision{
				Action:  feature_firewall.ActionBlock,
				RuleTag: rule.Match.RuleTag,
			}, true
		case Rule_Limit:
			if decision, blocked := f.evaluateLimit(ctx, routingCtx, rule); blocked {
				return decision, true
			}
		}
	}

	return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
}

func (f *Firewall) evaluateLimit(ctx context.Context, routingCtx routing.Context, rule *compiledRule) (feature_firewall.Decision, bool) {
	if f.ct == nil || rule == nil || rule.Limit == nil || rule.Limit.GetMaxConnections() == 0 {
		return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
	}

	sourceIP, destinationIP := connectionCounterIPs(ctx, routingCtx)
	var (
		counterMode   = connectionLimitCounterMode(rule.Limit)
		window        = connectionLimitWindow(rule.Limit)
		counterType   feature_conntrack.CounterType
		count         uint32
		decision      feature_firewall.Decision
		maxConnection = rule.Limit.GetMaxConnections()
	)

	switch rule.Limit.GetKey() {
	case ConnectionLimit_SrcIp:
		if sourceIP == "" {
			return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
		}
		counterType = feature_conntrack.CounterTypeSourceIP
		count = f.ct.CountConnections(counterMode, counterType, sourceIP, "", window)
		decision.SourceIP = sourceIP
	case ConnectionLimit_DstIp:
		if destinationIP == "" {
			return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
		}
		counterType = feature_conntrack.CounterTypeDestinationIP
		count = f.ct.CountConnections(counterMode, counterType, "", destinationIP, window)
		decision.DestinationIP = destinationIP
	case ConnectionLimit_SrcDstIp:
		if sourceIP == "" || destinationIP == "" {
			return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
		}
		counterType = feature_conntrack.CounterTypeSourceDestinationIP
		count = f.ct.CountConnections(counterMode, counterType, sourceIP, destinationIP, window)
		decision.SourceIP = sourceIP
		decision.DestinationIP = destinationIP
	case ConnectionLimit_SrcPrefix:
		if sourceIP == "" {
			return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
		}
		sourcePrefix, ok := resolveLimitPrefix(sourceIP, rule.SourceLimitPrefixes)
		if !ok {
			return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
		}
		counterType = feature_conntrack.CounterTypeSourcePrefix
		count = f.ct.CountConnections(counterMode, counterType, sourcePrefix, "", window)
		decision.SourceIP = sourceIP
		decision.SourcePrefix = sourcePrefix
	case ConnectionLimit_DstPrefix:
		if destinationIP == "" {
			return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
		}
		destinationPrefix, ok := resolveLimitPrefix(destinationIP, rule.TargetLimitPrefixes)
		if !ok {
			return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
		}
		counterType = feature_conntrack.CounterTypeDestinationPrefix
		count = f.ct.CountConnections(counterMode, counterType, "", destinationPrefix, window)
		decision.DestinationIP = destinationIP
		decision.DestinationPrefix = destinationPrefix
	default:
		return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
	}

	if count <= maxConnection {
		return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
	}

	decision.Action = feature_firewall.ActionBlock
	decision.RuleTag = rule.Match.RuleTag
	decision.CounterMode = counterMode
	decision.CounterType = counterType
	decision.Count = count
	decision.Max = maxConnection
	decision.Window = window
	return decision, true
}

func connectionLimitCounterMode(limit *ConnectionLimit) feature_conntrack.CounterMode {
	if limit == nil {
		return feature_conntrack.CounterModeActiveConnections
	}
	switch limit.GetMode() {
	case ConnectionLimit_NewConnections:
		return feature_conntrack.CounterModeNewConnections
	default:
		return feature_conntrack.CounterModeActiveConnections
	}
}

func connectionLimitWindow(limit *ConnectionLimit) time.Duration {
	if limit == nil || limit.GetWindowSeconds() == 0 {
		return 0
	}
	return time.Duration(limit.GetWindowSeconds()) * time.Second
}

func connectionCounterIPs(ctx context.Context, routingCtx routing.Context) (string, string) {
	sourceIP := firstRoutingIP(routingCtx.GetSourceIPs())
	destinationIP := currentDestinationIP(ctx, routingCtx)
	return sourceIP, destinationIP
}

func compileRuleLimitPrefixes(compiled *compiledRule, match *router.RoutingRule) error {
	if compiled == nil || match == nil || compiled.Action != Rule_Limit || compiled.Limit == nil {
		return nil
	}
	switch compiled.Limit.GetKey() {
	case ConnectionLimit_SrcPrefix:
		prefixes, err := extractLimitPrefixes(match.GetSourceGeoip(), "source/sourceIP")
		if err != nil {
			return err
		}
		compiled.SourceLimitPrefixes = prefixes
	case ConnectionLimit_DstPrefix:
		prefixes, err := extractLimitPrefixes(match.GetGeoip(), "ip")
		if err != nil {
			return err
		}
		compiled.TargetLimitPrefixes = prefixes
	}
	return nil
}

func extractLimitPrefixes(geoips []*router.GeoIP, fieldName string) ([]limitPrefix, error) {
	if len(geoips) == 0 {
		return nil, errors.New("firewall prefix limit requires explicit ", fieldName, " CIDR entries")
	}
	prefixes := make([]limitPrefix, 0)
	for _, geoip := range geoips {
		if geoip == nil {
			continue
		}
		if geoip.GetReverseMatch() {
			return nil, errors.New("firewall prefix limit does not support reverse CIDR in ", fieldName)
		}
		if strings.TrimSpace(geoip.GetCountryCode()) != "" {
			return nil, errors.New("firewall prefix limit requires explicit CIDR entries in ", fieldName)
		}
		for _, cidr := range geoip.GetCidr() {
			prefix, err := limitPrefixFromCIDR(cidr)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix)
		}
	}
	if len(prefixes) == 0 {
		return nil, errors.New("firewall prefix limit requires explicit ", fieldName, " CIDR entries")
	}
	return prefixes, nil
}

func limitPrefixFromCIDR(cidr *router.CIDR) (limitPrefix, error) {
	if cidr == nil || len(cidr.GetIp()) == 0 {
		return limitPrefix{}, errors.New("firewall prefix limit got empty CIDR")
	}
	addr, ok := netip.AddrFromSlice(cidr.GetIp())
	if !ok {
		return limitPrefix{}, errors.New("firewall prefix limit got invalid CIDR")
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	prefix, err := addr.Prefix(int(cidr.GetPrefix()))
	if err != nil {
		return limitPrefix{}, errors.New("firewall prefix limit got invalid prefix").Base(err)
	}
	prefix = prefix.Masked()
	return limitPrefix{
		Prefix:  prefix,
		Literal: prefix.String(),
	}, nil
}

func resolveLimitPrefix(ip string, prefixes []limitPrefix) (string, bool) {
	if ip == "" || len(prefixes) == 0 {
		return "", false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	bestBits := -1
	bestLiteral := ""
	for _, candidate := range prefixes {
		if !candidate.Prefix.Contains(addr) {
			continue
		}
		bits := candidate.Prefix.Bits()
		if bits > bestBits || (bits == bestBits && (bestLiteral == "" || candidate.Literal < bestLiteral)) {
			bestBits = bits
			bestLiteral = candidate.Literal
		}
	}
	return bestLiteral, bestLiteral != ""
}

func firstRoutingIP(ips []net.IP) string {
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		return ip.String()
	}
	return ""
}

func currentDestinationIP(ctx context.Context, _ routing.Context) string {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) > 0 {
		ob := outbounds[len(outbounds)-1]
		if ob != nil {
			if ob.Target.IsValid() && ob.Target.Address != nil && ob.Target.Address.Family().IsIP() {
				return ob.Target.Address.String()
			}
			if ob.OriginalTarget.IsValid() && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address.Family().IsIP() {
				return ob.OriginalTarget.Address.String()
			}
		}
	}
	return ""
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		f := new(Firewall)
		if err := core.RequireFeatures(ctx, func(counter feature_conntrack.Manager) error {
			return f.Init(config.(*Config), counter)
		}); err != nil {
			return nil, err
		}
		return f, nil
	}))
}
