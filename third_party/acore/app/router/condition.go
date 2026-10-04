package router

import (
	"context"
	"regexp"
	"strings"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/strmatcher"
	"github.com/ImAubrey/acore/features/routing"
)

type Condition interface {
	Apply(ctx routing.Context) bool
}

type ConditionChan []Condition

func NewConditionChan() *ConditionChan {
	var condChan ConditionChan = make([]Condition, 0, 8)
	return &condChan
}

func (v *ConditionChan) Add(cond Condition) *ConditionChan {
	*v = append(*v, cond)
	return v
}

// Apply applies all conditions registered in this chan.
func (v *ConditionChan) Apply(ctx routing.Context) bool {
	for _, cond := range *v {
		if !cond.Apply(ctx) {
			return false
		}
	}
	return true
}

func (v *ConditionChan) Len() int {
	return len(*v)
}

var matcherTypeMap = map[Domain_Type]strmatcher.Type{
	Domain_Plain:  strmatcher.Substr,
	Domain_Regex:  strmatcher.Regex,
	Domain_Domain: strmatcher.Domain,
	Domain_Full:   strmatcher.Full,
}

type DomainMatcher struct {
	pos        strmatcher.IndexMatcher
	neg        strmatcher.IndexMatcher
	matchEmpty bool
}

const DomainAttrReverseMatch = "reverse_match"
const DomainAttrMatchEmpty = "match_empty"

func hasDomainBoolAttr(d *Domain, key string) bool {
	for _, attr := range d.Attribute {
		if strings.EqualFold(attr.Key, key) && attr.GetBoolValue() {
			return true
		}
	}
	return false
}

func isDomainReverse(d *Domain) bool {
	return hasDomainBoolAttr(d, DomainAttrReverseMatch)
}

func isDomainMatchEmpty(d *Domain) bool {
	return hasDomainBoolAttr(d, DomainAttrMatchEmpty)
}

func NewMphMatcherGroup(domains []*Domain) (*DomainMatcher, error) {
	var pos, neg *strmatcher.MphMatcherGroup
	matchEmpty := false
	for _, d := range domains {
		if isDomainMatchEmpty(d) {
			matchEmpty = true
			continue
		}
		matcherType, f := matcherTypeMap[d.Type]
		if !f {
			errors.LogError(context.Background(), "ignore unsupported domain type ", d.Type, " of rule ", d.Value)
			continue
		}
		isReverse := isDomainReverse(d)
		target := &pos
		if isReverse {
			target = &neg
		}
		if *target == nil {
			*target = strmatcher.NewMphMatcherGroup()
		}
		_, err := (*target).AddPattern(d.Value, matcherType)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "ignore domain rule ", d.Type, " ", d.Value)
			continue
		}
	}
	var posIdx, negIdx strmatcher.IndexMatcher
	if pos != nil {
		pos.Build()
		posIdx = pos
	}
	if neg != nil {
		neg.Build()
		negIdx = neg
	}
	return &DomainMatcher{pos: posIdx, neg: negIdx, matchEmpty: matchEmpty}, nil
}

func (m *DomainMatcher) ApplyDomain(domain string) bool {
	domain = strings.ToLower(domain)
	if m.neg != nil {
		if mph, ok := m.neg.(*strmatcher.MphMatcherGroup); ok {
			if mph.MatchAny(domain) {
				return false
			}
		} else if len(m.neg.Match(domain)) > 0 {
			return false
		}
	}
	if m.pos == nil {
		return true
	}
	if mph, ok := m.pos.(*strmatcher.MphMatcherGroup); ok {
		return mph.MatchAny(domain)
	}
	return len(m.pos.Match(domain)) > 0
}

// Apply implements Condition.
func (m *DomainMatcher) Apply(ctx routing.Context) bool {
	domain := ctx.GetTargetDomain()
	if len(domain) == 0 {
		return m.matchEmpty
	}
	if m.matchEmpty && m.pos == nil && m.neg == nil {
		return false
	}
	return m.ApplyDomain(domain)
}

type MatcherAsType byte

const (
	MatcherAsType_Local MatcherAsType = iota
	MatcherAsType_Source
	MatcherAsType_Target
	MatcherAsType_VlessRoute // for port
)

type IPMatcher struct {
	matcher GeoIPMatcher
	asType  MatcherAsType
}

func NewIPMatcher(geoips []*GeoIP, asType MatcherAsType) (*IPMatcher, error) {
	matcher, err := BuildOptimizedGeoIPMatcher(geoips...)
	if err != nil {
		return nil, err
	}
	return &IPMatcher{matcher: matcher, asType: asType}, nil
}

// Apply implements Condition.
func (m *IPMatcher) Apply(ctx routing.Context) bool {
	var ips []net.IP

	switch m.asType {
	case MatcherAsType_Local:
		ips = ctx.GetLocalIPs()
	case MatcherAsType_Source:
		ips = ctx.GetSourceIPs()
	case MatcherAsType_Target:
		ips = ctx.GetTargetIPs()
	default:
		panic("unk asType")
	}

	return m.matcher.AnyMatch(ips)
}

type PortMatcher struct {
	port   net.MemoryPortList
	asType MatcherAsType
}

// NewPortMatcher create a new port matcher that can match source or local or destination port
func NewPortMatcher(list *net.PortList, asType MatcherAsType) *PortMatcher {
	return &PortMatcher{
		port:   net.PortListFromProto(list),
		asType: asType,
	}
}

// Apply implements Condition.
func (v *PortMatcher) Apply(ctx routing.Context) bool {
	switch v.asType {
	case MatcherAsType_Local:
		return v.port.Contains(ctx.GetLocalPort())
	case MatcherAsType_Source:
		return v.port.Contains(ctx.GetSourcePort())
	case MatcherAsType_Target:
		return v.port.Contains(ctx.GetTargetPort())
	case MatcherAsType_VlessRoute:
		return v.port.Contains(ctx.GetVlessRoute())
	default:
		panic("unk asType")
	}
}

type NetworkMatcher struct {
	list [8]bool
}

func NewNetworkMatcher(network []net.Network) NetworkMatcher {
	var matcher NetworkMatcher
	for _, n := range network {
		matcher.list[int(n)] = true
	}
	return matcher
}

// Apply implements Condition.
func (v NetworkMatcher) Apply(ctx routing.Context) bool {
	return v.list[int(ctx.GetNetwork())]
}

type UserMatcher struct {
	user    []string
	pattern []*regexp.Regexp
}

func NewUserMatcher(users []string) *UserMatcher {
	usersCopy := make([]string, 0, len(users))
	patternsCopy := make([]*regexp.Regexp, 0, len(users))
	for _, user := range users {
		if len(user) > 0 {
			if len(user) > 7 && strings.HasPrefix(user, "regexp:") {
				if re, err := regexp.Compile(user[7:]); err == nil {
					patternsCopy = append(patternsCopy, re)
				}
				// Items of users slice with an invalid regexp syntax are ignored.
				continue
			}
			usersCopy = append(usersCopy, user)
		}
	}
	return &UserMatcher{
		user:    usersCopy,
		pattern: patternsCopy,
	}
}

// Apply implements Condition.
func (v *UserMatcher) Apply(ctx routing.Context) bool {
	user := ctx.GetUser()
	if len(user) == 0 {
		return false
	}
	for _, u := range v.user {
		if u == user {
			return true
		}
	}
	for _, re := range v.pattern {
		if re.MatchString(user) {
			return true
		}
	}
	return false
}

type InboundTagMatcher struct {
	tags []string
}

func NewInboundTagMatcher(tags []string) *InboundTagMatcher {
	tagsCopy := make([]string, 0, len(tags))
	for _, tag := range tags {
		if len(tag) > 0 {
			tagsCopy = append(tagsCopy, tag)
		}
	}
	return &InboundTagMatcher{
		tags: tagsCopy,
	}
}

// Apply implements Condition.
func (v *InboundTagMatcher) Apply(ctx routing.Context) bool {
	tag := ctx.GetInboundTag()
	if len(tag) == 0 {
		return false
	}
	for _, t := range v.tags {
		if t == tag {
			return true
		}
	}
	return false
}

type ProtocolMatcher struct {
	protocols []string
}

func NewProtocolMatcher(protocols []string) *ProtocolMatcher {
	pCopy := make([]string, 0, len(protocols))

	for _, p := range protocols {
		if len(p) > 0 {
			pCopy = append(pCopy, p)
		}
	}

	return &ProtocolMatcher{
		protocols: pCopy,
	}
}

// Apply implements Condition.
func (m *ProtocolMatcher) Apply(ctx routing.Context) bool {
	if len(m.protocols) == 0 {
		return false
	}
	protocol := ctx.GetProtocol()
	alpn := ""
	if attrs := ctx.GetAttributes(); attrs != nil {
		alpn = attrs["alpn"]
	}
	return matchProtocolPatterns(m.protocols, protocol, alpn)
}

func parseProtocolPattern(p string) (neg bool, pattern string, ok bool) {
	if p == "" {
		return false, "", false
	}
	if p[0] == '!' {
		neg = true
		p = p[1:]
	}
	if p == "" {
		return false, "", false
	}
	return neg, p, true
}

func matchProtocolPattern(pattern, protocol, alpn string) bool {
	if matchALPNProtocol(pattern, alpn) {
		return true
	}
	return strings.HasPrefix(protocol, pattern)
}

func matchProtocolPatterns(patterns []string, protocol, alpn string) bool {
	hasValidPattern := false
	hasInclude := false
	includeMatched := false

	for _, raw := range patterns {
		neg, pattern, ok := parseProtocolPattern(raw)
		if !ok {
			continue
		}
		hasValidPattern = true
		matched := matchProtocolPattern(pattern, protocol, alpn)
		if neg {
			if matched {
				return false
			}
			continue
		}
		hasInclude = true
		if matched {
			includeMatched = true
		}
	}

	if !hasValidPattern {
		return false
	}
	if hasInclude {
		return includeMatched
	}
	return true
}

func protocolPatternMentionsCandidate(pattern, candidate string) bool {
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

func protocolPatternsNeedSniffing(patterns []string, candidate string) bool {
	if candidate == "" {
		return false
	}
	hasValidPattern := false
	hasInclude := false
	includeMentioned := false
	excludeMentioned := false

	for _, raw := range patterns {
		neg, pattern, ok := parseProtocolPattern(raw)
		if !ok {
			continue
		}
		hasValidPattern = true
		if !neg {
			hasInclude = true
		}
		if !protocolPatternMentionsCandidate(pattern, candidate) {
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

func matchALPNProtocol(p, alpn string) bool {
	if alpn == "" {
		return false
	}
	lp := strings.ToLower(p)
	if lp == "alpn" {
		return true
	}
	if strings.HasPrefix(lp, "alpn:") {
		target := strings.ToLower(p[len("alpn:"):])
		if target == "" {
			return true
		}
		return strings.HasPrefix(strings.ToLower(alpn), target)
	}
	if strings.HasPrefix(lp, "alpn=") {
		target := strings.ToLower(p[len("alpn="):])
		if target == "" {
			return true
		}
		return strings.HasPrefix(strings.ToLower(alpn), target)
	}
	return false
}

type AttributeMatcher struct {
	configuredKeys map[string]*regexp.Regexp
	ja4ExactKeys   map[string]string
	ja4DBKeys      map[string]ja4DBMatcher
}

type ja4DBMatcher struct {
	set *ja4TagSet
	tag string
}

func NewAttributeMatcher(configured map[string]string) (*AttributeMatcher, error) {
	m := &AttributeMatcher{
		configuredKeys: make(map[string]*regexp.Regexp),
	}
	for key, value := range configured {
		if strings.EqualFold(key, InternalReLookupAttr) {
			continue
		}
		if strings.EqualFold(key, InternalDestVlessRouteAttr) {
			continue
		}
		if strings.EqualFold(key, InternalVlessRouteTargetAttr) {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(key))
		if k == "" {
			continue
		}
		if strings.EqualFold(k, "ja4") {
			if fp, valid := normalizeJA4FingerprintFast(value); valid {
				if m.ja4ExactKeys == nil {
					m.ja4ExactKeys = make(map[string]string)
				}
				m.ja4ExactKeys[k] = fp
				continue
			}
			if file, tag, ok := DecodeJA4DBAttributeValue(value); ok {
				set, err := getJA4TagSet(file, tag)
				if err != nil {
					return nil, err
				}
				if m.ja4DBKeys == nil {
					m.ja4DBKeys = make(map[string]ja4DBMatcher)
				}
				matcher := ja4DBMatcher{set: set}
				if strings.TrimSpace(tag) != "!" {
					matcher.tag = normalizeJA4MatchedTag(file, tag)
				}
				m.ja4DBKeys[k] = matcher
				continue
			}
		}
		m.configuredKeys[k] = regexp.MustCompile(value)
	}
	if len(m.configuredKeys) == 0 && len(m.ja4ExactKeys) == 0 && len(m.ja4DBKeys) == 0 {
		return nil, nil
	}
	return m, nil
}

func lookupAttribute(attrs map[string]string, key string) (string, bool) {
	a, ok := attrs[key]
	if ok {
		return a, true
	}
	// Fallback to case-insensitive lookup without allocating a copy map.
	for k, v := range attrs {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// Match implements attributes matching.
func (m *AttributeMatcher) Match(attrs map[string]string) bool {
	for key, regex := range m.configuredKeys {
		a, ok := lookupAttribute(attrs, key)
		if !ok || !regex.MatchString(a) {
			return false
		}
	}
	for key, expected := range m.ja4ExactKeys {
		a, ok := lookupAttribute(attrs, key)
		if !ok {
			return false
		}
		fp, valid := normalizeJA4FingerprintFast(a)
		if !valid || fp != expected {
			return false
		}
	}
	ja4Tag := ""
	for key, matcher := range m.ja4DBKeys {
		a, ok := lookupAttribute(attrs, key)
		if !ok {
			return false
		}
		// Fast-path: when JA4 attribute is already normalized, skip lower/trim normalization.
		// Fallback remains compatible with mixed-case or padded values.
		fp, valid := normalizeJA4FingerprintFast(a)
		if !valid || matcher.set == nil {
			return false
		}
		if !matcher.set.ContainsNormalized(fp) {
			return false
		}
		if matcher.tag != "" {
			ja4Tag = matcher.tag
		}
	}
	if ja4Tag != "" && attrs != nil {
		attrs["ja4_tag"] = ja4Tag
	}
	return true
}

// Apply implements Condition.
func (m *AttributeMatcher) Apply(ctx routing.Context) bool {
	attributes := ctx.GetAttributes()
	if attributes == nil {
		return false
	}
	return m.Match(attributes)
}
