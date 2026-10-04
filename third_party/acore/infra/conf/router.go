package conf

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/platform/filesystem"
	"github.com/ImAubrey/acore/common/serial"
	"google.golang.org/protobuf/proto"
)

var ja4FingerprintPattern = regexp.MustCompile(`^[tq]\d{2}[a-z]\d{4}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$`)

// StrategyConfig represents a strategy config
type StrategyConfig struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

type BalancingRule struct {
	Tag         string         `json:"tag"`
	Selectors   StringList     `json:"selector"`
	Strategy    StrategyConfig `json:"strategy"`
	FallbackTag string         `json:"fallbackTag"`
}

// Build builds the balancing rule
func (r *BalancingRule) Build() (*router.BalancingRule, error) {
	if r.Tag == "" {
		return nil, errors.New("empty balancer tag")
	}
	if len(r.Selectors) == 0 {
		return nil, errors.New("empty selector list")
	}

	r.Strategy.Type = strings.ToLower(strings.TrimSpace(r.Strategy.Type))
	switch r.Strategy.Type {
	case "":
		r.Strategy.Type = strategyRandom
	case strategyRandom, strategyLeastLoad, strategyLeastPing, strategyRoundRobin, strategySelector, strategyFallback:
	default:
		return nil, errors.New("unknown balancing strategy: " + r.Strategy.Type)
	}

	settings := []byte("{}")
	if r.Strategy.Settings != nil {
		settings = ([]byte)(*r.Strategy.Settings)
	}
	rawConfig, err := strategyConfigLoader.LoadWithID(settings, r.Strategy.Type)
	if err != nil {
		return nil, errors.New("failed to parse to strategy config.").Base(err)
	}
	var ts proto.Message
	if builder, ok := rawConfig.(Buildable); ok {
		ts, err = builder.Build()
		if err != nil {
			return nil, err
		}
	}

	return &router.BalancingRule{
		Strategy:         r.Strategy.Type,
		StrategySettings: serial.ToTypedMessage(ts),
		FallbackTag:      r.FallbackTag,
		OutboundSelector: r.Selectors,
		Tag:              r.Tag,
	}, nil
}

type RouterConfig struct {
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy *string           `json:"domainStrategy"`
	DomainRecover  *string           `json:"domainRecover"`
	Balancers      []*BalancingRule  `json:"balancers"`
}

func (c *RouterConfig) getDomainStrategy() router.Config_DomainStrategy {
	ds := ""
	if c.DomainStrategy != nil {
		ds = *c.DomainStrategy
	}

	switch strings.ToLower(ds) {
	case "ipifnonmatch":
		return router.Config_IpIfNonMatch
	case "ipondemand":
		return router.Config_IpOnDemand
	default:
		return router.Config_AsIs
	}
}

func (c *RouterConfig) Build() (*router.Config, error) {
	config := new(router.Config)
	config.DomainStrategy = c.getDomainStrategy()
	domainRecoverMode, err := c.getDomainRecoverMode()
	if err != nil {
		return nil, err
	}

	var rawRuleList []json.RawMessage
	if c != nil {
		rawRuleList = c.RuleList
	}

	for _, rawRule := range rawRuleList {
		rule, err := ParseRule(rawRule)
		if err != nil {
			return nil, err
		}
		config.Rule = append(config.Rule, rule)
	}
	if domainRecoverMode != router.DomainRecoverOff {
		config.Rule = append(config.Rule, &router.RoutingRule{
			InboundTag: []string{router.InternalDomainRecoverInboundTag},
			Attributes: map[string]string{
				router.InternalDomainRecoverAttr: domainRecoverMode.String(),
			},
		})
	}
	for _, rawBalancer := range c.Balancers {
		balancer, err := rawBalancer.Build()
		if err != nil {
			return nil, err
		}
		config.BalancingRule = append(config.BalancingRule, balancer)
	}
	return config, nil
}

func (c *RouterConfig) getDomainRecoverMode() (router.DomainRecoverMode, error) {
	raw := ""
	if c.DomainRecover != nil {
		raw = *c.DomainRecover
	}
	mode, ok := router.ParseDomainRecoverMode(raw)
	if !ok {
		return router.DomainRecoverOff, errors.New("unsupported domain recover mode: ", raw)
	}
	return mode, nil
}

type RouterRule struct {
	RuleTag     string            `json:"ruleTag"`
	Destination routerDestination `json:"destination"`
	OutboundTag string            `json:"outboundTag"`
	BalancerTag string            `json:"balancerTag"`
}

type destVlessRouteValue struct {
	Value uint32
}

type vlessRouteTargetRange struct {
	From uint32 `json:"from"`
	To   uint32 `json:"to"`
}

type routerDestination struct {
	Tag        string               `json:"tag"`
	VlessRoute *destVlessRouteValue `json:"vlessRoute"`
}

type vlessRouteTarget struct {
	Ranges      []vlessRouteTargetRange `json:"ranges"`
	Destination string                  `json:"destination"`
}

type vlessRouteValue struct {
	PortList     *PortList
	QuickTargets []vlessRouteTarget
}

func (v *destVlessRouteValue) String() string {
	return strconv.FormatUint(uint64(v.Value), 10)
}

func (d *routerDestination) TargetTag() string {
	if d == nil {
		return ""
	}
	return strings.TrimSpace(d.Tag)
}

func (d *routerDestination) IsEmpty() bool {
	return d.TargetTag() == "" && d.VlessRoute == nil
}

func (d *routerDestination) UnmarshalJSON(data []byte) error {
	var tag string
	if err := json.Unmarshal(data, &tag); err == nil {
		d.Tag = strings.TrimSpace(tag)
		d.VlessRoute = nil
		return nil
	}

	type rawRouterDestination struct {
		Tag        string               `json:"tag"`
		VlessRoute *destVlessRouteValue `json:"vlessRoute"`
	}
	var raw rawRouterDestination
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.New("invalid destination: ", string(data)).Base(err)
	}
	raw.Tag = strings.TrimSpace(raw.Tag)
	if raw.Tag == "" {
		return errors.New("invalid destination: empty tag")
	}

	d.Tag = raw.Tag
	d.VlessRoute = raw.VlessRoute
	return nil
}

func (v *destVlessRouteValue) UnmarshalJSON(data []byte) error {
	var numeric uint32
	if err := json.Unmarshal(data, &numeric); err == nil {
		if _, err := net.PortFromInt(numeric); err != nil {
			return errors.New("invalid destVlessRoute: ", numeric).Base(err)
		}
		v.Value = numeric
		return nil
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.New("invalid destVlessRoute: ", string(data)).Base(err)
	}

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("invalid destVlessRoute: empty value")
	}
	parsed, err := strconv.ParseUint(raw, 0, 16)
	if err != nil {
		return errors.New("invalid destVlessRoute: ", raw).Base(err)
	}
	if _, err := net.PortFromInt(uint32(parsed)); err != nil {
		return errors.New("invalid destVlessRoute: ", raw).Base(err)
	}
	v.Value = uint32(parsed)
	return nil
}

func (v *vlessRouteValue) UnmarshalJSON(data []byte) error {
	var portList PortList
	if err := portList.UnmarshalJSON(data); err == nil {
		v.PortList = &portList
		return nil
	}

	var rawTargets []string
	if err := json.Unmarshal(data, &rawTargets); err != nil {
		return errors.New("invalid vlessRoute: ", string(data)).Base(err)
	}
	if len(rawTargets) == 0 {
		return errors.New("invalid vlessRoute: empty array")
	}

	quickTargets := make([]vlessRouteTarget, 0, len(rawTargets))
	for _, rawTarget := range rawTargets {
		target, err := parseVlessRouteTarget(rawTarget)
		if err != nil {
			return err
		}
		quickTargets = append(quickTargets, target)
	}
	v.QuickTargets = quickTargets
	return nil
}

func (v *vlessRouteValue) QuickTargetsJSON() (string, error) {
	if len(v.QuickTargets) == 0 {
		return "", nil
	}
	payload, err := json.Marshal(v.QuickTargets)
	if err != nil {
		return "", errors.New("invalid vlessRoute quick targets").Base(err)
	}
	return string(payload), nil
}

func parseVlessRouteTarget(raw string) (vlessRouteTarget, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return vlessRouteTarget{}, errors.New("invalid vlessRoute quick target: empty value")
	}

	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return vlessRouteTarget{}, errors.New("invalid vlessRoute quick target: ", raw)
	}

	portSpec := strings.TrimSpace(parts[0])
	destination := strings.TrimSpace(parts[1])
	if portSpec == "" || destination == "" {
		return vlessRouteTarget{}, errors.New("invalid vlessRoute quick target: ", raw)
	}

	var portList PortList
	if err := portList.UnmarshalJSON([]byte(strconv.Quote(portSpec))); err != nil {
		return vlessRouteTarget{}, errors.New("invalid vlessRoute quick target: ", raw).Base(err)
	}

	target := vlessRouteTarget{
		Ranges:      make([]vlessRouteTargetRange, 0, len(portList.Range)),
		Destination: destination,
	}
	for _, portRange := range portList.Range {
		target.Ranges = append(target.Ranges, vlessRouteTargetRange{
			From: portRange.From,
			To:   portRange.To,
		})
	}
	return target, nil
}

func ParseIP(s string) (*router.CIDR, error) {
	var addr, mask string
	i := strings.Index(s, "/")
	if i < 0 {
		addr = s
	} else {
		addr = s[:i]
		mask = s[i+1:]
	}
	ip := net.ParseAddress(addr)
	switch ip.Family() {
	case net.AddressFamilyIPv4:
		bits := uint32(32)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, errors.New("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 32 {
			return nil, errors.New("invalid network mask for router: ", bits)
		}
		return &router.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	case net.AddressFamilyIPv6:
		bits := uint32(128)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, errors.New("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 128 {
			return nil, errors.New("invalid network mask for router: ", bits)
		}
		return &router.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	default:
		return nil, errors.New("unsupported address for router: ", s)
	}
}

func loadGeoIP(code string) ([]*router.CIDR, error) {
	return loadIP("geoip.dat", code)
}

var (
	cacheMu sync.RWMutex

	FileCache = make(map[string][]byte)
	IPCache   = make(map[string]*router.GeoIP)
	SiteCache = make(map[string]*router.GeoSite)
)

// ResetRoutingDataCaches clears temporary routing data caches used while building config.
// Caches are process-global and should be scoped to one build to avoid stale data after updates.
func ResetRoutingDataCaches() {
	cacheMu.Lock()
	FileCache = make(map[string][]byte)
	IPCache = make(map[string]*router.GeoIP)
	SiteCache = make(map[string]*router.GeoSite)
	cacheMu.Unlock()
}

func loadFile(file string) ([]byte, error) {
	cacheMu.RLock()
	if cached := FileCache[file]; len(cached) > 0 {
		cacheMu.RUnlock()
		return cached, nil
	}
	cacheMu.RUnlock()

	bs, err := filesystem.ReadAsset(file)
	if err != nil {
		return nil, errors.New("failed to open file: ", file).Base(err)
	}
	if len(bs) == 0 {
		return nil, errors.New("empty file: ", file)
	}

	cacheMu.Lock()
	if cached := FileCache[file]; len(cached) > 0 {
		cacheMu.Unlock()
		return cached, nil
	}
	FileCache[file] = bs
	cacheMu.Unlock()
	return bs, nil
}

func loadIP(file, code string) ([]*router.CIDR, error) {
	index := file + ":" + code
	cacheMu.RLock()
	if cached := IPCache[index]; cached != nil {
		cacheMu.RUnlock()
		return cached.Cidr, nil
	}
	cacheMu.RUnlock()

	bs, err := loadFile(file)
	if err != nil {
		return nil, errors.New("failed to load file: ", file).Base(err)
	}
	bs = find(bs, []byte(code))
	if bs == nil {
		return nil, errors.New("code not found in ", file, ": ", code)
	}

	var geoip router.GeoIP
	if err := proto.Unmarshal(bs, &geoip); err != nil {
		return nil, errors.New("error unmarshal IP in ", file, ": ", code).Base(err)
	}

	cacheMu.Lock()
	if cached := IPCache[index]; cached != nil {
		cacheMu.Unlock()
		return cached.Cidr, nil
	}
	IPCache[index] = &geoip
	cacheMu.Unlock()
	return geoip.Cidr, nil
}

func loadSite(file, code string) ([]*router.Domain, error) {
	index := file + ":" + code
	cacheMu.RLock()
	if cached := SiteCache[index]; cached != nil {
		cacheMu.RUnlock()
		return cached.Domain, nil
	}
	cacheMu.RUnlock()

	bs, err := loadFile(file)
	if err != nil {
		return nil, errors.New("failed to load file: ", file).Base(err)
	}
	bs = find(bs, []byte(code))
	if bs == nil {
		return nil, errors.New("list not found in ", file, ": ", code)
	}

	var geosite router.GeoSite
	if err := proto.Unmarshal(bs, &geosite); err != nil {
		return nil, errors.New("error unmarshal Site in ", file, ": ", code).Base(err)
	}

	cacheMu.Lock()
	if cached := SiteCache[index]; cached != nil {
		cacheMu.Unlock()
		return cached.Domain, nil
	}
	SiteCache[index] = &geosite
	cacheMu.Unlock()
	return geosite.Domain, nil
}

func normalizeJA4AttributePattern(raw string) (string, error) {
	pattern := strings.TrimSpace(raw)
	if pattern == "" {
		// Empty ja4 attr is treated as a sniffing trigger-only marker.
		return "", nil
	}
	if _, _, ok := router.DecodeJA4DBAttributeValue(pattern); ok {
		return pattern, nil
	}
	if ja4FingerprintPattern.MatchString(strings.ToLower(pattern)) {
		return strings.ToLower(pattern), nil
	}
	return router.EncodeJA4DBAttributeValue("ja4.db", pattern), nil
}

func normalizeRoutingAttributes(attrs map[string]string) (map[string]string, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		if strings.EqualFold(key, "ja4") {
			pattern, err := normalizeJA4AttributePattern(value)
			if err != nil {
				return nil, errors.New("invalid ja4 attribute pattern: ", value).Base(err)
			}
			out[key] = pattern
			continue
		}
		out[key] = value
	}
	return out, nil
}

func DecodeVarint(buf []byte) (x uint64, n int) {
	for shift := uint(0); shift < 64; shift += 7 {
		if n >= len(buf) {
			return 0, 0
		}
		b := uint64(buf[n])
		n++
		x |= (b & 0x7F) << shift
		if (b & 0x80) == 0 {
			return x, n
		}
	}

	// The number is too large to represent in a 64-bit value.
	return 0, 0
}

func find(data, code []byte) []byte {
	codeL := len(code)
	if codeL == 0 {
		return nil
	}
	for {
		dataL := len(data)
		if dataL < 2 {
			return nil
		}
		x, y := DecodeVarint(data[1:])
		if x == 0 && y == 0 {
			return nil
		}
		headL, bodyL := 1+y, int(x)
		dataL -= headL
		if dataL < bodyL {
			return nil
		}
		data = data[headL:]
		if int(data[1]) == codeL {
			for i := 0; i < codeL && data[2+i] == code[i]; i++ {
				if i+1 == codeL {
					return data[:bodyL]
				}
			}
		}
		if dataL == bodyL {
			return nil
		}
		data = data[bodyL:]
	}
}

type AttributeMatcher interface {
	Match(*router.Domain) bool
}

type BooleanMatcher string

func (m BooleanMatcher) Match(domain *router.Domain) bool {
	for _, attr := range domain.Attribute {
		if attr.Key == string(m) {
			return true
		}
	}
	return false
}

type AttributeList struct {
	matcher []AttributeMatcher
}

func (al *AttributeList) Match(domain *router.Domain) bool {
	for _, matcher := range al.matcher {
		if !matcher.Match(domain) {
			return false
		}
	}
	return true
}

func (al *AttributeList) IsEmpty() bool {
	return len(al.matcher) == 0
}

func parseAttrs(attrs []string) *AttributeList {
	al := new(AttributeList)
	for _, attr := range attrs {
		lc := strings.ToLower(attr)
		al.matcher = append(al.matcher, BooleanMatcher(lc))
	}
	return al
}

func loadGeositeWithAttr(file string, siteWithAttr string) ([]*router.Domain, error) {
	parts := strings.Split(siteWithAttr, "@")
	if len(parts) == 0 {
		return nil, errors.New("empty site")
	}
	country := strings.ToUpper(parts[0])
	attrs := parseAttrs(parts[1:])
	domains, err := loadSite(file, country)
	if err != nil {
		return nil, err
	}

	if attrs.IsEmpty() {
		return domains, nil
	}

	filteredDomains := make([]*router.Domain, 0, len(domains))
	for _, domain := range domains {
		if attrs.Match(domain) {
			filteredDomains = append(filteredDomains, domain)
		}
	}

	return filteredDomains, nil
}

func markDomainsReverse(domains []*router.Domain) []*router.Domain {
	for _, d := range domains {
		d.Attribute = append(d.Attribute, &router.Domain_Attribute{
			Key: router.DomainAttrReverseMatch,
			TypedValue: &router.Domain_Attribute_BoolValue{
				BoolValue: true,
			},
		})
	}
	return domains
}

func parseDomainRule(domain string) ([]*router.Domain, error) {
	if domain == "!" {
		return []*router.Domain{
			{
				Type:  router.Domain_Plain,
				Value: "",
				Attribute: []*router.Domain_Attribute{
					{
						Key: router.DomainAttrMatchEmpty,
						TypedValue: &router.Domain_Attribute_BoolValue{
							BoolValue: true,
						},
					},
				},
			},
		}, nil
	}
	if strings.HasPrefix(domain, "geosite:") {
		country := domain[8:]
		isReverse := false
		if strings.HasPrefix(country, "!") {
			isReverse = true
			country = country[1:]
			if len(country) == 0 {
				return nil, errors.New("empty geosite in rule")
			}
		}
		domains, err := loadGeositeWithAttr("geosite.dat", country)
		if err != nil {
			return nil, errors.New("failed to load geosite: ", country).Base(err)
		}
		if isReverse {
			domains = markDomainsReverse(domains)
		}
		return domains, nil
	}
	isExtDatFile := 0
	{
		const prefix = "ext:"
		if strings.HasPrefix(domain, prefix) {
			isExtDatFile = len(prefix)
		}
		const prefixQualified = "ext-domain:"
		if strings.HasPrefix(domain, prefixQualified) {
			isExtDatFile = len(prefixQualified)
		}
	}
	if isExtDatFile != 0 {
		kv := strings.Split(domain[isExtDatFile:], ":")
		if len(kv) != 2 {
			return nil, errors.New("invalid external resource: ", domain)
		}
		filename := kv[0]
		country := kv[1]
		isReverse := false
		if strings.HasPrefix(country, "!") {
			isReverse = true
			country = country[1:]
			if len(country) == 0 {
				return nil, errors.New("empty geosite in rule")
			}
		}
		domains, err := loadGeositeWithAttr(filename, country)
		if err != nil {
			return nil, errors.New("failed to load external sites: ", country, " from ", filename).Base(err)
		}
		if isReverse {
			domains = markDomainsReverse(domains)
		}
		return domains, nil
	}

	domainRule := new(router.Domain)
	switch {
	case strings.HasPrefix(domain, "regexp:"):
		domainRule.Type = router.Domain_Regex
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "domain:"):
		domainRule.Type = router.Domain_Domain
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "full:"):
		domainRule.Type = router.Domain_Full
		domainRule.Value = domain[5:]

	case strings.HasPrefix(domain, "keyword:"):
		domainRule.Type = router.Domain_Plain
		domainRule.Value = domain[8:]

	case strings.HasPrefix(domain, "dotless:"):
		domainRule.Type = router.Domain_Regex
		switch substr := domain[8:]; {
		case substr == "":
			domainRule.Value = "^[^.]*$"
		case !strings.Contains(substr, "."):
			domainRule.Value = "^[^.]*" + substr + "[^.]*$"
		default:
			return nil, errors.New("substr in dotless rule should not contain a dot: ", substr)
		}

	default:
		domainRule.Type = router.Domain_Plain
		domainRule.Value = domain
	}
	return []*router.Domain{domainRule}, nil
}

func ToCidrList(ips StringList) ([]*router.GeoIP, error) {
	var geoipList []*router.GeoIP
	var customCidrs []*router.CIDR
	var customNegCidrs []*router.CIDR

	for _, ip := range ips {
		if strings.HasPrefix(ip, "geoip:") {
			country := ip[6:]
			isReverseMatch := false
			if strings.HasPrefix(ip, "geoip:!") {
				country = ip[7:]
				isReverseMatch = true
			}
			if len(country) == 0 {
				return nil, errors.New("empty country name in rule")
			}
			geoip, err := loadGeoIP(strings.ToUpper(country))
			if err != nil {
				return nil, errors.New("failed to load GeoIP: ", country).Base(err)
			}

			geoipList = append(geoipList, &router.GeoIP{
				CountryCode:  strings.ToUpper(country),
				Cidr:         geoip,
				ReverseMatch: isReverseMatch,
			})
			continue
		}
		isExtDatFile := 0
		{
			const prefix = "ext:"
			if strings.HasPrefix(ip, prefix) {
				isExtDatFile = len(prefix)
			}
			const prefixQualified = "ext-ip:"
			if strings.HasPrefix(ip, prefixQualified) {
				isExtDatFile = len(prefixQualified)
			}
		}
		if isExtDatFile != 0 {
			kv := strings.Split(ip[isExtDatFile:], ":")
			if len(kv) != 2 {
				return nil, errors.New("invalid external resource: ", ip)
			}

			filename := kv[0]
			country := kv[1]
			if len(filename) == 0 || len(country) == 0 {
				return nil, errors.New("empty filename or empty country in rule")
			}

			isReverseMatch := false
			if strings.HasPrefix(country, "!") {
				country = country[1:]
				isReverseMatch = true
			}
			geoip, err := loadIP(filename, strings.ToUpper(country))
			if err != nil {
				return nil, errors.New("failed to load IPs: ", country, " from ", filename).Base(err)
			}

			geoipList = append(geoipList, &router.GeoIP{
				CountryCode:  strings.ToUpper(filename + "_" + country),
				Cidr:         geoip,
				ReverseMatch: isReverseMatch,
			})

			continue
		}

		isReverseMatch := false
		if strings.HasPrefix(ip, "!") {
			isReverseMatch = true
			ip = ip[1:]
			if len(ip) == 0 {
				return nil, errors.New("invalid IP: empty after !")
			}
		}

		ipRule, err := ParseIP(ip)
		if err != nil {
			return nil, errors.New("invalid IP: ", ip).Base(err)
		}

		if isReverseMatch {
			customNegCidrs = append(customNegCidrs, ipRule)
		} else {
			customCidrs = append(customCidrs, ipRule)
		}
	}

	if len(customCidrs) > 0 {
		geoipList = append(geoipList, &router.GeoIP{
			Cidr: customCidrs,
		})
	}
	if len(customNegCidrs) > 0 {
		geoipList = append(geoipList, &router.GeoIP{
			Cidr:         customNegCidrs,
			ReverseMatch: true,
		})
	}

	return geoipList, nil
}

func parseFieldRuleWithOptions(msg json.RawMessage, allowNoDestination bool) (*router.RoutingRule, error) {
	type RawFieldRule struct {
		RouterRule
		Domain         *StringList       `json:"domain"`
		Domains        *StringList       `json:"domains"`
		IP             *StringList       `json:"ip"`
		Port           *PortList         `json:"port"`
		Network        *NetworkList      `json:"network"`
		SourceIP       *StringList       `json:"sourceIP"`
		Source         *StringList       `json:"source"`
		SourcePort     *PortList         `json:"sourcePort"`
		User           *StringList       `json:"user"`
		VlessRoute     *vlessRouteValue  `json:"vlessRoute"`
		InboundTag     *StringList       `json:"inboundTag"`
		Protocols      *StringList       `json:"protocol"`
		ALPN           *StringList       `json:"alpn"`
		Attributes     map[string]string `json:"attrs"`
		LocalIP        *StringList       `json:"localIP"`
		LocalPort      *PortList         `json:"localPort"`
		RequireRuleTag *StringList       `json:"requireRuleTag"`
		ReLookup       bool              `json:"reLookup"`
	}
	rawFieldRule := new(RawFieldRule)
	err := json.Unmarshal(msg, rawFieldRule)
	if err != nil {
		return nil, err
	}
	if rawFieldRule.ReLookup {
		if rawFieldRule.Attributes == nil {
			rawFieldRule.Attributes = make(map[string]string)
		}
		rawFieldRule.Attributes[router.InternalReLookupAttr] = "true"
	}
	if rawFieldRule.Destination.VlessRoute != nil {
		if rawFieldRule.Attributes == nil {
			rawFieldRule.Attributes = make(map[string]string)
		}
		rawFieldRule.Attributes[router.InternalDestVlessRouteAttr] = rawFieldRule.Destination.VlessRoute.String()
	}

	rule := new(router.RoutingRule)
	rule.RuleTag = rawFieldRule.RuleTag
	if strings.HasPrefix(rule.RuleTag, "!") {
		return nil, errors.New("ruleTag must not start with '!'")
	}

	destination := rawFieldRule.Destination.TargetTag()
	outboundTag := strings.TrimSpace(rawFieldRule.OutboundTag)
	balancerTag := strings.TrimSpace(rawFieldRule.BalancerTag)
	switch {
	case destination != "" && outboundTag != "" && destination != outboundTag:
		return nil, errors.New("routing rule target conflict: destination=", destination, " outboundTag=", outboundTag)
	case destination != "" && balancerTag != "" && destination != balancerTag:
		return nil, errors.New("routing rule target conflict: destination=", destination, " balancerTag=", balancerTag)
	case outboundTag != "" && balancerTag != "" && outboundTag != balancerTag:
		return nil, errors.New("routing rule target conflict: outboundTag=", outboundTag, " balancerTag=", balancerTag)
	}

	target := destination
	if target == "" {
		target = outboundTag
	}
	if target == "" {
		target = balancerTag
	}

	hasVlessRouteQuickTargets := rawFieldRule.VlessRoute != nil && len(rawFieldRule.VlessRoute.QuickTargets) > 0
	if hasVlessRouteQuickTargets {
		if target != "" {
			return nil, errors.New("routing rule vlessRoute quick target mode must not set destination/outboundTag/balancerTag")
		}
		if rawFieldRule.Attributes == nil {
			rawFieldRule.Attributes = make(map[string]string)
		}
		encoded, err := rawFieldRule.VlessRoute.QuickTargetsJSON()
		if err != nil {
			return nil, err
		}
		rawFieldRule.Attributes[router.InternalVlessRouteTargetAttr] = encoded
	}

	if target != "" {
		rule.TargetTag = &router.RoutingRule_Tag{Tag: target}
	} else if !allowNoDestination && rawFieldRule.RuleTag == "" && !hasVlessRouteQuickTargets {
		return nil, errors.New("routing rule with no destination must set ruleTag")
	}

	if rawFieldRule.Domain != nil {
		for _, domain := range *rawFieldRule.Domain {
			rules, err := parseDomainRule(domain)
			if err != nil {
				return nil, errors.New("failed to parse domain rule: ", domain).Base(err)
			}
			rule.Domain = append(rule.Domain, rules...)
		}
	}

	if rawFieldRule.Domains != nil {
		for _, domain := range *rawFieldRule.Domains {
			rules, err := parseDomainRule(domain)
			if err != nil {
				return nil, errors.New("failed to parse domain rule: ", domain).Base(err)
			}
			rule.Domain = append(rule.Domain, rules...)
		}
	}

	if rawFieldRule.IP != nil {
		geoipList, err := ToCidrList(*rawFieldRule.IP)
		if err != nil {
			return nil, err
		}
		rule.Geoip = geoipList
	}

	if rawFieldRule.Port != nil {
		rule.PortList = rawFieldRule.Port.Build()
	}

	if rawFieldRule.Network != nil {
		rule.Networks = rawFieldRule.Network.Build()
	}

	if rawFieldRule.SourceIP == nil {
		rawFieldRule.SourceIP = rawFieldRule.Source
	}

	if rawFieldRule.SourceIP != nil {
		geoipList, err := ToCidrList(*rawFieldRule.SourceIP)
		if err != nil {
			return nil, err
		}
		rule.SourceGeoip = geoipList
	}

	if rawFieldRule.SourcePort != nil {
		rule.SourcePortList = rawFieldRule.SourcePort.Build()
	}

	if rawFieldRule.LocalIP != nil {
		geoipList, err := ToCidrList(*rawFieldRule.LocalIP)
		if err != nil {
			return nil, err
		}
		rule.LocalGeoip = geoipList
	}

	if rawFieldRule.LocalPort != nil {
		rule.LocalPortList = rawFieldRule.LocalPort.Build()
	}

	if rawFieldRule.User != nil {
		for _, s := range *rawFieldRule.User {
			rule.UserEmail = append(rule.UserEmail, s)
		}
	}

	if rawFieldRule.VlessRoute != nil && rawFieldRule.VlessRoute.PortList != nil {
		rule.VlessRouteList = rawFieldRule.VlessRoute.PortList.Build()
	}

	if rawFieldRule.InboundTag != nil {
		for _, s := range *rawFieldRule.InboundTag {
			rule.InboundTag = append(rule.InboundTag, s)
		}
	}

	if rawFieldRule.Protocols != nil {
		for _, s := range *rawFieldRule.Protocols {
			rule.Protocol = append(rule.Protocol, s)
		}
	}
	if rawFieldRule.ALPN != nil {
		for _, s := range *rawFieldRule.ALPN {
			pattern, err := normalizeALPNProtocolPattern(s)
			if err != nil {
				return nil, errors.New("invalid alpn rule: ", s).Base(err)
			}
			rule.Protocol = append(rule.Protocol, pattern)
		}
	}

	if len(rawFieldRule.Attributes) > 0 {
		attrs, err := normalizeRoutingAttributes(rawFieldRule.Attributes)
		if err != nil {
			return nil, err
		}
		rule.Attributes = attrs
	}

	if rawFieldRule.RequireRuleTag != nil {
		rule.RequireRuleTag = append(rule.RequireRuleTag, *rawFieldRule.RequireRuleTag...)
	}

	rule.ReLookup = rawFieldRule.ReLookup

	return rule, nil
}

func parseFieldRule(msg json.RawMessage) (*router.RoutingRule, error) {
	return parseFieldRuleWithOptions(msg, false)
}

func normalizeALPNProtocolPattern(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty value")
	}

	neg := false
	if strings.HasPrefix(s, "!") {
		neg = true
		s = strings.TrimSpace(strings.TrimPrefix(s, "!"))
	}
	if s == "" {
		return "", errors.New("empty value after negation")
	}

	ls := strings.ToLower(s)
	switch {
	case ls == "alpn", strings.HasPrefix(ls, "alpn:"), strings.HasPrefix(ls, "alpn="):
		// Already expressed as protocol matcher pattern.
	default:
		s = "alpn:" + s
	}

	if neg {
		return "!" + s, nil
	}
	return s, nil
}

func ParseRule(msg json.RawMessage) (*router.RoutingRule, error) {
	rawRule := new(RouterRule)
	err := json.Unmarshal(msg, rawRule)
	if err != nil {
		return nil, errors.New("invalid router rule").Base(err)
	}

	fieldrule, err := parseFieldRule(msg)
	if err != nil {
		return nil, errors.New("invalid field rule").Base(err)
	}
	return fieldrule, nil
}
