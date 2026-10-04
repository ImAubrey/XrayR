package router

import "strings"

type DomainRecoverMode uint8

const (
	DomainRecoverOff DomainRecoverMode = iota
	DomainRecoverSnifferFirst
	DomainRecoverIPReDisCover
)

func ParseDomainRecoverMode(raw string) (DomainRecoverMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return DomainRecoverOff, true
	case "snifferfirst":
		return DomainRecoverSnifferFirst, true
	case "iprediscover":
		return DomainRecoverIPReDisCover, true
	default:
		return DomainRecoverOff, false
	}
}

func (m DomainRecoverMode) String() string {
	switch m {
	case DomainRecoverSnifferFirst:
		return "snifferfirst"
	case DomainRecoverIPReDisCover:
		return "iprediscover"
	default:
		return "off"
	}
}

func parseInternalDomainRecoverRule(rule *RoutingRule) (DomainRecoverMode, bool) {
	if rule == nil || len(rule.Attributes) == 0 {
		return DomainRecoverOff, false
	}
	rawMode, ok := rule.Attributes[InternalDomainRecoverAttr]
	if !ok {
		return DomainRecoverOff, false
	}
	markerFound := false
	for _, tag := range rule.InboundTag {
		if strings.EqualFold(tag, InternalDomainRecoverInboundTag) {
			markerFound = true
			break
		}
	}
	if !markerFound {
		return DomainRecoverOff, false
	}
	mode, ok := ParseDomainRecoverMode(rawMode)
	if !ok {
		return DomainRecoverOff, true
	}
	return mode, true
}
