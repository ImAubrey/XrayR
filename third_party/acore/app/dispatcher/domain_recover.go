package dispatcher

import (
	"strings"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	feature_dns "github.com/ImAubrey/acore/features/dns"
)

type domainRecoverMode uint8

const (
	domainRecoverOff domainRecoverMode = iota
	domainRecoverSnifferFirst
	domainRecoverIPReDisCover
)

type domainRecoverModeProvider interface {
	DomainRecoverMode() string
}

func parseDomainRecoverMode(raw string) domainRecoverMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "snifferfirst":
		return domainRecoverSnifferFirst
	case "iprediscover":
		return domainRecoverIPReDisCover
	default:
		return domainRecoverOff
	}
}

func (d *DefaultDispatcher) getDomainRecoverMode() domainRecoverMode {
	if provider, ok := d.router.(domainRecoverModeProvider); ok {
		return parseDomainRecoverMode(provider.DomainRecoverMode())
	}
	return domainRecoverOff
}

func (d *DefaultDispatcher) lookupDomainByIPFromDNSCache(destination net.Destination) string {
	if !destination.Address.Family().IsIP() || d.dns == nil {
		return ""
	}
	reverser, ok := d.dns.(feature_dns.IPDomainLookup)
	if !ok {
		return ""
	}
	domain, found := reverser.LookupDomainByIP(destination.Address.IP())
	if !found {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(domain), ".")
}

func pickRecoveredDomain(mode domainRecoverMode, sniffedDomain string, cachedDomain string) (string, string) {
	sniffedDomain = strings.TrimSuffix(strings.TrimSpace(sniffedDomain), ".")
	cachedDomain = strings.TrimSuffix(strings.TrimSpace(cachedDomain), ".")

	switch mode {
	case domainRecoverSnifferFirst:
		if sniffedDomain != "" {
			return sniffedDomain, "sniffer"
		}
		if cachedDomain != "" {
			return cachedDomain, "dns"
		}
	case domainRecoverIPReDisCover:
		if cachedDomain != "" {
			return cachedDomain, "dns"
		}
		if sniffedDomain != "" {
			return sniffedDomain, "sniffer"
		}
	}
	return "", ""
}

func setRecoveredRouteTarget(ob *session.Outbound, destination net.Destination, domain string) {
	if ob == nil || domain == "" {
		return
	}
	routeTarget := destination
	routeTarget.Address = net.ParseAddress(domain)
	ob.RouteTarget = routeTarget
}

func hasDomainRouteTarget(ob *session.Outbound) bool {
	if ob == nil {
		return false
	}
	if ob.RouteTarget.IsValid() && ob.RouteTarget.Address.Family().IsDomain() {
		return true
	}
	return ob.Target.IsValid() && ob.Target.Address.Family().IsDomain()
}

func normalizeDomainSourceForConntrack(source string, protocol string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "dns":
		return "dns"
	case "sniffer", "sniff":
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		if strings.HasPrefix(protocol, "tls") || strings.HasPrefix(protocol, "quic") {
			return "sni"
		}
		return "sniff"
	case "sni":
		return "sni"
	default:
		return ""
	}
}

func setConnectionDomainSource(conn conntrack.Connection, source string, protocol string) {
	if conn == nil {
		return
	}
	normalized := normalizeDomainSourceForConntrack(source, protocol)
	if normalized == "" {
		return
	}
	conn.SetDomainSource(normalized)
}
