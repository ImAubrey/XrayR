package dns

import (
	"context"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/routing"
)

// ResolvableContext is an implementation of routing.Context, with domain resolving capability.
type ResolvableContext struct {
	routing.Context
	dnsClient dns.Client
	cacheIPs  []net.IP
	hasError  bool
}

// Forward rule tag operations to the underlying context when supported.
func (ctx *ResolvableContext) AddRuleTag(tag string) {
	if mgr, ok := ctx.Context.(routing.RuleTagManager); ok {
		mgr.AddRuleTag(tag)
	}
}

func (ctx *ResolvableContext) HasRuleTag(tag string) bool {
	if mgr, ok := ctx.Context.(routing.RuleTagManager); ok {
		return mgr.HasRuleTag(tag)
	}
	return false
}

// MarkRuleMatched forwards mark flag to underlying context when supported.
func (ctx *ResolvableContext) MarkRuleMatched() {
	if marker, ok := ctx.Context.(interface {
		MarkRuleMatched()
	}); ok {
		marker.MarkRuleMatched()
	}
}

func (ctx *ResolvableContext) HasRuleMark() bool {
	if marker, ok := ctx.Context.(interface {
		HasRuleMark() bool
	}); ok {
		return marker.HasRuleMark()
	}
	return false
}

// GetTargetIPs overrides original routing.Context's implementation.
func (ctx *ResolvableContext) GetTargetIPs() []net.IP {
	if len(ctx.cacheIPs) > 0 {
		return ctx.cacheIPs
	}

	// If the underlying context already carries resolved IPs (e.g., TPROXY/FOLLOWREDIRECT),
	// respect them first instead of re-resolving the sniffed domain.
	if base := ctx.Context.GetTargetIPs(); len(base) > 0 {
		ctx.cacheIPs = base
		return base
	}

	if ctx.hasError {
		return nil
	}

	if domain := ctx.GetTargetDomain(); len(domain) != 0 {
		// Respect client stack preference: if source is v4-only, query A only; if v6-only, query AAAA only.
		srcIPs := ctx.GetSourceIPs()
		ipv4Only, ipv6Only := false, false
		for _, ip := range srcIPs {
			if ip.To4() != nil {
				ipv4Only = true
			} else {
				ipv6Only = true
			}
		}
		switch {
		case ipv4Only && !ipv6Only:
			ipv6Only = false
		case ipv6Only && !ipv4Only:
			ipv4Only = false
		default:
			ipv4Only, ipv6Only = true, true
		}

		ips, _, err := ctx.dnsClient.LookupIP(domain, dns.IPOption{
			IPv4Enable: ipv4Only,
			IPv6Enable: ipv6Only,
			FakeEnable: false,
		})
		if err == nil {
			ctx.cacheIPs = ips
			return ips
		}
		errors.LogInfoInner(context.Background(), err, "resolve ip for ", domain)
	}

	if ips := ctx.Context.GetTargetIPs(); len(ips) != 0 {
		ctx.cacheIPs = ips
		return ips
	}

	ctx.hasError = true
	return nil
}

// ContextWithDNSClient creates a new routing context with domain resolving capability.
// Resolved domain IPs can be retrieved by GetTargetIPs().
func ContextWithDNSClient(ctx routing.Context, client dns.Client) routing.Context {
	return &ResolvableContext{Context: ctx, dnsClient: client}
}
