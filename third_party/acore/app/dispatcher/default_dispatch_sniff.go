package dispatcher

import (
	"context"
	"strings"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/transport"
)

type forceSniffingConfig struct {
	wireguard bool
	mtproto   bool
	zerotier  bool
	ech       bool
	dot       bool
	rdp       bool
	mqtt      bool
	ntp       bool
	postgres  bool
	ikev2     bool
	dtls      bool
	ja4       bool
}

func (c forceSniffingConfig) enabled() bool {
	return c.wireguard ||
		c.mtproto ||
		c.zerotier ||
		c.ech ||
		c.dot ||
		c.rdp ||
		c.mqtt ||
		c.ntp ||
		c.postgres ||
		c.ikev2 ||
		c.dtls ||
		c.ja4
}

func (c forceSniffingConfig) shouldPublishProtocol(sniffingEnabled bool, protocol string) bool {
	if sniffingEnabled {
		return true
	}
	switch {
	case c.ja4 && (strings.EqualFold(protocol, "tls") || strings.EqualFold(protocol, "quic")):
		return true
	case strings.EqualFold(protocol, "wireguard"):
		return true
	case strings.EqualFold(protocol, "mtproto"):
		return true
	case strings.EqualFold(protocol, "zerotier"):
		return true
	case strings.EqualFold(protocol, "ech"):
		return true
	case strings.EqualFold(protocol, "dot"):
		return true
	case strings.EqualFold(protocol, "rdp"):
		return true
	case strings.EqualFold(protocol, "mqtt"):
		return true
	case strings.EqualFold(protocol, "ntp"):
		return true
	case strings.HasPrefix(strings.ToLower(protocol), "postgres"):
		return true
	case strings.EqualFold(protocol, "ikev2"):
		return true
	case strings.EqualFold(protocol, "dtls"):
		return true
	default:
		return false
	}
}

func (d *DefaultDispatcher) buildForceSniffingConfig(ctx context.Context, routingCtx routing.Context) forceSniffingConfig {
	return forceSniffingConfig{
		wireguard: d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "wireguard"),
		mtproto:   d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "mtproto"),
		zerotier:  d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "zerotier"),
		ech:       d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "ech"),
		dot:       d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "dot"),
		rdp:       d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "rdp"),
		mqtt:      d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "mqtt"),
		ntp:       d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "ntp"),
		postgres:  d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "postgres"),
		ikev2:     d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "ikev2"),
		dtls:      d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "dtls"),
		ja4:       d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "ja4"),
	}
}

func sniffingRequestWantsProtocol(request session.SniffingRequest, protocol string) bool {
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.EqualFold(strings.TrimSpace(p), protocol) {
			return true
		}
	}
	return false
}

func (d *DefaultDispatcher) buildSniffContext(
	ctx context.Context,
	routingCtx routing.Context,
	content *session.Content,
	sniffingRequest session.SniffingRequest,
	force forceSniffingConfig,
) (context.Context, session.SniffingRequest) {
	sniffCtx := ctx
	if sniffingRequest.Enabled && d.shouldEnableProtocolSniffingWithRoutingContext(ctx, routingCtx, "dns") {
		sniffingRequest.OverrideDestinationForProtocol = appendSniffingProtocol(sniffingRequest.OverrideDestinationForProtocol, "dns")
		content.SniffingRequest.OverrideDestinationForProtocol = sniffingRequest.OverrideDestinationForProtocol
		sniffCtx = context.WithValue(sniffCtx, dnsSniffingEnabledKey{}, true)
	}
	if force.ech {
		sniffCtx = context.WithValue(sniffCtx, echSniffingEnabledKey{}, true)
	}
	if force.mtproto {
		sniffCtx = context.WithValue(sniffCtx, mtProtoSniffingEnabledKey{}, true)
	}
	if force.zerotier {
		sniffCtx = context.WithValue(sniffCtx, zeroTierSniffingEnabledKey{}, true)
	}
	if force.ja4 {
		sniffCtx = context.WithValue(sniffCtx, ja4SniffingEnabledKey{}, true)
	}
	return sniffCtx, sniffingRequest
}

func (d *DefaultDispatcher) sniffAndApplyRouting(
	ctx context.Context,
	routingCtx routing.Context,
	content *session.Content,
	sniffingRequest session.SniffingRequest,
	force forceSniffingConfig,
	outbound *transport.Link,
	reader buf.TimeoutReader,
	destination *net.Destination,
	ob *session.Outbound,
	conn conntrack.Connection,
) (SniffResult, error) {
	sniffCtx, sniffingRequest := d.buildSniffContext(ctx, routingCtx, content, sniffingRequest, force)
	cReader := &cachedReader{reader: reader}
	outbound.Reader = cReader
	result, err := sniffer(sniffCtx, cReader, sniffingRequest.MetadataOnly, destination.Network)
	d.maybeSetJA4TagFromDB(content, conn)

	if err == nil {
		protocol := result.Protocol()
		if force.shouldPublishProtocol(sniffingRequest.Enabled, protocol) {
			content.Protocol = protocol
			if conn != nil {
				conn.SetProtocol(content.Protocol)
			}
		}
	}

	// Only apply destination override when sniffing is enabled on inbound.
	if sniffingRequest.Enabled && err == nil && d.shouldOverride(sniffCtx, result, sniffingRequest, *destination) {
		d.applySniffDestinationOverride(ctx, ob, destination, sniffingRequest, result, conn)
	}
	return result, err
}

func (d *DefaultDispatcher) applySniffDestinationOverride(
	ctx context.Context,
	ob *session.Outbound,
	destination *net.Destination,
	sniffingRequest session.SniffingRequest,
	result SniffResult,
	conn conntrack.Connection,
) {
	domain := result.Domain()
	logSniffedDomain(ctx, domain, result)

	updatedDestination := *destination
	updatedDestination.Address = net.ParseAddress(domain)
	*destination = updatedDestination

	protocolForDomain := sniffResultProtocol(result)
	setConnectionDomainSource(conn, "sniffer", protocolForDomain)

	isFakeIP := false
	if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
		isFakeIP = true
	}
	if isDNSProtocol(protocolForDomain) || (sniffingRequest.RouteOnly && protocolForDomain != "fakedns" && protocolForDomain != "fakedns+others" && !isFakeIP) {
		ob.RouteTarget = updatedDestination
		return
	}
	ob.Target = updatedDestination
}

func (d *DefaultDispatcher) applyDomainRecover(
	ob *session.Outbound,
	originalDestination net.Destination,
	result SniffResult,
	sniffErr error,
	conn conntrack.Connection,
) {
	mode := d.getDomainRecoverMode()
	if mode == domainRecoverOff {
		return
	}
	if mode == domainRecoverSnifferFirst && hasDomainRouteTarget(ob) {
		return
	}

	sniffedDomain := ""
	protocolForDomain := ""
	if sniffErr == nil && result != nil {
		sniffedDomain = result.Domain()
		protocolForDomain = sniffResultProtocol(result)
	}

	cachedDomain := d.lookupDomainByIPFromDNSCache(originalDestination)
	recoveredDomain, recoveredSource := pickRecoveredDomain(mode, sniffedDomain, cachedDomain)
	if recoveredDomain == "" {
		return
	}
	setRecoveredRouteTarget(ob, originalDestination, recoveredDomain)
	setConnectionDomainSource(conn, recoveredSource, protocolForDomain)
}

func sniffResultProtocol(result SniffResult) string {
	protocol := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		return resComp.ProtocolForDomainResult()
	}
	return protocol
}
