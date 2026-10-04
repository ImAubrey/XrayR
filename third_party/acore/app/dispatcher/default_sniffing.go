package dispatcher

import (
	"context"
	"encoding/binary"
	stderrs "errors"
	"regexp"
	"strings"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/routing"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
)

var errSniffingTimeout = errors.New("timeout on sniffing")

func (d *DefaultDispatcher) getExcludeDomainRegexp(ctx context.Context, pattern string) (*regexp.Regexp, bool) {
	if v, ok := d.excludeDomainRegexCache.Load(pattern); ok {
		c := v.(compiledExcludeDomainRegex)
		if c.bad || c.re == nil {
			return nil, false
		}
		return c.re, true
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		errors.LogInfoInner(ctx, err, "Unable to compile exclude-domain regex")
		d.excludeDomainRegexCache.Store(pattern, compiledExcludeDomainRegex{bad: true})
		return nil, false
	}

	d.excludeDomainRegexCache.Store(pattern, compiledExcludeDomainRegex{re: re})
	return re, true
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination net.Destination) bool {
	domain := result.Domain()
	if domain == "" {
		return false
	}
	for _, exclude := range request.ExcludeForDomain {
		if strings.HasPrefix(exclude, "regexp:") {
			pattern := exclude[7:]
			re, ok := d.getExcludeDomainRegexp(ctx, pattern)
			if !ok {
				continue
			}
			if re.MatchString(domain) {
				return false
			}
		} else {
			if strings.EqualFold(domain, exclude) {
				return false
			}
		}
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) || strings.HasPrefix(p, protocolString) {
			return true
		}
		if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && protocolString != "bittorrent" && p == "fakedns" &&
			fkr0.IsIPInIPPool(destination.Address) {
			errors.LogInfo(ctx, "Using sniffer ", protocolString, " since the fake DNS missed")
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}

	return false
}

func (d *DefaultDispatcher) shouldEnableProtocolSniffingWithRoutingContext(ctx context.Context, routingCtx routing.Context, protocol string) bool {
	if d.router == nil && d.fw == nil {
		return false
	}
	// JA4 passive sniffing is intentionally driven by rule presence (attrs.ja4),
	// not per-connection context pruning, to avoid missing fingerprints on flows
	// that only become attributable after sniffing.
	if strings.EqualFold(protocol, "ja4") {
		if d.router != nil {
			if checker, ok := d.router.(sniffingProtocolChecker); ok && checker.ShouldSniffProtocol(protocol) {
				return true
			}
		}
		if d.fw != nil {
			if checker, ok := d.fw.(sniffingProtocolChecker); ok && checker.ShouldSniffProtocol(protocol) {
				return true
			}
		}
		return false
	}
	if routingCtx == nil {
		routingCtx = routing_session.AsRoutingContext(ctx)
	}
	if shouldSniffForFeature(d.router, protocol, routingCtx) {
		return true
	}
	if shouldSniffForFeature(d.fw, protocol, routingCtx) {
		return true
	}
	return false
}

func shouldSniffForFeature(feature interface{}, protocol string, routingCtx routing.Context) bool {
	if feature == nil {
		return false
	}
	if checker, ok := feature.(sniffingProtocolContextChecker); ok {
		return checker.ShouldSniffProtocolForContext(protocol, routingCtx)
	}
	if checker, ok := feature.(sniffingProtocolChecker); ok {
		return checker.ShouldSniffProtocol(protocol)
	}
	return false
}

func appendSniffingProtocol(list []string, protocol string) []string {
	for _, p := range list {
		if strings.EqualFold(p, protocol) {
			return list
		}
	}
	return append(list, protocol)
}

func isDNSProtocol(protocol string) bool {
	return strings.HasPrefix(strings.ToLower(protocol), "dns")
}

func alpnShortHint(alpn string) string {
	switch {
	case alpn == "http/1.1" || alpn == "http/1.0":
		return "H1"
	case alpn == "h2" || strings.HasPrefix(alpn, "h2-"):
		return "H2"
	case alpn == "h3" || strings.HasPrefix(alpn, "h3-"):
		return "H3"
	default:
		return ""
	}
}

func logSniffedDomain(ctx context.Context, domain string, result SniffResult) {
	alpn := ""
	if ap, ok := result.(interface{ ALPN() string }); ok {
		alpn = ap.ALPN()
	}
	if alpn == "" {
		errors.LogInfo(ctx, "sniffed domain: ", domain)
		return
	}
	if hint := alpnShortHint(alpn); hint != "" {
		errors.LogInfo(ctx, "sniffed domain: ", domain, " alpn: ", alpn, " (", hint, ")")
		return
	}
	errors.LogInfo(ctx, "sniffed domain: ", domain, " alpn: ", alpn)
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	payload := buf.NewWithSize(32767)
	defer payload.Release()

	sniffer := NewSniffer(ctx)

	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		if metadataErr == nil {
			setALPNAttribute(ctx, metaresult)
		}
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		const (
			baseBudget = 200 * time.Millisecond
			// Fragmented TLS ClientHello (e.g. freedom fragment "tlshello") may arrive slowly
			// over many small records. Give TLS-like traffic a longer window to finish.
			extendedTLSBudget = 2 * time.Second
			// QUIC ClientHello is carried by CRYPTO frames and may span multiple packets.
			extendedQUICBudget = 500 * time.Millisecond
		)
		start := time.Now()
		budget := baseBudget
		extended := false
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				remaining := budget - time.Since(start)
				if remaining <= 0 {
					return nil, errSniffingTimeout
				}
				if err := cReader.Cache(payload, remaining); err != nil {
					return nil, err
				}

				if !payload.IsEmpty() {
					payloadBytes := payload.Bytes()
					isLikelyTLS := isLikelyTLSHandshake(payloadBytes)
					isLikelyQUIC := network == net.Network_UDP && isLikelyQUICInitial(payloadBytes)
					result, err := sniffer.Sniff(ctx, payloadBytes, network)

					// mihomo-style targeted supplementary read:
					// when sniffer can tell "need at least N bytes", try to fill once immediately.
					if needLen, ok := protocol.NeedMoreDataLen(err); ok && needLen > len(payloadBytes) {
						if !extended {
							if isLikelyTLS && budget < extendedTLSBudget {
								budget = extendedTLSBudget
								extended = true
							} else if (isLikelyQUIC || network == net.Network_UDP) && budget < extendedQUICBudget {
								budget = extendedQUICBudget
								extended = true
							}
						}
						remaining = budget - time.Since(start)
						if remaining <= 0 {
							return nil, errSniffingTimeout
						}
						if err := cReader.Cache(payload, remaining); err != nil {
							return nil, err
						}
						if payload.Len() < int32(needLen) {
							continue
						}
						payloadBytes = payload.Bytes()
						isLikelyTLS = isLikelyTLSHandshake(payloadBytes)
						isLikelyQUIC = network == net.Network_UDP && isLikelyQUICInitial(payloadBytes)
						result, err = sniffer.Sniff(ctx, payloadBytes, network)
					}

					switch {
					case stderrs.Is(err, common.ErrNoClue): // No Clue: protocol not matches, and sniffer cannot determine whether there will be a match or not
						// TLS ClientHello may be fragmented into tiny slices. For TLS-like bytes,
						// treat this as partial data and keep waiting instead of counting as a failed attempt.
						if isLikelyTLS {
							if !extended && budget < extendedTLSBudget {
								budget = extendedTLSBudget
								extended = true
							}
						} else if isLikelyQUIC {
							if !extended && budget < extendedQUICBudget {
								budget = extendedQUICBudget
								extended = true
							}
						} else {
							totalAttempt++
						}
					case stderrs.Is(err, protocol.ErrProtoNeedMoreData): // Protocol Need More Data: protocol matches, but need more data to complete sniffing
						// in this case, do not add totalAttempt(allow to read until timeout)
						if !extended {
							if isLikelyTLS && budget < extendedTLSBudget {
								budget = extendedTLSBudget
								extended = true
							} else if isLikelyQUIC && budget < extendedQUICBudget {
								budget = extendedQUICBudget
								extended = true
							}
						}
					default:
						return result, err
					}
				} else {
					totalAttempt++
				}
				if totalAttempt >= 2 {
					return nil, errSniffingTimeout
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		setALPNAttribute(ctx, metaresult)
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		result := CompositeResult(metaresult, contentResult)
		setALPNAttribute(ctx, result)
		setTLSSNIAttribute(ctx, contentResult)
		setTLSVersionAttribute(ctx, result)
		setJA4Attribute(ctx, result)
		return result, nil
	}
	if contentErr == nil {
		setALPNAttribute(ctx, contentResult)
		setTLSSNIAttribute(ctx, contentResult)
		setTLSVersionAttribute(ctx, contentResult)
		setJA4Attribute(ctx, contentResult)
	}
	return contentResult, contentErr
}

const (
	quicVersionDraft29 uint32 = 0xff00001d
	quicVersion1       uint32 = 0x1
)

func isLikelyTLSHandshake(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	// TLS record header prefix:
	// [0] ContentType = 0x16 (handshake)
	// [1] VersionMajor = 0x03
	if payload[0] != 0x16 {
		return false
	}
	if len(payload) == 1 {
		return true
	}
	return payload[1] == 0x03
}

func isLikelyQUICInitial(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}

	typeByte := payload[0]
	// QUIC Initial packet starts with long header and fixed bit.
	if typeByte&0x80 == 0 || typeByte&0x40 == 0 {
		return false
	}
	// Initial packet type is 0b00 in long-header packet type bits.
	if typeByte&0x30 != 0x00 {
		return false
	}
	if len(payload) < 5 {
		return true
	}

	version := binary.BigEndian.Uint32(payload[1:5])
	return version == quicVersionDraft29 || version == quicVersion1
}

func setALPNAttribute(ctx context.Context, result SniffResult) {
	if result == nil {
		return
	}
	ap, ok := result.(interface{ ALPN() string })
	if !ok {
		return
	}
	alpn := ap.ALPN()
	if alpn == "" {
		return
	}
	if conn := conntrack.ConnectionFromContext(ctx); conn != nil {
		conn.SetALPN(alpn)
	}
	if content := session.ContentFromContext(ctx); content != nil {
		if content.Attribute("alpn") == "" {
			content.SetAttribute("alpn", alpn)
		}
	}
}

func setTLSSNIAttribute(ctx context.Context, result SniffResult) {
	if !isTLSResult(result) {
		return
	}
	hasSNI := "0"
	if result.Domain() != "" {
		hasSNI = "1"
	}
	if content := session.ContentFromContext(ctx); content != nil {
		if content.Attribute("tls_sni") == "" {
			content.SetAttribute("tls_sni", hasSNI)
		}
	}
}

func setTLSVersionAttribute(ctx context.Context, result SniffResult) {
	if !isTLSResult(result) {
		return
	}
	tlsVersion, ok := result.(interface{ TLSVersion() string })
	if !ok {
		return
	}
	v := tlsVersion.TLSVersion()
	if v == "" {
		return
	}
	if content := session.ContentFromContext(ctx); content != nil {
		if content.Attribute("tls_version") == "" {
			content.SetAttribute("tls_version", v)
		}
	}
}

func setJA4Attribute(ctx context.Context, result SniffResult) {
	if !isJA4CapableResult(result) {
		return
	}
	ja4Provider, ok := result.(interface{ JA4() string })
	if !ok {
		return
	}
	ja4 := strings.TrimSpace(ja4Provider.JA4())
	if ja4 == "" {
		return
	}
	if conn := conntrack.ConnectionFromContext(ctx); conn != nil {
		conn.SetJA4(ja4)
	}
	if content := session.ContentFromContext(ctx); content != nil {
		if content.Attribute("ja4") == "" {
			content.SetAttribute("ja4", ja4)
		}
	}
}

func (d *DefaultDispatcher) maybeSetJA4TagFromDB(content *session.Content, conn conntrack.Connection) {
	if d == nil || d.router == nil || content == nil {
		return
	}
	if content.Attribute("ja4_tag") != "" {
		return
	}
	ja4 := strings.TrimSpace(content.Attribute("ja4"))
	if ja4 == "" {
		return
	}

	// Keep auto-labeling bound to JA4 passive-sniffing intent.
	if checker, ok := d.router.(sniffingProtocolChecker); !ok || !checker.ShouldSniffProtocol("ja4") {
		return
	}
	resolver, ok := d.router.(ja4TagLookupRouter)
	if !ok {
		return
	}
	tag := strings.TrimSpace(resolver.LookupJA4Tag(ja4))
	if tag == "" {
		return
	}
	content.SetAttribute("ja4_tag", tag)
	if conn != nil {
		conn.SetJA4Tag(tag)
	}
}

func isTLSResult(result SniffResult) bool {
	if result == nil {
		return false
	}
	if strings.EqualFold(result.Protocol(), "tls") {
		return true
	}
	// Composite sniff results may carry TLS either on domain side (e.g. trojan)
	// or protocol side (e.g. fakedns+tls). Treat either as TLS attributes source.
	if resComp, ok := result.(SnifferResultComposite); ok {
		return strings.EqualFold(resComp.ProtocolForDomainResult(), "tls")
	}
	return false
}

func isJA4CapableResult(result SniffResult) bool {
	if result == nil {
		return false
	}
	if strings.EqualFold(result.Protocol(), "tls") || strings.EqualFold(result.Protocol(), "quic") {
		return true
	}
	if resComp, ok := result.(SnifferResultComposite); ok {
		p := resComp.ProtocolForDomainResult()
		return strings.EqualFold(p, "tls") || strings.EqualFold(p, "quic")
	}
	return false
}
