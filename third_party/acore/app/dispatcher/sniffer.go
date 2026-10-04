package dispatcher

import (
	"context"
	stderrs "errors"
	"strings"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/protocol/bittorrent"
	dnsproto "github.com/ImAubrey/acore/common/protocol/dns"
	"github.com/ImAubrey/acore/common/protocol/dtls"
	"github.com/ImAubrey/acore/common/protocol/ech"
	"github.com/ImAubrey/acore/common/protocol/http"
	"github.com/ImAubrey/acore/common/protocol/ike"
	"github.com/ImAubrey/acore/common/protocol/mqtt"
	"github.com/ImAubrey/acore/common/protocol/ntp"
	"github.com/ImAubrey/acore/common/protocol/postgres"
	"github.com/ImAubrey/acore/common/protocol/quic"
	"github.com/ImAubrey/acore/common/protocol/rdp"
	"github.com/ImAubrey/acore/common/protocol/socks"
	"github.com/ImAubrey/acore/common/protocol/ssh"
	"github.com/ImAubrey/acore/common/protocol/stun"
	"github.com/ImAubrey/acore/common/protocol/tls"
	wgproto "github.com/ImAubrey/acore/common/protocol/wireguard"
	"github.com/ImAubrey/acore/common/session"
)

type SniffResult interface {
	Protocol() string
	Domain() string
}

type protocolSniffer func(context.Context, []byte) (SniffResult, error)

type protocolSnifferWithMetadata struct {
	protocolSniffer protocolSniffer
	// A Metadata sniffer will be invoked on connection establishment only, with nil body,
	// for both TCP and UDP connections
	// It will not be shown as a traffic type for routing unless there is no other successful sniffing.
	metadataSniffer bool
	network         net.Network
	// tlsOnly sniffers are only invoked when TCP payload looks like a TLS handshake.
	tlsOnly bool
}

type Sniffer struct {
	sniffer []protocolSnifferWithMetadata
}

type dnsSniffingEnabledKey struct{}
type echSniffingEnabledKey struct{}
type zeroTierSniffingEnabledKey struct{}
type mtProtoSniffingEnabledKey struct{}
type ja4SniffingEnabledKey struct{}

const dotDefaultPort = net.Port(853)

var errNotDoT = stderrs.New("not dot")

func tcpSniffer(fn protocolSniffer) protocolSnifferWithMetadata {
	return protocolSnifferWithMetadata{
		protocolSniffer: fn,
		network:         net.Network_TCP,
	}
}

func tcpTLSSniffer(fn protocolSniffer) protocolSnifferWithMetadata {
	return protocolSnifferWithMetadata{
		protocolSniffer: fn,
		network:         net.Network_TCP,
		tlsOnly:         true,
	}
}

func udpSniffer(fn protocolSniffer) protocolSnifferWithMetadata {
	return protocolSnifferWithMetadata{
		protocolSniffer: fn,
		network:         net.Network_UDP,
	}
}

func sniffHTTP(ctx context.Context, b []byte) (SniffResult, error) { return http.SniffHTTP(b, ctx) }
func sniffSOCKS4(_ context.Context, b []byte) (SniffResult, error) { return socks.SniffSOCKS4(b) }
func sniffSOCKS5(_ context.Context, b []byte) (SniffResult, error) { return socks.SniffSOCKS5(b) }
func sniffSSH(_ context.Context, b []byte) (SniffResult, error)    { return ssh.SniffSSH(b) }
func sniffDNSTCP(_ context.Context, b []byte) (SniffResult, error) { return dnsproto.SniffDNS(b, true) }
func sniffDNSUDP(_ context.Context, b []byte) (SniffResult, error) {
	return dnsproto.SniffDNS(b, false)
}
func sniffECH(_ context.Context, b []byte) (SniffResult, error)  { return ech.SniffECH(b) }
func sniffRDP(_ context.Context, b []byte) (SniffResult, error)  { return rdp.SniffRDP(b) }
func sniffMQTT(_ context.Context, b []byte) (SniffResult, error) { return mqtt.SniffMQTT(b) }
func sniffPostgres(_ context.Context, b []byte) (SniffResult, error) {
	return postgres.SniffPostgres(b)
}
func sniffBittorrent(_ context.Context, b []byte) (SniffResult, error) {
	return bittorrent.SniffBittorrent(b)
}
func sniffSTUN(_ context.Context, b []byte) (SniffResult, error) { return stun.SniffSTUN(b) }
func sniffWireGuard(_ context.Context, b []byte) (SniffResult, error) {
	return wgproto.SniffWireGuard(b)
}
func sniffNTP(_ context.Context, b []byte) (SniffResult, error)   { return ntp.SniffNTP(b) }
func sniffIKEv2(_ context.Context, b []byte) (SniffResult, error) { return ike.SniffIKEv2(b) }
func sniffDTLS(_ context.Context, b []byte) (SniffResult, error)  { return dtls.SniffDTLS(b) }
func sniffQUIC(ctx context.Context, b []byte) (SniffResult, error) {
	return quic.SniffQUICWithJA4(b, shouldEnableJA4Sniffer(ctx))
}
func sniffUTP(_ context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffUTP(b) }

func sniffTLS(ctx context.Context, b []byte) (SniffResult, error) {
	return tls.SniffTLSWithJA4(b, shouldEnableJA4Sniffer(ctx))
}

func hasDoTPort(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		if inbound.Source.Port == dotDefaultPort || inbound.Local.Port == dotDefaultPort {
			return true
		}
	}
	outbounds := session.OutboundsFromContext(ctx)
	for i := len(outbounds) - 1; i >= 0; i-- {
		ob := outbounds[i]
		if ob == nil {
			continue
		}
		if ob.Target.Port == dotDefaultPort || ob.OriginalTarget.Port == dotDefaultPort {
			return true
		}
	}
	return false
}

func isDoTALPN(alpn string) bool {
	switch strings.ToLower(strings.TrimSpace(alpn)) {
	case "dot", "dns":
		return true
	default:
		return false
	}
}

type dotSniffResult struct {
	alpn       string
	tlsVersion string
	ja4        string
}

func (dotSniffResult) Protocol() string     { return "dot" }
func (dotSniffResult) Domain() string       { return "" }
func (r dotSniffResult) ALPN() string       { return r.alpn }
func (r dotSniffResult) TLSVersion() string { return r.tlsVersion }
func (r dotSniffResult) JA4() string        { return r.ja4 }

func sniffDOT(ctx context.Context, b []byte) (SniffResult, error) {
	hdr, err := tls.SniffTLSWithJA4(b, shouldEnableJA4Sniffer(ctx))
	if err != nil {
		return nil, err
	}
	if !isDoTALPN(hdr.ALPN()) && !hasDoTPort(ctx) {
		return nil, errNotDoT
	}
	return dotSniffResult{
		alpn:       hdr.ALPN(),
		tlsVersion: hdr.TLSVersion(),
		ja4:        hdr.JA4(),
	}, nil
}

func NewSniffer(ctx context.Context) *Sniffer {
	// Pre-allocate to avoid reallocations; the final size depends on optional DNS/ECH sniffers.
	sniffers := make([]protocolSnifferWithMetadata, 0, 32)
	sniffers = append(sniffers,
		tcpTLSSniffer(sniffTLS),
		tcpTLSSniffer(sniffDOT),
		tcpSniffer(sniffHTTP),
		tcpSniffer(sniffSOCKS4),
		tcpSniffer(sniffSOCKS5),
		tcpSniffer(sniffSSH),
	)
	if shouldEnableDNSSniffer(ctx) {
		sniffers = append(sniffers,
			tcpSniffer(sniffDNSTCP),
			udpSniffer(sniffDNSUDP),
		)
	}
	if shouldEnableECHSniffer(ctx) {
		sniffers = append(sniffers, tcpTLSSniffer(sniffECH))
	}
	if shouldEnableMTProtoSniffer(ctx) {
		sniffers = append(sniffers, tcpSniffer(sniffMTProto))
	}
	if shouldEnableZeroTierSniffer(ctx) {
		sniffers = append(sniffers, udpSniffer(sniffZeroTier))
	}
	sniffers = append(sniffers,
		tcpSniffer(sniffRDP),
		tcpSniffer(sniffMQTT),
		tcpSniffer(sniffPostgres),
		tcpSniffer(sniffBittorrent),
		tcpSniffer(sniffSTUN),
		udpSniffer(sniffWireGuard),
		udpSniffer(sniffNTP),
		udpSniffer(sniffIKEv2),
		udpSniffer(sniffDTLS),
		udpSniffer(sniffQUIC),
		udpSniffer(sniffSTUN),
		udpSniffer(sniffUTP),
	)
	ret := &Sniffer{sniffer: sniffers}

	if fakeDNSSniffer, err := newFakeDNSSniffer(ctx); err == nil {
		// Sniffer mutates its internal slice in-place while probing. Keep a stable copy of the
		// original sniffers for the FakeDNS "then others" fallback.
		others := append([]protocolSnifferWithMetadata(nil), ret.sniffer...)

		ret.sniffer = append(ret.sniffer, fakeDNSSniffer)
		if fakeDNSThenOthers, err := newFakeDNSThenOthers(ctx, fakeDNSSniffer, others); err == nil {
			ret.sniffer = append([]protocolSnifferWithMetadata{fakeDNSThenOthers}, ret.sniffer...)
		}
	}

	return ret
}

var errUnknownContent = errors.New("unknown content")

func shouldEnableDNSSniffer(ctx context.Context) bool {
	v := ctx.Value(dnsSniffingEnabledKey{})
	if enabled, ok := v.(bool); ok && enabled {
		return true
	}
	return false
}

func shouldEnableECHSniffer(ctx context.Context) bool {
	v := ctx.Value(echSniffingEnabledKey{})
	if enabled, ok := v.(bool); ok && enabled {
		return true
	}
	return false
}

func shouldEnableZeroTierSniffer(ctx context.Context) bool {
	v := ctx.Value(zeroTierSniffingEnabledKey{})
	if enabled, ok := v.(bool); ok && enabled {
		return true
	}
	return false
}

func shouldEnableMTProtoSniffer(ctx context.Context) bool {
	v := ctx.Value(mtProtoSniffingEnabledKey{})
	if enabled, ok := v.(bool); ok && enabled {
		return true
	}
	return false
}

func shouldEnableJA4Sniffer(ctx context.Context) bool {
	v := ctx.Value(ja4SniffingEnabledKey{})
	if enabled, ok := v.(bool); ok && enabled {
		return true
	}
	return false
}

func isDOTProtocol(protocolName string) bool {
	return strings.EqualFold(strings.TrimSpace(protocolName), "dot")
}

func (s *Sniffer) Sniff(c context.Context, payload []byte, network net.Network) (SniffResult, error) {
	switch network {
	case net.Network_TCP:
		return s.sniffByNetwork(c, payload, network, isLikelyTLSHandshake(payload))
	case net.Network_UDP:
		return s.sniffByNetwork(c, payload, network, false)
	default:
		return s.sniffByNetwork(c, payload, network, false)
	}
}

func (s *Sniffer) sniffByNetwork(c context.Context, payload []byte, network net.Network, allowTLSSniffers bool) (SniffResult, error) {
	sniffers := s.sniffer

	type sniffTask struct {
		idx int
		si  protocolSnifferWithMetadata
	}
	type sniffOutcome struct {
		idx    int
		si     protocolSnifferWithMetadata
		result SniffResult
		err    error
	}

	tasks := make([]sniffTask, 0, len(sniffers))
	for i, si := range sniffers {
		if si.metadataSniffer || si.network != network {
			continue
		}
		if si.tlsOnly && !allowTLSSniffers {
			continue
		}
		tasks = append(tasks, sniffTask{idx: i, si: si})
	}

	if len(tasks) == 0 {
		s.sniffer = nil
		return nil, errUnknownContent
	}

	outcomes := make(chan sniffOutcome, len(tasks))
	for _, task := range tasks {
		task := task
		// Each sniffer runs concurrently; pass an isolated payload snapshot to
		// avoid races with subsequent cache refreshes.
		payloadSnapshot := append([]byte(nil), payload...)
		go func(localPayload []byte) {
			result, err := task.si.protocolSniffer(c, localPayload)
			outcomes <- sniffOutcome{idx: task.idx, si: task.si, result: result, err: err}
		}(payloadSnapshot)
	}

	noCluesByIdx := make(map[int]protocolSnifferWithMetadata, len(tasks))
	var firstNeedMore *sniffOutcome
	successes := make([]sniffOutcome, 0, 2)
	for i := 0; i < len(tasks); i++ {
		outcome := <-outcomes
		if outcome.err == nil && outcome.result != nil {
			// Keep all positive hits so we can resolve protocol conflicts after draining
			// all goroutines (for example prefer TLS over incidental Trojan matches).
			successes = append(successes, outcome)
			continue
		}
		if stderrs.Is(outcome.err, common.ErrNoClue) {
			noCluesByIdx[outcome.idx] = outcome.si
			continue
		}
		if stderrs.Is(outcome.err, protocol.ErrProtoNeedMoreData) {
			if firstNeedMore == nil {
				keep := outcome
				firstNeedMore = &keep
			}
		}
	}

	if len(successes) > 0 {
		// DoT is a strict TLS subset. Prefer it over generic TLS when both hit.
		for _, s := range successes {
			if isDOTProtocol(s.result.Protocol()) {
				return s.result, nil
			}
		}
		// Fallback: preserve original "fastest positive wins" behavior.
		return successes[0].result, nil
	}

	if firstNeedMore != nil {
		s.sniffer = []protocolSnifferWithMetadata{firstNeedMore.si}
		return nil, firstNeedMore.err
	}

	if len(noCluesByIdx) > 0 {
		write := 0
		for _, task := range tasks {
			si, ok := noCluesByIdx[task.idx]
			if !ok {
				continue
			}
			sniffers[write] = si
			write++
		}
		s.sniffer = sniffers[:write]
		return nil, common.ErrNoClue
	}

	s.sniffer = nil
	return nil, errUnknownContent
}

func (s *Sniffer) SniffMetadata(c context.Context) (SniffResult, error) {
	sniffers := s.sniffer
	write := 0
	for read := 0; read < len(sniffers); read++ {
		si := sniffers[read]
		sniffer := si.protocolSniffer
		if !si.metadataSniffer {
			sniffers[write] = si
			write++
			continue
		}
		result, err := sniffer(c, nil)
		if stderrs.Is(err, common.ErrNoClue) {
			sniffers[write] = si
			write++
			continue
		}

		if err == nil && result != nil {
			return result, nil
		}
	}

	if write > 0 {
		s.sniffer = sniffers[:write]
		return nil, common.ErrNoClue
	}

	s.sniffer = nil
	return nil, errUnknownContent
}

func CompositeResult(domainResult SniffResult, protocolResult SniffResult) SniffResult {
	return &compositeResult{domainResult: domainResult, protocolResult: protocolResult}
}

type compositeResult struct {
	domainResult   SniffResult
	protocolResult SniffResult
}

func (c compositeResult) Protocol() string {
	return c.protocolResult.Protocol()
}

func (c compositeResult) Domain() string {
	return c.domainResult.Domain()
}

func (c compositeResult) ProtocolForDomainResult() string {
	return c.domainResult.Protocol()
}

func (c compositeResult) ALPN() string {
	if ap, ok := c.protocolResult.(interface{ ALPN() string }); ok {
		return ap.ALPN()
	}
	if ap, ok := c.domainResult.(interface{ ALPN() string }); ok {
		return ap.ALPN()
	}
	return ""
}

func (c compositeResult) TLSVersion() string {
	if tv, ok := c.domainResult.(interface{ TLSVersion() string }); ok {
		if v := tv.TLSVersion(); v != "" {
			return v
		}
	}
	if tv, ok := c.protocolResult.(interface{ TLSVersion() string }); ok {
		return tv.TLSVersion()
	}
	return ""
}

func (c compositeResult) JA4() string {
	if fp, ok := c.domainResult.(interface{ JA4() string }); ok {
		if v := fp.JA4(); v != "" {
			return v
		}
	}
	if fp, ok := c.protocolResult.(interface{ JA4() string }); ok {
		return fp.JA4()
	}
	return ""
}

type SnifferResultComposite interface {
	ProtocolForDomainResult() string
}

type SnifferIsProtoSubsetOf interface {
	IsProtoSubsetOf(protocolName string) bool
}
