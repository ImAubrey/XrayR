package firewall

import (
	"bytes"
	"context"
	"math/bits"
	"strings"
	"sync"

	xnet "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/features/conntrack"
	feature_firewall "github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/routing"
)

const (
	flowProtocolTrojanTLSInTLS = "flow:trojan-tls-in-tls"
	flowProtocolShadowsocks    = "flow:shadowsocks"
)

var trojanTLSCCSRecord = []byte{20, 3, 3, 0, 1, 1}

// NewFlowObserver builds a live stream observer for routed traffic when any firewall rule needs it.
func (f *Firewall) NewFlowObserver(ctx context.Context, routingCtx routing.Context, onDecision func(feature_firewall.Decision)) feature_firewall.FlowObserver {
	if f == nil || routingCtx == nil || onDecision == nil {
		return nil
	}

	var trojanDetector *trojanTLSInTLSDetector
	if f.shouldInspectFlowProtocolWithContext(flowProtocolTrojanTLSInTLS, routingCtx) {
		trojanDetector = newTrojanTLSInTLSDetector()
	}
	var shadowsocksDetector *shadowsocksDetector
	if f.shouldInspectFlowProtocolWithContext(flowProtocolShadowsocks, routingCtx) && shouldEnableShadowsocksFlowDetection(routingCtx) {
		shadowsocksDetector = newShadowsocksDetector()
	}
	if trojanDetector == nil && shadowsocksDetector == nil {
		return nil
	}

	return &flowObserver{
		ctx:                 ctx,
		routingCtx:          routingCtx,
		firewall:            f,
		onDecision:          onDecision,
		trojanDetector:      trojanDetector,
		shadowsocksDetector: shadowsocksDetector,
	}
}

type flowObserver struct {
	ctx        context.Context
	routingCtx routing.Context
	firewall   *Firewall
	onDecision func(feature_firewall.Decision)

	mu                  sync.Mutex
	trojanDetector      *trojanTLSInTLSDetector
	shadowsocksDetector *shadowsocksDetector
	triggeredMask       uint8
	closed              bool
}

func (o *flowObserver) CloneFlowObserver() feature_firewall.FlowObserver {
	if o == nil {
		return nil
	}
	clone := &flowObserver{
		ctx:        o.ctx,
		routingCtx: o.routingCtx,
		firewall:   o.firewall,
		onDecision: o.onDecision,
	}
	if o.trojanDetector != nil {
		clone.trojanDetector = newTrojanTLSInTLSDetector()
	}
	if o.shadowsocksDetector != nil {
		clone.shadowsocksDetector = newShadowsocksDetector()
	}
	return clone
}

func (o *flowObserver) OnUpload(b []byte) {
	o.handleUpload(b)
}

func (o *flowObserver) OnDownload(b []byte) {
	o.handleDownload(b)
}

func (o *flowObserver) OnClose(err error) {
	o.handleClose(err)
	o.mu.Lock()
	o.closed = true
	o.mu.Unlock()
}

const (
	flowObserverTrojanMatched uint8 = 1 << iota
	flowObserverShadowsocksMatched
)

func (o *flowObserver) handleUpload(b []byte) {
	if o == nil || len(b) == 0 {
		return
	}
	o.handleDetectors(
		func() bool {
			return o.trojanDetector != nil && o.trojanDetector.OnUpload(b)
		},
		func() bool {
			return o.shadowsocksDetector != nil && o.shadowsocksDetector.OnUpload(b)
		},
	)
}

func (o *flowObserver) handleDownload(b []byte) {
	if o == nil || len(b) == 0 {
		return
	}
	o.handleDetectors(
		func() bool {
			return o.trojanDetector != nil && o.trojanDetector.OnDownload(b)
		},
		func() bool {
			return o.shadowsocksDetector != nil && o.shadowsocksDetector.OnDownload(b)
		},
	)
}

func (o *flowObserver) handleClose(err error) {
	if o == nil {
		return
	}
	o.handleDetectors(
		func() bool {
			return o.trojanDetector != nil && o.trojanDetector.OnClose(err)
		},
		func() bool {
			return o.shadowsocksDetector != nil && o.shadowsocksDetector.OnClose(err)
		},
	)
}

func (o *flowObserver) handleDetectors(trojanStep func() bool, shadowsocksStep func() bool) {
	if o == nil {
		return
	}

	var decisions [2]feature_firewall.Decision
	decisionCount := 0

	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	if o.triggeredMask&flowObserverTrojanMatched == 0 && trojanStep != nil && trojanStep() {
		if decision, blocked := o.onDetectorMatchedLocked(flowObserverTrojanMatched, flowProtocolTrojanTLSInTLS); blocked {
			decisions[decisionCount] = decision
			decisionCount++
		}
	}
	if o.triggeredMask&flowObserverShadowsocksMatched == 0 && shadowsocksStep != nil && shadowsocksStep() {
		if decision, blocked := o.onDetectorMatchedLocked(flowObserverShadowsocksMatched, flowProtocolShadowsocks); blocked {
			decisions[decisionCount] = decision
			decisionCount++
		}
	}
	o.mu.Unlock()

	for i := 0; i < decisionCount; i++ {
		o.onDecision(decisions[i])
	}
}

func (o *flowObserver) onDetectorMatchedLocked(mask uint8, protocol string) (feature_firewall.Decision, bool) {
	o.triggeredMask |= mask
	if conn := conntrack.ConnectionFromContext(o.ctx); conn != nil {
		conn.SetProtocol(protocol)
	}
	if decision, blocked := o.firewall.evaluateObservedProtocol(o.ctx, o.routingCtx, protocol); blocked {
		return decision, true
	}
	return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
}

func (f *Firewall) shouldInspectFlowProtocolWithContext(protocol string, ctx routing.Context) bool {
	if ctx == nil || protocol == "" {
		return false
	}
	return f.ruleNeedsFlowProtocol(protocol, ctx)
}

func shouldEnableShadowsocksFlowDetection(ctx routing.Context) bool {
	if ctx == nil || ctx.GetNetwork() != xnet.Network_TCP {
		return false
	}
	if protocol := strings.TrimSpace(strings.ToLower(ctx.GetProtocol())); protocol != "" && protocol != flowProtocolShadowsocks {
		return false
	}
	attrs := ctx.GetAttributes()
	return !hasKnownNonShadowsocksMetadata(attrs)
}

func hasKnownNonShadowsocksMetadata(attrs map[string]string) bool {
	if len(attrs) == 0 {
		return false
	}
	for _, key := range []string{"alpn", "tls_version", "ja4", "host", ":authority", ":method", ":path"} {
		if strings.TrimSpace(attrs[key]) != "" {
			return true
		}
	}
	switch strings.TrimSpace(attrs["tls_sni"]) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func (f *Firewall) ruleNeedsFlowProtocol(protocol string, ctx routing.Context) bool {
	marked := false
	if marker, ok := ctx.(interface{ HasRuleMark() bool }); ok {
		marked = marker.HasRuleMark()
	}
	for _, rule := range f.rules {
		if rule == nil || rule.Match == nil {
			continue
		}
		if marked && !rule.Match.HasRequire {
			continue
		}
		if !protocolPatternsNeedSniffing(rule.Match.Protocols, protocol) {
			continue
		}
		cond := rule.Match.ConditionNoProtocol
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

func (f *Firewall) evaluateObservedProtocol(ctx context.Context, routingCtx routing.Context, protocol string) (feature_firewall.Decision, bool) {
	if routingCtx == nil || protocol == "" {
		return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
	}
	if decision, terminal := f.evaluatePass(ctx, newObservedProtocolContext(routingCtx, protocol)); terminal {
		return decision, decision.Action == feature_firewall.ActionBlock
	}
	return feature_firewall.Decision{Action: feature_firewall.ActionAllow}, false
}

type observedProtocolContext struct {
	routing.Context
	protocol string
	ruleTags map[string]struct{}
	marked   bool
}

func newObservedProtocolContext(ctx routing.Context, protocol string) *observedProtocolContext {
	override := &observedProtocolContext{
		Context:  ctx,
		protocol: protocol,
	}
	if marker, ok := ctx.(interface{ HasRuleMark() bool }); ok {
		override.marked = marker.HasRuleMark()
	}
	return override
}

func (c *observedProtocolContext) GetProtocol() string {
	if c == nil {
		return ""
	}
	return c.protocol
}

func (c *observedProtocolContext) AddRuleTag(tag string) {
	if c == nil || tag == "" {
		return
	}
	if c.ruleTags == nil {
		c.ruleTags = make(map[string]struct{})
	}
	c.ruleTags[tag] = struct{}{}
}

func (c *observedProtocolContext) HasRuleTag(tag string) bool {
	if c == nil || tag == "" {
		return false
	}
	if _, ok := c.ruleTags[tag]; ok {
		return true
	}
	if manager, ok := c.Context.(routing.RuleTagManager); ok {
		return manager.HasRuleTag(tag)
	}
	return false
}

func (c *observedProtocolContext) MarkRuleMatched() {
	if c != nil {
		c.marked = true
	}
}

func (c *observedProtocolContext) HasRuleMark() bool {
	return c != nil && c.marked
}

type trojanTLSInTLSDetector struct {
	uploading          bool
	downloading        bool
	sawTLSClientHello  bool
	sawTLSServerFlight bool
	upCount            int
	downCount          int
	matched            bool
}

func newTrojanTLSInTLSDetector() *trojanTLSInTLSDetector {
	return &trojanTLSInTLSDetector{}
}

func (d *trojanTLSInTLSDetector) Protocol() string { return flowProtocolTrojanTLSInTLS }

func (d *trojanTLSInTLSDetector) OnUpload(b []byte) bool {
	if d == nil || d.matched || len(b) == 0 {
		return false
	}
	if looksLikeTLSHandshakeRecord(b) {
		d.sawTLSClientHello = true
	}
	if shouldStartTrojanTLSApplicationFlight(d, b) {
		d.uploading = true
		d.downloading = false
		d.upCount = 0
		d.downCount = 0
	}
	if d.uploading {
		d.upCount += len(b)
	}
	if d.downloading {
		d.downloading = false
		if d.matchesCurrentTrojanWindow() {
			return true
		}
		d.upCount = 0
		d.downCount = 0
	}
	return false
}

func (d *trojanTLSInTLSDetector) OnDownload(b []byte) bool {
	if d == nil || d.matched || len(b) == 0 {
		return false
	}
	if d.sawTLSClientHello && looksLikeTLSHandshakeRecord(b) {
		d.sawTLSServerFlight = true
	}
	if d.uploading {
		d.uploading = false
		d.downloading = true
	}
	if d.downloading {
		d.downCount += len(b)
	}
	return false
}

func (d *trojanTLSInTLSDetector) OnClose(error) bool {
	if d == nil || d.matched {
		return false
	}
	return d.matchesCurrentTrojanWindow()
}

func (d *trojanTLSInTLSDetector) matchesCurrentTrojanWindow() bool {
	if d == nil || d.matched {
		return false
	}
	if d.upCount >= 550 && d.upCount <= 900 &&
		((d.downCount >= 170 && d.downCount <= 180) || (d.downCount >= 3000 && d.downCount <= 7500)) {
		d.matched = true
		return true
	}
	return false
}

func shouldStartTrojanTLSApplicationFlight(d *trojanTLSInTLSDetector, b []byte) bool {
	if d == nil || len(b) < len(trojanTLSCCSRecord) {
		return false
	}
	if !bytes.Equal(b[:len(trojanTLSCCSRecord)], trojanTLSCCSRecord) {
		return false
	}
	if d.upCount == 0 && !d.downloading {
		return true
	}
	return d.sawTLSServerFlight && !d.uploading && !d.downloading
}

func looksLikeTLSHandshakeRecord(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03
}

type shadowsocksDetector struct {
	uploadChunk []byte
	evaluated   bool
	matched     bool
}

func newShadowsocksDetector() *shadowsocksDetector {
	return &shadowsocksDetector{}
}

func (d *shadowsocksDetector) Protocol() string { return flowProtocolShadowsocks }

func (d *shadowsocksDetector) OnUpload(b []byte) bool {
	if d == nil || d.matched || d.evaluated || len(b) == 0 {
		return false
	}
	d.uploadChunk = appendDetectorChunk(d.uploadChunk, b, 96)
	if len(d.uploadChunk) < 32 {
		return false
	}
	if looksLikeCommonTLSOrHTTP(d.uploadChunk) {
		d.evaluated = true
		return false
	}
	if len(d.uploadChunk) < 48 {
		return false
	}
	if !looksLikeShadowsocksFirstPayload(d.uploadChunk) {
		d.evaluated = true
		return false
	}
	d.evaluated = true
	d.matched = true
	return true
}

func (d *shadowsocksDetector) OnDownload(b []byte) bool {
	return false
}

func (d *shadowsocksDetector) OnClose(error) bool { return false }

func looksLikeCommonTLSOrHTTP(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) >= 2 && b[1] == 0x03 {
		switch b[0] {
		case 0x14, 0x15, 0x16, 0x17:
			return true
		}
	}
	if len(b) >= 2 && b[0] == 0x16 && b[1] == 0x03 {
		return true
	}
	upper := bytes.ToUpper(bytes.TrimSpace(b))
	for _, prefix := range [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("CONNECT "),
	} {
		if bytes.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func appendDetectorChunk(dst []byte, src []byte, max int) []byte {
	if len(dst) >= max || len(src) == 0 {
		return dst
	}
	need := max - len(dst)
	if need > len(src) {
		need = len(src)
	}
	return append(dst, src[:need]...)
}

func looksLikeShadowsocksFirstPayload(b []byte) bool {
	if len(b) < 32 {
		return false
	}
	if len(b) > 64 {
		b = b[:64]
	}

	printableCount := 0
	longestPrintableRun := 0
	currentPrintableRun := 0
	prefixPrintable := true
	oneBits := 0
	prefixLimit := len(b)
	if prefixLimit > 6 {
		prefixLimit = 6
	}

	for i, v := range b {
		printable := isLikelyPrintableASCII(v)
		if printable {
			printableCount++
			currentPrintableRun++
			if currentPrintableRun > longestPrintableRun {
				longestPrintableRun = currentPrintableRun
			}
		} else {
			currentPrintableRun = 0
			if i < prefixLimit {
				prefixPrintable = false
			}
		}
		oneBits += bits.OnesCount8(v)
	}

	asciiRatio := float64(printableCount) / float64(len(b))
	bitDensity := float64(oneBits) / float64(len(b)*8)
	return !prefixPrintable &&
		asciiRatio < 0.35 &&
		longestPrintableRun < 6 &&
		bitDensity >= 0.42 &&
		bitDensity <= 0.58
}

func isLikelyPrintableASCII(v byte) bool {
	switch {
	case v == '\r', v == '\n', v == '\t':
		return true
	case v >= 0x20 && v <= 0x7e:
		return true
	default:
		return false
	}
}
