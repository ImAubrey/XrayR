package metrics

import (
	"encoding/json"
	stdnet "net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/features/conntrack"
)

var connectionsOnce sync.Once
var connMu sync.RWMutex
var connManager conntrack.Manager

func setConntrackManager(m conntrack.Manager) {
	connMu.Lock()
	connManager = m
	connMu.Unlock()
}

func registerConnectionsRoutes() {
	connectionsOnce.Do(func() {
		http.HandleFunc("/connections", connectionsHandler)
		http.HandleFunc("/connections/stream", connectionsStreamHandler)
		http.HandleFunc("/connections/close", connectionsCloseHandler)
		http.HandleFunc("/connections/counters", connectionsCountersHandler)
	})
}

func connectionsHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, buildGroupedSnapshot())
}

func connectionsStreamHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	interval := parseInterval(r, 1000)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Send initial snapshot immediately.
	sendSSE(w, buildGroupedSnapshot())
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			sendSSE(w, buildGroupedSnapshot())
			flusher.Flush()
		}
	}
}

type closeConnectionsRequest struct {
	IDs []uint32 `json:"ids"`
}

type closeConnectionsResponse struct {
	Requested int      `json:"requested"`
	Closed    []uint32 `json:"closed"`
	Failed    []uint32 `json:"failed"`
}

func connectionsCloseHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", metricsCORSAllowHeaders)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req closeConnectionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	ids := normalizeCloseIDs(req.IDs)
	if len(ids) == 0 {
		http.Error(w, "ids required", http.StatusBadRequest)
		return
	}

	connMu.RLock()
	mgr := connManager
	connMu.RUnlock()
	if mgr == nil {
		http.Error(w, "conntrack unavailable", http.StatusServiceUnavailable)
		return
	}
	closer, ok := mgr.(interface{ CloseConnection(uint32) bool })
	if !ok {
		http.Error(w, "close not supported", http.StatusNotImplemented)
		return
	}

	closed := make([]uint32, 0, len(ids))
	failed := make([]uint32, 0)
	for _, id := range ids {
		if closer.CloseConnection(id) {
			closed = append(closed, id)
		} else {
			failed = append(failed, id)
		}
	}

	writeJSON(w, closeConnectionsResponse{
		Requested: len(ids),
		Closed:    closed,
		Failed:    failed,
	})
}

func sendSSE(w http.ResponseWriter, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n\n"))
}

func writeJSON(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(payload)
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", metricsCORSAllowHeaders)
}

func parseInterval(r *http.Request, defaultMs int) time.Duration {
	interval := r.URL.Query().Get("interval")
	if interval == "" {
		return time.Duration(defaultMs) * time.Millisecond
	}
	ms, err := strconv.Atoi(interval)
	if err != nil || ms <= 0 {
		return time.Duration(defaultMs) * time.Millisecond
	}
	if ms < 200 {
		ms = 200
	}
	return time.Duration(ms) * time.Millisecond
}

type countersResponse struct {
	Type          string        `json:"type"`
	Mode          string        `json:"mode"`
	WindowSeconds uint32        `json:"windowSeconds,omitempty"`
	Count         uint32        `json:"count"`
	Counters      []counterView `json:"counters,omitempty"`
}

type counterView struct {
	SourceIP          string `json:"sourceIP,omitempty"`
	DestinationIP     string `json:"destinationIP,omitempty"`
	SourcePrefix      string `json:"sourcePrefix,omitempty"`
	DestinationPrefix string `json:"destinationPrefix,omitempty"`
	Count             uint32 `json:"count"`
}

func connectionsCountersHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	counterType, ok := parseCounterType(r.URL.Query().Get("type"))
	if !ok {
		http.Error(w, "invalid counter type", http.StatusBadRequest)
		return
	}
	counterMode, ok := parseCounterMode(r.URL.Query().Get("mode"))
	if !ok {
		http.Error(w, "invalid counter mode", http.StatusBadRequest)
		return
	}
	window, windowSeconds, ok := parseCounterWindow(counterMode, r.URL.Query().Get("windowSeconds"))
	if !ok {
		http.Error(w, "invalid counter window", http.StatusBadRequest)
		return
	}

	connMu.RLock()
	mgr := connManager
	connMu.RUnlock()
	if mgr == nil {
		writeJSON(w, countersResponse{
			Type:          counterTypeName(counterType),
			Mode:          counterModeName(counterMode),
			WindowSeconds: windowSeconds,
		})
		return
	}

	sourceIP := normalizeIPLiteral(r.URL.Query().Get("sourceIP"))
	destinationIP := normalizeIPLiteral(r.URL.Query().Get("destinationIP"))
	sourcePrefix := normalizePrefixLiteral(r.URL.Query().Get("sourcePrefix"))
	destinationPrefix := normalizePrefixLiteral(r.URL.Query().Get("destinationPrefix"))

	switch counterType {
	case conntrack.CounterTypeSourceIP:
		if sourceIP != "" {
			writeJSON(w, countersResponse{
				Type:          counterTypeName(counterType),
				Mode:          counterModeName(counterMode),
				WindowSeconds: windowSeconds,
				Count:         mgr.CountConnections(counterMode, counterType, sourceIP, "", window),
			})
			return
		}
	case conntrack.CounterTypeDestinationIP:
		if destinationIP != "" {
			writeJSON(w, countersResponse{
				Type:          counterTypeName(counterType),
				Mode:          counterModeName(counterMode),
				WindowSeconds: windowSeconds,
				Count:         mgr.CountConnections(counterMode, counterType, "", destinationIP, window),
			})
			return
		}
	case conntrack.CounterTypeSourceDestinationIP:
		if sourceIP != "" && destinationIP != "" {
			writeJSON(w, countersResponse{
				Type:          counterTypeName(counterType),
				Mode:          counterModeName(counterMode),
				WindowSeconds: windowSeconds,
				Count:         mgr.CountConnections(counterMode, counterType, sourceIP, destinationIP, window),
			})
			return
		}
	case conntrack.CounterTypeSourcePrefix:
		if sourcePrefix == "" {
			http.Error(w, "sourcePrefix required for sourcePrefix counter", http.StatusBadRequest)
			return
		}
		count := mgr.CountConnections(counterMode, counterType, sourcePrefix, "", window)
		writeJSON(w, countersResponse{
			Type:          counterTypeName(counterType),
			Mode:          counterModeName(counterMode),
			WindowSeconds: windowSeconds,
			Count:         count,
			Counters: []counterView{{
				SourcePrefix: sourcePrefix,
				Count:        count,
			}},
		})
		return
	case conntrack.CounterTypeDestinationPrefix:
		if destinationPrefix == "" {
			http.Error(w, "destinationPrefix required for destinationPrefix counter", http.StatusBadRequest)
			return
		}
		count := mgr.CountConnections(counterMode, counterType, "", destinationPrefix, window)
		writeJSON(w, countersResponse{
			Type:          counterTypeName(counterType),
			Mode:          counterModeName(counterMode),
			WindowSeconds: windowSeconds,
			Count:         count,
			Counters: []counterView{{
				DestinationPrefix: destinationPrefix,
				Count:             count,
			}},
		})
		return
	}

	counters := mgr.ListConnectionCounters(counterMode, counterType, window)
	limit := 0
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	views := make([]counterView, 0, len(counters))
	for _, counter := range counters {
		if sourceIP != "" && counter.SourceIP != sourceIP {
			continue
		}
		if destinationIP != "" && counter.DestinationIP != destinationIP {
			continue
		}
		if sourcePrefix != "" && counter.SourcePrefix != sourcePrefix {
			continue
		}
		if destinationPrefix != "" && counter.DestinationPrefix != destinationPrefix {
			continue
		}
		views = append(views, counterView{
			SourceIP:          counter.SourceIP,
			DestinationIP:     counter.DestinationIP,
			SourcePrefix:      counter.SourcePrefix,
			DestinationPrefix: counter.DestinationPrefix,
			Count:             counter.Count,
		})
	}
	if limit > 0 && len(views) > limit {
		views = views[:limit]
	}

	writeJSON(w, countersResponse{
		Type:          counterTypeName(counterType),
		Mode:          counterModeName(counterMode),
		WindowSeconds: windowSeconds,
		Counters:      views,
	})
}

func parseCounterType(raw string) (conntrack.CounterType, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "srcip", "sourceip", "source_ip":
		return conntrack.CounterTypeSourceIP, true
	case "dstip", "destinationip", "destination_ip":
		return conntrack.CounterTypeDestinationIP, true
	case "srcdstip", "sourcedestinationip", "source_destination_ip", "src-dst-ip":
		return conntrack.CounterTypeSourceDestinationIP, true
	case "srcprefix", "sourceprefix", "source_prefix", "src-prefix":
		return conntrack.CounterTypeSourcePrefix, true
	case "dstprefix", "destinationprefix", "destination_prefix", "dst-prefix":
		return conntrack.CounterTypeDestinationPrefix, true
	default:
		return 0, false
	}
}

func counterTypeName(counterType conntrack.CounterType) string {
	switch counterType {
	case conntrack.CounterTypeSourceIP:
		return "sourceIP"
	case conntrack.CounterTypeDestinationIP:
		return "destinationIP"
	case conntrack.CounterTypeSourceDestinationIP:
		return "sourceDestinationIP"
	case conntrack.CounterTypeSourcePrefix:
		return "sourcePrefix"
	case conntrack.CounterTypeDestinationPrefix:
		return "destinationPrefix"
	default:
		return ""
	}
}

func parseCounterMode(raw string) (conntrack.CounterMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "active", "activeconnections", "active_connections":
		return conntrack.CounterModeActiveConnections, true
	case "new", "newconnections", "new_connections":
		return conntrack.CounterModeNewConnections, true
	default:
		return 0, false
	}
}

func counterModeName(counterMode conntrack.CounterMode) string {
	switch counterMode {
	case conntrack.CounterModeActiveConnections:
		return "activeConnections"
	case conntrack.CounterModeNewConnections:
		return "newConnections"
	default:
		return ""
	}
}

func parseCounterWindow(counterMode conntrack.CounterMode, raw string) (time.Duration, uint32, bool) {
	if counterMode != conntrack.CounterModeNewConnections {
		return 0, 0, strings.TrimSpace(raw) == ""
	}
	seconds, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
	if err != nil || seconds == 0 {
		return 0, 0, false
	}
	return time.Duration(seconds) * time.Second, uint32(seconds), true
}

type groupedSnapshot struct {
	DownloadTotal int64             `json:"downloadTotal"`
	UploadTotal   int64             `json:"uploadTotal"`
	Connections   []groupedConnView `json:"connections"`
}

type groupedConnView struct {
	ID              string       `json:"id"`
	Metadata        connMetadata `json:"metadata"`
	Upload          int64        `json:"upload"`
	Download        int64        `json:"download"`
	Start           string       `json:"start"`
	Chains          []string     `json:"chains,omitempty"`
	Rule            string       `json:"rule,omitempty"`
	RulePayload     string       `json:"rulePayload,omitempty"`
	ConnectionCount int          `json:"connectionCount,omitempty"`
	Details         []connDetail `json:"details,omitempty"`
	startTime       time.Time
	lastActive      time.Time
}

type connDetail struct {
	ID          string       `json:"id"`
	Metadata    connMetadata `json:"metadata"`
	Upload      int64        `json:"upload"`
	Download    int64        `json:"download"`
	Start       string       `json:"start"`
	LastSeen    string       `json:"lastSeen"`
	Chains      []string     `json:"chains,omitempty"`
	Rule        string       `json:"rule,omitempty"`
	RulePayload string       `json:"rulePayload,omitempty"`
}

type connMetadata struct {
	Network         string `json:"network,omitempty"`
	Type            string `json:"type,omitempty"`
	FirewallFlow    string `json:"firewallFlow,omitempty"`
	ALPN            string `json:"alpn,omitempty"`
	JA4             string `json:"ja4,omitempty"`
	JA4Tag          string `json:"ja4Tag,omitempty"`
	DomainSource    string `json:"domainSource,omitempty"`
	SourceIP        string `json:"sourceIP,omitempty"`
	SourcePort      uint32 `json:"sourcePort,omitempty"`
	LocalIP         string `json:"localIP,omitempty"`
	LocalPort       uint32 `json:"localPort,omitempty"`
	AcoreSrcIP      string `json:"acoreSrcIP,omitempty"`
	AcoreSrcPort    uint32 `json:"acoreSrcPort,omitempty"`
	DestinationIP   string `json:"destinationIP,omitempty"`
	DestinationPort uint32 `json:"destinationPort,omitempty"`
	Host            string `json:"host,omitempty"`
	InboundTag      string `json:"inboundTag,omitempty"`
	OutboundTag     string `json:"outboundTag,omitempty"`
	User            string `json:"user,omitempty"`
}

func buildGroupedSnapshot() groupedSnapshot {
	connMu.RLock()
	mgr := connManager
	connMu.RUnlock()
	if mgr == nil {
		return groupedSnapshot{}
	}
	snaps := mgr.List()
	counterCounts := groupedCounterSnapshot(mgr)
	grouped := make(map[string]*groupedConnView, len(snaps))

	var totalUp int64
	var totalDown int64

	for _, snap := range snaps {
		meta := buildMetadata(snap)
		key := groupKey(meta)
		entry := grouped[key]
		if entry == nil {
			entry = &groupedConnView{
				ID:          key,
				Metadata:    meta,
				Start:       snap.Start.Format(time.RFC3339Nano),
				startTime:   snap.Start,
				lastActive:  snap.LastSeen,
				Chains:      buildChains(snap),
				Rule:        snap.RouteTag,
				RulePayload: snap.RouteTag,
			}
			grouped[key] = entry
		} else {
			entry.Metadata = mergeMetadata(entry.Metadata, meta)
			if entry.Rule != "" && snap.RouteTag != "" && entry.Rule != snap.RouteTag {
				entry.Rule = "mixed"
			}
			if entry.RulePayload != "" && snap.RouteTag != "" && entry.RulePayload != snap.RouteTag {
				entry.RulePayload = "mixed"
			}
			if len(entry.Chains) == 0 {
				entry.Chains = buildChains(snap)
			}
		}
		entry.Upload += snap.Upload
		entry.Download += snap.Download
		entry.ConnectionCount++
		entry.Details = append(entry.Details, connDetail{
			ID:          strconv.FormatUint(uint64(snap.ID), 10),
			Metadata:    meta,
			Upload:      snap.Upload,
			Download:    snap.Download,
			Start:       snap.Start.Format(time.RFC3339Nano),
			LastSeen:    snap.LastSeen.Format(time.RFC3339Nano),
			Chains:      buildChains(snap),
			Rule:        snap.RouteTag,
			RulePayload: snap.RouteTag,
		})
		if entry.startTime.IsZero() || snap.Start.Before(entry.startTime) {
			entry.startTime = snap.Start
			entry.Start = snap.Start.Format(time.RFC3339Nano)
		}
		if snap.LastSeen.After(entry.lastActive) {
			entry.lastActive = snap.LastSeen
		}
	}

	list := make([]groupedConnView, 0, len(grouped))
	for _, v := range grouped {
		if count, ok := counterCounts[groupCounterMapKey(v.Metadata.SourceIP, v.Metadata.DestinationIP)]; ok && count > 0 {
			v.ConnectionCount = int(count)
		}
		totalUp += v.Upload
		totalDown += v.Download
		sort.Slice(v.Details, func(i, j int) bool {
			return v.Details[i].LastSeen > v.Details[j].LastSeen
		})
		list = append(list, *v)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].lastActive.After(list[j].lastActive)
	})

	return groupedSnapshot{
		DownloadTotal: totalDown,
		UploadTotal:   totalUp,
		Connections:   list,
	}
}

func groupedCounterSnapshot(mgr conntrack.Manager) map[string]uint32 {
	if mgr == nil {
		return nil
	}
	counters := mgr.ListConnectionCounters(conntrack.CounterModeActiveConnections, conntrack.CounterTypeSourceDestinationIP, 0)
	if len(counters) == 0 {
		return nil
	}
	result := make(map[string]uint32, len(counters))
	for _, counter := range counters {
		key := groupCounterMapKey(counter.SourceIP, counter.DestinationIP)
		if key == "" {
			continue
		}
		result[key] = counter.Count
	}
	return result
}

func buildMetadata(snap conntrack.Snapshot) connMetadata {
	meta := connMetadata{
		Network:     snap.Network.SystemString(),
		InboundTag:  snap.InboundTag,
		OutboundTag: snap.OutboundTag,
		User:        snap.User,
		JA4:         snap.JA4,
		JA4Tag:      snap.JA4Tag,
	}
	if snap.Protocol != "" {
		if isFirewallFlowProtocol(snap.Protocol) {
			meta.FirewallFlow = snap.Protocol
			meta.Type = snap.InboundName
		} else {
			meta.Type = snap.Protocol
		}
	} else {
		meta.Type = snap.InboundName
	}
	if snap.ALPN != "" {
		meta.ALPN = snap.ALPN
	}
	if snap.DomainSource != "" {
		meta.DomainSource = strings.ToLower(strings.TrimSpace(snap.DomainSource))
	}
	if snap.Source.IsValid() {
		meta.SourceIP = normalizeIPLiteral(snap.Source.Address.String())
		meta.SourcePort = uint32(snap.Source.Port)
	}
	if snap.Local.IsValid() {
		meta.LocalIP = normalizeIPLiteral(snap.Local.Address.String())
		meta.LocalPort = uint32(snap.Local.Port)
	}
	if snap.OutboundLocal.IsValid() {
		meta.AcoreSrcIP = normalizeIPLiteral(snap.OutboundLocal.Address.String())
		meta.AcoreSrcPort = uint32(snap.OutboundLocal.Port)
	}

	dest := snap.Target
	if !dest.IsValid() {
		dest = snap.Destination
	}
	if dest.IsValid() && dest.Address.Family().IsDomain() && snap.Destination.IsValid() && snap.Destination.Address.Family().IsIP() {
		dest = snap.Destination
	}
	if dest.IsValid() {
		meta.DestinationPort = uint32(dest.Port)
		if dest.Address.Family().IsDomain() {
			meta.Host = dest.Address.Domain()
		} else {
			meta.DestinationIP = normalizeIPLiteral(dest.Address.String())
		}
	}
	if meta.DestinationIP == "" && meta.Host != "" {
		if ip := normalizeIPLiteral(meta.Host); isIPLiteral(ip) {
			meta.DestinationIP = ip
			meta.Host = ""
		}
	}
	if meta.Host == "" && snap.Target.IsValid() && snap.Target.Address.Family().IsDomain() {
		meta.Host = snap.Target.Address.Domain()
	}
	if meta.Host == "" && snap.Destination.IsValid() && snap.Destination.Address.Family().IsDomain() {
		meta.Host = snap.Destination.Address.Domain()
	}
	return meta
}

func buildChains(snap conntrack.Snapshot) []string {
	if snap.OutboundTag != "" {
		return []string{snap.OutboundTag}
	}
	if snap.OutboundName != "" {
		return []string{snap.OutboundName}
	}
	return nil
}

func groupKey(meta connMetadata) string {
	dst := normalizeIPLiteral(meta.DestinationIP)
	if dst == "" {
		dst = normalizeIPLiteral(meta.Host)
	}
	src := normalizeIPLiteral(meta.SourceIP)
	if src == "" {
		src = "unknown"
	}
	if dst == "" {
		dst = "unknown"
	}
	return src + "->" + dst
}

func groupCounterMapKey(sourceIP string, destinationIP string) string {
	sourceIP = normalizeIPLiteral(sourceIP)
	destinationIP = normalizeIPLiteral(destinationIP)
	if sourceIP == "" || destinationIP == "" {
		return ""
	}
	return sourceIP + "->" + destinationIP
}

func normalizeIPLiteral(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if raw == "" {
		return ""
	}
	if ip := stdnet.ParseIP(raw); ip != nil {
		return ip.String()
	}
	return raw
}

func normalizePrefixLiteral(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return ""
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return ""
	}
	return prefix.Masked().String()
}

func isIPLiteral(value string) bool {
	return stdnet.ParseIP(value) != nil
}

func isFirewallFlowProtocol(protocol string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(protocol)), "flow:")
}

func normalizeCloseIDs(ids []uint32) []uint32 {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[uint32]struct{}, len(ids))
	out := make([]uint32, 0, len(ids))
	for _, id := range ids {
		if id == 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func mergeMetadata(base connMetadata, incoming connMetadata) connMetadata {
	base.Network = mergeString(base.Network, incoming.Network)
	base.Type = mergeString(base.Type, incoming.Type)
	base.FirewallFlow = mergeString(base.FirewallFlow, incoming.FirewallFlow)
	base.ALPN = mergeString(base.ALPN, incoming.ALPN)
	base.DomainSource = mergeString(base.DomainSource, incoming.DomainSource)
	base.SourceIP = mergeString(base.SourceIP, incoming.SourceIP)
	base.LocalIP = mergeString(base.LocalIP, incoming.LocalIP)
	base.AcoreSrcIP = mergeString(base.AcoreSrcIP, incoming.AcoreSrcIP)
	base.DestinationIP = mergeString(base.DestinationIP, incoming.DestinationIP)
	base.Host = mergeString(base.Host, incoming.Host)
	base.InboundTag = mergeString(base.InboundTag, incoming.InboundTag)
	base.OutboundTag = mergeString(base.OutboundTag, incoming.OutboundTag)
	base.User = mergeString(base.User, incoming.User)
	return base
}

func mergeString(current string, incoming string) string {
	if current == "" {
		return incoming
	}
	if incoming == "" || current == incoming {
		return current
	}
	return "mixed"
}
