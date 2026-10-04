package conntrack

import (
	"io"
	stdnet "net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
)

// NewManager creates a new in-memory connection tracker.
func NewManager() *ManagerImpl {
	return &ManagerImpl{
		conns:                  make(map[uint32]*record),
		sourceCounts:           make(map[string]uint32),
		destinationCounts:      make(map[string]uint32),
		sourceDestinationCount: make(map[string]uint32),
		sourceEvents:           make(map[string][]int64),
		destinationEvents:      make(map[string][]int64),
		sourceDestinationEvent: make(map[string][]int64),
	}
}

// ManagerImpl is the default in-memory implementation of Manager.
type ManagerImpl struct {
	mu                     sync.RWMutex
	conns                  map[uint32]*record
	sourceCounts           map[string]uint32
	destinationCounts      map[string]uint32
	sourceDestinationCount map[string]uint32
	sourceEvents           map[string][]int64
	destinationEvents      map[string][]int64
	sourceDestinationEvent map[string][]int64
	nextID                 atomic.Uint32
}

// Type implements common.HasType.
func (*ManagerImpl) Type() interface{} {
	return ManagerType()
}

// Start implements common.Runnable.
func (*ManagerImpl) Start() error { return nil }

// Close implements common.Closable.
func (*ManagerImpl) Close() error { return nil }

// NewConnection implements Manager.
func (m *ManagerImpl) NewConnection(meta Meta) Connection {
	if m == nil {
		return nil
	}
	if meta.Start.IsZero() {
		meta.Start = time.Now()
	}
	id := meta.ID
	if id == 0 {
		id = m.nextID.Add(1)
	}

	r := &record{
		id:          id,
		meta:        meta,
		mgr:         m,
		createdUnix: meta.Start.UnixNano(),
	}
	r.lastSeen.Store(meta.Start.Unix())

	m.mu.Lock()
	if _, exists := m.conns[id]; exists {
		id = m.nextID.Add(1)
		r.id = id
	}
	m.conns[id] = r
	m.refreshCounterKeysLocked(r, meta.Source, meta.Destination, meta.Target)
	m.refreshEventKeysLocked(r, meta.Source, meta.Destination, meta.Target)
	m.mu.Unlock()

	return r
}

// List implements Manager.
func (m *ManagerImpl) List() []Snapshot {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Snapshot, 0, len(m.conns))
	for _, conn := range m.conns {
		result = append(result, conn.Snapshot())
	}
	return result
}

// CountConnections implements Manager.
func (m *ManagerImpl) CountConnections(counterMode CounterMode, counterType CounterType, sourceKey, destinationKey string, window time.Duration) uint32 {
	if m == nil {
		return 0
	}
	switch counterType {
	case CounterTypeSourceIP:
		sourceKey = normalizeCounterIPLiteral(sourceKey)
	case CounterTypeDestinationIP:
		destinationKey = normalizeCounterIPLiteral(destinationKey)
	case CounterTypeSourceDestinationIP:
		sourceKey = normalizeCounterIPLiteral(sourceKey)
		destinationKey = normalizeCounterIPLiteral(destinationKey)
	case CounterTypeSourcePrefix:
		sourceKey = normalizeCounterPrefixLiteral(sourceKey)
	case CounterTypeDestinationPrefix:
		destinationKey = normalizeCounterPrefixLiteral(destinationKey)
	default:
		return 0
	}

	if counterMode == CounterModeNewConnections {
		if window <= 0 {
			return 0
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.countEventConnectionsLocked(counterType, sourceKey, destinationKey, window)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	switch counterType {
	case CounterTypeSourceIP:
		return m.sourceCounts[sourceKey]
	case CounterTypeDestinationIP:
		return m.destinationCounts[destinationKey]
	case CounterTypeSourceDestinationIP:
		return m.sourceDestinationCount[counterPairKey(sourceKey, destinationKey)]
	case CounterTypeSourcePrefix:
		return countPrefixedCounters(m.sourceCounts, sourceKey)
	case CounterTypeDestinationPrefix:
		return countPrefixedCounters(m.destinationCounts, destinationKey)
	default:
		return 0
	}
}

// ListConnectionCounters implements Manager.
func (m *ManagerImpl) ListConnectionCounters(counterMode CounterMode, counterType CounterType, window time.Duration) []CounterSnapshot {
	if m == nil {
		return nil
	}

	if counterMode == CounterModeNewConnections {
		if window <= 0 {
			return nil
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.listEventConnectionCountersLocked(counterType, window)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	switch counterType {
	case CounterTypeSourceIP:
		result := make([]CounterSnapshot, 0, len(m.sourceCounts))
		for sourceIP, count := range m.sourceCounts {
			result = append(result, CounterSnapshot{
				Mode:     counterMode,
				Type:     counterType,
				SourceIP: sourceIP,
				Count:    count,
			})
		}
		sort.Slice(result, func(i, j int) bool {
			if result[i].Count != result[j].Count {
				return result[i].Count > result[j].Count
			}
			return result[i].SourceIP < result[j].SourceIP
		})
		return result
	case CounterTypeDestinationIP:
		result := make([]CounterSnapshot, 0, len(m.destinationCounts))
		for destinationIP, count := range m.destinationCounts {
			result = append(result, CounterSnapshot{
				Mode:          counterMode,
				Type:          counterType,
				DestinationIP: destinationIP,
				Count:         count,
			})
		}
		sort.Slice(result, func(i, j int) bool {
			if result[i].Count != result[j].Count {
				return result[i].Count > result[j].Count
			}
			return result[i].DestinationIP < result[j].DestinationIP
		})
		return result
	case CounterTypeSourceDestinationIP:
		result := make([]CounterSnapshot, 0, len(m.sourceDestinationCount))
		for pair, count := range m.sourceDestinationCount {
			sourceIP, destinationIP := splitCounterPairKey(pair)
			result = append(result, CounterSnapshot{
				Mode:          counterMode,
				Type:          counterType,
				SourceIP:      sourceIP,
				DestinationIP: destinationIP,
				Count:         count,
			})
		}
		sort.Slice(result, func(i, j int) bool {
			if result[i].Count != result[j].Count {
				return result[i].Count > result[j].Count
			}
			if result[i].SourceIP != result[j].SourceIP {
				return result[i].SourceIP < result[j].SourceIP
			}
			return result[i].DestinationIP < result[j].DestinationIP
		})
		return result
	case CounterTypeSourcePrefix, CounterTypeDestinationPrefix:
		return nil
	default:
		return nil
	}
}

// CloseConnection attempts to interrupt a tracked connection by ID.
func (m *ManagerImpl) CloseConnection(id uint32) bool {
	if m == nil || id == 0 {
		return false
	}
	m.mu.RLock()
	conn := m.conns[id]
	m.mu.RUnlock()
	if conn == nil {
		return false
	}
	return conn.RequestClose()
}

// CloseConnections attempts to interrupt multiple tracked connections by ID.
func (m *ManagerImpl) CloseConnections(ids []uint32) int {
	if m == nil || len(ids) == 0 {
		return 0
	}
	closed := 0
	for _, id := range ids {
		if m.CloseConnection(id) {
			closed++
		}
	}
	return closed
}

func (m *ManagerImpl) remove(id uint32) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if conn := m.conns[id]; conn != nil {
		m.releaseCounterKeysLocked(conn)
		delete(m.conns, id)
	}
	m.mu.Unlock()
}

type record struct {
	id       uint32
	meta     Meta
	metaLock sync.RWMutex
	mgr      *ManagerImpl
	closeMu  sync.Mutex
	closer   func()

	upload      atomic.Int64
	download    atomic.Int64
	lastSeen    atomic.Int64
	closeOnce   sync.Once
	createdUnix int64

	counterSourceIP      string
	counterDestinationIP string
	counterPair          string

	eventSourceIP      string
	eventDestinationIP string
	eventPair          string
}

func (r *record) ID() uint32 {
	if r == nil {
		return 0
	}
	return r.id
}

func (r *record) AddUpload(n int64) {
	if r == nil || n <= 0 {
		return
	}
	r.upload.Add(n)
	r.lastSeen.Store(time.Now().Unix())
}

func (r *record) AddDownload(n int64) {
	if r == nil || n <= 0 {
		return
	}
	r.download.Add(n)
	r.lastSeen.Store(time.Now().Unix())
}

func (r *record) SetOutboundTag(tag string) {
	if r == nil || tag == "" {
		return
	}
	r.metaLock.Lock()
	r.meta.OutboundTag = tag
	r.metaLock.Unlock()
}

func (r *record) SetOutboundName(name string) {
	if r == nil || name == "" {
		return
	}
	r.metaLock.Lock()
	r.meta.OutboundName = name
	r.metaLock.Unlock()
}

func (r *record) SetRouteTag(tag string) {
	if r == nil || tag == "" {
		return
	}
	r.metaLock.Lock()
	r.meta.RouteTag = tag
	r.metaLock.Unlock()
}

func (r *record) SetTarget(dest net.Destination) {
	if r == nil || !dest.IsValid() {
		return
	}
	r.metaLock.Lock()
	if r.meta.Target == dest {
		r.metaLock.Unlock()
		return
	}
	source := r.meta.Source
	destination := r.meta.Destination
	r.meta.Target = dest
	r.metaLock.Unlock()
	if r.mgr != nil {
		r.mgr.updateCounterTarget(r, source, destination, dest)
	}
}

func (r *record) SetOutboundLocal(dest net.Destination) {
	if r == nil || !dest.IsValid() {
		return
	}
	r.metaLock.Lock()
	r.meta.OutboundLocal = dest
	r.metaLock.Unlock()
}

func (r *record) SetProtocol(protocol string) {
	if r == nil || protocol == "" {
		return
	}
	r.metaLock.Lock()
	r.meta.Protocol = protocol
	r.metaLock.Unlock()
}

func (r *record) SetALPN(alpn string) {
	if r == nil || alpn == "" {
		return
	}
	r.metaLock.Lock()
	r.meta.ALPN = alpn
	r.metaLock.Unlock()
}

func (r *record) SetJA4(ja4 string) {
	if r == nil || ja4 == "" {
		return
	}
	r.metaLock.Lock()
	r.meta.JA4 = ja4
	r.metaLock.Unlock()
}

func (r *record) SetJA4Tag(tag string) {
	if r == nil || tag == "" {
		return
	}
	r.metaLock.Lock()
	r.meta.JA4Tag = tag
	r.metaLock.Unlock()
}

func (r *record) SetDomainSource(source string) {
	if r == nil || source == "" {
		return
	}
	r.metaLock.Lock()
	r.meta.DomainSource = source
	r.metaLock.Unlock()
}

func (r *record) SetCloser(closer func()) {
	if r == nil || closer == nil {
		return
	}
	r.closeMu.Lock()
	r.closer = closer
	r.closeMu.Unlock()
}

func (r *record) RequestClose() bool {
	if r == nil {
		return false
	}
	r.closeMu.Lock()
	closer := r.closer
	r.closeMu.Unlock()
	if closer == nil {
		return false
	}
	closer()
	return true
}

func (r *record) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{}
	}
	r.metaLock.RLock()
	meta := r.meta
	r.metaLock.RUnlock()

	last := r.lastSeen.Load()
	lastSeen := time.Unix(last, 0)
	if last == 0 {
		lastSeen = meta.Start
	}

	return Snapshot{
		ID:            r.id,
		Start:         meta.Start,
		LastSeen:      lastSeen,
		Network:       meta.Network,
		Source:        meta.Source,
		Local:         meta.Local,
		OutboundLocal: meta.OutboundLocal,
		Destination:   meta.Destination,
		Target:        meta.Target,
		InboundTag:    meta.InboundTag,
		InboundName:   meta.InboundName,
		OutboundTag:   meta.OutboundTag,
		OutboundName:  meta.OutboundName,
		User:          meta.User,
		Protocol:      meta.Protocol,
		ALPN:          meta.ALPN,
		JA4:           meta.JA4,
		JA4Tag:        meta.JA4Tag,
		DomainSource:  meta.DomainSource,
		RouteTag:      meta.RouteTag,
		Upload:        r.upload.Load(),
		Download:      r.download.Load(),
	}
}

func (r *record) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		if r.mgr != nil {
			r.mgr.remove(r.id)
		}
	})
}

func (m *ManagerImpl) updateCounterTarget(r *record, source net.Destination, destination net.Destination, target net.Destination) {
	if m == nil || r == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if current := m.conns[r.id]; current != r {
		return
	}
	m.refreshCounterKeysLocked(r, source, destination, target)
	m.refreshEventKeysLocked(r, source, destination, target)
}

func (m *ManagerImpl) refreshCounterKeysLocked(r *record, source net.Destination, destination net.Destination, target net.Destination) {
	if m == nil || r == nil {
		return
	}
	newSourceIP := sourceCounterIP(source)
	newDestinationIP := destinationCounterIP(destination, target)
	newPair := counterPairKey(newSourceIP, newDestinationIP)

	if r.counterSourceIP != newSourceIP {
		decrementCounter(m.sourceCounts, r.counterSourceIP)
		incrementCounter(m.sourceCounts, newSourceIP)
		r.counterSourceIP = newSourceIP
	}
	if r.counterDestinationIP != newDestinationIP {
		decrementCounter(m.destinationCounts, r.counterDestinationIP)
		incrementCounter(m.destinationCounts, newDestinationIP)
		r.counterDestinationIP = newDestinationIP
	}
	if r.counterPair != newPair {
		decrementCounter(m.sourceDestinationCount, r.counterPair)
		incrementCounter(m.sourceDestinationCount, newPair)
		r.counterPair = newPair
	}
}

func (m *ManagerImpl) releaseCounterKeysLocked(r *record) {
	if m == nil || r == nil {
		return
	}
	decrementCounter(m.sourceCounts, r.counterSourceIP)
	decrementCounter(m.destinationCounts, r.counterDestinationIP)
	decrementCounter(m.sourceDestinationCount, r.counterPair)
	r.counterSourceIP = ""
	r.counterDestinationIP = ""
	r.counterPair = ""
}

func (m *ManagerImpl) refreshEventKeysLocked(r *record, source net.Destination, destination net.Destination, target net.Destination) {
	if m == nil || r == nil || r.createdUnix == 0 {
		return
	}
	newSourceIP := sourceCounterIP(source)
	newDestinationIP := destinationCounterIP(destination, target)
	newPair := counterPairKey(newSourceIP, newDestinationIP)

	if r.eventSourceIP != newSourceIP {
		moveCounterEvent(m.sourceEvents, r.eventSourceIP, newSourceIP, r.createdUnix)
		r.eventSourceIP = newSourceIP
	}
	if r.eventDestinationIP != newDestinationIP {
		moveCounterEvent(m.destinationEvents, r.eventDestinationIP, newDestinationIP, r.createdUnix)
		r.eventDestinationIP = newDestinationIP
	}
	if r.eventPair != newPair {
		moveCounterEvent(m.sourceDestinationEvent, r.eventPair, newPair, r.createdUnix)
		r.eventPair = newPair
	}
}

func incrementCounter(m map[string]uint32, key string) {
	if key == "" || m == nil {
		return
	}
	m[key]++
}

func decrementCounter(m map[string]uint32, key string) {
	if key == "" || m == nil {
		return
	}
	if current := m[key]; current <= 1 {
		delete(m, key)
		return
	}
	m[key]--
}

func moveCounterEvent(m map[string][]int64, oldKey string, newKey string, ts int64) {
	if m == nil || ts == 0 || oldKey == newKey {
		return
	}
	removeCounterEvent(m, oldKey, ts)
	appendCounterEvent(m, newKey, ts)
}

func appendCounterEvent(m map[string][]int64, key string, ts int64) {
	if key == "" || m == nil || ts == 0 {
		return
	}
	m[key] = append(m[key], ts)
}

func removeCounterEvent(m map[string][]int64, key string, ts int64) {
	if key == "" || m == nil || ts == 0 {
		return
	}
	events := m[key]
	if len(events) == 0 {
		return
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i] != ts {
			continue
		}
		copy(events[i:], events[i+1:])
		events = events[:len(events)-1]
		if len(events) == 0 {
			delete(m, key)
		} else {
			m[key] = events
		}
		return
	}
}

func pruneCounterEvents(events []int64, cutoff int64) []int64 {
	if len(events) == 0 {
		return nil
	}
	if cutoff <= 0 {
		return events
	}
	write := 0
	for _, ts := range events {
		if ts < cutoff {
			continue
		}
		events[write] = ts
		write++
	}
	if write == 0 {
		return nil
	}
	return events[:write]
}

func (m *ManagerImpl) countEventConnectionsLocked(counterType CounterType, sourceKey, destinationKey string, window time.Duration) uint32 {
	cutoff := time.Now().Add(-window).UnixNano()
	switch counterType {
	case CounterTypeSourceIP:
		events := pruneCounterEvents(m.sourceEvents[sourceKey], cutoff)
		if len(events) == 0 {
			delete(m.sourceEvents, sourceKey)
			return 0
		}
		m.sourceEvents[sourceKey] = events
		return uint32(len(events))
	case CounterTypeDestinationIP:
		events := pruneCounterEvents(m.destinationEvents[destinationKey], cutoff)
		if len(events) == 0 {
			delete(m.destinationEvents, destinationKey)
			return 0
		}
		m.destinationEvents[destinationKey] = events
		return uint32(len(events))
	case CounterTypeSourceDestinationIP:
		key := counterPairKey(sourceKey, destinationKey)
		events := pruneCounterEvents(m.sourceDestinationEvent[key], cutoff)
		if len(events) == 0 {
			delete(m.sourceDestinationEvent, key)
			return 0
		}
		m.sourceDestinationEvent[key] = events
		return uint32(len(events))
	case CounterTypeSourcePrefix:
		return countPrefixedEvents(m.sourceEvents, sourceKey, cutoff)
	case CounterTypeDestinationPrefix:
		return countPrefixedEvents(m.destinationEvents, destinationKey, cutoff)
	default:
		return 0
	}
}

func (m *ManagerImpl) listEventConnectionCountersLocked(counterType CounterType, window time.Duration) []CounterSnapshot {
	cutoff := time.Now().Add(-window).UnixNano()
	switch counterType {
	case CounterTypeSourceIP:
		result := make([]CounterSnapshot, 0, len(m.sourceEvents))
		for sourceIP, events := range m.sourceEvents {
			events = pruneCounterEvents(events, cutoff)
			if len(events) == 0 {
				delete(m.sourceEvents, sourceIP)
				continue
			}
			m.sourceEvents[sourceIP] = events
			result = append(result, CounterSnapshot{
				Mode:     CounterModeNewConnections,
				Type:     counterType,
				SourceIP: sourceIP,
				Count:    uint32(len(events)),
			})
		}
		sortCounterSnapshots(result)
		return result
	case CounterTypeDestinationIP:
		result := make([]CounterSnapshot, 0, len(m.destinationEvents))
		for destinationIP, events := range m.destinationEvents {
			events = pruneCounterEvents(events, cutoff)
			if len(events) == 0 {
				delete(m.destinationEvents, destinationIP)
				continue
			}
			m.destinationEvents[destinationIP] = events
			result = append(result, CounterSnapshot{
				Mode:          CounterModeNewConnections,
				Type:          counterType,
				DestinationIP: destinationIP,
				Count:         uint32(len(events)),
			})
		}
		sortCounterSnapshots(result)
		return result
	case CounterTypeSourceDestinationIP:
		result := make([]CounterSnapshot, 0, len(m.sourceDestinationEvent))
		for pair, events := range m.sourceDestinationEvent {
			events = pruneCounterEvents(events, cutoff)
			if len(events) == 0 {
				delete(m.sourceDestinationEvent, pair)
				continue
			}
			m.sourceDestinationEvent[pair] = events
			sourceIP, destinationIP := splitCounterPairKey(pair)
			result = append(result, CounterSnapshot{
				Mode:          CounterModeNewConnections,
				Type:          counterType,
				SourceIP:      sourceIP,
				DestinationIP: destinationIP,
				Count:         uint32(len(events)),
			})
		}
		sortCounterSnapshots(result)
		return result
	case CounterTypeSourcePrefix, CounterTypeDestinationPrefix:
		return nil
	default:
		return nil
	}
}

func sortCounterSnapshots(result []CounterSnapshot) {
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		if result[i].SourcePrefix != result[j].SourcePrefix {
			return result[i].SourcePrefix < result[j].SourcePrefix
		}
		if result[i].DestinationPrefix != result[j].DestinationPrefix {
			return result[i].DestinationPrefix < result[j].DestinationPrefix
		}
		if result[i].SourceIP != result[j].SourceIP {
			return result[i].SourceIP < result[j].SourceIP
		}
		return result[i].DestinationIP < result[j].DestinationIP
	})
}

func sourceCounterIP(source net.Destination) string {
	if !source.IsValid() || source.Address == nil {
		return ""
	}
	return normalizeCounterIPLiteral(source.Address.String())
}

func destinationCounterIP(destination net.Destination, target net.Destination) string {
	if target.IsValid() && target.Address != nil && target.Address.Family().IsIP() {
		return normalizeCounterIPLiteral(target.Address.String())
	}
	if destination.IsValid() && destination.Address != nil && destination.Address.Family().IsIP() {
		return normalizeCounterIPLiteral(destination.Address.String())
	}
	return ""
}

func normalizeCounterIPLiteral(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if raw == "" {
		return ""
	}
	if ip := stdnet.ParseIP(raw); ip != nil {
		return ip.String()
	}
	return ""
}

func normalizeCounterPrefixLiteral(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return ""
	}
	return prefix.Masked().String()
}

func countPrefixedCounters(counts map[string]uint32, rawPrefix string) uint32 {
	prefix, ok := parseCounterPrefix(rawPrefix)
	if !ok {
		return 0
	}
	var total uint32
	for rawIP, count := range counts {
		if !counterPrefixContains(prefix, rawIP) {
			continue
		}
		total += count
	}
	return total
}

func countPrefixedEvents(events map[string][]int64, rawPrefix string, cutoff int64) uint32 {
	prefix, ok := parseCounterPrefix(rawPrefix)
	if !ok {
		return 0
	}
	var total uint32
	for rawIP, timestamps := range events {
		pruned := pruneCounterEvents(timestamps, cutoff)
		if len(pruned) == 0 {
			delete(events, rawIP)
			continue
		}
		events[rawIP] = pruned
		if !counterPrefixContains(prefix, rawIP) {
			continue
		}
		total += uint32(len(pruned))
	}
	return total
}

func parseCounterPrefix(raw string) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(normalizeCounterPrefixLiteral(raw))
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

func counterPrefixContains(prefix netip.Prefix, rawIP string) bool {
	ip, err := netip.ParseAddr(normalizeCounterIPLiteral(rawIP))
	if err != nil {
		return false
	}
	return prefix.Contains(ip)
}

const counterPairSeparator = "\x00"

func counterPairKey(sourceIP string, destinationIP string) string {
	sourceIP = normalizeCounterIPLiteral(sourceIP)
	destinationIP = normalizeCounterIPLiteral(destinationIP)
	if sourceIP == "" || destinationIP == "" {
		return ""
	}
	return sourceIP + counterPairSeparator + destinationIP
}

func splitCounterPairKey(key string) (string, string) {
	if key == "" {
		return "", ""
	}
	parts := strings.SplitN(key, counterPairSeparator, 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// CountingReader wraps a buf.Reader and reports read sizes.
type CountingReader struct {
	Reader buf.Reader
	add    func(int64)
}

// NewCountingReader wraps a reader if add is provided.
func NewCountingReader(reader buf.Reader, add func(int64)) buf.Reader {
	if reader == nil || add == nil {
		return reader
	}
	return &CountingReader{Reader: reader, add: add}
}

// ReadMultiBuffer implements buf.Reader.
func (r *CountingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if r.add != nil && mb != nil {
		r.add(int64(mb.Len()))
	}
	return mb, err
}

// ReadMultiBufferTimeout implements buf.TimeoutReader when the underlying reader supports it.
func (r *CountingReader) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	if tr, ok := r.Reader.(buf.TimeoutReader); ok {
		mb, err := tr.ReadMultiBufferTimeout(d)
		if r.add != nil && mb != nil {
			r.add(int64(mb.Len()))
		}
		return mb, err
	}
	return r.ReadMultiBuffer()
}

// Interrupt forwards interruption if supported.
func (r *CountingReader) Interrupt() {
	if ir, ok := r.Reader.(common.Interruptible); ok {
		ir.Interrupt()
	}
}

// Close forwards close if supported.
func (r *CountingReader) Close() error {
	if c, ok := r.Reader.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// CountingWriter wraps a buf.Writer and reports written sizes.
type CountingWriter struct {
	Writer buf.Writer
	add    func(int64)
}

// NewCountingWriter wraps a writer if add is provided.
func NewCountingWriter(writer buf.Writer, add func(int64)) buf.Writer {
	if writer == nil || add == nil {
		return writer
	}
	return &CountingWriter{Writer: writer, add: add}
}

// WriteMultiBuffer implements buf.Writer.
func (w *CountingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.add != nil && mb != nil {
		w.add(int64(mb.Len()))
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// Interrupt forwards interruption if supported.
func (w *CountingWriter) Interrupt() {
	if ir, ok := w.Writer.(common.Interruptible); ok {
		ir.Interrupt()
	}
}

// Close forwards close if supported.
func (w *CountingWriter) Close() error {
	if c, ok := w.Writer.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
