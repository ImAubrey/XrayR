// Package dns is an implementation of core.DNS feature.
package dns

import (
	"context"
	go_errors "errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/common/strmatcher"
	"github.com/ImAubrey/acore/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// DNS is a DNS rely server.
type DNS struct {
	sync.RWMutex
	disableFallback        bool
	disableFallbackIfMatch bool
	enableParallelQuery    bool
	optimisticCache        bool
	serveExpiredTTL        uint32
	ipOption               *dns.IPOption
	hosts                  *StaticHosts
	clients                []*Client
	ctx                    context.Context
	domainMatcher          strmatcher.IndexMatcher
	matcherInfos           []*DomainMatcherInfo
	checkSystem            bool
	cacheSizeBytes         int64
	cachePerStoreBytes     int64
	ipDomainCacheMu        sync.RWMutex
	ipDomainCache          map[string]ipDomainCacheEntry
	ipDomainCacheSizeBytes int64
	ipDomainTouch          uint64
	ipDomainLastCleanup    time.Time
}

// DomainMatcherInfo contains information attached to index returned by Server.domainMatcher
type DomainMatcherInfo struct {
	clientIdx     uint16
	domainRuleIdx uint16
}

type ipDomainCacheEntry struct {
	domain string
	expire time.Time
	touch  uint64
}

type dnsRuntimeSnapshot struct {
	disableFallback        bool
	disableFallbackIfMatch bool
	enableParallelQuery    bool
	optimisticCache        bool
	serveExpiredTTL        uint32
	ipOption               dns.IPOption
	hosts                  *StaticHosts
	clients                []*Client
	ctx                    context.Context
	domainMatcher          strmatcher.IndexMatcher
	matcherInfos           []*DomainMatcherInfo
	checkSystem            bool
	cachePerStoreBytes     int64
}

const (
	ipDomainCacheCleanupInterval = 5 * time.Minute
	defaultDNSCacheSizeBytes     = 8 * 1024 * 1024
	minDNSCacheStoreSizeBytes    = 256 * 1024
)

// New creates a new DNS server with given configuration.
func New(ctx context.Context, config *Config) (*DNS, error) {
	var clientIP net.IP
	switch len(config.ClientIp) {
	case 0, net.IPv4len, net.IPv6len:
		clientIP = net.IP(config.ClientIp)
	default:
		return nil, errors.New("unexpected client IP length ", len(config.ClientIp))
	}

	var ipOption dns.IPOption
	optimisticCache := true
	if config.OptimisticCache != nil {
		optimisticCache = config.GetOptimisticCache()
	}
	cacheSizeBytes := int64(config.GetCacheSize())
	if cacheSizeBytes <= 0 {
		cacheSizeBytes = defaultDNSCacheSizeBytes
	}
	cacheStores := len(config.NameServer)
	if cacheStores <= 0 {
		cacheStores = 1
	}
	cachePerStoreBytes := cacheSizeBytes / int64(cacheStores+1) // +1 for IP->domain reverse cache
	if cachePerStoreBytes <= 0 {
		cachePerStoreBytes = cacheSizeBytes
	}
	if cachePerStoreBytes < minDNSCacheStoreSizeBytes {
		cachePerStoreBytes = minDNSCacheStoreSizeBytes
	}

	checkSystem := false
	switch config.QueryStrategy {
	case QueryStrategy_USE_IP:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
	case QueryStrategy_USE_SYS:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
		checkSystem = true
	case QueryStrategy_USE_IP4:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		ipOption = dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: false,
		}
	default:
		return nil, errors.New("unexpected query strategy ", config.QueryStrategy)
	}

	hosts, err := NewStaticHosts(config.StaticHosts)
	if err != nil {
		return nil, errors.New("failed to create hosts").Base(err)
	}

	var clients []*Client
	domainRuleCount := 0

	var defaultTag = config.Tag
	if len(config.Tag) == 0 {
		defaultTag = generateRandomTag()
	}

	for _, ns := range config.NameServer {
		domainRuleCount += len(ns.PrioritizedDomain)
	}

	// MatcherInfos is ensured to cover the maximum index domainMatcher could return, where matcher's index starts from 1
	matcherInfos := make([]*DomainMatcherInfo, domainRuleCount+1)
	domainMatcher := &strmatcher.MatcherGroup{}

	for _, ns := range config.NameServer {
		clientIdx := len(clients)
		updateDomain := func(domainRule strmatcher.Matcher, originalRuleIdx int, matcherInfos []*DomainMatcherInfo) {
			midx := domainMatcher.Add(domainRule)
			matcherInfos[midx] = &DomainMatcherInfo{
				clientIdx:     uint16(clientIdx),
				domainRuleIdx: uint16(originalRuleIdx),
			}
		}

		myClientIP := clientIP
		switch len(ns.ClientIp) {
		case net.IPv4len, net.IPv6len:
			myClientIP = net.IP(ns.ClientIp)
		}

		disableCache := config.DisableCache
		if ns.DisableCache != nil {
			disableCache = *ns.DisableCache
		}

		serveStale := optimisticCache
		if ns.OptimisticCache != nil {
			serveStale = ns.GetOptimisticCache()
		} else if ns.ServeStale != nil {
			serveStale = *ns.ServeStale
		}

		serveExpiredTTL := config.ServeExpiredTTL
		if ns.ServeExpiredTTL != nil {
			serveExpiredTTL = *ns.ServeExpiredTTL
		}

		var tag = defaultTag
		if len(ns.Tag) > 0 {
			tag = ns.Tag
		}
		tag, outboundTags := decodeDNSTag(tag, defaultTag)
		clientIPOption := ResolveIpOptionOverride(ns.QueryStrategy, ipOption)
		if !clientIPOption.IPv4Enable && !clientIPOption.IPv6Enable {
			return nil, errors.New("no QueryStrategy available for ", ns.Address)
		}

		client, err := NewClient(ctx, ns, myClientIP, disableCache, serveStale, serveExpiredTTL, cachePerStoreBytes, tag, outboundTags, clientIPOption, &matcherInfos, updateDomain)
		if err != nil {
			return nil, errors.New("failed to create client").Base(err)
		}
		clients = append(clients, client)
	}

	// If there is no DNS client in config, add a `localhost` DNS client
	if len(clients) == 0 {
		clients = append(clients, NewLocalDNSClient(ipOption))
	}

	return &DNS{
		hosts:                  hosts,
		ipOption:               &ipOption,
		clients:                clients,
		ctx:                    ctx,
		domainMatcher:          domainMatcher,
		matcherInfos:           matcherInfos,
		disableFallback:        config.DisableFallback,
		disableFallbackIfMatch: config.DisableFallbackIfMatch,
		enableParallelQuery:    config.EnableParallelQuery,
		optimisticCache:        optimisticCache,
		serveExpiredTTL:        config.GetServeExpiredTTL(),
		cacheSizeBytes:         cacheSizeBytes,
		cachePerStoreBytes:     cachePerStoreBytes,
		checkSystem:            checkSystem,
		ipDomainCache:          make(map[string]ipDomainCacheEntry),
	}, nil
}

func (s *DNS) runtimeSnapshot() dnsRuntimeSnapshot {
	s.RLock()
	defer s.RUnlock()

	snap := dnsRuntimeSnapshot{
		disableFallback:        s.disableFallback,
		disableFallbackIfMatch: s.disableFallbackIfMatch,
		enableParallelQuery:    s.enableParallelQuery,
		optimisticCache:        s.optimisticCache,
		serveExpiredTTL:        s.serveExpiredTTL,
		hosts:                  s.hosts,
		clients:                append([]*Client(nil), s.clients...),
		ctx:                    s.ctx,
		domainMatcher:          s.domainMatcher,
		matcherInfos:           append([]*DomainMatcherInfo(nil), s.matcherInfos...),
		checkSystem:            s.checkSystem,
		cachePerStoreBytes:     s.cachePerStoreBytes,
	}
	if s.ipOption != nil {
		snap.ipOption = *s.ipOption
	}
	return snap
}

func (s *DNS) reverseCachePolicy() (bool, uint32) {
	s.RLock()
	optimistic := s.optimisticCache
	serveExpiredTTL := s.serveExpiredTTL
	s.RUnlock()
	return optimistic, serveExpiredTTL
}

func (s *DNS) reverseCacheStoreLimit() int64 {
	s.RLock()
	limit := s.cachePerStoreBytes
	s.RUnlock()
	return limit
}

// Type implements common.HasType.
func (*DNS) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (s *DNS) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *DNS) Close() error {
	return nil
}

// Reload replaces runtime DNS settings without restarting the core instance.
func (s *DNS) Reload(config *Config) error {
	if config == nil {
		return errors.New("dns config is nil")
	}
	next, err := New(s.ctx, config)
	if err != nil {
		return err
	}

	s.Lock()
	s.disableFallback = next.disableFallback
	s.disableFallbackIfMatch = next.disableFallbackIfMatch
	s.enableParallelQuery = next.enableParallelQuery
	s.optimisticCache = next.optimisticCache
	s.serveExpiredTTL = next.serveExpiredTTL
	s.ipOption = next.ipOption
	s.hosts = next.hosts
	s.clients = next.clients
	s.domainMatcher = next.domainMatcher
	s.matcherInfos = next.matcherInfos
	s.checkSystem = next.checkSystem
	s.cacheSizeBytes = next.cacheSizeBytes
	s.cachePerStoreBytes = next.cachePerStoreBytes
	s.Unlock()

	// Preserve reverse cache across reload; only enforce updated size policy.
	s.ipDomainCacheMu.Lock()
	now := time.Now()
	s.cleanupIPDomainCacheLocked(now, true)
	s.enforceIPDomainCacheSizeLocked(now)
	s.ipDomainCacheMu.Unlock()
	return nil
}

// IsOwnLink implements proxy.dns.ownLinkVerifier
func (s *DNS) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return false
	}
	runtime := s.runtimeSnapshot()
	for _, client := range runtime.clients {
		if client.tag == inbound.Tag {
			return true
		}
	}
	return false
}

// LookupIP implements dns.Client.
func (s *DNS) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	runtime := s.runtimeSnapshot()

	// Normalize the FQDN form query
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil, 0, errors.New("empty domain name")
	}

	if runtime.checkSystem {
		supportIPv4, supportIPv6 := checkRoutes()
		option.IPv4Enable = option.IPv4Enable && supportIPv4
		option.IPv6Enable = option.IPv6Enable && supportIPv6
	} else {
		option.IPv4Enable = option.IPv4Enable && runtime.ipOption.IPv4Enable
		option.IPv6Enable = option.IPv6Enable && runtime.ipOption.IPv6Enable
	}

	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns.ErrEmptyResponse
	}

	// Static host lookup
	switch addrs, err := runtime.hosts.Lookup(domain, option); {
	case err != nil:
		if go_errors.Is(err, dns.ErrEmptyResponse) {
			return nil, 0, dns.ErrEmptyResponse
		}
		return nil, 0, errors.New("returning nil for domain ", domain).Base(err)
	case addrs == nil: // Domain not recorded in static host
		break
	case len(addrs) == 0: // Domain recorded, but no valid IP returned (e.g. IPv4 address with only IPv6 enabled)
		return nil, 0, dns.ErrEmptyResponse
	case len(addrs) == 1 && addrs[0].Family().IsDomain(): // Domain replacement
		errors.LogInfo(runtime.ctx, "domain replaced: ", domain, " -> ", addrs[0].Domain())
		domain = addrs[0].Domain()
	default: // Successfully found ip records in static host
		errors.LogInfo(runtime.ctx, "returning ", len(addrs), " IP(s) for domain ", domain, " -> ", addrs)
		ips, err := toNetIP(addrs)
		if err != nil {
			return nil, 0, err
		}
		s.storeIPDomainCache(domain, ips, 10)
		return ips, 10, nil // Hosts ttl is 10
	}

	// Name servers lookup
	var (
		ips []net.IP
		ttl uint32
		err error
	)
	if runtime.enableParallelQuery {
		ips, ttl, err = s.parallelQuery(runtime, domain, option)
	} else {
		ips, ttl, err = s.serialQuery(runtime, domain, option)
	}
	if err != nil {
		return nil, 0, err
	}
	s.storeIPDomainCache(domain, ips, ttl)
	return ips, ttl, nil
}

// LookupRecord implements optional dns.RecordQuery interface.
func (s *DNS) LookupRecord(domain string, queryType uint16, option dns.IPOption) ([]string, uint32, error) {
	reqType := dnsmessage.Type(queryType)
	switch reqType {
	case dnsmessage.TypeA:
		option.IPv4Enable = true
		option.IPv6Enable = false
		option.FakeEnable = false
		ips, ttl, err := s.LookupIP(domain, option)
		if err != nil {
			return nil, 0, err
		}
		out := make([]string, 0, len(ips))
		for _, ip := range ips {
			text := strings.TrimSpace(ip.String())
			if text == "" {
				continue
			}
			out = append(out, text)
		}
		if len(out) == 0 {
			return nil, 0, dns.ErrEmptyResponse
		}
		return out, ttl, nil
	case dnsmessage.TypeAAAA:
		option.IPv4Enable = false
		option.IPv6Enable = true
		option.FakeEnable = false
		ips, ttl, err := s.LookupIP(domain, option)
		if err != nil {
			return nil, 0, err
		}
		out := make([]string, 0, len(ips))
		for _, ip := range ips {
			text := strings.TrimSpace(ip.String())
			if text == "" {
				continue
			}
			out = append(out, text)
		}
		if len(out) == 0 {
			return nil, 0, dns.ErrEmptyResponse
		}
		return out, ttl, nil
	}

	runtime := s.runtimeSnapshot()
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return nil, 0, errors.New("empty domain name")
	}

	// Keep static host domain rewrite behavior for non-IP records.
	switch addrs, err := runtime.hosts.Lookup(domain, dns.IPOption{IPv4Enable: true, IPv6Enable: true}); {
	case err != nil:
		if go_errors.Is(err, dns.ErrEmptyResponse) {
			return nil, 0, dns.ErrEmptyResponse
		}
		return nil, 0, errors.New("returning nil for domain ", domain).Base(err)
	case addrs == nil:
	case len(addrs) == 1 && addrs[0].Family().IsDomain():
		errors.LogInfo(runtime.ctx, "domain replaced: ", domain, " -> ", addrs[0].Domain())
		domain = strings.TrimSuffix(addrs[0].Domain(), ".")
	}

	return s.serialRecordQuery(runtime, domain, reqType, option)
}

func (s *DNS) serialRecordQuery(runtime dnsRuntimeSnapshot, domain string, reqType dnsmessage.Type, option dns.IPOption) ([]string, uint32, error) {
	var errs []error
	for _, client := range s.sortClients(runtime, domain, option.OutboundTag) {
		if strings.EqualFold(client.Name(), "FakeDNS") {
			errors.LogDebug(runtime.ctx, "skip DNS record query for domain ", domain, " at server ", client.Name(), " type ", reqType)
			continue
		}
		records, ttl, err := client.QueryRecord(runtime.ctx, domain, reqType, option)
		if len(records) > 0 {
			return records, ttl, nil
		}
		errors.LogInfoInner(runtime.ctx, err, "failed to lookup record for domain ", domain, " at server ", client.Name(), " type ", reqType)
		if err == nil {
			err = dns.ErrEmptyResponse
		}
		errs = append(errs, err)
	}
	return nil, 0, mergeQueryErrors(domain, errs)
}

func (s *DNS) LookupDomainByIP(ip net.IP) (string, bool) {
	key := ipDomainCacheKey(ip)
	if key == "" {
		return "", false
	}
	now := time.Now()

	s.ipDomainCacheMu.RLock()
	entry, found := s.ipDomainCache[key]
	s.ipDomainCacheMu.RUnlock()
	if !found {
		return "", false
	}
	if s.reverseCacheEntryExpiredForLookup(entry, now) {
		s.ipDomainCacheMu.Lock()
		if current, ok := s.ipDomainCache[key]; ok && s.reverseCacheEntryExpiredForLookup(current, now) {
			s.deleteIPDomainCacheEntryLocked(key)
		}
		s.ipDomainCacheMu.Unlock()
		return "", false
	}
	return entry.domain, true
}

// LookupDomainCache reports forward-cache state for domain and query option.
func (s *DNS) LookupDomainCache(domain string, option dns.IPOption) dns.DomainCacheStatus {
	runtime := s.runtimeSnapshot()

	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return dns.DomainCacheStatus{State: dns.DomainCacheStateMiss}
	}

	if runtime.checkSystem {
		supportIPv4, supportIPv6 := checkRoutes()
		option.IPv4Enable = option.IPv4Enable && supportIPv4
		option.IPv6Enable = option.IPv6Enable && supportIPv6
	} else {
		option.IPv4Enable = option.IPv4Enable && runtime.ipOption.IPv4Enable
		option.IPv6Enable = option.IPv6Enable && runtime.ipOption.IPv6Enable
	}
	if !option.IPv4Enable && !option.IPv6Enable {
		return dns.DomainCacheStatus{State: dns.DomainCacheStateMiss}
	}

	switch addrs, err := runtime.hosts.Lookup(domain, option); {
	case err != nil:
		break
	case addrs == nil:
		break
	case len(addrs) == 0:
		return dns.DomainCacheStatus{State: dns.DomainCacheStateMiss}
	case len(addrs) == 1 && addrs[0].Family().IsDomain():
		domain = strings.TrimSuffix(strings.TrimSpace(addrs[0].Domain()), ".")
	default:
		return dns.DomainCacheStatus{
			State:      dns.DomainCacheStateHit,
			TTLSeconds: 10,
			Source:     "hosts",
		}
	}

	fqdn := Fqdn(domain)
	clients := s.sortClients(runtime, domain, option.OutboundTag)
	for _, client := range clients {
		if client == nil || client.server == nil {
			continue
		}
		cached, ok := client.server.(interface{ getCacheController() *CacheController })
		if !ok {
			continue
		}
		controller := cached.getCacheController()
		if controller == nil {
			continue
		}
		rec := controller.findRecords(fqdn)
		ttl, found := lookupRecordTTL(rec, option)
		if !found {
			continue
		}
		if ttl > 0 {
			return dns.DomainCacheStatus{
				State:      dns.DomainCacheStateHit,
				TTLSeconds: ttl,
				Source:     "forward",
			}
		}
		return dns.DomainCacheStatus{
			State:      dns.DomainCacheStateExpired,
			TTLSeconds: ttl,
			Source:     "forward",
		}
	}

	return dns.DomainCacheStatus{State: dns.DomainCacheStateMiss}
}

// LookupRecordCache reports forward-cache state for domain and query type.
func (s *DNS) LookupRecordCache(domain string, queryType uint16, option dns.IPOption) dns.DomainCacheStatus {
	reqType := dnsmessage.Type(queryType)
	switch reqType {
	case dnsmessage.TypeA:
		option.IPv4Enable = true
		option.IPv6Enable = false
		option.FakeEnable = false
		return s.LookupDomainCache(domain, option)
	case dnsmessage.TypeAAAA:
		option.IPv4Enable = false
		option.IPv6Enable = true
		option.FakeEnable = false
		return s.LookupDomainCache(domain, option)
	}

	runtime := s.runtimeSnapshot()
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return dns.DomainCacheStatus{State: dns.DomainCacheStateMiss}
	}

	clients := s.sortClients(runtime, domain, option.OutboundTag)
	fqdn := Fqdn(domain)
	for _, client := range clients {
		if client == nil || client.server == nil {
			continue
		}
		cached, ok := client.server.(interface{ getCacheController() *CacheController })
		if !ok {
			continue
		}
		controller := cached.getCacheController()
		if controller == nil {
			continue
		}
		rec := controller.findRRRecord(fqdn, reqType)
		_, ttl, err := rec.getValues()
		if go_errors.Is(err, errRecordNotFound) {
			continue
		}
		if ttl > 0 {
			return dns.DomainCacheStatus{
				State:      dns.DomainCacheStateHit,
				TTLSeconds: ttl,
				Source:     "forward",
			}
		}
		return dns.DomainCacheStatus{
			State:      dns.DomainCacheStateExpired,
			TTLSeconds: ttl,
			Source:     "forward",
		}
	}

	return dns.DomainCacheStatus{State: dns.DomainCacheStateMiss}
}

func lookupRecordTTL(rec *record, option dns.IPOption) (int32, bool) {
	if rec == nil {
		return 0, false
	}

	ttl := int32(0)
	found := false
	appendTTL := func(item *IPRecord) {
		if item == nil {
			return
		}
		_, value, _ := item.getIPs()
		if !found || value < ttl {
			ttl = value
		}
		found = true
	}

	if option.IPv4Enable {
		appendTTL(rec.A)
	}
	if option.IPv6Enable {
		appendTTL(rec.AAAA)
	}
	return ttl, found
}

// GetCacheStats returns DNS cache statistics for forward and reverse caches.
func (s *DNS) GetCacheStats() dns.CacheStats {
	runtime := s.runtimeSnapshot()
	now := time.Now()
	storeSnapshots := make([]cacheStatsSnapshot, 0, len(runtime.clients)+1)
	for _, client := range runtime.clients {
		if client == nil || client.server == nil {
			continue
		}
		cached, ok := client.server.(interface{ getCacheController() *CacheController })
		if !ok {
			continue
		}
		controller := cached.getCacheController()
		if controller == nil {
			continue
		}
		storeSnapshots = append(storeSnapshots, controller.cacheStatsSnapshot(now))
	}
	storeSnapshots = append(storeSnapshots, s.reverseCacheStatsSnapshot(now, runtime.cachePerStoreBytes))
	sort.Slice(storeSnapshots, func(i, j int) bool {
		if storeSnapshots[i].storeType == storeSnapshots[j].storeType {
			return storeSnapshots[i].name < storeSnapshots[j].name
		}
		return storeSnapshots[i].storeType < storeSnapshots[j].storeType
	})

	out := dns.CacheStats{
		UpdatedAt: now,
		Stores:    make([]dns.CacheStoreStats, 0, len(storeSnapshots)),
	}
	for _, snapshot := range storeSnapshots {
		out.UsageBytes += snapshot.usageBytes
		out.LimitBytes += snapshot.limitBytes
		out.EntryCount += snapshot.entryCount
		out.ValidCount += snapshot.validCount
		out.ExpiredCount += snapshot.expiredCount
		out.Stores = append(out.Stores, dns.CacheStoreStats{
			Name:         snapshot.name,
			Type:         snapshot.storeType,
			UsageBytes:   snapshot.usageBytes,
			LimitBytes:   snapshot.limitBytes,
			EntryCount:   snapshot.entryCount,
			ValidCount:   snapshot.validCount,
			ExpiredCount: snapshot.expiredCount,
			UsageRatio:   snapshot.usageRatio,
			ValidRatio:   snapshot.validRatio,
			ExpiredRatio: snapshot.expiredRatio,
		})
	}
	out.UsageRatio = ratio(out.UsageBytes, out.LimitBytes)
	out.ValidRatio = ratio(out.ValidCount, out.EntryCount)
	out.ExpiredRatio = ratio(out.ExpiredCount, out.EntryCount)
	return out
}

// FlushCache clears forward and reverse DNS cache stores.
func (s *DNS) FlushCache() {
	runtime := s.runtimeSnapshot()
	for _, client := range runtime.clients {
		if client == nil || client.server == nil {
			continue
		}
		cached, ok := client.server.(interface{ getCacheController() *CacheController })
		if !ok {
			continue
		}
		controller := cached.getCacheController()
		if controller == nil {
			continue
		}
		controller.Clear()
	}

	s.ipDomainCacheMu.Lock()
	s.ipDomainCache = make(map[string]ipDomainCacheEntry)
	s.ipDomainCacheSizeBytes = 0
	s.ipDomainTouch = 0
	s.ipDomainLastCleanup = time.Time{}
	s.ipDomainCacheMu.Unlock()
}

func (s *DNS) reverseCacheStatsSnapshot(now time.Time, limitBytes int64) cacheStatsSnapshot {
	s.ipDomainCacheMu.RLock()
	defer s.ipDomainCacheMu.RUnlock()

	var usageBytes int64
	var validCount int64
	var expiredCount int64
	for key, entry := range s.ipDomainCache {
		usageBytes += s.reverseCacheEntrySize(key, entry)
		if now.After(entry.expire) {
			expiredCount++
		} else {
			validCount++
		}
	}
	entryCount := validCount + expiredCount
	return cacheStatsSnapshot{
		name:         "ip->domain",
		storeType:    "reverse",
		usageBytes:   usageBytes,
		limitBytes:   limitBytes,
		entryCount:   entryCount,
		validCount:   validCount,
		expiredCount: expiredCount,
		usageRatio:   ratio(usageBytes, limitBytes),
		validRatio:   ratio(validCount, entryCount),
		expiredRatio: ratio(expiredCount, entryCount),
	}
}

func ipDomainCacheKey(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func (s *DNS) storeIPDomainCache(domain string, ips []net.IP, ttl uint32) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" || len(ips) == 0 {
		return
	}
	if ttl == 0 {
		ttl = dns.DefaultTTL
	}
	now := time.Now()
	expire := now.Add(time.Duration(ttl) * time.Second)

	s.ipDomainCacheMu.Lock()
	for _, ip := range ips {
		key := ipDomainCacheKey(ip)
		if key == "" {
			continue
		}
		old, ok := s.ipDomainCache[key]
		if !ok || old.expire.Before(expire) || old.domain == domain {
			if ok {
				s.ipDomainCacheSizeBytes -= s.reverseCacheEntrySize(key, old)
			}
			s.ipDomainTouch++
			entry := ipDomainCacheEntry{
				domain: domain,
				expire: expire,
				touch:  s.ipDomainTouch,
			}
			s.ipDomainCache[key] = entry
			s.ipDomainCacheSizeBytes += s.reverseCacheEntrySize(key, entry)
		}
	}
	s.cleanupIPDomainCacheLocked(now, false)
	s.enforceIPDomainCacheSizeLocked(now)
	s.ipDomainCacheMu.Unlock()
}

func (s *DNS) reverseCacheEntryExpiredForLookup(entry ipDomainCacheEntry, now time.Time) bool {
	if !now.After(entry.expire) {
		return false
	}
	optimistic, serveExpiredTTL := s.reverseCachePolicy()
	if !optimistic {
		return true
	}
	if serveExpiredTTL == 0 {
		return false
	}
	staleDeadline := entry.expire.Add(time.Duration(serveExpiredTTL) * time.Second)
	return now.After(staleDeadline)
}

func (s *DNS) reverseCacheEntryExpiredForCleanup(entry ipDomainCacheEntry, now time.Time) bool {
	optimistic, serveExpiredTTL := s.reverseCachePolicy()
	if !optimistic {
		return now.After(entry.expire)
	}
	if serveExpiredTTL == 0 {
		return false
	}
	staleDeadline := entry.expire.Add(time.Duration(serveExpiredTTL) * time.Second)
	return now.After(staleDeadline)
}

func (s *DNS) reverseCacheEntryDeadline(entry ipDomainCacheEntry) (time.Time, bool) {
	optimistic, serveExpiredTTL := s.reverseCachePolicy()
	if !optimistic {
		return entry.expire, true
	}
	if serveExpiredTTL == 0 {
		return time.Time{}, false
	}
	return entry.expire.Add(time.Duration(serveExpiredTTL) * time.Second), true
}

func (s *DNS) reverseCacheEntrySize(key string, entry ipDomainCacheEntry) int64 {
	// key + value payload + conservative fixed overhead.
	return int64(len(key)+len(entry.domain)) + 64
}

func (s *DNS) deleteIPDomainCacheEntryLocked(key string) {
	if old, ok := s.ipDomainCache[key]; ok {
		delete(s.ipDomainCache, key)
		s.ipDomainCacheSizeBytes -= s.reverseCacheEntrySize(key, old)
		if s.ipDomainCacheSizeBytes < 0 {
			s.ipDomainCacheSizeBytes = 0
		}
	}
}

func (s *DNS) enforceIPDomainCacheSizeLocked(now time.Time) {
	limit := s.reverseCacheStoreLimit()
	if limit <= 0 || s.ipDomainCacheSizeBytes <= limit {
		return
	}
	// Try to evict truly expired entries first.
	s.cleanupIPDomainCacheLocked(now, true)
	if s.ipDomainCacheSizeBytes <= limit {
		return
	}

	type reverseEvictionCandidate struct {
		key      string
		deadline time.Time
		touch    uint64
		finite   bool
	}
	candidates := make([]reverseEvictionCandidate, 0, len(s.ipDomainCache))
	for key, entry := range s.ipDomainCache {
		deadline, finite := s.reverseCacheEntryDeadline(entry)
		candidates = append(candidates, reverseEvictionCandidate{
			key:      key,
			deadline: deadline,
			touch:    entry.touch,
			finite:   finite,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].finite != candidates[j].finite {
			return candidates[i].finite
		}
		if candidates[i].finite {
			if !candidates[i].deadline.Equal(candidates[j].deadline) {
				return candidates[i].deadline.Before(candidates[j].deadline)
			}
		}
		return candidates[i].touch < candidates[j].touch
	})
	for _, candidate := range candidates {
		if s.ipDomainCacheSizeBytes <= limit {
			return
		}
		s.deleteIPDomainCacheEntryLocked(candidate.key)
	}
}

func (s *DNS) cleanupIPDomainCacheLocked(now time.Time, force bool) {
	if len(s.ipDomainCache) == 0 {
		s.ipDomainLastCleanup = now
		return
	}
	if !force && now.Sub(s.ipDomainLastCleanup) < ipDomainCacheCleanupInterval {
		return
	}
	for key, entry := range s.ipDomainCache {
		if s.reverseCacheEntryExpiredForCleanup(entry, now) {
			s.deleteIPDomainCacheEntryLocked(key)
		}
	}
	s.ipDomainLastCleanup = now
}

func (s *DNS) sortClients(runtime dnsRuntimeSnapshot, domain string, outboundTag string) []*Client {
	clients := make([]*Client, 0, len(runtime.clients))
	clientUsed := make([]bool, len(runtime.clients))
	clientNames := make([]string, 0, len(runtime.clients))
	domainRules := []string{}
	eligible := make([]bool, len(runtime.clients))
	matched := 0
	if outboundTag != "" {
		for idx, client := range runtime.clients {
			if client.matchesOutboundTag(outboundTag) {
				eligible[idx] = true
				matched++
			}
		}
	}
	if outboundTag == "" || matched == 0 {
		for idx := range runtime.clients {
			eligible[idx] = true
		}
	}

	// Priority domain matching
	hasMatch := false
	MatchSlice := runtime.domainMatcher.Match(domain)
	sort.Slice(MatchSlice, func(i, j int) bool {
		return MatchSlice[i] < MatchSlice[j]
	})
	for _, match := range MatchSlice {
		info := runtime.matcherInfos[match]
		client := runtime.clients[info.clientIdx]
		if !eligible[info.clientIdx] {
			continue
		}
		domainRule := client.domains[info.domainRuleIdx]
		domainRules = append(domainRules, fmt.Sprintf("%s(DNS idx:%d)", domainRule, info.clientIdx))
		if clientUsed[info.clientIdx] {
			continue
		}
		clientUsed[info.clientIdx] = true
		clients = append(clients, client)
		clientNames = append(clientNames, client.Name())
		hasMatch = true
		if client.finalQuery {
			return clients
		}
	}

	if !(runtime.disableFallback || runtime.disableFallbackIfMatch && hasMatch) {
		// Default round-robin query
		for idx, client := range runtime.clients {
			if clientUsed[idx] || client.skipFallback || !eligible[idx] {
				continue
			}
			clientUsed[idx] = true
			clients = append(clients, client)
			clientNames = append(clientNames, client.Name())
			if client.finalQuery {
				return clients
			}
		}
	}

	if len(domainRules) > 0 {
		errors.LogDebug(runtime.ctx, "domain ", domain, " matches following rules: ", domainRules)
	}
	if len(clientNames) > 0 {
		if outboundTag != "" && matched > 0 {
			errors.LogDebug(runtime.ctx, "domain ", domain, " (outbound tag ", outboundTag, ") will use DNS in order: ", clientNames)
		} else {
			errors.LogDebug(runtime.ctx, "domain ", domain, " will use DNS in order: ", clientNames)
		}
	}

	if len(clients) == 0 {
		for idx, client := range runtime.clients {
			if !eligible[idx] {
				continue
			}
			clients = append(clients, client)
			clientNames = append(clientNames, client.Name())
			errors.LogWarning(runtime.ctx, "domain ", domain, " will use the first eligible DNS: ", clientNames)
			break
		}
		if len(clients) == 0 {
			if len(runtime.clients) > 0 {
				clients = append(clients, runtime.clients[0])
				clientNames = append(clientNames, runtime.clients[0].Name())
				errors.LogWarning(runtime.ctx, "domain ", domain, " will use the first DNS: ", clientNames)
			} else {
				errors.LogError(runtime.ctx, "no DNS clients available for domain ", domain, " and no default clients configured")
			}
		}
	}

	return clients
}

func mergeQueryErrors(domain string, errs []error) error {
	if len(errs) == 0 {
		return dns.ErrEmptyResponse
	}

	var noRNF error
	for _, err := range errs {
		if go_errors.Is(err, errRecordNotFound) {
			continue // server no response, ignore
		} else if noRNF == nil {
			noRNF = err
		} else if !go_errors.Is(err, noRNF) {
			return errors.New("returning nil for domain ", domain).Base(errors.Combine(errs...))
		}
	}
	if go_errors.Is(noRNF, dns.ErrEmptyResponse) {
		return dns.ErrEmptyResponse
	}
	if noRNF == nil {
		noRNF = errRecordNotFound
	}
	return errors.New("returning nil for domain ", domain).Base(noRNF)
}

func (s *DNS) serialQuery(runtime dnsRuntimeSnapshot, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	var errs []error
	for _, client := range s.sortClients(runtime, domain, option.OutboundTag) {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			errors.LogDebug(runtime.ctx, "skip DNS resolution for domain ", domain, " at server ", client.Name())
			continue
		}

		ips, ttl, err := client.QueryIP(runtime.ctx, domain, option)

		if len(ips) > 0 {
			return ips, ttl, nil
		}

		errors.LogInfoInner(runtime.ctx, err, "failed to lookup ip for domain ", domain, " at server ", client.Name(), " in serial query mode")
		if err == nil {
			err = dns.ErrEmptyResponse
		}
		errs = append(errs, err)
	}
	return nil, 0, mergeQueryErrors(domain, errs)
}

func (s *DNS) parallelQuery(runtime dnsRuntimeSnapshot, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	var errs []error
	clients := s.sortClients(runtime, domain, option.OutboundTag)

	resultsChan := asyncQueryAll(domain, option, clients, runtime.ctx)

	groups, groupOf := makeGroups( /*s.ctx,*/ clients)
	results := make([]*queryResult, len(clients))
	pending := make([]int, len(groups))
	for gi, g := range groups {
		pending[gi] = g.end - g.start + 1
	}

	nextGroup := 0
	for range clients {
		result := <-resultsChan
		results[result.index] = &result

		gi := groupOf[result.index]
		pending[gi]--

		for nextGroup < len(groups) {
			g := groups[nextGroup]

			// group race, minimum rtt -> return
			for j := g.start; j <= g.end; j++ {
				r := results[j]
				if r != nil && r.err == nil && len(r.ips) > 0 {
					return r.ips, r.ttl, nil
				}
			}

			// current group is incomplete and no one success -> continue pending
			if pending[nextGroup] > 0 {
				break
			}

			// all failed -> log and continue next group
			for j := g.start; j <= g.end; j++ {
				r := results[j]
				e := r.err
				if e == nil {
					e = dns.ErrEmptyResponse
				}
				errors.LogInfoInner(runtime.ctx, e, "failed to lookup ip for domain ", domain, " at server ", clients[j].Name(), " in parallel query mode")
				errs = append(errs, e)
			}
			nextGroup++
		}
	}

	return nil, 0, mergeQueryErrors(domain, errs)
}

type queryResult struct {
	ips   []net.IP
	ttl   uint32
	err   error
	index int
}

func asyncQueryAll(domain string, option dns.IPOption, clients []*Client, ctx context.Context) chan queryResult {
	if len(clients) == 0 {
		ch := make(chan queryResult)
		close(ch)
		return ch
	}

	ch := make(chan queryResult, len(clients))
	for i, client := range clients {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			errors.LogDebug(ctx, "skip DNS resolution for domain ", domain, " at server ", client.Name())
			ch <- queryResult{err: dns.ErrEmptyResponse, index: i}
			continue
		}

		go func(i int, c *Client) {
			qctx := ctx
			if !c.server.IsDisableCache() {
				nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeoutMs*2)
				qctx = nctx
				defer cancel()
			}
			ips, ttl, err := c.QueryIP(qctx, domain, option)
			ch <- queryResult{ips: ips, ttl: ttl, err: err, index: i}
		}(i, client)
	}
	return ch
}

type group struct{ start, end int }

// merge only adjacent and rule-equivalent Client into a single group
func makeGroups( /*ctx context.Context,*/ clients []*Client) ([]group, []int) {
	n := len(clients)
	if n == 0 {
		return nil, nil
	}
	groups := make([]group, 0, n)
	groupOf := make([]int, n)

	s, e := 0, 0
	for i := 1; i < n; i++ {
		if clients[i-1].policyID == clients[i].policyID {
			e = i
		} else {
			for k := s; k <= e; k++ {
				groupOf[k] = len(groups)
			}
			groups = append(groups, group{start: s, end: e})
			s, e = i, i
		}
	}
	for k := s; k <= e; k++ {
		groupOf[k] = len(groups)
	}
	groups = append(groups, group{start: s, end: e})

	// var b strings.Builder
	// b.WriteString("dns grouping: total clients=")
	// b.WriteString(strconv.Itoa(n))
	// b.WriteString(", groups=")
	// b.WriteString(strconv.Itoa(len(groups)))

	// for gi, g := range groups {
	// 	b.WriteString("\n  [")
	// 	b.WriteString(strconv.Itoa(g.start))
	// 	b.WriteString("..")
	// 	b.WriteString(strconv.Itoa(g.end))
	// 	b.WriteString("] gid=")
	// 	b.WriteString(strconv.Itoa(gi))
	// 	b.WriteString(" pid=")
	// 	b.WriteString(strconv.FormatUint(uint64(clients[g.start].policyID), 10))
	// 	b.WriteString(" members: ")

	// 	for i := g.start; i <= g.end; i++ {
	// 		if i > g.start {
	// 			b.WriteString(", ")
	// 		}
	// 		b.WriteString(strconv.Itoa(i))
	// 		b.WriteByte(':')
	// 		b.WriteString(clients[i].Name())
	// 	}
	// }
	// errors.LogDebug(ctx, b.String())

	return groups, groupOf
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

func probeRoutes() (ipv4 bool, ipv6 bool) {
	if conn, err := net.Dial("udp4", "192.33.4.12:53"); err == nil {
		ipv4 = true
		conn.Close()
	}
	if conn, err := net.Dial("udp6", "[2001:500:2::c]:53"); err == nil {
		ipv6 = true
		conn.Close()
	}
	return
}

var routeCache struct {
	sync.Once
	sync.RWMutex
	expire     time.Time
	ipv4, ipv6 bool
}

func checkRoutes() (bool, bool) {
	if !isGUIPlatform {
		routeCache.Once.Do(func() {
			routeCache.ipv4, routeCache.ipv6 = probeRoutes()
		})
		return routeCache.ipv4, routeCache.ipv6
	}

	routeCache.RWMutex.RLock()
	now := time.Now()
	if routeCache.expire.After(now) {
		routeCache.RWMutex.RUnlock()
		return routeCache.ipv4, routeCache.ipv6
	}
	routeCache.RWMutex.RUnlock()

	routeCache.RWMutex.Lock()
	defer routeCache.RWMutex.Unlock()

	now = time.Now()
	if routeCache.expire.After(now) { // double-check
		return routeCache.ipv4, routeCache.ipv6
	}
	routeCache.ipv4, routeCache.ipv6 = probeRoutes()    // ~2ms
	routeCache.expire = now.Add(100 * time.Millisecond) // ttl
	return routeCache.ipv4, routeCache.ipv6
}

var isGUIPlatform = detectGUIPlatform()

func detectGUIPlatform() bool {
	switch runtime.GOOS {
	case "android", "ios", "windows", "darwin":
		return true
	case "linux", "freebsd", "openbsd":
		if t := os.Getenv("XDG_SESSION_TYPE"); t == "wayland" || t == "x11" {
			return true
		}
		if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
			return true
		}
	}
	return false
}
