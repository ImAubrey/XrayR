package dns

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

const benchCacheEntries = 100000

type benchRecordEntry struct {
	key string
	rec *record
}

func makeBenchEntries(n int, now time.Time) []benchRecordEntry {
	out := make([]benchRecordEntry, 0, n)
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("bench-%d.example.com.", i)
		ttl := time.Duration((i%600)+30) * time.Second
		rec := &record{
			A: &IPRecord{
				IP:     nil,
				Expire: now.Add(ttl),
			},
		}
		// Keep roughly half with AAAA to mimic realistic mixed records.
		if i%2 == 0 {
			rec.AAAA = &IPRecord{
				IP:     nil,
				Expire: now.Add(ttl + 15*time.Second),
			}
		}
		out = append(out, benchRecordEntry{key: key, rec: rec})
	}
	return out
}

func buildControllerFromEntries(entries []benchRecordEntry, limit int64, now time.Time) *CacheController {
	c := NewCacheController("bench", false, true, 120)
	c.cacheSizeLimit = limit
	c.ips = make(map[string]*record, len(entries))
	for _, entry := range entries {
		c.ips[entry.key] = entry.rec
	}
	c.recomputeCacheSizeLocked()
	return c
}

func legacyEnforceCacheSizeLocked(c *CacheController, now time.Time) {
	if c.cacheSizeLimit <= 0 || c.cacheSizeBytes <= c.cacheSizeLimit {
		return
	}

	ref := c.cleanupReferenceTime(now)
	for domain, rec := range c.ips {
		if c.recordFullyExpired(rec, ref) {
			delete(c.ips, domain)
		}
	}
	c.recomputeCacheSizeLocked()
	if c.cacheSizeBytes <= c.cacheSizeLimit {
		return
	}

	for c.cacheSizeBytes > c.cacheSizeLimit && len(c.ips) > 0 {
		var (
			candidateKey      string
			candidateDeadline time.Time
			hasFiniteDeadline bool
		)

		for domain, rec := range c.ips {
			deadline, finite := c.recordCleanupDeadline(rec)
			if finite {
				if !hasFiniteDeadline || deadline.Before(candidateDeadline) {
					candidateKey = domain
					candidateDeadline = deadline
					hasFiniteDeadline = true
				}
				continue
			}
			if !hasFiniteDeadline && candidateKey == "" {
				candidateKey = domain
			}
		}

		if candidateKey == "" {
			break
		}
		delete(c.ips, candidateKey)
		c.recomputeCacheSizeLocked()
	}
}

func BenchmarkCacheEnforceCurrent100k(b *testing.B) {
	now := time.Now()
	entries := makeBenchEntries(benchCacheEntries, now)
	base := buildControllerFromEntries(entries, 1, now)
	targetLimit := base.cacheSizeBytes / 2
	if targetLimit <= 0 {
		b.Fatalf("invalid target limit: %d", targetLimit)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c := buildControllerFromEntries(entries, targetLimit, now)
		b.StartTimer()
		c.enforceCacheSizeLocked(now)
		if c.cacheSizeBytes > c.cacheSizeLimit {
			b.Fatalf("current enforce over limit: %d > %d", c.cacheSizeBytes, c.cacheSizeLimit)
		}
	}
}

func BenchmarkCacheEnforceLegacy100k(b *testing.B) {
	now := time.Now()
	entries := makeBenchEntries(benchCacheEntries, now)
	base := buildControllerFromEntries(entries, 1, now)
	targetLimit := base.cacheSizeBytes / 2
	if targetLimit <= 0 {
		b.Fatalf("invalid target limit: %d", targetLimit)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c := buildControllerFromEntries(entries, targetLimit, now)
		b.StartTimer()
		legacyEnforceCacheSizeLocked(c, now)
		if c.cacheSizeBytes > c.cacheSizeLimit {
			b.Fatalf("legacy enforce over limit: %d > %d", c.cacheSizeBytes, c.cacheSizeLimit)
		}
	}
}

func legacyEnforceIPDomainCacheSizeLocked(s *DNS, now time.Time) {
	if s.cachePerStoreBytes <= 0 || s.ipDomainCacheSizeBytes <= s.cachePerStoreBytes {
		return
	}
	s.cleanupIPDomainCacheLocked(now, true)
	if s.ipDomainCacheSizeBytes <= s.cachePerStoreBytes {
		return
	}

	for s.ipDomainCacheSizeBytes > s.cachePerStoreBytes && len(s.ipDomainCache) > 0 {
		var (
			candidateKey      string
			candidateTouch    uint64 = ^uint64(0)
			candidateDeadline time.Time
			hasFiniteDeadline bool
		)

		for key, entry := range s.ipDomainCache {
			deadline, finite := s.reverseCacheEntryDeadline(entry)
			if finite {
				if !hasFiniteDeadline || deadline.Before(candidateDeadline) || (deadline.Equal(candidateDeadline) && entry.touch < candidateTouch) {
					candidateKey = key
					candidateTouch = entry.touch
					candidateDeadline = deadline
					hasFiniteDeadline = true
				}
				continue
			}
			if hasFiniteDeadline {
				continue
			}
			if candidateKey == "" || entry.touch < candidateTouch {
				candidateKey = key
				candidateTouch = entry.touch
			}
		}
		if candidateKey == "" {
			return
		}
		s.deleteIPDomainCacheEntryLocked(candidateKey)
	}
}

func makeBenchReverseDNS(n int, now time.Time) *DNS {
	s := &DNS{
		optimisticCache:    true,
		serveExpiredTTL:    120,
		cachePerStoreBytes: 1,
		ipDomainCache:      make(map[string]ipDomainCacheEntry, n),
	}
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("203.0.113.%d", i%255)
		key = fmt.Sprintf("%s-%d", key, i)
		domain := fmt.Sprintf("bench-%d.example.com", i)
		exp := now.Add(time.Duration((i%600)+30) * time.Second)
		entry := ipDomainCacheEntry{
			domain: domain,
			expire: exp,
			touch:  uint64(i + 1),
		}
		s.ipDomainCache[key] = entry
		s.ipDomainCacheSizeBytes += s.reverseCacheEntrySize(key, entry)
	}
	s.cachePerStoreBytes = s.ipDomainCacheSizeBytes / 2
	return s
}

func BenchmarkReverseCacheEnforceCurrent100k(b *testing.B) {
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := makeBenchReverseDNS(benchCacheEntries, now)
		b.StartTimer()
		s.enforceIPDomainCacheSizeLocked(now)
		if s.ipDomainCacheSizeBytes > s.cachePerStoreBytes {
			b.Fatalf("current reverse enforce over limit: %d > %d", s.ipDomainCacheSizeBytes, s.cachePerStoreBytes)
		}
	}
}

func BenchmarkReverseCacheEnforceLegacy100k(b *testing.B) {
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := makeBenchReverseDNS(benchCacheEntries, now)
		b.StartTimer()
		legacyEnforceIPDomainCacheSizeLocked(s, now)
		if s.ipDomainCacheSizeBytes > s.cachePerStoreBytes {
			b.Fatalf("legacy reverse enforce over limit: %d > %d", s.ipDomainCacheSizeBytes, s.cachePerStoreBytes)
		}
	}
}

func TestLegacyAndCurrentEnforceChooseComparableBudget(t *testing.T) {
	now := time.Now()
	entries := makeBenchEntries(3000, now)
	base := buildControllerFromEntries(entries, 1, now)
	targetLimit := base.cacheSizeBytes / 2

	current := buildControllerFromEntries(entries, targetLimit, now)
	legacy := buildControllerFromEntries(entries, targetLimit, now)
	current.enforceCacheSizeLocked(now)
	legacyEnforceCacheSizeLocked(legacy, now)

	if current.cacheSizeBytes > current.cacheSizeLimit {
		t.Fatalf("current over limit: %d > %d", current.cacheSizeBytes, current.cacheSizeLimit)
	}
	if legacy.cacheSizeBytes > legacy.cacheSizeLimit {
		t.Fatalf("legacy over limit: %d > %d", legacy.cacheSizeBytes, legacy.cacheSizeLimit)
	}

	curDeadlines := make([]time.Time, 0, len(current.ips))
	for _, rec := range current.ips {
		if rec == nil {
			continue
		}
		if deadline, ok := current.recordCleanupDeadline(rec); ok {
			curDeadlines = append(curDeadlines, deadline)
		}
	}
	legDeadlines := make([]time.Time, 0, len(legacy.ips))
	for _, rec := range legacy.ips {
		if rec == nil {
			continue
		}
		if deadline, ok := legacy.recordCleanupDeadline(rec); ok {
			legDeadlines = append(legDeadlines, deadline)
		}
	}
	sort.Slice(curDeadlines, func(i, j int) bool { return curDeadlines[i].Before(curDeadlines[j]) })
	sort.Slice(legDeadlines, func(i, j int) bool { return legDeadlines[i].Before(legDeadlines[j]) })

	if len(curDeadlines) == 0 || len(legDeadlines) == 0 {
		t.Fatalf("unexpected empty deadlines after enforce")
	}
}
