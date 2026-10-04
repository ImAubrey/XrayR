package dnscache

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type rrCacheEntry struct {
	raw    []byte
	expire time.Time
}

// RRCache stores packed DNS responses by (qname, qtype) and serves stale entries with TTL=1.
type RRCache struct {
	mu         sync.RWMutex
	entries    map[string]*rrCacheEntry
	maxEntries int
}

func NewRRCache(maxEntries int) *RRCache {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &RRCache{
		entries:    make(map[string]*rrCacheEntry),
		maxEntries: maxEntries,
	}
}

func cacheKey(namespace string, domain string, qType uint16, qClass uint16) string {
	var b strings.Builder
	b.Grow(len(namespace) + len(domain) + 32)
	b.WriteString(namespace)
	b.WriteByte('|')
	b.WriteString(strings.ToLower(strings.TrimSuffix(domain, ".")))
	b.WriteByte('|')
	b.WriteString(dnsmessage.Type(qType).String())
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(qClass), 10))
	return b.String()
}

func ttlEligible(rr mdns.RR) bool {
	if rr == nil || rr.Header() == nil {
		return false
	}
	// OPT TTL stores extended RCODE/flags and must not be treated as cache TTL.
	return rr.Header().Rrtype != mdns.TypeOPT
}

func minRRTTL(records []mdns.RR) uint32 {
	if len(records) == 0 {
		return 0
	}
	minTTL := uint32(math.MaxUint32)
	for _, rr := range records {
		if !ttlEligible(rr) {
			continue
		}
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	if minTTL == math.MaxUint32 {
		return 0
	}
	return minTTL
}

func minMsgTTL(msg *mdns.Msg) uint32 {
	minTTL := minRRTTL(msg.Answer)
	if ttl := minRRTTL(msg.Ns); ttl > 0 && (minTTL == 0 || ttl < minTTL) {
		minTTL = ttl
	}
	if ttl := minRRTTL(msg.Extra); ttl > 0 && (minTTL == 0 || ttl < minTTL) {
		minTTL = ttl
	}
	return minTTL
}

func rewriteSectionTTL(records []mdns.RR, ttl uint32) {
	if len(records) == 0 {
		return
	}
	originMin := minRRTTL(records)
	if originMin == 0 {
		return
	}
	delta := originMin - ttl
	for _, rr := range records {
		if !ttlEligible(rr) {
			continue
		}
		if rr.Header().Ttl > delta {
			rr.Header().Ttl -= delta
		} else {
			rr.Header().Ttl = 1
		}
	}
}

func rewriteMsgTTL(msg *mdns.Msg, ttl uint32) {
	if ttl == 0 {
		ttl = 1
	}
	rewriteSectionTTL(msg.Answer, ttl)
	rewriteSectionTTL(msg.Ns, ttl)
	rewriteSectionTTL(msg.Extra, ttl)
}

func setMsgTTL(msg *mdns.Msg, ttl uint32) {
	if ttl == 0 {
		ttl = 1
	}
	for _, rr := range msg.Answer {
		if ttlEligible(rr) {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range msg.Ns {
		if ttlEligible(rr) {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range msg.Extra {
		if ttlEligible(rr) {
			rr.Header().Ttl = ttl
		}
	}
}

func (c *RRCache) evictIfNeededLocked() {
	if len(c.entries) < c.maxEntries {
		return
	}
	var victimKey string
	var victimExpire time.Time
	for k, v := range c.entries {
		if v == nil {
			victimKey = k
			break
		}
		if victimKey == "" || v.expire.Before(victimExpire) {
			victimKey = k
			victimExpire = v.expire
		}
	}
	if victimKey != "" {
		delete(c.entries, victimKey)
	}
}

// StorePacked stores one packed DNS response if it has a positive TTL and a question.
func (c *RRCache) StorePacked(namespace string, raw []byte, now time.Time) bool {
	if c == nil || len(raw) == 0 {
		return false
	}
	var msg mdns.Msg
	if err := msg.Unpack(raw); err != nil {
		return false
	}
	if len(msg.Question) == 0 {
		return false
	}
	ttl := minMsgTTL(&msg)
	if ttl == 0 {
		return false
	}
	q := msg.Question[0]
	key := cacheKey(namespace, q.Name, q.Qtype, q.Qclass)
	expire := now.Add(time.Duration(ttl) * time.Second)

	c.mu.Lock()
	c.evictIfNeededLocked()
	c.entries[key] = &rrCacheEntry{
		raw:    append([]byte(nil), raw...),
		expire: expire,
	}
	c.mu.Unlock()
	return true
}

// TryServe returns a packed DNS response with rewritten TTL and updated query id.
func (c *RRCache) TryServe(namespace string, id uint16, qType dnsmessage.Type, qClass dnsmessage.Class, domain string, now time.Time) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	key := cacheKey(namespace, domain, uint16(qType), uint16(qClass))
	c.mu.RLock()
	entry, found := c.entries[key]
	c.mu.RUnlock()
	if !found || entry == nil || len(entry.raw) == 0 {
		return nil, false
	}

	var msg mdns.Msg
	if err := msg.Unpack(entry.raw); err != nil {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	msg.Id = id
	if now.After(entry.expire) {
		setMsgTTL(&msg, 1)
	} else {
		ttl := uint32(time.Until(entry.expire).Seconds())
		if ttl < 1 {
			ttl = 1
		}
		rewriteMsgTTL(&msg, ttl)
	}
	raw, err := msg.Pack()
	if err != nil {
		return nil, false
	}
	return raw, true
}

var (
	defaultOnce    sync.Once
	defaultRRCache *RRCache
)

func DefaultRRCache() *RRCache {
	defaultOnce.Do(func() {
		defaultRRCache = NewRRCache(4096)
	})
	return defaultRRCache
}
