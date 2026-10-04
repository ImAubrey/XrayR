package dns

import (
	"context"
	go_errors "errors"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/signal/pubsub"
	"github.com/ImAubrey/acore/common/task"
	dns_feature "github.com/ImAubrey/acore/features/dns"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	minSizeForEmptyRebuild  = 512
	shrinkAbsoluteThreshold = 10240
	shrinkRatioThreshold    = 0.65
	migrationBatchSize      = 4096
)

type CacheController struct {
	name            string
	disableCache    bool
	serveStale      bool
	serveExpiredTTL int32
	cacheSizeLimit  int64
	cacheSizeBytes  int64

	ips      map[string]*record
	rr       map[string]*RRRecord
	dirtyips map[string]*record

	sync.RWMutex
	pub           *pubsub.Service
	cacheCleanup  *task.Periodic
	highWatermark int
	requestGroup  singleflight.Group
}

type cacheStatsSnapshot struct {
	name         string
	storeType    string
	usageBytes   int64
	limitBytes   int64
	entryCount   int64
	validCount   int64
	expiredCount int64
	usageRatio   float64
	validRatio   float64
	expiredRatio float64
}

func NewCacheController(name string, disableCache bool, serveStale bool, serveExpiredTTL uint32) *CacheController {
	c := &CacheController{
		name:            name,
		disableCache:    disableCache,
		serveStale:      serveStale,
		serveExpiredTTL: -int32(serveExpiredTTL),
		ips:             make(map[string]*record),
		rr:              make(map[string]*RRRecord),
		pub:             pubsub.NewService(),
	}

	c.cacheCleanup = &task.Periodic{
		Interval: 300 * time.Second,
		Execute:  c.CacheCleanup,
	}
	return c
}

// Clear drops all forward cache entries in this controller.
func (c *CacheController) Clear() {
	c.Lock()
	c.ips = make(map[string]*record)
	c.rr = make(map[string]*RRRecord)
	c.dirtyips = nil
	c.cacheSizeBytes = 0
	c.highWatermark = 0
	c.Unlock()
}

func (c *CacheController) SetCacheSizeLimit(limit int64) {
	c.Lock()
	c.cacheSizeLimit = limit
	// Keep a conservative full recompute here to self-heal any historical drift.
	c.recomputeCacheSizeLocked()
	c.enforceCacheSizeLocked(time.Now())
	c.Unlock()
}

// CacheCleanup clears expired items from cache
func (c *CacheController) CacheCleanup() error {
	expiredKeys, err := c.collectExpiredKeys()
	if err != nil {
		return err
	}
	c.writeAndShrink(expiredKeys)
	return nil
}

func (c *CacheController) collectExpiredKeys() ([]string, error) {
	c.RLock()
	defer c.RUnlock()

	if len(c.ips) == 0 && len(c.rr) == 0 {
		return nil, errors.New("nothing to do. stopping...")
	}

	// skip collection if a migration is in progress
	if c.dirtyips != nil {
		return nil, nil
	}

	now := time.Now()
	if c.serveStale && c.serveExpiredTTL != 0 {
		now = now.Add(time.Duration(c.serveExpiredTTL) * time.Second)
	}

	expiredKeys := make([]string, 0, len(c.ips)/4) // pre-allocate

	for domain, rec := range c.ips {
		if (rec.A != nil && rec.A.Expire.Before(now)) ||
			(rec.AAAA != nil && rec.AAAA.Expire.Before(now)) {
			expiredKeys = append(expiredKeys, domain)
		}
	}

	return expiredKeys, nil
}

func (c *CacheController) writeAndShrink(expiredKeys []string) {
	c.Lock()
	defer c.Unlock()

	// double check to prevent upper call multiple cleanup tasks
	if c.dirtyips != nil {
		return
	}

	lenBefore := len(c.ips)
	if lenBefore > c.highWatermark {
		c.highWatermark = lenBefore
	}

	now := time.Now()
	if c.serveStale && c.serveExpiredTTL != 0 {
		now = now.Add(time.Duration(c.serveExpiredTTL) * time.Second)
	}

	for _, domain := range expiredKeys {
		rec := c.ips[domain]
		if rec == nil {
			continue
		}
		oldSize := c.recordSize(domain, rec)
		if rec.A != nil && rec.A.Expire.Before(now) {
			rec.A = nil
		}
		if rec.AAAA != nil && rec.AAAA.Expire.Before(now) {
			rec.AAAA = nil
		}
		if rec.A == nil && rec.AAAA == nil {
			c.cacheSizeBytes -= oldSize
			delete(c.ips, domain)
			continue
		}
		newSize := c.recordSize(domain, rec)
		c.cacheSizeBytes += newSize - oldSize
	}

	for key, rec := range c.rr {
		if rec == nil || rec.Expire.Before(now) {
			c.cacheSizeBytes -= c.rrRecordSize(key, rec)
			if c.cacheSizeBytes < 0 {
				c.cacheSizeBytes = 0
			}
			delete(c.rr, key)
		}
	}

	lenAfter := len(c.ips)

	if lenAfter == 0 {
		if c.highWatermark >= minSizeForEmptyRebuild {
			errors.LogDebug(context.Background(), c.name,
				" rebuilding empty cache map to reclaim memory.",
				" size_before_cleanup=", lenBefore,
				" peak_size_before_rebuild=", c.highWatermark,
			)

			c.ips = make(map[string]*record)
			c.highWatermark = 0
		}
		if len(c.rr) == 0 {
			return
		}
	}

	if reductionFromPeak := c.highWatermark - lenAfter; reductionFromPeak > shrinkAbsoluteThreshold &&
		float64(reductionFromPeak) > float64(c.highWatermark)*shrinkRatioThreshold {
		errors.LogDebug(context.Background(), c.name,
			" shrinking cache map to reclaim memory.",
			" new_size=", lenAfter,
			" peak_size_before_shrink=", c.highWatermark,
			" reduction_since_peak=", reductionFromPeak,
		)

		c.dirtyips = c.ips
		c.ips = make(map[string]*record, int(float64(lenAfter)*1.1))
		c.highWatermark = lenAfter
		go c.migrate()
	}
	c.enforceCacheSizeLocked(now)

}

type migrationEntry struct {
	key   string
	value *record
}

func (c *CacheController) migrate() {
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(context.Background(), c.name, " panic during cache migration: ", r)
			c.Lock()
			c.dirtyips = nil
			// c.ips = make(map[string]*record)
			// c.highWatermark = 0
			c.Unlock()
		}
	}()

	c.RLock()
	dirtyips := c.dirtyips
	c.RUnlock()

	// double check to prevent upper call multiple cleanup tasks
	if dirtyips == nil {
		return
	}

	errors.LogDebug(context.Background(), c.name, " starting background cache migration for ", len(dirtyips), " items")

	batch := make([]migrationEntry, 0, migrationBatchSize)
	for domain, recD := range dirtyips {
		batch = append(batch, migrationEntry{domain, recD})

		if len(batch) >= migrationBatchSize {
			c.flush(batch)
			batch = batch[:0]
			runtime.Gosched()
		}
	}
	if len(batch) > 0 {
		c.flush(batch)
	}

	c.Lock()
	c.dirtyips = nil
	c.Unlock()

	errors.LogDebug(context.Background(), c.name, " cache migration completed")
}

func (c *CacheController) flush(batch []migrationEntry) {
	c.Lock()
	defer c.Unlock()

	for _, dirty := range batch {
		oldRec := c.ips[dirty.key]
		var oldSize int64
		if oldRec != nil {
			oldSize = c.recordSize(dirty.key, oldRec)
		}
		var merged *record

		if cur := c.ips[dirty.key]; cur != nil {
			merge := &record{}
			if cur.A == nil {
				merge.A = dirty.value.A
			} else {
				merge.A = cur.A
			}
			if cur.AAAA == nil {
				merge.AAAA = dirty.value.AAAA
			} else {
				merge.AAAA = cur.AAAA
			}
			merged = merge
		} else {
			merged = dirty.value
		}
		c.ips[dirty.key] = merged
		newSize := c.recordSize(dirty.key, merged)
		c.cacheSizeBytes += newSize - oldSize
	}
	c.enforceCacheSizeLocked(time.Now())
}

func (c *CacheController) updateRecord(req *dnsRequest, rep *IPRecord) {
	rtt := time.Since(req.start)

	switch req.reqType {
	case dnsmessage.TypeA:
		c.pub.Publish(req.domain+"4", rep)
	case dnsmessage.TypeAAAA:
		c.pub.Publish(req.domain+"6", rep)
	}

	if c.disableCache {
		errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt)
		return
	}

	c.Lock()
	lockWait := time.Since(req.start) - rtt

	newRec := &record{}
	oldRec := c.ips[req.domain]
	var dirtyRec *record
	if c.dirtyips != nil {
		dirtyRec = c.dirtyips[req.domain]
	}

	var pubRecord *IPRecord
	var pubSuffix string

	switch req.reqType {
	case dnsmessage.TypeA:
		newRec.A = rep
		if oldRec != nil && oldRec.AAAA != nil {
			newRec.AAAA = oldRec.AAAA
			pubRecord = oldRec.AAAA
		} else if dirtyRec != nil && dirtyRec.AAAA != nil {
			pubRecord = dirtyRec.AAAA
		}
		pubSuffix = "6"
	case dnsmessage.TypeAAAA:
		newRec.AAAA = rep
		if oldRec != nil && oldRec.A != nil {
			newRec.A = oldRec.A
			pubRecord = oldRec.A
		} else if dirtyRec != nil && dirtyRec.A != nil {
			pubRecord = dirtyRec.A
		}
		pubSuffix = "4"
	}

	var oldSize int64
	if oldRec != nil {
		oldSize = c.recordSize(req.domain, oldRec)
	}
	c.ips[req.domain] = newRec
	newSize := c.recordSize(req.domain, newRec)
	c.cacheSizeBytes += newSize - oldSize
	c.enforceCacheSizeLocked(time.Now())
	c.Unlock()

	if pubRecord != nil {
		_, ttl, err := pubRecord.getIPs()
		if ttl > 0 && !go_errors.Is(err, errRecordNotFound) {
			c.pub.Publish(req.domain+pubSuffix, pubRecord)
		}
	}

	errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt, ", lock: ", lockWait)

	if !c.serveStale || c.serveExpiredTTL != 0 {
		common.Must(c.cacheCleanup.Start())
	}
}

func (c *CacheController) cleanupReferenceTime(now time.Time) time.Time {
	if c.serveStale && c.serveExpiredTTL != 0 {
		return now.Add(time.Duration(c.serveExpiredTTL) * time.Second)
	}
	return now
}

func (c *CacheController) recordSize(domain string, rec *record) int64 {
	size := int64(len(domain) + 24)
	if rec == nil {
		return size
	}
	size += c.ipRecordSize(rec.A)
	size += c.ipRecordSize(rec.AAAA)
	return size
}

func (c *CacheController) rrRecordSize(key string, rec *RRRecord) int64 {
	size := int64(len(key) + 40)
	if rec == nil {
		return size
	}
	size += 56
	for _, value := range rec.Values {
		size += int64(len(value)) + 8
	}
	return size
}

func (c *CacheController) ipRecordSize(rec *IPRecord) int64 {
	if rec == nil {
		return 0
	}
	size := int64(56)
	for _, ip := range rec.IP {
		size += int64(len(ip)) + 8
	}
	return size
}

func (c *CacheController) recomputeCacheSizeLocked() {
	var total int64
	for domain, rec := range c.ips {
		total += c.recordSize(domain, rec)
	}
	for key, rec := range c.rr {
		total += c.rrRecordSize(key, rec)
	}
	c.cacheSizeBytes = total
}

func (c *CacheController) recordFullyExpired(rec *record, ref time.Time) bool {
	if rec == nil {
		return true
	}
	aExpired := rec.A == nil || rec.A.Expire.Before(ref)
	aaaaExpired := rec.AAAA == nil || rec.AAAA.Expire.Before(ref)
	return aExpired && aaaaExpired
}

func (c *CacheController) recordCleanupDeadline(rec *record) (time.Time, bool) {
	if rec == nil {
		return time.Time{}, true
	}
	ttlExt := time.Duration(0)
	if c.serveStale {
		if c.serveExpiredTTL == 0 {
			ttlExt = 0
		} else {
			ttlExt = time.Duration(-c.serveExpiredTTL) * time.Second
		}
	}

	hasDeadline := false
	var deadline time.Time
	setDeadline := func(expire time.Time) {
		candidate := expire
		if c.serveStale {
			if c.serveExpiredTTL == 0 {
				return
			}
			candidate = expire.Add(ttlExt)
		}
		if !hasDeadline || candidate.Before(deadline) {
			deadline = candidate
			hasDeadline = true
		}
	}

	if rec.A != nil {
		setDeadline(rec.A.Expire)
	}
	if rec.AAAA != nil {
		setDeadline(rec.AAAA.Expire)
	}
	return deadline, hasDeadline
}

func (c *CacheController) rrRecordFullyExpired(rec *RRRecord, ref time.Time) bool {
	if rec == nil {
		return true
	}
	return rec.Expire.Before(ref)
}

func (c *CacheController) rrRecordCleanupDeadline(rec *RRRecord) (time.Time, bool) {
	if rec == nil {
		return time.Time{}, true
	}
	if !c.serveStale {
		return rec.Expire, true
	}
	if c.serveExpiredTTL == 0 {
		return time.Time{}, false
	}
	return rec.Expire.Add(time.Duration(-c.serveExpiredTTL) * time.Second), true
}

func (c *CacheController) enforceCacheSizeLocked(now time.Time) {
	if c.cacheSizeLimit <= 0 || c.cacheSizeBytes <= c.cacheSizeLimit {
		return
	}

	ref := c.cleanupReferenceTime(now)
	// First pass: remove entries that are already outside optimistic cache window.
	for domain, rec := range c.ips {
		if c.recordFullyExpired(rec, ref) {
			c.cacheSizeBytes -= c.recordSize(domain, rec)
			delete(c.ips, domain)
		}
	}
	for key, rec := range c.rr {
		if c.rrRecordFullyExpired(rec, ref) {
			c.cacheSizeBytes -= c.rrRecordSize(key, rec)
			delete(c.rr, key)
		}
	}
	if c.cacheSizeBytes < 0 {
		c.cacheSizeBytes = 0
	}
	if c.cacheSizeBytes <= c.cacheSizeLimit {
		return
	}

	type evictionCandidate struct {
		key      string
		deadline time.Time
		isRR     bool
	}

	// Still above limit: pick finite-deadline entries first in one scan.
	candidates := make([]evictionCandidate, 0, len(c.ips)+len(c.rr))
	for domain, rec := range c.ips {
		deadline, finite := c.recordCleanupDeadline(rec)
		if !finite {
			continue
		}
		candidates = append(candidates, evictionCandidate{
			key:      domain,
			deadline: deadline,
			isRR:     false,
		})
	}
	for key, rec := range c.rr {
		deadline, finite := c.rrRecordCleanupDeadline(rec)
		if !finite {
			continue
		}
		candidates = append(candidates, evictionCandidate{
			key:      key,
			deadline: deadline,
			isRR:     true,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].deadline.Before(candidates[j].deadline)
	})
	for _, candidate := range candidates {
		if c.cacheSizeBytes <= c.cacheSizeLimit {
			break
		}
		if !candidate.isRR {
			rec := c.ips[candidate.key]
			if rec == nil {
				continue
			}
			c.cacheSizeBytes -= c.recordSize(candidate.key, rec)
			delete(c.ips, candidate.key)
			continue
		}
		rec := c.rr[candidate.key]
		if rec == nil {
			continue
		}
		c.cacheSizeBytes -= c.rrRecordSize(candidate.key, rec)
		delete(c.rr, candidate.key)
	}
	if c.cacheSizeBytes < 0 {
		c.cacheSizeBytes = 0
	}
	if c.cacheSizeBytes <= c.cacheSizeLimit {
		return
	}

	// No finite deadlines left (e.g. optimistic cache forever): arbitrary fallback.
	for domain, rec := range c.ips {
		if c.cacheSizeBytes <= c.cacheSizeLimit {
			break
		}
		c.cacheSizeBytes -= c.recordSize(domain, rec)
		delete(c.ips, domain)
	}
	for key, rec := range c.rr {
		if c.cacheSizeBytes <= c.cacheSizeLimit {
			break
		}
		c.cacheSizeBytes -= c.rrRecordSize(key, rec)
		delete(c.rr, key)
	}
	if c.cacheSizeBytes < 0 {
		c.cacheSizeBytes = 0
	}
}

func (c *CacheController) cacheStatsSnapshot(now time.Time) cacheStatsSnapshot {
	c.RLock()
	defer c.RUnlock()

	records := make(map[string]*record, len(c.ips)+len(c.dirtyips))
	for domain, rec := range c.dirtyips {
		records[domain] = rec
	}
	for domain, rec := range c.ips {
		if rec == nil {
			continue
		}
		existing := records[domain]
		if existing == nil {
			records[domain] = rec
			continue
		}
		records[domain] = &record{
			A:    pickRecordField(rec.A, existing.A),
			AAAA: pickRecordField(rec.AAAA, existing.AAAA),
		}
	}

	var usageBytes int64
	var validCount int64
	var expiredCount int64
	for domain, rec := range records {
		if rec == nil {
			continue
		}
		usageBytes += c.recordSize(domain, rec)
		validCount, expiredCount = countRecordState(rec.A, now, validCount, expiredCount)
		validCount, expiredCount = countRecordState(rec.AAAA, now, validCount, expiredCount)
	}
	for key, rec := range c.rr {
		if rec == nil {
			continue
		}
		usageBytes += c.rrRecordSize(key, rec)
		validCount, expiredCount = countRRRecordState(rec, now, validCount, expiredCount)
	}
	entryCount := validCount + expiredCount

	return cacheStatsSnapshot{
		name:         c.name,
		storeType:    "forward",
		usageBytes:   usageBytes,
		limitBytes:   c.cacheSizeLimit,
		entryCount:   entryCount,
		validCount:   validCount,
		expiredCount: expiredCount,
		usageRatio:   ratio(usageBytes, c.cacheSizeLimit),
		validRatio:   ratio(validCount, entryCount),
		expiredRatio: ratio(expiredCount, entryCount),
	}
}

func pickRecordField(primary *IPRecord, fallback *IPRecord) *IPRecord {
	if primary != nil {
		return primary
	}
	return fallback
}

func countRecordState(rec *IPRecord, now time.Time, valid int64, expired int64) (int64, int64) {
	if rec == nil {
		return valid, expired
	}
	if rec.Expire.After(now) {
		return valid + 1, expired
	}
	return valid, expired + 1
}

func countRRRecordState(rec *RRRecord, now time.Time, valid int64, expired int64) (int64, int64) {
	if rec == nil {
		return valid, expired
	}
	if rec.Expire.After(now) {
		return valid + 1, expired
	}
	return valid, expired + 1
}

func ratio(value int64, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(value) / float64(total)
}

func (c *CacheController) findRecords(domain string) *record {
	c.RLock()
	defer c.RUnlock()

	rec := c.ips[domain]
	if rec == nil && c.dirtyips != nil {
		rec = c.dirtyips[domain]
	}
	return rec
}

func rrPubSubKey(domain string, reqType dnsmessage.Type) string {
	return domain + "#" + strconv.Itoa(int(reqType))
}

func rrCacheKey(domain string, reqType dnsmessage.Type) string {
	return domain + "|" + strconv.Itoa(int(reqType))
}

func (c *CacheController) findRRRecord(domain string, reqType dnsmessage.Type) *RRRecord {
	c.RLock()
	defer c.RUnlock()
	return c.rr[rrCacheKey(domain, reqType)]
}

func (c *CacheController) registerSubscribers(domain string, option dns_feature.IPOption) (sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
	// ipv4 and ipv6 belong to different subscription groups
	if option.IPv4Enable {
		sub4 = c.pub.Subscribe(domain + "4")
	}
	if option.IPv6Enable {
		sub6 = c.pub.Subscribe(domain + "6")
	}
	return
}

func (c *CacheController) registerRRSubscriber(domain string, reqType dnsmessage.Type) *pubsub.Subscriber {
	return c.pub.Subscribe(rrPubSubKey(domain, reqType))
}

func (c *CacheController) updateRRRecord(req *dnsRequest, rec *RRRecord) {
	if rec == nil || req == nil {
		return
	}
	c.Lock()
	key := rrCacheKey(req.domain, req.reqType)
	old := c.rr[key]
	oldSize := c.rrRecordSize(key, old)
	c.rr[key] = rec
	newSize := c.rrRecordSize(key, rec)
	c.cacheSizeBytes += newSize - oldSize
	c.enforceCacheSizeLocked(time.Now())
	c.Unlock()
	c.pub.Publish(rrPubSubKey(req.domain, req.reqType), rec)
	if !c.serveStale || c.serveExpiredTTL != 0 {
		common.Must(c.cacheCleanup.Start())
	}
}

func closeSubscribers(sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
	if sub4 != nil {
		sub4.Close()
	}
	if sub6 != nil {
		sub6.Close()
	}
}
