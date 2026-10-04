package dns

import (
	"time"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/features"
)

// IPOption is an object for IP query options.
type IPOption struct {
	IPv4Enable  bool
	IPv6Enable  bool
	FakeEnable  bool
	OutboundTag string
}

// Client is a Acore feature for querying DNS information.
//
// acore:api:stable
type Client interface {
	features.Feature

	// LookupIP returns IP address for the given domain. IPs may contain IPv4 and/or IPv6 addresses.
	LookupIP(domain string, option IPOption) ([]net.IP, uint32, error)
}

// IPDomainLookup optionally provides reverse lookup from an IP to a cached domain.
type IPDomainLookup interface {
	LookupDomainByIP(ip net.IP) (string, bool)
}

// CacheStoreStats describes one DNS cache store.
type CacheStoreStats struct {
	Name         string
	Type         string
	UsageBytes   int64
	LimitBytes   int64
	EntryCount   int64
	ValidCount   int64
	ExpiredCount int64
	UsageRatio   float64
	ValidRatio   float64
	ExpiredRatio float64
}

// CacheStats is an aggregate DNS cache snapshot.
type CacheStats struct {
	UsageBytes   int64
	LimitBytes   int64
	EntryCount   int64
	ValidCount   int64
	ExpiredCount int64
	UsageRatio   float64
	ValidRatio   float64
	ExpiredRatio float64
	UpdatedAt    time.Time
	Stores       []CacheStoreStats
}

// CacheStatsProvider optionally provides DNS cache statistics.
type CacheStatsProvider interface {
	GetCacheStats() CacheStats
}

// CacheFlusher optionally provides DNS cache clear capability.
type CacheFlusher interface {
	FlushCache()
}

// DomainCacheState represents lookup state for a domain in DNS cache.
type DomainCacheState string

const (
	DomainCacheStateUnknown DomainCacheState = "unknown"
	DomainCacheStateMiss    DomainCacheState = "miss"
	DomainCacheStateHit     DomainCacheState = "hit"
	DomainCacheStateExpired DomainCacheState = "expired"
)

// DomainCacheStatus describes cache status for a domain lookup.
type DomainCacheStatus struct {
	State      DomainCacheState
	TTLSeconds int32
	Source     string
}

// DomainCacheLookup optionally provides cache state lookup before DNS query.
type DomainCacheLookup interface {
	LookupDomainCache(domain string, option IPOption) DomainCacheStatus
}

// RecordQuery optionally provides DNS RR lookup by query type.
type RecordQuery interface {
	LookupRecord(domain string, queryType uint16, option IPOption) ([]string, uint32, error)
}

// RecordCacheLookup optionally provides cache state lookup by query type.
type RecordCacheLookup interface {
	LookupRecordCache(domain string, queryType uint16, option IPOption) DomainCacheStatus
}

// ClientType returns the type of Client interface. Can be used for implementing common.HasType.
//
// acore:api:beta
func ClientType() interface{} {
	return (*Client)(nil)
}

// ErrEmptyResponse indicates that DNS query succeeded but no answer was returned.
var ErrEmptyResponse = errors.New("empty response")

const DefaultTTL = 300

type RCodeError uint16

func (e RCodeError) Error() string {
	return serial.Concat("rcode: ", uint16(e))
}

func (RCodeError) IP() net.IP {
	panic("Calling IP() on a RCodeError.")
}

func (RCodeError) Domain() string {
	panic("Calling Domain() on a RCodeError.")
}

func (RCodeError) Family() net.AddressFamily {
	panic("Calling Family() on a RCodeError.")
}

func (e RCodeError) String() string {
	return e.Error()
}

var _ net.Address = (*RCodeError)(nil)

func RCodeFromError(err error) uint16 {
	if err == nil {
		return 0
	}
	cause := errors.Cause(err)
	if r, ok := cause.(RCodeError); ok {
		return uint16(r)
	}
	return 0
}
