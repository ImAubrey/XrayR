package metrics

import (
	"encoding/json"
	go_errors "errors"
	"net/http"
	"strings"
	"sync"
	"time"

	xnet "github.com/ImAubrey/acore/common/net"
	feature_dns "github.com/ImAubrey/acore/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

var dnsCacheOnce sync.Once

type dnsCacheStoreResponse struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	UsageBytes   int64   `json:"usageBytes"`
	LimitBytes   int64   `json:"limitBytes"`
	EntryCount   int64   `json:"entryCount"`
	ValidCount   int64   `json:"validCount"`
	ExpiredCount int64   `json:"expiredCount"`
	UsageRatio   float64 `json:"usageRatio"`
	ValidRatio   float64 `json:"validRatio"`
	ExpiredRatio float64 `json:"expiredRatio"`
}

type dnsCacheResponse struct {
	Available    bool                    `json:"available"`
	Error        string                  `json:"error,omitempty"`
	UsageBytes   int64                   `json:"usageBytes"`
	LimitBytes   int64                   `json:"limitBytes"`
	EntryCount   int64                   `json:"entryCount"`
	ValidCount   int64                   `json:"validCount"`
	ExpiredCount int64                   `json:"expiredCount"`
	UsageRatio   float64                 `json:"usageRatio"`
	ValidRatio   float64                 `json:"validRatio"`
	ExpiredRatio float64                 `json:"expiredRatio"`
	UpdatedAt    string                  `json:"updatedAt"`
	Stores       []dnsCacheStoreResponse `json:"stores,omitempty"`
}

type dnsCacheFlushResponse struct {
	Ok        bool   `json:"ok"`
	UpdatedAt string `json:"updatedAt"`
}

type dnsQueryTypeResponse struct {
	Value     string `json:"value"`
	Supported bool   `json:"supported"`
}

type dnsQueryTypesResponse struct {
	Types []dnsQueryTypeResponse `json:"types"`
}

type dnsQueryTypeSpec struct {
	Value   string
	ReqType dnsmessage.Type
	Option  feature_dns.IPOption
}

type dnsQueryRequest struct {
	Domain      string `json:"domain"`
	Type        string `json:"type"`
	OutboundTag string `json:"outboundTag,omitempty"`
}

type dnsQueryCacheResponse struct {
	State      string `json:"state"`
	TTLSeconds int32  `json:"ttlSeconds"`
	Source     string `json:"source,omitempty"`
}

type dnsQueryResponse struct {
	Ok          bool                  `json:"ok"`
	Domain      string                `json:"domain"`
	Type        string                `json:"type"`
	Records     []string              `json:"records"`
	TTL         uint32                `json:"ttl"`
	CacheBefore dnsQueryCacheResponse `json:"cacheBefore"`
	CacheAfter  dnsQueryCacheResponse `json:"cacheAfter"`
	Error       string                `json:"error,omitempty"`
	QueriedAt   string                `json:"queriedAt"`
}

var dnsQueryTypeSpecs = []dnsQueryTypeSpec{
	{Value: "A", ReqType: dnsmessage.TypeA, Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: false, FakeEnable: false}},
	{Value: "AAAA", ReqType: dnsmessage.TypeAAAA, Option: feature_dns.IPOption{IPv4Enable: false, IPv6Enable: true, FakeEnable: false}},
	{Value: "TXT", ReqType: dnsmessage.TypeTXT, Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
	{Value: "CNAME", ReqType: dnsmessage.TypeCNAME, Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
	{Value: "MX", ReqType: dnsmessage.TypeMX, Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
	{Value: "NS", ReqType: dnsmessage.TypeNS, Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
	{Value: "SRV", ReqType: dnsmessage.TypeSRV, Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
	{Value: "PTR", ReqType: dnsmessage.TypePTR, Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
	{Value: "CAA", ReqType: dnsmessage.Type(257), Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
	{Value: "NAPTR", ReqType: dnsmessage.Type(35), Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
	{Value: "SOA", ReqType: dnsmessage.TypeSOA, Option: feature_dns.IPOption{IPv4Enable: true, IPv6Enable: true, FakeEnable: false}},
}

var dnsQueryTypes = buildDNSQueryTypeResponses(dnsQueryTypeSpecs)

func registerDNSCacheRoutes() {
	dnsCacheOnce.Do(func() {
		http.HandleFunc("/dns/cache", dnsCacheHandler)
		http.HandleFunc("/dns/cache/flush", dnsCacheFlushHandler)
		http.HandleFunc("/dns/query/types", dnsQueryTypesHandler)
		http.HandleFunc("/dns/query", dnsQueryHandler)
	})
}

func dnsCacheHandler(w http.ResponseWriter, r *http.Request) {
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

	stats, err := loadDNSCacheStats()
	if err != nil {
		writeJSON(w, dnsCacheResponse{
			Available: false,
			Error:     err.Error(),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
	writeJSON(w, buildDNSCacheResponse(stats))
}

func dnsCacheFlushHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := flushDNSCache(); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "dns cache flush failed", err.Error())
		return
	}

	writeJSON(w, dnsCacheFlushResponse{
		Ok:        true,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func dnsQueryTypesHandler(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, dnsQueryTypesResponse{Types: dnsQueryTypes})
}

func dnsQueryHandler(w http.ResponseWriter, r *http.Request) {
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

	var req dnsQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	queryType, reqType, option, ok := resolveDNSQueryType(strings.TrimSpace(req.Type))
	if !ok {
		writeJSONError(
			w,
			http.StatusBadRequest,
			"unsupported dns query type",
			"supported types: "+supportedDNSQueryTypesText(),
		)
		return
	}
	option.OutboundTag = strings.TrimSpace(req.OutboundTag)

	inst := getRuntimeInstance()
	if inst == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "dns query unavailable", "runtime instance unavailable")
		return
	}
	client, ok := inst.GetFeature(feature_dns.ClientType()).(feature_dns.Client)
	if !ok || client == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "dns query unavailable", "dns client unavailable")
		return
	}

	cacheBefore := lookupDNSQueryCache(client, domain, reqType, option)
	var (
		records []string
		ttl     uint32
		err     error
	)
	if lookup, ok := client.(feature_dns.RecordQuery); ok {
		records, ttl, err = lookup.LookupRecord(domain, uint16(reqType), option)
	} else {
		if reqType != dnsmessage.TypeA && reqType != dnsmessage.TypeAAAA {
			writeJSONError(
				w,
				http.StatusServiceUnavailable,
				"dns query unavailable",
				"dns record query interface unavailable",
			)
			return
		}
		var ips []xnet.IP
		ips, ttl, err = client.LookupIP(domain, option)
		records = formatDNSQueryRecords(ips)
	}
	cacheAfter := lookupDNSQueryCache(client, domain, reqType, option)

	resp := dnsQueryResponse{
		Ok:          err == nil || go_errors.Is(err, feature_dns.ErrEmptyResponse),
		Domain:      domain,
		Type:        queryType,
		Records:     records,
		TTL:         ttl,
		CacheBefore: cacheBefore,
		CacheAfter:  cacheAfter,
		QueriedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err != nil && !go_errors.Is(err, feature_dns.ErrEmptyResponse) {
		resp.Error = err.Error()
	}
	writeJSON(w, resp)
}

func loadDNSCacheStats() (feature_dns.CacheStats, error) {
	inst := getRuntimeInstance()
	if inst == nil {
		return feature_dns.CacheStats{}, errDNSCacheUnavailable("runtime instance unavailable")
	}
	client, ok := inst.GetFeature(feature_dns.ClientType()).(feature_dns.Client)
	if !ok || client == nil {
		return feature_dns.CacheStats{}, errDNSCacheUnavailable("dns client unavailable")
	}
	provider, ok := client.(feature_dns.CacheStatsProvider)
	if !ok {
		return feature_dns.CacheStats{}, errDNSCacheUnavailable("dns cache stats unsupported")
	}
	return provider.GetCacheStats(), nil
}

func flushDNSCache() error {
	inst := getRuntimeInstance()
	if inst == nil {
		return errDNSCacheUnavailable("runtime instance unavailable")
	}
	client, ok := inst.GetFeature(feature_dns.ClientType()).(feature_dns.Client)
	if !ok || client == nil {
		return errDNSCacheUnavailable("dns client unavailable")
	}
	flusher, ok := client.(feature_dns.CacheFlusher)
	if !ok {
		return errDNSCacheUnavailable("dns cache flush unsupported")
	}
	flusher.FlushCache()
	return nil
}

type dnsCacheUnavailableError string

func (e dnsCacheUnavailableError) Error() string {
	return string(e)
}

func errDNSCacheUnavailable(msg string) error {
	return dnsCacheUnavailableError(msg)
}

func buildDNSQueryTypeResponses(specs []dnsQueryTypeSpec) []dnsQueryTypeResponse {
	types := make([]dnsQueryTypeResponse, 0, len(specs))
	for _, spec := range specs {
		types = append(types, dnsQueryTypeResponse{
			Value:     spec.Value,
			Supported: true,
		})
	}
	return types
}

func supportedDNSQueryTypesText() string {
	values := make([]string, 0, len(dnsQueryTypeSpecs))
	for _, spec := range dnsQueryTypeSpecs {
		values = append(values, spec.Value)
	}
	return strings.Join(values, ", ")
}

func buildDNSCacheResponse(stats feature_dns.CacheStats) dnsCacheResponse {
	updatedAt := stats.UpdatedAt.UTC().Format(time.RFC3339)
	if stats.UpdatedAt.IsZero() {
		updatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	resp := dnsCacheResponse{
		Available:    true,
		UsageBytes:   stats.UsageBytes,
		LimitBytes:   stats.LimitBytes,
		EntryCount:   stats.EntryCount,
		ValidCount:   stats.ValidCount,
		ExpiredCount: stats.ExpiredCount,
		UsageRatio:   stats.UsageRatio,
		ValidRatio:   stats.ValidRatio,
		ExpiredRatio: stats.ExpiredRatio,
		UpdatedAt:    updatedAt,
		Stores:       make([]dnsCacheStoreResponse, 0, len(stats.Stores)),
	}
	for _, store := range stats.Stores {
		resp.Stores = append(resp.Stores, dnsCacheStoreResponse{
			Name:         store.Name,
			Type:         store.Type,
			UsageBytes:   store.UsageBytes,
			LimitBytes:   store.LimitBytes,
			EntryCount:   store.EntryCount,
			ValidCount:   store.ValidCount,
			ExpiredCount: store.ExpiredCount,
			UsageRatio:   store.UsageRatio,
			ValidRatio:   store.ValidRatio,
			ExpiredRatio: store.ExpiredRatio,
		})
	}
	return resp
}

func resolveDNSQueryType(value string) (string, dnsmessage.Type, feature_dns.IPOption, bool) {
	target := strings.ToUpper(strings.TrimSpace(value))
	if target == "" {
		target = "A"
	}
	for _, spec := range dnsQueryTypeSpecs {
		if spec.Value == target {
			return spec.Value, spec.ReqType, spec.Option, true
		}
	}
	return "", 0, feature_dns.IPOption{}, false
}

func formatDNSQueryRecords(ips []xnet.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		text := strings.TrimSpace(ip.String())
		if text == "" {
			continue
		}
		out = append(out, text)
	}
	return out
}

func lookupDNSDomainCache(client feature_dns.Client, domain string, option feature_dns.IPOption) dnsQueryCacheResponse {
	lookup, ok := client.(feature_dns.DomainCacheLookup)
	if !ok {
		return dnsQueryCacheResponse{State: string(feature_dns.DomainCacheStateUnknown)}
	}
	status := lookup.LookupDomainCache(domain, option)
	return dnsQueryCacheFromStatus(status)
}

func lookupDNSQueryCache(client feature_dns.Client, domain string, reqType dnsmessage.Type, option feature_dns.IPOption) dnsQueryCacheResponse {
	if reqType == dnsmessage.TypeA || reqType == dnsmessage.TypeAAAA {
		return lookupDNSDomainCache(client, domain, option)
	}
	lookup, ok := client.(feature_dns.RecordCacheLookup)
	if !ok {
		return dnsQueryCacheResponse{State: string(feature_dns.DomainCacheStateUnknown)}
	}
	status := lookup.LookupRecordCache(domain, uint16(reqType), option)
	return dnsQueryCacheFromStatus(status)
}

func dnsQueryCacheFromStatus(status feature_dns.DomainCacheStatus) dnsQueryCacheResponse {
	state := strings.TrimSpace(string(status.State))
	if state == "" {
		state = string(feature_dns.DomainCacheStateUnknown)
	}
	return dnsQueryCacheResponse{
		State:      state,
		TTLSeconds: status.TTLSeconds,
		Source:     strings.TrimSpace(status.Source),
	}
}
