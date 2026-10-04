package metrics

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
)

const (
	metricsAccessKeyHeader   = "X-Access-Key"
	metricsAccessKeyQueryKey = "access_key"
	metricsCORSAllowHeaders  = "Content-Type, X-Access-Key"
	pprofPathPrefix          = "/debug/pprof"
)

var metricsAccessKeyMu sync.RWMutex
var metricsAccessKey string

func setMetricsAccessKey(value string) {
	metricsAccessKeyMu.Lock()
	metricsAccessKey = strings.TrimSpace(value)
	metricsAccessKeyMu.Unlock()
}

func getMetricsAccessKey() string {
	metricsAccessKeyMu.RLock()
	defer metricsAccessKeyMu.RUnlock()
	return metricsAccessKey
}

func isMetricsAuthorized(r *http.Request) bool {
	key := getMetricsAccessKey()
	if key == "" {
		return true
	}
	if r == nil {
		return false
	}
	candidate := strings.TrimSpace(r.Header.Get(metricsAccessKeyHeader))
	if candidate == "" {
		candidate = strings.TrimSpace(r.URL.Query().Get(metricsAccessKeyQueryKey))
	}
	if candidate == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(key)) == 1
}

func wrapMetricsHandler(next http.Handler) http.Handler {
	if next == nil {
		next = http.DefaultServeMux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r != nil && r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		// Keep profiling endpoints hidden unless access key is configured.
		if r != nil && strings.HasPrefix(r.URL.Path, pprofPathPrefix) && getMetricsAccessKey() == "" {
			http.NotFound(w, r)
			return
		}
		if !isMetricsAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
