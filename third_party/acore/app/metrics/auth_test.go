package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrapMetricsHandler_HidesPprofWhenNoAccessKey(t *testing.T) {
	t.Cleanup(func() { setMetricsAccessKey("") })
	setMetricsAccessKey("")

	nextCalled := false
	h := wrapMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/profile", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected pprof request to be blocked when access key is empty")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestWrapMetricsHandler_AllowsNonPprofWhenNoAccessKey(t *testing.T) {
	t.Cleanup(func() { setMetricsAccessKey("") })
	setMetricsAccessKey("")

	nextCalled := false
	h := wrapMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics/connections", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected non-pprof request to pass through")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestWrapMetricsHandler_RequiresKeyWhenConfigured(t *testing.T) {
	t.Cleanup(func() { setMetricsAccessKey("") })
	setMetricsAccessKey("secret")

	nextCalled := false
	h := wrapMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics/connections", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected unauthorized request to be blocked")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWrapMetricsHandler_AllowsPprofWithValidKey(t *testing.T) {
	t.Cleanup(func() { setMetricsAccessKey("") })
	setMetricsAccessKey("secret")

	nextCalled := false
	h := wrapMetricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/profile", nil)
	req.Header.Set(metricsAccessKeyHeader, "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected authorized pprof request to pass through")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
