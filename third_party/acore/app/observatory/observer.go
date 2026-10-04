package observatory

import (
	"context"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	proxymanOutbound "github.com/ImAubrey/acore/app/proxyman/outbound"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	v2net "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/common/signal/done"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/extension"
	"github.com/ImAubrey/acore/features/outbound"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

const (
	defaultTestURL        = "https://connectivitycheck.gstatic.com/generate_204"
	defaultInterval       = 10 * time.Second
	defaultFailed         = 1
	defaultFailedInterval = 2 * time.Second
	defaultProbeTimeout   = 5 * time.Second
	failureDelayMs        = int64(99999999)
	defaultHistorySize    = 10
	defaultProbeLimit     = 10
)

type probeResult struct {
	Alive bool
	Delay int64
	Err   error
}

type outboundState struct {
	status           *OutboundStatus
	consecutiveFails int
	history          *probeHistory
}

type subscriptionObservation struct {
	tags    []string
	testURL string
}

type probeSample struct {
	ok    bool
	delay time.Duration
}

type probeHistory struct {
	size    int
	samples []probeSample
}

func newProbeHistory(size int) *probeHistory {
	if size <= 0 {
		return nil
	}
	return &probeHistory{size: size}
}

func (h *probeHistory) Add(ok bool, delay time.Duration) {
	if h == nil || h.size <= 0 {
		return
	}
	sample := probeSample{ok: ok, delay: delay}
	if len(h.samples) < h.size {
		h.samples = append(h.samples, sample)
		return
	}
	copy(h.samples, h.samples[1:])
	h.samples[len(h.samples)-1] = sample
}

func (h *probeHistory) Snapshot() *HealthPingMeasurementResult {
	if h == nil || len(h.samples) == 0 {
		return nil
	}
	var (
		all     int64
		fail    int64
		success int64
		min     time.Duration
		max     time.Duration
		sum     float64
		sumSq   float64
	)
	for _, sample := range h.samples {
		all++
		if !sample.ok {
			fail++
			continue
		}
		success++
		if success == 1 {
			min = sample.delay
			max = sample.delay
		} else {
			if sample.delay < min {
				min = sample.delay
			}
			if sample.delay > max {
				max = sample.delay
			}
		}
		value := float64(sample.delay)
		sum += value
		sumSq += value * value
	}
	var average time.Duration
	var deviation time.Duration
	if success > 0 {
		mean := sum / float64(success)
		variance := sumSq/float64(success) - mean*mean
		if variance < 0 {
			variance = 0
		}
		average = time.Duration(mean)
		deviation = time.Duration(math.Sqrt(variance))
	}
	return &HealthPingMeasurementResult{
		All:       all,
		Fail:      fail,
		Deviation: int64(deviation),
		Average:   int64(average),
		Max:       int64(max),
		Min:       int64(min),
	}
}

func newOutboundState(tag string) *outboundState {
	return &outboundState{
		status: &OutboundStatus{
			Alive:           true,
			Delay:           0,
			LastErrorReason: "",
			OutboundTag:     tag,
			LastSeenTime:    0,
			LastTryTime:     0,
		},
		history: newProbeHistory(defaultHistorySize),
	}
}

type Observer struct {
	configMu sync.RWMutex
	config   *Config
	ctx      context.Context

	statusMu sync.RWMutex
	states   map[string]*outboundState

	subscriptionMu      sync.RWMutex
	subscriptionEntries map[string]subscriptionObservation
	tagTestURL          map[string]string

	inflightMu sync.Mutex
	inflight   map[string]struct{}

	probeMu sync.RWMutex
	tcping  bool

	schedulerMu    sync.Mutex
	schedulerReset chan struct{}

	finished *done.Instance

	ohm outbound.Manager
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	outbounds, ok := o.selectOutbounds()
	if !ok {
		return &ObservationResult{Status: nil}, nil
	}
	outbounds = uniqueTags(outbounds)
	o.ensureStatesFor(outbounds)
	statuses := o.snapshotStatuses(outbounds)
	return &ObservationResult{Status: statuses}, nil
}

func (o *Observer) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *Observer) Start() error {
	o.statusMu.Lock()
	if o.states == nil {
		o.states = make(map[string]*outboundState)
	}
	o.statusMu.Unlock()
	o.subscriptionMu.Lock()
	if o.subscriptionEntries == nil {
		o.subscriptionEntries = make(map[string]subscriptionObservation)
	}
	if o.tagTestURL == nil {
		o.tagTestURL = make(map[string]string)
	}
	o.subscriptionMu.Unlock()
	o.inflightMu.Lock()
	if o.inflight == nil {
		o.inflight = make(map[string]struct{})
	}
	o.inflightMu.Unlock()
	o.schedulerMu.Lock()
	if o.schedulerReset == nil {
		o.schedulerReset = make(chan struct{}, 1)
	}
	o.schedulerMu.Unlock()
	o.finished = done.New()
	go o.runScheduler()
	return nil
}

func (o *Observer) Close() error {
	if o.finished == nil {
		return nil
	}
	o.finished.Close()
	return nil
}

// Reload updates observatory runtime config without restarting the core instance.
func (o *Observer) Reload(config *Config) error {
	if config == nil {
		return errors.New("observatory config is nil")
	}
	o.configMu.Lock()
	o.config = config
	o.configMu.Unlock()
	o.setTCPing(config.Tcping)
	o.notifySchedulerReset()
	return nil
}

func (o *Observer) SetProbeMode(mode string) error {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	switch normalized {
	case "tcp":
		o.setTCPing(true)
		return nil
	case "http":
		o.setTCPing(false)
		return nil
	default:
		return errors.New("unsupported probe mode")
	}
}

func (o *Observer) GetProbeMode() string {
	if o.isTCPing() {
		return "tcp"
	}
	return "http"
}

func (o *Observer) TriggerProbe(ctx context.Context) (int, error) {
	if o == nil {
		return 0, errors.New("observatory unavailable")
	}
	outbounds, ok := o.selectOutbounds()
	if !ok {
		return 0, errors.New("observatory selectors are empty")
	}
	outbounds = uniqueTags(outbounds)
	if len(outbounds) == 0 {
		return 0, nil
	}
	go o.runProbeBatch(outbounds, nil)
	return len(outbounds), nil
}

func (o *Observer) runScheduler() {
	interval := o.probeInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	resetCh := o.schedulerResetSignal()
	o.runScheduledProbe()
	for {
		select {
		case <-ticker.C:
			o.runScheduledProbe()
		case <-resetCh:
			ticker.Reset(o.probeInterval())
		case <-o.finished.Wait():
			return
		}
	}
}

func (o *Observer) runScheduledProbe() {
	outbounds, ok := o.selectOutbounds()
	if !ok {
		return
	}
	outbounds = uniqueTags(outbounds)
	o.syncStates(outbounds)
	if len(outbounds) == 0 {
		return
	}
	o.runProbeBatch(outbounds, o.finished.Wait())
}

func (o *Observer) runProbeBatch(outbounds []string, stop <-chan struct{}) {
	if len(outbounds) == 0 {
		return
	}
	limit := o.probeLimit(len(outbounds))
	group := new(errgroup.Group)
	if limit > 0 {
		group.SetLimit(limit)
	}
	for _, tag := range outbounds {
		outboundTag := strings.TrimSpace(tag)
		if outboundTag == "" {
			continue
		}
		tag := outboundTag
		group.Go(func() error {
			o.runProbeForTag(tag, stop)
			return nil
		})
	}
	_ = group.Wait()
}

func (o *Observer) runProbeForTag(tag string, stop <-chan struct{}) {
	if !o.beginProbe(tag) {
		return
	}
	defer o.endProbe(tag)
	failedLimit := o.failedLimit()
	failedInterval := o.failedInterval()
	for attempt := 1; attempt <= failedLimit; attempt++ {
		if o.shouldStop(stop) {
			return
		}
		result := o.probe(tag)
		o.updateStatusForResult(tag, result, failedLimit)
		if result.Alive || attempt == failedLimit {
			return
		}
		if !o.sleepOrStop(failedInterval, stop) {
			return
		}
	}
}

func (o *Observer) beginProbe(tag string) bool {
	o.inflightMu.Lock()
	defer o.inflightMu.Unlock()
	if o.inflight == nil {
		o.inflight = make(map[string]struct{})
	}
	if _, ok := o.inflight[tag]; ok {
		return false
	}
	o.inflight[tag] = struct{}{}
	return true
}

func (o *Observer) endProbe(tag string) {
	o.inflightMu.Lock()
	delete(o.inflight, tag)
	o.inflightMu.Unlock()
}

func (o *Observer) shouldStop(stop <-chan struct{}) bool {
	if stop != nil {
		select {
		case <-stop:
			return true
		default:
		}
	}
	if o.finished != nil {
		select {
		case <-o.finished.Wait():
			return true
		default:
		}
	}
	return false
}

func (o *Observer) probeLimit(total int) int {
	if total <= 0 {
		return 0
	}
	limit := defaultProbeLimit
	if limit <= 0 || limit > total {
		limit = total
	}
	return limit
}

func (o *Observer) probe(tag string) probeResult {
	if o.isTCPing() {
		return o.probeTCP(tag)
	}
	return o.probeHTTP(tag)
}

func (o *Observer) probeTCP(tag string) probeResult {
	probeURL := o.testURLForTag(tag)
	dest, err := parseTCPDestination(probeURL)
	if err != nil {
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "tcp", probeURL, result)
		return result
	}
	probeTimeout := o.probeTimeout()
	ctx, cancel := context.WithTimeout(o.baseContext(), probeTimeout)
	defer cancel()
	conn, ob, errCh, err := o.outboundConn(ctx, tag, dest)
	if err != nil {
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "tcp", probeURL, result)
		return result
	}
	defer conn.Close()
	// Measure TCP probe delay from the inner outbound dialing stage.
	delay, err := waitForOutboundConn(ctx, ob, errCh, time.Now())
	if err != nil {
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "tcp", probeURL, result)
		return result
	}
	result := probeResult{Alive: true, Delay: delay}
	o.logProbeResult(tag, "tcp", probeURL, result)
	return result
}

func (o *Observer) probeHTTP(tag string) probeResult {
	probeURL := o.testURLForTag(tag)
	httpURL, err := normalizeHTTPTestURL(probeURL)
	if err != nil {
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "http", probeURL, result)
		return result
	}
	dest, err := parseTCPDestination(probeURL)
	if err != nil {
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "http", probeURL, result)
		return result
	}
	probeTimeout := o.probeTimeout()
	ctx, cancel := context.WithTimeout(o.baseContext(), probeTimeout)
	defer cancel()
	conn, ob, errCh, err := o.outboundConn(ctx, tag, dest)
	if err != nil {
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "http", httpURL, result)
		return result
	}
	defer conn.Close()
	if errCh != nil {
		go func() {
			select {
			case err := <-errCh:
				if err != nil {
					errors.LogInfo(o.ctx, "observatory probe http outbound error (errCh) tag ", tag, " dest ", dest, " err ", err)
				}
			case <-ctx.Done():
			}
		}()
	}
	if _, err := waitForOutboundConn(ctx, ob, errCh, time.Now()); err != nil {
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "http", httpURL, result)
		return result
	}
	used := make(chan struct{}, 1)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				select {
				case used <- struct{}{}:
					return conn, nil
				default:
					return nil, errors.New("probe http connection already used")
				}
			},
			TLSHandshakeTimeout: probeTimeout,
		},
		Timeout: probeTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err != nil {
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "http", httpURL, result)
		return result
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			errors.LogInfo(o.ctx, "observatory probe http error outbound ", tag, " url ", httpURL, " op ", urlErr.Op, " err ", urlErr.Err)
		} else {
			errors.LogInfo(o.ctx, "observatory probe http error outbound ", tag, " url ", httpURL, " err ", err)
		}
		result := probeResult{Alive: false, Err: err}
		o.logProbeResult(tag, "http", httpURL, result)
		return result
	}
	if resp.Body != nil {
		resp.Body.Close()
	}
	result := probeResult{Alive: true, Delay: time.Since(start).Milliseconds()}
	o.logProbeResult(tag, "http", httpURL, result)
	return result
}

func (o *Observer) outboundConn(ctx context.Context, tag string, dest v2net.Destination) (net.Conn, *session.Outbound, <-chan error, error) {
	if o.ohm == nil {
		return nil, nil, nil, errors.New("outbound manager unavailable")
	}
	handler := o.ohm.GetHandler(tag)
	if handler == nil {
		return nil, nil, nil, errors.New("outbound handler not found: " + tag)
	}
	return proxymanOutbound.DialOutboundConn(ctx, handler, tag, dest)
}

func waitForOutboundConn(ctx context.Context, ob *session.Outbound, errCh <-chan error, start time.Time) (int64, error) {
	if ob == nil {
		return 0, errors.New("outbound session missing")
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ob.Conn != nil {
			return time.Since(start).Milliseconds(), nil
		}
		select {
		case err := <-errCh:
			if err == nil {
				err = errors.New("outbound error")
			}
			return 0, err
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (o *Observer) updateStatusForResult(tag string, result probeResult, failedLimit int) {
	now := time.Now().Unix()
	o.statusMu.Lock()
	if o.states == nil {
		o.states = make(map[string]*outboundState)
	}
	state, ok := o.states[tag]
	if !ok {
		state = newOutboundState(tag)
		o.states[tag] = state
	}
	state.status.OutboundTag = tag
	state.status.LastTryTime = now
	if result.Alive {
		if state.history != nil {
			state.history.Add(true, time.Duration(result.Delay)*time.Millisecond)
		}
		state.consecutiveFails = 0
		state.status.Alive = true
		state.status.Delay = result.Delay
		state.status.LastSeenTime = now
		state.status.LastErrorReason = ""
		o.statusMu.Unlock()
		return
	}
	state.consecutiveFails++
	if state.history != nil {
		state.history.Add(false, 0)
	}
	if result.Err != nil {
		state.status.LastErrorReason = result.Err.Error()
	}
	if state.consecutiveFails >= failedLimit {
		state.status.Alive = false
		state.status.Delay = failureDelayMs
	}
	o.statusMu.Unlock()
}

func (o *Observer) logProbeResult(tag, mode, target string, result probeResult) {
	if result.Alive {
		errors.LogInfo(o.ctx, "observatory probe ", mode, " outbound ", tag, " target ", target, " ok delay ", result.Delay, "ms")
		return
	}
	errText := "unknown"
	if result.Err != nil {
		errText = result.Err.Error()
	}
	errors.LogInfo(o.ctx, "observatory probe ", mode, " outbound ", tag, " target ", target, " failed: ", errText)
}

func (o *Observer) syncStates(outbounds []string) {
	o.statusMu.Lock()
	defer o.statusMu.Unlock()
	if o.states == nil {
		o.states = make(map[string]*outboundState)
	}
	if len(outbounds) == 0 {
		for tag := range o.states {
			delete(o.states, tag)
		}
		return
	}
	keep := make(map[string]struct{}, len(outbounds))
	for _, tag := range outbounds {
		if tag == "" {
			continue
		}
		keep[tag] = struct{}{}
		if _, ok := o.states[tag]; ok {
			continue
		}
		o.states[tag] = newOutboundState(tag)
	}
	for tag := range o.states {
		if _, ok := keep[tag]; ok {
			continue
		}
		delete(o.states, tag)
	}
}

func (o *Observer) ensureStatesFor(outbounds []string) {
	if len(outbounds) == 0 {
		return
	}
	o.statusMu.Lock()
	defer o.statusMu.Unlock()
	if o.states == nil {
		o.states = make(map[string]*outboundState)
	}
	for _, tag := range outbounds {
		if tag == "" {
			continue
		}
		if _, ok := o.states[tag]; ok {
			continue
		}
		o.states[tag] = newOutboundState(tag)
	}
}

func (o *Observer) snapshotStatuses(outbounds []string) []*OutboundStatus {
	if len(outbounds) == 0 {
		return nil
	}
	outbounds = append([]string(nil), outbounds...)
	sort.Strings(outbounds)
	statuses := make([]*OutboundStatus, 0, len(outbounds))
	o.statusMu.RLock()
	defer o.statusMu.RUnlock()
	for _, tag := range outbounds {
		state, ok := o.states[tag]
		if !ok || state.status == nil {
			continue
		}
		copyStatus, ok := proto.Clone(state.status).(*OutboundStatus)
		if !ok || copyStatus == nil {
			continue
		}
		if state.history != nil {
			copyStatus.HealthPing = state.history.Snapshot()
		}
		statuses = append(statuses, copyStatus)
	}
	return statuses
}

func (o *Observer) selectOutbounds() ([]string, bool) {
	selectors := o.subjectSelectors()
	if len(selectors) == 0 {
		return nil, false
	}
	hs, ok := o.ohm.(outbound.HandlerSelector)
	if !ok {
		errors.LogWarning(o.ctx, "outbound.Manager is not a HandlerSelector")
		return nil, false
	}
	outbounds := hs.Select(selectors)
	if outbounds == nil {
		outbounds = []string{}
	}
	return outbounds, true
}

func (o *Observer) subjectSelectors() []string {
	selectors := make([]string, 0)
	cfg := o.currentConfig()
	if cfg != nil && len(cfg.SubjectSelector) > 0 {
		selectors = append(selectors, cfg.SubjectSelector...)
	}
	o.subscriptionMu.RLock()
	for _, item := range o.subscriptionEntries {
		if len(item.tags) == 0 {
			continue
		}
		selectors = append(selectors, item.tags...)
	}
	o.subscriptionMu.RUnlock()
	return uniqueTags(selectors)
}

func (o *Observer) testURL() string {
	cfg := o.currentConfig()
	if cfg != nil && strings.TrimSpace(cfg.TestUrl) != "" {
		return cfg.TestUrl
	}
	return defaultTestURL
}

func (o *Observer) testURLForTag(tag string) string {
	trimmedTag := strings.TrimSpace(tag)
	if trimmedTag != "" {
		o.subscriptionMu.RLock()
		if o.tagTestURL != nil {
			if custom := strings.TrimSpace(o.tagTestURL[trimmedTag]); custom != "" {
				o.subscriptionMu.RUnlock()
				return custom
			}
		}
		o.subscriptionMu.RUnlock()
	}
	return o.testURL()
}

func (o *Observer) UpdateSubscriptionObservation(name string, tags []string, testURL string) bool {
	subName := strings.TrimSpace(name)
	if subName == "" {
		return false
	}
	cleanTags := uniqueTags(tags)
	cleanTestURL := strings.TrimSpace(testURL)

	o.subscriptionMu.Lock()
	defer o.subscriptionMu.Unlock()
	if o.subscriptionEntries == nil {
		o.subscriptionEntries = make(map[string]subscriptionObservation)
	}
	current, exists := o.subscriptionEntries[subName]
	changed := false
	if len(cleanTags) == 0 {
		if exists {
			delete(o.subscriptionEntries, subName)
			changed = true
		}
	} else {
		next := subscriptionObservation{
			tags:    cleanTags,
			testURL: cleanTestURL,
		}
		if !exists || !sameSubscriptionObservation(current, next) {
			o.subscriptionEntries[subName] = next
			changed = true
		}
	}
	if changed || o.tagTestURL == nil {
		o.tagTestURL = buildTagTestURLMap(o.subscriptionEntries)
	}
	return changed
}

func sameSubscriptionObservation(a, b subscriptionObservation) bool {
	if strings.TrimSpace(a.testURL) != strings.TrimSpace(b.testURL) {
		return false
	}
	if len(a.tags) != len(b.tags) {
		return false
	}
	for i := range a.tags {
		if strings.TrimSpace(a.tags[i]) != strings.TrimSpace(b.tags[i]) {
			return false
		}
	}
	return true
}

func buildTagTestURLMap(entries map[string]subscriptionObservation) map[string]string {
	if len(entries) == 0 {
		return map[string]string{}
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	m := make(map[string]string)
	for _, key := range keys {
		entry := entries[key]
		testURL := strings.TrimSpace(entry.testURL)
		if testURL == "" {
			continue
		}
		for _, tag := range entry.tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			m[tag] = testURL
		}
	}
	return m
}

func (o *Observer) probeInterval() time.Duration {
	cfg := o.currentConfig()
	if cfg == nil || cfg.Interval <= 0 {
		return defaultInterval
	}
	return time.Duration(cfg.Interval)
}

func (o *Observer) failedLimit() int {
	cfg := o.currentConfig()
	if cfg == nil || cfg.Failed <= 0 {
		return defaultFailed
	}
	return int(cfg.Failed)
}

func (o *Observer) failedInterval() time.Duration {
	cfg := o.currentConfig()
	if cfg == nil || cfg.FailedInterval <= 0 {
		return defaultFailedInterval
	}
	return time.Duration(cfg.FailedInterval)
}

func (o *Observer) probeTimeout() time.Duration {
	return defaultProbeTimeout
}

func (o *Observer) baseContext() context.Context {
	if o.ctx != nil {
		return o.ctx
	}
	return context.Background()
}

func (o *Observer) isTCPing() bool {
	o.probeMu.RLock()
	tcping := o.tcping
	o.probeMu.RUnlock()
	return tcping
}

func (o *Observer) setTCPing(value bool) {
	o.probeMu.Lock()
	o.tcping = value
	o.probeMu.Unlock()
}

func (o *Observer) sleepOrStop(d time.Duration, stop <-chan struct{}) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	var done <-chan struct{}
	if o.finished != nil {
		done = o.finished.Wait()
	}
	select {
	case <-timer.C:
		return true
	case <-stop:
		return false
	case <-done:
		return false
	}
}

func (o *Observer) currentConfig() *Config {
	o.configMu.RLock()
	cfg := o.config
	o.configMu.RUnlock()
	return cfg
}

func (o *Observer) schedulerResetSignal() chan struct{} {
	o.schedulerMu.Lock()
	ch := o.schedulerReset
	o.schedulerMu.Unlock()
	return ch
}

func (o *Observer) notifySchedulerReset() {
	ch := o.schedulerResetSignal()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

func normalizeHTTPTestURL(raw string) (string, error) {
	destination := strings.TrimSpace(raw)
	if destination == "" {
		return "", errors.New("missing test url")
	}
	parsed, err := url.Parse(destination)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "http" || scheme == "https" {
		if parsed.Hostname() == "" {
			return "", errors.New("missing host")
		}
		return destination, nil
	}
	host := parsed.Hostname()
	portStr := parsed.Port()
	if host == "" && !strings.Contains(destination, "://") {
		if strings.Contains(destination, ":") {
			if splitHost, splitPort, err := net.SplitHostPort(destination); err == nil {
				host = splitHost
				portStr = splitPort
			}
		}
		if host == "" {
			host = strings.TrimSpace(parsed.Path)
			if idx := strings.Index(host, "/"); idx >= 0 {
				host = host[:idx]
			}
		}
	}
	if host == "" {
		return "", errors.New("missing host")
	}
	normalizedScheme := "http"
	if portStr == "443" {
		normalizedScheme = "https"
	}
	hostPort := host
	if portStr != "" {
		hostPort = net.JoinHostPort(host, portStr)
	} else if strings.Contains(host, ":") {
		hostPort = "[" + host + "]"
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return normalizedScheme + "://" + hostPort + path, nil
}

func parseTCPDestination(raw string) (v2net.Destination, error) {
	destination := strings.TrimSpace(raw)
	if destination == "" {
		return v2net.Destination{}, errors.New("missing test url")
	}
	parsed, err := url.Parse(destination)
	if err != nil {
		return v2net.Destination{}, err
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := parsed.Hostname()
	portStr := parsed.Port()
	if host == "" && !strings.Contains(destination, "://") {
		if strings.Contains(destination, ":") {
			if splitHost, splitPort, err := net.SplitHostPort(destination); err == nil {
				host = splitHost
				portStr = splitPort
			}
		}
		if host == "" {
			host = strings.TrimSpace(parsed.Path)
			if idx := strings.Index(host, "/"); idx >= 0 {
				host = host[:idx]
			}
		}
	}
	if host == "" {
		return v2net.Destination{}, errors.New("missing host")
	}
	if portStr == "" {
		switch scheme {
		case "https":
			portStr = "443"
		case "http", "":
			portStr = "80"
		case "tcp":
			return v2net.Destination{}, errors.New("missing port")
		default:
			portStr = "80"
		}
	}
	port, err := v2net.PortFromString(portStr)
	if err != nil {
		return v2net.Destination{}, err
	}
	return v2net.TCPDestination(v2net.ParseAddress(host), port), nil
}

func uniqueTags(tags []string) []string {
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func New(ctx context.Context, config *Config) (*Observer, error) {
	var outboundManager outbound.Manager
	err := core.RequireFeatures(ctx, func(om outbound.Manager) {
		outboundManager = om
	})
	if err != nil {
		return nil, errors.New("Cannot get depended features").Base(err)
	}
	observer := &Observer{
		config:              config,
		ctx:                 ctx,
		ohm:                 outboundManager,
		states:              make(map[string]*outboundState),
		inflight:            make(map[string]struct{}),
		subscriptionEntries: make(map[string]subscriptionObservation),
		tagTestURL:          make(map[string]string),
	}
	if config != nil {
		observer.tcping = config.Tcping
	}
	return observer, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
