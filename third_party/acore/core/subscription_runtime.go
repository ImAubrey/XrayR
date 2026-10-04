package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/ja4db"
	xnet "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/net/cnc"
	"github.com/ImAubrey/acore/common/platform"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/extension"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	subparser "github.com/ImAubrey/acore/infra/subscription"
	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"
)

// subscriptionRuntime holds runtime state for scheduled subscription refresh.
type subscriptionRuntime struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	cron   *cron.Cron

	outboundMu      sync.Mutex
	outbounds       map[string]map[string]struct{}       // subName -> tag set
	managedRewrites map[string]map[string]map[string]any // subName -> tag -> rewrite
	persistMu       sync.Mutex
	persistPath     string
}

const subscriptionBootstrapRetryInterval = time.Minute

func (s *Instance) startSubscriptionRuntime() {
	cfg, ok := GetSubscriptionRuntimeConfig()
	if !ok || cfg == nil {
		return
	}
	if len(cfg.Outbound) == 0 && len(cfg.Database) == 0 {
		return
	}

	ctx, cancel := context.WithCancel(s.ctx)
	rt := &subscriptionRuntime{
		cancel:          cancel,
		outbounds:       make(map[string]map[string]struct{}),
		managedRewrites: cloneSubscriptionManagedRewrites(cfg.ManagedRewrites),
		persistPath:     resolveSubscriptionRuntimePersistPath(),
	}
	for subName, tags := range cfg.ManagedOutbounds {
		name := strings.TrimSpace(subName)
		if name == "" {
			continue
		}
		if set := tagsToSet(tags); len(set) > 0 {
			rt.outbounds[name] = set
		}
	}

	// Cron parser: standard 5-field (min hour dom month dow) + descriptors like @daily/@every.
	rt.cron = cron.New(cron.WithParser(cron.NewParser(
		cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
	)))
	rt.cron.Start()

	s.subscriptionRuntime = rt
	s.cleanupInactiveRuntimeSubscriptions(cfg)

	// Outbound subscriptions.
	for _, sub := range cfg.Outbound {
		sub := sub
		subName := strings.TrimSpace(sub.Name)
		if subName == "" {
			subName = "subscription"
		}
		interval := strings.TrimSpace(sub.Interval)
		cronExpr := strings.TrimSpace(sub.Cron)
		scheduleActive := false
		if interval != "" && cronExpr != "" {
			errors.LogWarning(s.ctx, "subscription: interval and cron/crontab cannot both be set; skipping schedule for ", subName)
		} else if interval != "" {
			d, err := time.ParseDuration(interval)
			if err != nil || d <= 0 {
				errors.LogWarning(s.ctx, "subscription: invalid interval for ", subName, ": ", interval)
			} else {
				scheduleActive = true
				rt.wg.Add(1)
				go func() {
					defer rt.wg.Done()
					t := time.NewTicker(d)
					defer t.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-t.C:
							_ = s.refreshOutboundSubscription(ctx, cfg.SubscriptionInbound, subName, sub)
						}
					}
				}()
			}
		} else if cronExpr != "" {
			if _, err := rt.cron.AddFunc(cronExpr, func() {
				_ = s.refreshOutboundSubscription(ctx, cfg.SubscriptionInbound, subName, sub)
			}); err != nil {
				errors.LogWarning(s.ctx, "subscription: invalid cron for ", subName, ": ", cronExpr, " (", err, ")")
			} else {
				scheduleActive = true
			}
		}

		// Always do an initial refresh for runtime-managed subscriptions.
		rt.wg.Add(1)
		go func(scheduleActive bool) {
			defer rt.wg.Done()
			if s.refreshOutboundSubscription(ctx, cfg.SubscriptionInbound, subName, sub) {
				return
			}
			if scheduleActive {
				return
			}
			errors.LogWarning(s.ctx, "subscription: initial outbound refresh failed for ", subName, "; retrying every ", subscriptionBootstrapRetryInterval)
			s.retryOutboundSubscriptionUntilSuccess(ctx, cfg.SubscriptionInbound, subName, sub)
		}(scheduleActive)
	}

	// Database subscriptions.
	for _, db := range cfg.Database {
		db := db
		key := strings.TrimSpace(db.Type)
		if key == "" {
			key = "database"
		}
		interval := strings.TrimSpace(db.Interval)
		cronExpr := strings.TrimSpace(db.Cron)
		scheduleActive := false
		if interval != "" && cronExpr != "" {
			errors.LogWarning(s.ctx, "subscription: interval and cron/crontab cannot both be set; skipping schedule for database ", key)
		} else if interval != "" {
			d, err := time.ParseDuration(interval)
			if err != nil || d <= 0 {
				errors.LogWarning(s.ctx, "subscription: invalid interval for database ", key, ": ", interval)
			} else {
				scheduleActive = true
				rt.wg.Add(1)
				go func() {
					defer rt.wg.Done()
					t := time.NewTicker(d)
					defer t.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-t.C:
							_ = s.refreshDatabaseSubscription(ctx, cfg.SubscriptionInbound, key, db)
						}
					}
				}()
			}
		} else if cronExpr != "" {
			if _, err := rt.cron.AddFunc(cronExpr, func() {
				_ = s.refreshDatabaseSubscription(ctx, cfg.SubscriptionInbound, key, db)
			}); err != nil {
				errors.LogWarning(s.ctx, "subscription: invalid cron for database ", key, ": ", cronExpr, " (", err, ")")
			} else {
				scheduleActive = true
			}
		}

		rt.wg.Add(1)
		go func(scheduleActive bool) {
			defer rt.wg.Done()
			if s.refreshDatabaseSubscription(ctx, cfg.SubscriptionInbound, key, db) {
				return
			}
			if scheduleActive {
				return
			}
			errors.LogWarning(s.ctx, "subscription: initial database refresh failed for ", key, "; retrying every ", subscriptionBootstrapRetryInterval)
			s.retryDatabaseSubscriptionUntilSuccess(ctx, cfg.SubscriptionInbound, key, db)
		}(scheduleActive)
	}
}

func normalizeRuntimeSubscriptionName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "subscription"
	}
	return name
}

func (s *Instance) cleanupInactiveRuntimeSubscriptions(cfg *SubscriptionRuntimeConfig) {
	rt := s.subscriptionRuntime
	if rt == nil || cfg == nil {
		return
	}

	active := make(map[string]struct{}, len(cfg.Outbound))
	for _, sub := range cfg.Outbound {
		active[normalizeRuntimeSubscriptionName(sub.Name)] = struct{}{}
	}

	rt.outboundMu.Lock()
	stale := make(map[string]map[string]struct{})
	for subName, tags := range rt.outbounds {
		name := normalizeRuntimeSubscriptionName(subName)
		if _, ok := active[name]; ok {
			continue
		}
		stale[name] = cloneTagSet(tags)
		delete(rt.outbounds, subName)
	}
	rt.outboundMu.Unlock()

	if len(stale) == 0 {
		return
	}

	obm, _ := s.GetFeature(outbound.ManagerType()).(outbound.Manager)
	for subName, tags := range stale {
		if obm != nil {
			for tag := range tags {
				h := obm.GetHandler(tag)
				if h != nil {
					_ = h.Close()
				}
				_ = obm.RemoveHandler(s.ctx, tag)
			}
		}
		s.persistRuntimeSubscriptionOutbounds(subName, nil, nil)
		s.clearRuntimeSubscriptionObservatory(subName)
	}
}

func (s *Instance) clearRuntimeSubscriptionObservatory(subName string) {
	subName = normalizeRuntimeSubscriptionName(subName)
	obs, ok := s.GetFeature(extension.ObservatoryType()).(extension.Observatory)
	if !ok || obs == nil {
		return
	}
	updater, ok := obs.(runtimeSubscriptionObservatory)
	if !ok || updater == nil {
		return
	}
	updater.UpdateSubscriptionObservation(subName, nil, "")
}

func (s *Instance) retryOutboundSubscriptionUntilSuccess(ctx context.Context, inboundTag string, subName string, sub SubscriptionOutboundConfig) {
	t := time.NewTicker(subscriptionBootstrapRetryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.refreshOutboundSubscription(ctx, inboundTag, subName, sub) {
				errors.LogInfo(s.ctx, "subscription: outbound refresh recovered for ", subName)
				return
			}
		}
	}
}

func (s *Instance) retryDatabaseSubscriptionUntilSuccess(ctx context.Context, inboundTag string, key string, db SubscriptionDatabaseConfig) {
	t := time.NewTicker(subscriptionBootstrapRetryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.refreshDatabaseSubscription(ctx, inboundTag, key, db) {
				errors.LogInfo(s.ctx, "subscription: database refresh recovered for ", key)
				return
			}
		}
	}
}

func (s *Instance) stopSubscriptionRuntime() {
	if s.subscriptionRuntime == nil {
		return
	}
	s.subscriptionRuntime.cancel()
	s.subscriptionRuntime.wg.Wait()
	if s.subscriptionRuntime.cron != nil {
		ctx := s.subscriptionRuntime.cron.Stop()
		<-ctx.Done()
	}
	s.subscriptionRuntime = nil
}

func (s *Instance) refreshOutboundSubscription(ctx context.Context, inboundTag string, subName string, sub SubscriptionOutboundConfig) bool {
	body, hint, err := s.loadSubscriptionResource(ctx, inboundTag, sub.URL)
	if err != nil {
		errors.LogWarning(s.ctx, "subscription: failed to load outbound subscription ", subName, ": ", err)
		return false
	}

	format := strings.TrimSpace(sub.Format)
	if format == "" {
		format = "auto"
	}
	parsed, err := subparser.ParseOutboundSubscription(body, format, hint)
	if err != nil {
		errors.LogWarning(s.ctx, "subscription: failed to parse outbound subscription ", subName, ": ", err)
		return false
	}
	for _, w := range parsed.Warnings {
		if w != "" {
			errors.LogWarning(s.ctx, "subscription: ", subName, ": ", w)
		}
	}

	outbounds, tags, err := prepareRuntimeOutboundObjects(parsed.Outbounds, subName, sub.TagPrefix)
	if err != nil {
		errors.LogWarning(s.ctx, "subscription: failed to prepare outbound objects for ", subName, ": ", err)
		return false
	}
	outbounds = applyRuntimeManagedOutboundRewrites(outbounds, s.runtimeManagedRewrites(subName))

	obConfigs, err := buildOutboundHandlerConfigsFromJSON(outbounds)
	if err != nil {
		errors.LogWarning(s.ctx, "subscription: failed to build outbound configs for ", subName, ": ", err)
		return false
	}

	appliedTags := s.applyRuntimeOutbounds(subName, tags, obConfigs)
	s.persistRuntimeSubscriptionOutbounds(subName, outbounds, appliedTags)
	s.applyRuntimeSubscriptionObservatory(subName, sub, appliedTags)
	return true
}

type runtimeSubscriptionObservatory interface {
	UpdateSubscriptionObservation(name string, tags []string, testURL string) bool
}

type runtimeSubscriptionProbeTrigger interface {
	TriggerProbe(ctx context.Context) (int, error)
}

func (s *Instance) applyRuntimeSubscriptionObservatory(subName string, sub SubscriptionOutboundConfig, tags map[string]struct{}) {
	if !sub.Observatory {
		return
	}
	subName = strings.TrimSpace(subName)
	if subName == "" {
		subName = "subscription"
	}
	testURL := strings.TrimSpace(sub.ObservatoryTestURL)
	tagList := make([]string, 0, len(tags))
	for tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		tagList = append(tagList, tag)
	}
	sort.Strings(tagList)
	obs, ok := s.GetFeature(extension.ObservatoryType()).(extension.Observatory)
	if !ok || obs == nil {
		return
	}
	updater, ok := obs.(runtimeSubscriptionObservatory)
	if !ok || updater == nil {
		return
	}
	changed := updater.UpdateSubscriptionObservation(subName, tagList, testURL)
	if !changed || len(tagList) == 0 {
		return
	}
	trigger, ok := obs.(runtimeSubscriptionProbeTrigger)
	if !ok || trigger == nil {
		return
	}
	go func() {
		if _, err := trigger.TriggerProbe(s.ctx); err != nil {
			errors.LogWarning(s.ctx, "subscription: failed to trigger observatory probe for ", subName, ": ", err)
		}
	}()
}

func (s *Instance) runtimeManagedRewrites(subName string) map[string]map[string]any {
	rt := s.subscriptionRuntime
	if rt == nil {
		return nil
	}
	subName = strings.TrimSpace(subName)
	if subName == "" {
		return nil
	}
	return rt.managedRewrites[subName]
}

func applyRuntimeManagedOutboundRewrites(outbounds []json.RawMessage, rewrites map[string]map[string]any) []json.RawMessage {
	if len(outbounds) == 0 || len(rewrites) == 0 {
		return outbounds
	}
	for i := range outbounds {
		var ob map[string]any
		if err := json.Unmarshal(outbounds[i], &ob); err != nil {
			continue
		}
		tag := strings.TrimSpace(asString(ob["tag"]))
		if tag == "" {
			continue
		}
		rewrite := rewrites[tag]
		if len(rewrite) == 0 {
			continue
		}
		mergeRuntimeRewriteMaps(ob, rewrite)
		// rewrite must not override tag.
		ob["tag"] = tag
		b, err := json.Marshal(ob)
		if err != nil {
			continue
		}
		outbounds[i] = b
	}
	return outbounds
}

func mergeRuntimeRewriteMaps(dst map[string]any, patch map[string]any) {
	if dst == nil || len(patch) == 0 {
		return
	}
	for key, value := range patch {
		k := strings.TrimSpace(key)
		if k == "" || strings.EqualFold(k, "tag") {
			continue
		}
		if value == nil {
			continue
		}
		if patchMap, ok := value.(map[string]any); ok {
			current, _ := dst[k].(map[string]any)
			if current == nil {
				current = make(map[string]any)
			}
			mergeRuntimeRewriteMaps(current, patchMap)
			if len(current) > 0 {
				dst[k] = current
			}
			continue
		}
		dst[k] = value
	}
}

func prepareRuntimeOutboundObjects(outbounds []json.RawMessage, subName string, tagPrefix string) ([]json.RawMessage, map[string]struct{}, error) {
	subName = strings.TrimSpace(subName)
	if subName == "" {
		subName = "subscription"
	}
	tagPrefix = strings.TrimSpace(tagPrefix)

	tags := make(map[string]struct{})
	prepared := make([]json.RawMessage, 0, len(outbounds))
	for i, raw := range outbounds {
		var ob map[string]any
		if err := json.Unmarshal(raw, &ob); err != nil {
			return nil, nil, err
		}
		tag, _ := ob["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			tag = subName + "-" + strconv.Itoa(i)
		}
		if tagPrefix != "" {
			tag = tagPrefix + tag
		}
		ob["tag"] = tag
		// Keep management markers for introspection (ignored by core builder).
		ob["managed"] = map[string]any{
			"subscription": subName,
		}

		b, err := json.Marshal(ob)
		if err != nil {
			return nil, nil, err
		}
		prepared = append(prepared, b)
		tags[tag] = struct{}{}
	}
	return prepared, tags, nil
}

func buildOutboundHandlerConfigsFromJSON(outbounds []json.RawMessage) ([]*OutboundHandlerConfig, error) {
	if len(outbounds) == 0 {
		return nil, nil
	}
	wrapper := struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}{Outbounds: outbounds}
	payload, err := json.Marshal(wrapper)
	if err != nil {
		return nil, err
	}

	var cfg *Config
	var loadErr error
	withSubscriptionRuntimeConfigSuppressed(func() {
		cfg, loadErr = LoadConfig("json", bytes.NewReader(payload))
	})
	if loadErr != nil {
		return nil, loadErr
	}
	return cfg.Outbound, nil
}

func (s *Instance) applyRuntimeOutbounds(subName string, nextTags map[string]struct{}, nextConfigs []*OutboundHandlerConfig) map[string]struct{} {
	rt := s.subscriptionRuntime
	if rt == nil {
		return nil
	}

	obm, ok := s.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok || obm == nil {
		errors.LogWarning(s.ctx, "subscription: outbound manager unavailable")
		return nil
	}

	rt.outboundMu.Lock()
	prevTags := cloneTagSet(rt.outbounds[subName])
	rt.outboundMu.Unlock()

	if nextTags == nil {
		nextTags = map[string]struct{}{}
	}

	// Remove stale tags previously managed by this subscription.
	for tag := range prevTags {
		if _, keep := nextTags[tag]; keep {
			continue
		}
		h := obm.GetHandler(tag)
		if h != nil {
			_ = h.Close()
			_ = obm.RemoveHandler(s.ctx, tag)
		}
	}

	appliedTags := make(map[string]struct{})

	// Sync current tags. Only tags previously managed by this subscription can be overwritten.
	for _, cfg := range nextConfigs {
		if cfg == nil || strings.TrimSpace(cfg.Tag) == "" {
			continue
		}
		tag := cfg.Tag
		_, shouldExist := nextTags[tag]
		if !shouldExist {
			continue
		}
		_, wasManagedByThisSubscription := prevTags[tag]
		if h := obm.GetHandler(tag); h != nil {
			if !wasManagedByThisSubscription {
				errors.LogWarning(s.ctx, "subscription: tag conflict with non-managed outbound; skipping ", tag)
				continue
			}
			_ = h.Close()
			_ = obm.RemoveHandler(s.ctx, tag)
		}
		if err := AddOutboundHandler(s, cfg); err != nil {
			errors.LogWarning(s.ctx, "subscription: failed to add outbound ", tag, ": ", err)
			continue
		}
		appliedTags[tag] = struct{}{}
	}

	// Store tags currently managed by this subscription.
	rt.outboundMu.Lock()
	if len(appliedTags) == 0 {
		delete(rt.outbounds, subName)
	} else {
		rt.outbounds[subName] = appliedTags
	}
	rt.outboundMu.Unlock()
	return cloneTagSet(appliedTags)
}

func (s *Instance) persistRuntimeSubscriptionOutbounds(subName string, prepared []json.RawMessage, appliedTags map[string]struct{}) {
	rt := s.subscriptionRuntime
	if rt == nil {
		return
	}
	path := strings.TrimSpace(rt.persistPath)
	if path == "" {
		return
	}
	subName = strings.TrimSpace(subName)
	if subName == "" {
		return
	}

	rt.persistMu.Lock()
	defer rt.persistMu.Unlock()

	root, format, err := readRuntimeConfigObject(path)
	if err != nil {
		errors.LogWarning(s.ctx, "subscription: failed to read runtime persist config ", path, ": ", err)
		return
	}

	var current []any
	if raw, ok := root["outbounds"].([]any); ok {
		current = raw
	}
	next := make([]any, 0, len(current)+len(prepared))
	for _, item := range current {
		typed, ok := item.(map[string]any)
		if !ok {
			next = append(next, item)
			continue
		}
		managedBy := normalizeManagedSubscriptionName(typed)
		if managedBy == subName {
			continue
		}
		next = append(next, typed)
	}
	subRewrites := rt.managedRewrites[subName]
	for _, raw := range prepared {
		var ob map[string]any
		if err := json.Unmarshal(raw, &ob); err != nil {
			continue
		}
		tag := strings.TrimSpace(asString(ob["tag"]))
		if tag == "" {
			continue
		}
		if _, ok := appliedTags[tag]; !ok {
			continue
		}
		if rewrite := subRewrites[tag]; len(rewrite) > 0 {
			ob["managed"] = map[string]any{
				"subscription": subName,
				"rewrite":      cloneSubscriptionRuntimeAnyMap(rewrite),
			}
		} else {
			ob["managed"] = map[string]any{
				"subscription": subName,
			}
		}
		next = append(next, ob)
	}
	root["outbounds"] = next
	if err := writeRuntimeConfigObject(path, format, root); err != nil {
		errors.LogWarning(s.ctx, "subscription: failed to persist outbounds to ", path, ": ", err)
	}
}

func tagsToSet(tags []string) map[string]struct{} {
	if len(tags) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		set[tag] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func cloneTagSet(in map[string]struct{}) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for tag := range in {
		out[tag] = struct{}{}
	}
	return out
}

func resolveSubscriptionRuntimePersistPath() string {
	candidates := resolveSubscriptionRuntimePersistCandidates()
	if len(candidates) == 0 {
		return ""
	}
	fallback := ""
	for _, path := range candidates {
		if strings.EqualFold(strings.TrimSpace(path), "stdin:") {
			continue
		}
		if !isRuntimePersistSupported(path) {
			continue
		}
		if !isRuntimeRegularFile(path) {
			continue
		}
		if fallback == "" {
			fallback = path
		}
		root, _, err := readRuntimeConfigObject(path)
		if err != nil {
			continue
		}
		if _, ok := root["outbounds"].([]any); ok {
			return path
		}
	}
	return fallback
}

func resolveSubscriptionRuntimePersistCandidates() []string {
	var out []string
	if info, ok := GetStartupInfo(); ok {
		for _, path := range info.ConfigFiles {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			out = append(out, path)
		}
	}
	if len(out) == 0 {
		if cwd, err := os.Getwd(); err == nil && cwd != "" {
			for _, name := range []string{"config.json", "config.jsonc", "config.yaml", "config.yml"} {
				out = append(out, filepath.Join(cwd, name))
			}
		}
	}
	seen := map[string]struct{}{}
	uniq := make([]string, 0, len(out))
	for _, path := range out {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		uniq = append(uniq, path)
	}
	return uniq
}

func isRuntimeRegularFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func detectRuntimeConfigFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return "yaml"
	case ".jsonc":
		return "jsonc"
	case ".json":
		return "json"
	default:
		return ""
	}
}

func isRuntimePersistSupported(path string) bool {
	return detectRuntimeConfigFormat(path) != ""
}

func readRuntimeConfigObject(path string) (map[string]any, string, error) {
	format := detectRuntimeConfigFormat(path)
	if format == "" {
		return nil, format, errors.New("unsupported config format")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, format, err
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return map[string]any{}, format, nil
	}
	var root map[string]any
	switch format {
	case "yaml":
		if err := yaml.Unmarshal([]byte(trimmed), &root); err != nil {
			return nil, format, err
		}
	default:
		if format == "jsonc" {
			trimmed = stripRuntimeJSONComments(trimmed)
		}
		if err := json.Unmarshal([]byte(trimmed), &root); err != nil {
			return nil, format, err
		}
	}
	if root == nil {
		root = map[string]any{}
	}
	return root, format, nil
}

func writeRuntimeConfigObject(path string, format string, root map[string]any) error {
	if format == "" {
		return errors.New("unsupported config format")
	}
	if root == nil {
		root = map[string]any{}
	}
	var payload []byte
	var err error
	if format == "yaml" {
		payload, err = yaml.Marshal(root)
	} else {
		payload, err = json.MarshalIndent(root, "", "  ")
	}
	if err != nil {
		return err
	}
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		payload = append(payload, '\n')
	}
	return os.WriteFile(path, payload, 0o644)
}

func stripRuntimeJSONComments(input string) string {
	var out strings.Builder
	out.Grow(len(input))
	inString := false
	escaped := false
	inLineComment := false
	inBlockComment := false

	for i := 0; i < len(input); i++ {
		ch := input[i]
		var next byte
		if i+1 < len(input) {
			next = input[i+1]
		}
		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				out.WriteByte(ch)
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && next == '/' {
				inBlockComment = false
				i++
				continue
			}
			if ch == '\n' {
				out.WriteByte(ch)
			}
			continue
		}
		if inString {
			out.WriteByte(ch)
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '/' && next == '/' {
			inLineComment = true
			i++
			continue
		}
		if ch == '/' && next == '*' {
			inBlockComment = true
			i++
			continue
		}
		if ch == '"' {
			inString = true
			out.WriteByte(ch)
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}

func normalizeManagedSubscriptionName(ob map[string]any) string {
	if ob == nil {
		return ""
	}
	if v := strings.TrimSpace(asString(ob["subscription"])); v != "" {
		return v
	}
	if managedObj, ok := ob["managed"].(map[string]any); ok {
		if v := strings.TrimSpace(asString(managedObj["subscription"])); v != "" {
			return v
		}
	}
	return strings.TrimSpace(asString(ob["managed"]))
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func (s *Instance) refreshDatabaseSubscription(ctx context.Context, inboundTag string, key string, db SubscriptionDatabaseConfig) bool {
	t := strings.TrimSpace(strings.ToLower(db.Type))
	var filename string
	var prepared []byte
	switch t {
	case "geoip":
		filename = "geoip.dat"
	case "geosite":
		filename = "geosite.dat"
	case "ja4":
		filename = "ja4.db"
	default:
		errors.LogWarning(s.ctx, "subscription: invalid database type: ", db.Type)
		return false
	}

	body, hint, err := s.loadSubscriptionResource(ctx, inboundTag, db.URL)
	if err != nil {
		errors.LogWarning(s.ctx, "subscription: failed to load database ", key, ": ", err)
		return false
	}
	_ = hint
	prepared = body
	if t == "ja4" {
		prepared, err = ja4db.PrepareForSubscription(body, db.SourceType)
		if err != nil {
			errors.LogWarning(s.ctx, "subscription: failed to prepare ja4 database ", key, ": ", err)
			return false
		}
	}

	dst := platform.GetAssetLocation(filename)
	if err := writeFileAtomic(dst, prepared, 0o644); err != nil {
		errors.LogWarning(s.ctx, "subscription: failed to write database ", filename, ": ", err)
		return false
	}
	return true
}

func (s *Instance) loadSubscriptionResource(ctx context.Context, inboundTag string, rawURL string) ([]byte, string, error) {
	if strings.EqualFold(strings.TrimSpace(rawURL), "stdin:") {
		return nil, "", errors.New("subscription url must not be stdin:")
	}
	u, err := decodeMaybeBase64URL(rawURL)
	if err != nil {
		return nil, "", err
	}

	lower := strings.ToLower(u)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		client := s.getSubscriptionHTTPClient(inboundTag)
		resp, err := client.Get(u)
		if err != nil {
			return nil, u, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, u, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			preview := strings.TrimSpace(string(body))
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			return nil, u, errors.New("http status ", resp.Status, ": ", preview)
		}
		return body, u, nil
	}

	path := u
	if strings.HasPrefix(lower, "file://") {
		path = strings.TrimPrefix(u, "file://")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, "", errors.New("empty subscription path")
	}

	resolved := path
	if !filepath.IsAbs(path) {
		baseDirs := subscriptionBaseDirs()
		if len(baseDirs) > 0 {
			found := ""
			for _, base := range baseDirs {
				candidate := filepath.Join(base, path)
				if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() {
					found = candidate
					break
				}
			}
			if found != "" {
				resolved = found
			} else {
				resolved = filepath.Join(baseDirs[0], path)
			}
		}
	}

	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, resolved, err
	}
	return b, resolved, nil
}

func subscriptionBaseDirs() []string {
	var dirs []string
	if info, ok := GetStartupInfo(); ok {
		if strings.TrimSpace(info.ConfDir) != "" {
			dirs = append(dirs, strings.TrimSpace(info.ConfDir))
		}
		if d := commonConfigDir(info.ConfigFiles); d != "" {
			dirs = append(dirs, d)
		}
		if strings.TrimSpace(info.Cwd) != "" {
			dirs = append(dirs, strings.TrimSpace(info.Cwd))
		}
	}
	if len(dirs) == 0 {
		if cwd, err := os.Getwd(); err == nil && cwd != "" {
			dirs = append(dirs, cwd)
		}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func commonConfigDir(files []string) string {
	if len(files) == 0 {
		return ""
	}
	firstDir := ""
	for _, f := range files {
		if f == "" || strings.EqualFold(f, "stdin:") {
			continue
		}
		d := filepath.Dir(f)
		if firstDir == "" {
			firstDir = d
			continue
		}
		if !strings.EqualFold(firstDir, d) {
			return ""
		}
	}
	return firstDir
}

func decodeMaybeBase64URL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty url")
	}
	lower := strings.ToLower(s)
	var payload string
	switch {
	case strings.HasPrefix(lower, "base64:"):
		payload = s[len("base64:"):]
	case strings.HasPrefix(lower, "b64:"):
		payload = s[len("b64:"):]
	case strings.HasPrefix(lower, "base64://"):
		payload = s[len("base64://"):]
	case strings.HasPrefix(lower, "b64://"):
		payload = s[len("b64://"):]
	default:
		return s, nil
	}
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "", errors.New("empty base64 url payload")
	}
	var decoded []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		decoded, err = enc.DecodeString(payload)
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", errors.New("invalid base64 url").Base(err)
	}
	return strings.TrimSpace(string(decoded)), nil
}

func (s *Instance) getSubscriptionHTTPClient(inboundTag string) *http.Client {
	if strings.TrimSpace(inboundTag) == "" {
		return &http.Client{Timeout: 30 * time.Second}
	}

	dispatcher, ok := s.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	if !ok || dispatcher == nil {
		// Fallback to direct HTTP if dispatcher isn't available.
		return &http.Client{Timeout: 30 * time.Second}
	}

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			portNum, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, err
			}
			port, err := xnet.PortFromInt(uint32(portNum))
			if err != nil {
				return nil, err
			}
			dest := xnet.TCPDestination(xnet.ParseAddress(host), port)
			sctx := session.ContextWithInbound(ctx, &session.Inbound{Tag: inboundTag})
			link, err := dispatcher.Dispatch(sctx, dest)
			if err != nil {
				return nil, err
			}
			return cnc.NewConnection(
				cnc.ConnectionInputMulti(link.Writer),
				cnc.ConnectionOutputMulti(link.Reader),
			), nil
		},
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

func writeFileAtomic(dst string, data []byte, perm os.FileMode) error {
	if dst == "" {
		return errors.New("empty destination")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}
