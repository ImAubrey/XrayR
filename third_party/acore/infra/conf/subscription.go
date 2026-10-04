package conf

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/platform"
	"github.com/ImAubrey/acore/core"
	subparser "github.com/ImAubrey/acore/infra/subscription"
)

type SubscriptionConfig struct {
	SubscriptionInbound string                   `json:"subscription-inbound"`
	Outbound            OutboundSubscriptionList `json:"outbound"`
	Database            DatabaseSubscriptionList `json:"database"`
	Full                FullSubscriptionList     `json:"full"`
}

type OutboundSubscriptionConfig struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Format    string `json:"format"`
	TagPrefix string `json:"tagPrefix"`
	Insert    string `json:"insert"`
	Interval  string `json:"interval"`
	Cron      string `json:"cron"`
	Crontab   string `json:"crontab"`
	Enabled   *bool  `json:"enabled"`
	// Observatory enables including this subscription's nodes in observatory selection.
	Observatory *SubscriptionObservatoryConfig `json:"observatory"`
}

type SubscriptionObservatoryConfig struct {
	Enabled    *bool  `json:"enabled"`
	TestURL    string `json:"testUrl"`
	TestURLAlt string `json:"testURL"`
	ProbeURL   string `json:"probeURL"`
}

func (c *SubscriptionObservatoryConfig) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*c = SubscriptionObservatoryConfig{}
		return nil
	}
	var enabled bool
	if err := json.Unmarshal(data, &enabled); err == nil {
		*c = SubscriptionObservatoryConfig{Enabled: &enabled}
		return nil
	}
	var enabledStr string
	if err := json.Unmarshal(data, &enabledStr); err == nil {
		switch strings.ToLower(strings.TrimSpace(enabledStr)) {
		case "true", "1", "yes", "on":
			enabled = true
			*c = SubscriptionObservatoryConfig{Enabled: &enabled}
			return nil
		case "false", "0", "no", "off":
			enabled = false
			*c = SubscriptionObservatoryConfig{Enabled: &enabled}
			return nil
		default:
			return errors.New("invalid subscription.outbound.observatory string value: " + enabledStr)
		}
	}
	type observatoryAlias SubscriptionObservatoryConfig
	var alias observatoryAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return errors.New("invalid subscription.outbound.observatory")
	}
	*c = SubscriptionObservatoryConfig(alias)
	return nil
}

func (c OutboundSubscriptionConfig) isEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

func (c OutboundSubscriptionConfig) cronExpr() string {
	if v := strings.TrimSpace(c.Cron); v != "" {
		return v
	}
	return strings.TrimSpace(c.Crontab)
}

func (c OutboundSubscriptionConfig) observatoryEnabled() bool {
	if c.Observatory == nil {
		return false
	}
	if c.Observatory.Enabled == nil {
		return true
	}
	return *c.Observatory.Enabled
}

func (c OutboundSubscriptionConfig) observatoryTestURL() string {
	if c.Observatory == nil {
		return ""
	}
	return firstNonEmptyString(
		strings.TrimSpace(c.Observatory.TestURL),
		strings.TrimSpace(c.Observatory.TestURLAlt),
		strings.TrimSpace(c.Observatory.ProbeURL),
	)
}

type DatabaseSubscriptionConfig struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	SourceType string `json:"sourceType"`
	Format     string `json:"format"`
	Interval   string `json:"interval"`
	Cron       string `json:"cron"`
	Crontab    string `json:"crontab"`
	Enabled    *bool  `json:"enabled"`
}

func (c DatabaseSubscriptionConfig) isEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

func (c DatabaseSubscriptionConfig) cronExpr() string {
	if v := strings.TrimSpace(c.Cron); v != "" {
		return v
	}
	return strings.TrimSpace(c.Crontab)
}

func (c DatabaseSubscriptionConfig) sourceType() string {
	if v := strings.TrimSpace(c.SourceType); v != "" {
		return v
	}
	return strings.TrimSpace(c.Format)
}

// NOTE: reserved for future.
type FullSubscriptionConfig map[string]any

type OutboundSubscriptionList []OutboundSubscriptionConfig

func (l *OutboundSubscriptionList) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*l = nil
		return nil
	}
	var single OutboundSubscriptionConfig
	singleErr := json.Unmarshal(data, &single)
	if singleErr == nil {
		*l = OutboundSubscriptionList{single}
		return nil
	}
	var list []OutboundSubscriptionConfig
	listErr := json.Unmarshal(data, &list)
	if listErr == nil {
		*l = OutboundSubscriptionList(list)
		return nil
	}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		return errors.New("invalid subscription.outbound").Base(listErr)
	}
	return errors.New("invalid subscription.outbound").Base(singleErr)
}

type DatabaseSubscriptionList []DatabaseSubscriptionConfig

func (l *DatabaseSubscriptionList) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*l = nil
		return nil
	}
	var single DatabaseSubscriptionConfig
	if err := json.Unmarshal(data, &single); err == nil {
		*l = DatabaseSubscriptionList{single}
		return nil
	}
	var list []DatabaseSubscriptionConfig
	if err := json.Unmarshal(data, &list); err == nil {
		*l = DatabaseSubscriptionList(list)
		return nil
	}
	return errors.New("invalid subscription.database")
}

type FullSubscriptionList []FullSubscriptionConfig

func (l *FullSubscriptionList) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*l = nil
		return nil
	}
	var single FullSubscriptionConfig
	if err := json.Unmarshal(data, &single); err == nil {
		*l = FullSubscriptionList{single}
		return nil
	}
	var list []FullSubscriptionConfig
	if err := json.Unmarshal(data, &list); err == nil {
		*l = FullSubscriptionList(list)
		return nil
	}
	return errors.New("invalid subscription.full")
}

type SubscriptionPostProcessingStage struct{}

func (SubscriptionPostProcessingStage) Process(config *Config) error {
	if core.IsSubscriptionRuntimeConfigSuppressed() {
		return nil
	}

	// No subscription block: clear runtime config and return.
	if config.Subscription == nil {
		core.SetSubscriptionRuntimeConfig(nil)
		return nil
	}

	sub := config.Subscription
	inboundTag := strings.TrimSpace(sub.SubscriptionInbound)
	baseDirs := subscriptionBaseDirs()

	if len(sub.Full) > 0 {
		errors.LogWarning(context.Background(), "subscription.full is reserved but not implemented; ignoring")
	}

	var runtime core.SubscriptionRuntimeConfig
	runtime.SubscriptionInbound = inboundTag
	runtime.ManagedOutbounds = collectManagedOutboundTags(config.OutboundConfigs)
	runtime.ManagedRewrites = collectManagedOutboundRewritesBySubscription(config.OutboundConfigs)

	// Expand/load-time apply outbound subscriptions when not runtime-managed.
	var runtimeOutbounds OutboundSubscriptionList
	for _, obSub := range sub.Outbound {
		if !obSub.isEnabled() {
			continue
		}
		if err := validateSchedule(obSub.Interval, obSub.cronExpr()); err != nil {
			return errors.New("invalid outbound subscription schedule").Base(err)
		}
		obsEnabled := obSub.observatoryEnabled()
		if inboundTag != "" || strings.TrimSpace(obSub.Interval) != "" || strings.TrimSpace(obSub.cronExpr()) != "" || obsEnabled {
			runtimeOutbounds = append(runtimeOutbounds, obSub)
			runtime.Outbound = append(runtime.Outbound, core.SubscriptionOutboundConfig{
				Name:               strings.TrimSpace(obSub.Name),
				URL:                strings.TrimSpace(obSub.URL),
				Format:             strings.TrimSpace(obSub.Format),
				TagPrefix:          strings.TrimSpace(obSub.TagPrefix),
				Insert:             strings.TrimSpace(obSub.Insert),
				Interval:           strings.TrimSpace(obSub.Interval),
				Cron:               strings.TrimSpace(obSub.cronExpr()),
				Observatory:        obsEnabled,
				ObservatoryTestURL: strings.TrimSpace(obSub.observatoryTestURL()),
			})
			continue
		}

		if err := applyOutboundSubscriptionAtLoad(config, obSub, baseDirs); err != nil {
			return err
		}
	}
	sub.Outbound = runtimeOutbounds

	// Apply database subscriptions at load time when not runtime-managed.
	var runtimeDatabases DatabaseSubscriptionList
	for _, dbSub := range sub.Database {
		if !dbSub.isEnabled() {
			continue
		}
		if err := validateSchedule(dbSub.Interval, dbSub.cronExpr()); err != nil {
			return errors.New("invalid database subscription schedule").Base(err)
		}
		if inboundTag != "" || strings.TrimSpace(dbSub.Interval) != "" || strings.TrimSpace(dbSub.cronExpr()) != "" {
			runtimeDatabases = append(runtimeDatabases, dbSub)
			runtime.Database = append(runtime.Database, core.SubscriptionDatabaseConfig{
				Type:       strings.TrimSpace(dbSub.Type),
				URL:        strings.TrimSpace(dbSub.URL),
				SourceType: strings.TrimSpace(dbSub.sourceType()),
				Interval:   strings.TrimSpace(dbSub.Interval),
				Cron:       strings.TrimSpace(dbSub.cronExpr()),
			})
			continue
		}
		if err := applyDatabaseSubscriptionAtLoad(dbSub, baseDirs); err != nil {
			return err
		}
	}
	sub.Database = runtimeDatabases

	if len(runtime.Outbound) == 0 && len(runtime.Database) == 0 {
		core.SetSubscriptionRuntimeConfig(nil)
	} else {
		core.SetSubscriptionRuntimeConfig(&runtime)
	}

	// Remove empty subscription block from the effective merged config (-dump behavior).
	if len(sub.Outbound) == 0 && len(sub.Database) == 0 && inboundTag == "" {
		config.Subscription = nil
	}

	return nil
}

func validateSchedule(interval string, cronExpr string) error {
	interval = strings.TrimSpace(interval)
	cronExpr = strings.TrimSpace(cronExpr)
	if interval == "" && cronExpr == "" {
		return nil
	}
	if interval != "" && cronExpr != "" {
		return errors.New("interval and cron/crontab cannot both be set")
	}
	if interval != "" {
		if _, err := time.ParseDuration(interval); err != nil {
			return errors.New("invalid interval: " + interval).Base(err)
		}
	}
	return nil
}

func subscriptionBaseDirs() []string {
	var dirs []string
	if info, ok := core.GetStartupInfo(); ok {
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

func loadSubscriptionBytes(rawURL string, baseDirs []string) ([]byte, string, error) {
	if strings.EqualFold(strings.TrimSpace(rawURL), "stdin:") {
		return nil, "", errors.New("subscription url must not be stdin:")
	}
	decodedURL, err := decodeMaybeBase64URL(rawURL)
	if err != nil {
		return nil, "", err
	}

	if strings.HasPrefix(strings.ToLower(decodedURL), "http://") || strings.HasPrefix(strings.ToLower(decodedURL), "https://") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(decodedURL)
		if err != nil {
			return nil, decodedURL, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, decodedURL, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			preview := strings.TrimSpace(string(body))
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			return nil, decodedURL, errors.New("http status ", resp.Status, ": ", preview)
		}
		return body, decodedURL, nil
	}

	path := decodedURL
	if strings.HasPrefix(strings.ToLower(path), "file://") {
		path = strings.TrimPrefix(path, "file://")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, decodedURL, errors.New("empty subscription path")
	}

	resolved := path
	if !filepath.IsAbs(path) && len(baseDirs) > 0 {
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
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, resolved, err
	}
	return b, resolved, nil
}

func applyOutboundSubscriptionAtLoad(config *Config, sub OutboundSubscriptionConfig, baseDirs []string) error {
	subName := strings.TrimSpace(sub.Name)
	if subName == "" {
		subName = "subscription"
	}
	insert := strings.TrimSpace(strings.ToLower(sub.Insert))
	switch insert {
	case "", "tail", "append":
		insert = "tail"
	case "head", "prepend":
		insert = "head"
	default:
		return errors.New("invalid subscription.outbound.insert: " + sub.Insert)
	}
	format := strings.TrimSpace(sub.Format)
	if format == "" {
		format = "auto"
	}

	body, resolved, err := loadSubscriptionBytes(sub.URL, baseDirs)
	if err != nil {
		return errors.New("failed to load subscription: ", sub.URL, " (", resolved, ")").Base(err)
	}
	parsed, err := subparser.ParseOutboundSubscription(body, format, resolved)
	if err != nil {
		return errors.New("failed to parse subscription: ", sub.URL).Base(err)
	}
	for _, w := range parsed.Warnings {
		errors.LogWarning(context.Background(), "subscription warning: ", w)
	}

	var outbounds []OutboundDetourConfig
	for _, raw := range parsed.Outbounds {
		var ob OutboundDetourConfig
		if err := json.Unmarshal(raw, &ob); err != nil {
			return errors.New("invalid outbound in subscription").Base(err)
		}
		outbounds = append(outbounds, ob)
	}

	outbounds = applyOutboundSubscriptionDefaults(outbounds, subName, strings.TrimSpace(sub.TagPrefix))
	outbounds = applyManagedOutboundRewrites(outbounds, collectManagedOutboundRewritesForSubscription(config.OutboundConfigs, subName))

	// Accept management: remove existing managed outbounds first, then merge new.
	config.OutboundConfigs = removeManagedOutbounds(config.OutboundConfigs, subName)
	config.OutboundConfigs = mergeOutbounds(config.OutboundConfigs, outbounds, insert)
	return nil
}

func applyOutboundSubscriptionDefaults(outbounds []OutboundDetourConfig, subName string, tagPrefix string) []OutboundDetourConfig {
	if subName == "" {
		subName = "subscription"
	}
	for i := range outbounds {
		ob := &outbounds[i]
		tag := strings.TrimSpace(ob.Tag)
		if tag == "" {
			tag = subName + "-" + strconv.Itoa(i)
		}
		if tagPrefix != "" {
			tag = tagPrefix + tag
		}
		ob.Tag = tag
		ob.Managed = &ManagedOutboundConfig{Subscription: subName}
	}
	return outbounds
}

func removeManagedOutbounds(current []OutboundDetourConfig, subName string) []OutboundDetourConfig {
	if subName == "" {
		return current
	}
	out := make([]OutboundDetourConfig, 0, len(current))
	for _, ob := range current {
		if managedSubscriptionName(ob.Managed) == subName || strings.TrimSpace(ob.Subscription) == subName {
			continue
		}
		out = append(out, ob)
	}
	return out
}

func mergeOutbounds(current []OutboundDetourConfig, add []OutboundDetourConfig, insert string) []OutboundDetourConfig {
	toInsert := make([]OutboundDetourConfig, 0, len(add))
	for _, ob := range add {
		if strings.TrimSpace(ob.Tag) == "" {
			continue
		}
		found := -1
		for idx := range current {
			if current[idx].Tag == ob.Tag {
				found = idx
				break
			}
		}
		if found >= 0 {
			// Keep local/non-managed outbounds intact when tag conflicts.
			continue
		} else {
			toInsert = append(toInsert, ob)
		}
	}
	if len(toInsert) == 0 {
		return current
	}
	if insert == "head" {
		return append(toInsert, current...)
	}
	return append(current, toInsert...)
}

func collectManagedOutboundTags(outbounds []OutboundDetourConfig) map[string][]string {
	if len(outbounds) == 0 {
		return nil
	}
	managed := make(map[string]map[string]struct{})
	for _, ob := range outbounds {
		tag := strings.TrimSpace(ob.Tag)
		if tag == "" {
			continue
		}
		subName := strings.TrimSpace(ob.Subscription)
		if subName == "" {
			subName = managedSubscriptionName(ob.Managed)
		}
		if subName == "" {
			continue
		}
		tagSet := managed[subName]
		if tagSet == nil {
			tagSet = make(map[string]struct{})
			managed[subName] = tagSet
		}
		tagSet[tag] = struct{}{}
	}
	if len(managed) == 0 {
		return nil
	}
	out := make(map[string][]string, len(managed))
	for subName, tagSet := range managed {
		tags := make([]string, 0, len(tagSet))
		for tag := range tagSet {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		out[subName] = tags
	}
	return out
}

func collectManagedOutboundRewritesBySubscription(outbounds []OutboundDetourConfig) map[string]map[string]map[string]any {
	if len(outbounds) == 0 {
		return nil
	}
	out := make(map[string]map[string]map[string]any)
	for _, ob := range outbounds {
		tag := strings.TrimSpace(ob.Tag)
		if tag == "" {
			continue
		}
		subName := strings.TrimSpace(ob.Subscription)
		if subName == "" {
			subName = managedSubscriptionName(ob.Managed)
		}
		if subName == "" {
			continue
		}
		rewrite := managedRewritePatch(ob.Managed)
		if len(rewrite) == 0 {
			continue
		}
		byTag := out[subName]
		if byTag == nil {
			byTag = make(map[string]map[string]any)
			out[subName] = byTag
		}
		byTag[tag] = cloneManagedRewrite(rewrite)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func collectManagedOutboundRewritesForSubscription(outbounds []OutboundDetourConfig, subName string) map[string]map[string]any {
	subName = strings.TrimSpace(subName)
	if len(outbounds) == 0 || subName == "" {
		return nil
	}
	out := make(map[string]map[string]any)
	for _, ob := range outbounds {
		tag := strings.TrimSpace(ob.Tag)
		if tag == "" {
			continue
		}
		managedBy := strings.TrimSpace(ob.Subscription)
		if managedBy == "" {
			managedBy = managedSubscriptionName(ob.Managed)
		}
		if managedBy != subName {
			continue
		}
		rewrite := managedRewritePatch(ob.Managed)
		if len(rewrite) == 0 {
			continue
		}
		out[tag] = cloneManagedRewrite(rewrite)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func applyManagedOutboundRewrites(outbounds []OutboundDetourConfig, rewrites map[string]map[string]any) []OutboundDetourConfig {
	if len(outbounds) == 0 || len(rewrites) == 0 {
		return outbounds
	}
	for i := range outbounds {
		tag := strings.TrimSpace(outbounds[i].Tag)
		if tag == "" {
			continue
		}
		rewrite := rewrites[tag]
		if len(rewrite) == 0 {
			continue
		}
		raw, err := json.Marshal(outbounds[i])
		if err != nil {
			continue
		}
		var merged map[string]any
		if err := json.Unmarshal(raw, &merged); err != nil {
			continue
		}
		mergeManagedRewriteMaps(merged, rewrite)
		// tag cannot be overridden by rewrite.
		merged["tag"] = tag
		rewrittenRaw, err := json.Marshal(merged)
		if err != nil {
			continue
		}
		var rewritten OutboundDetourConfig
		if err := json.Unmarshal(rewrittenRaw, &rewritten); err != nil {
			continue
		}
		rewritten.Tag = tag
		outbounds[i] = rewritten
	}
	return outbounds
}

func mergeManagedRewriteMaps(dst map[string]any, patch map[string]any) {
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
			mergeManagedRewriteMaps(current, patchMap)
			if len(current) > 0 {
				dst[k] = current
			}
			continue
		}
		dst[k] = value
	}
}

func applyDatabaseSubscriptionAtLoad(sub DatabaseSubscriptionConfig, baseDirs []string) error {
	t := strings.TrimSpace(strings.ToLower(sub.Type))
	var file string
	var prepared []byte
	switch t {
	case "geoip":
		file = "geoip.dat"
	case "geosite":
		file = "geosite.dat"
	case "ja4":
		file = "ja4.db"
	default:
		return errors.New("invalid subscription.database.type: " + sub.Type)
	}

	body, resolved, err := loadSubscriptionBytes(sub.URL, baseDirs)
	if err != nil {
		return errors.New("failed to load database subscription: ", sub.URL, " (", resolved, ")").Base(err)
	}
	prepared = body
	if t == "ja4" {
		prepared, err = ja4db.PrepareForSubscription(body, sub.sourceType())
		if err != nil {
			return errors.New("failed to prepare ja4 database subscription: ", sub.URL).Base(err)
		}
	}
	dst := platform.GetAssetLocation(file)
	if err := writeFileAtomic(dst, prepared, 0o644); err != nil {
		return errors.New("failed to write asset: ", dst).Base(err)
	}
	return nil
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
