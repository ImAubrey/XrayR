package core

import (
	"sync/atomic"
)

type SubscriptionOutboundConfig struct {
	Name               string
	URL                string
	Format             string
	TagPrefix          string
	Insert             string
	Interval           string
	Cron               string
	Observatory        bool
	ObservatoryTestURL string
}

type SubscriptionDatabaseConfig struct {
	Type       string
	URL        string
	SourceType string
	Interval   string
	Cron       string
}

type SubscriptionRuntimeConfig struct {
	SubscriptionInbound string
	Outbound            []SubscriptionOutboundConfig
	Database            []SubscriptionDatabaseConfig
	ManagedOutbounds    map[string][]string                  // subscription name -> managed outbound tags
	ManagedRewrites     map[string]map[string]map[string]any // subscription name -> tag -> rewrite patch
}

var subscriptionRuntimeConfig atomic.Value // *SubscriptionRuntimeConfig
var subscriptionRuntimeConfigSuppress int32

func IsSubscriptionRuntimeConfigSuppressed() bool {
	return atomic.LoadInt32(&subscriptionRuntimeConfigSuppress) > 0
}

func withSubscriptionRuntimeConfigSuppressed(fn func()) {
	atomic.AddInt32(&subscriptionRuntimeConfigSuppress, 1)
	defer atomic.AddInt32(&subscriptionRuntimeConfigSuppress, -1)
	fn()
}

func SetSubscriptionRuntimeConfig(cfg *SubscriptionRuntimeConfig) {
	if cfg == nil {
		subscriptionRuntimeConfig.Store((*SubscriptionRuntimeConfig)(nil))
		return
	}
	clone := &SubscriptionRuntimeConfig{
		SubscriptionInbound: cfg.SubscriptionInbound,
		Outbound:            append([]SubscriptionOutboundConfig{}, cfg.Outbound...),
		Database:            append([]SubscriptionDatabaseConfig{}, cfg.Database...),
		ManagedOutbounds:    cloneSubscriptionManagedOutbounds(cfg.ManagedOutbounds),
		ManagedRewrites:     cloneSubscriptionManagedRewrites(cfg.ManagedRewrites),
	}
	subscriptionRuntimeConfig.Store(clone)
}

func GetSubscriptionRuntimeConfig() (*SubscriptionRuntimeConfig, bool) {
	if v := subscriptionRuntimeConfig.Load(); v != nil {
		cfg, _ := v.(*SubscriptionRuntimeConfig)
		if cfg == nil {
			return nil, false
		}
		clone := &SubscriptionRuntimeConfig{
			SubscriptionInbound: cfg.SubscriptionInbound,
			Outbound:            append([]SubscriptionOutboundConfig{}, cfg.Outbound...),
			Database:            append([]SubscriptionDatabaseConfig{}, cfg.Database...),
			ManagedOutbounds:    cloneSubscriptionManagedOutbounds(cfg.ManagedOutbounds),
			ManagedRewrites:     cloneSubscriptionManagedRewrites(cfg.ManagedRewrites),
		}
		return clone, true
	}
	return nil, false
}

func cloneSubscriptionManagedOutbounds(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for name, tags := range in {
		out[name] = append([]string{}, tags...)
	}
	return out
}

func cloneSubscriptionManagedRewrites(in map[string]map[string]map[string]any) map[string]map[string]map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]map[string]map[string]any, len(in))
	for subName, tagMap := range in {
		if len(tagMap) == 0 {
			continue
		}
		nextTagMap := make(map[string]map[string]any, len(tagMap))
		for tag, rewrite := range tagMap {
			nextTagMap[tag] = cloneSubscriptionRuntimeAnyMap(rewrite)
		}
		out[subName] = nextTagMap
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneSubscriptionRuntimeAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		switch typed := value.(type) {
		case map[string]any:
			out[key] = cloneSubscriptionRuntimeAnyMap(typed)
		default:
			out[key] = typed
		}
	}
	return out
}
