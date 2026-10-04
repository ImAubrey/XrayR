package metrics

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/app/commander"
	"github.com/ImAubrey/acore/app/observatory"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/features/extension"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
)

type nodeOutboundView struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
}

type nodeStatusView struct {
	Alive        bool   `json:"alive"`
	Delay        int64  `json:"delay"`
	LastError    string `json:"lastError"`
	LastSeenTime int64  `json:"lastSeenTime"`
	LastTryTime  int64  `json:"lastTryTime"`
}

type balancerGroupView struct {
	Tag              string   `json:"tag"`
	CurrentTarget    string   `json:"currentTarget,omitempty"`
	OverrideTarget   string   `json:"overrideTarget,omitempty"`
	PrincipleTargets []string `json:"principleTargets,omitempty"`
	Strategy         string   `json:"strategy,omitempty"`
	FallbackTag      string   `json:"fallbackTag,omitempty"`
	ManualSelectable bool     `json:"manualSelectable,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type nodesResponse struct {
	Outbounds []nodeOutboundView        `json:"outbounds"`
	Groups    []balancerGroupView       `json:"groups"`
	Statuses  map[string]nodeStatusView `json:"statuses"`
	Errors    map[string]string         `json:"errors,omitempty"`
	UpdatedAt string                    `json:"updatedAt"`
}

var nodesOnce sync.Once
var nodesMu sync.RWMutex
var nodesOutbound outbound.Manager
var nodesRouter routing.Router
var nodesObservatory extension.Observatory

func setNodesDependencies(om outbound.Manager, router routing.Router, obs extension.Observatory) {
	nodesMu.Lock()
	nodesOutbound = om
	nodesRouter = router
	nodesObservatory = obs
	nodesMu.Unlock()
}

func getNodesDependencies() (outbound.Manager, routing.Router, extension.Observatory) {
	nodesMu.RLock()
	defer nodesMu.RUnlock()
	return nodesOutbound, nodesRouter, nodesObservatory
}

func registerNodesRoutes() {
	nodesOnce.Do(func() {
		http.HandleFunc("/nodes", nodesHandler)
		http.HandleFunc("/balancer/override", balancerOverrideHandler)
		http.HandleFunc("/observatory/probe", observatoryProbeHandler)
		http.HandleFunc("/observatory/probe/trigger", observatoryProbeTriggerHandler)
	})
}

func nodesHandler(w http.ResponseWriter, r *http.Request) {
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

	om, router, obs := getNodesDependencies()
	resp := nodesResponse{
		Outbounds: []nodeOutboundView{},
		Groups:    []balancerGroupView{},
		Statuses:  map[string]nodeStatusView{},
		Errors:    map[string]string{},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if om == nil {
		resp.Errors["outbounds"] = "outbound manager unavailable"
		writeJSON(w, resp)
		return
	}

	resp.Outbounds = listOutboundViews(om)

	if obs != nil {
		statuses, err := fetchOutboundStatuses(obs)
		if err != nil {
			resp.Errors["statuses"] = err.Error()
		} else {
			resp.Statuses = statuses
		}
	}

	if router != nil {
		groups, err := fetchBalancerGroups(router)
		if err != nil {
			resp.Errors["groups"] = err.Error()
		} else {
			enrichBalancerStatuses(groups, resp.Statuses)
			resp.Groups = groups
			if settings := getSettingsSnapshot(); len(settings.BalancerTags) > 0 {
				resp.Groups = filterGroupsByTags(resp.Groups, settings.BalancerTags)
			}
		}
	}

	if len(resp.Errors) == 0 {
		resp.Errors = nil
	}

	writeJSON(w, resp)
}

func listOutboundViews(om outbound.Manager) []nodeOutboundView {
	handlers := om.ListHandlers(context.Background())
	outbounds := make([]nodeOutboundView, 0, len(handlers))
	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		if _, ok := handler.(*commander.Outbound); ok {
			continue
		}
		tag := handler.Tag()
		if tag == "" {
			continue
		}
		settings := handler.ProxySettings()
		if settings == nil {
			continue
		}
		outbounds = append(outbounds, nodeOutboundView{
			Tag:  tag,
			Type: outboundType(settings.Type),
		})
	}
	return outbounds
}

func outboundType(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "unknown"
	}
	return value
}

func fetchOutboundStatuses(obs extension.Observatory) (map[string]nodeStatusView, error) {
	report, err := obs.GetObservation(context.Background())
	if err != nil {
		return nil, err
	}
	result, ok := report.(*observatory.ObservationResult)
	if !ok {
		return nil, errors.New("unexpected observatory result")
	}
	out := make(map[string]nodeStatusView, len(result.Status))
	for _, status := range result.Status {
		tag := status.OutboundTag
		if tag == "" {
			continue
		}
		out[tag] = nodeStatusView{
			Alive:        status.Alive,
			Delay:        status.Delay,
			LastError:    status.LastErrorReason,
			LastSeenTime: status.LastSeenTime,
			LastTryTime:  status.LastTryTime,
		}
	}
	return out, nil
}

func fetchBalancerGroups(router routing.Router) ([]balancerGroupView, error) {
	lister, ok := router.(routing.BalancerLister)
	if !ok {
		return nil, nil
	}
	tags := lister.ListBalancerTags()
	if len(tags) == 0 {
		return []balancerGroupView{}, nil
	}
	groups := make([]balancerGroupView, 0, len(tags))
	overrider, _ := router.(routing.BalancerOverrider)
	principle, _ := router.(routing.BalancerPrincipleTarget)
	infoProvider, _ := router.(routing.BalancerInfoProvider)
	resolver, _ := router.(routing.DestinationResolver)
	for _, tag := range tags {
		entry := balancerGroupView{Tag: tag}
		if overrider != nil {
			if target, err := overrider.GetOverrideTarget(tag); err == nil {
				entry.OverrideTarget = target
			} else if entry.Error == "" {
				entry.Error = err.Error()
			}
		}
		if principle != nil {
			if targets, err := principle.GetPrincipleTarget(tag); err == nil {
				entry.PrincipleTargets = targets
			} else if entry.Error == "" {
				entry.Error = err.Error()
			}
		}
		if infoProvider != nil {
			if info, err := infoProvider.GetBalancerInfo(tag); err == nil {
				entry.Strategy = info.Strategy
				entry.FallbackTag = info.FallbackTag
			} else if entry.Error == "" {
				entry.Error = err.Error()
			}
		}
		normalizedStrategy := normalizeBalancerStrategy(entry.Strategy)
		needsCurrentTarget := normalizedStrategy == "fallback" ||
			normalizedStrategy == "selector" ||
			normalizedStrategy == "leastping" ||
			strings.TrimSpace(entry.FallbackTag) != ""
		if resolver != nil && needsCurrentTarget {
			if current, err := resolver.ResolveDestination(tag); err == nil {
				entry.CurrentTarget = strings.TrimSpace(current)
			} else if entry.Error == "" {
				entry.Error = err.Error()
			}
		}
		entry.ManualSelectable = isManualSelectable(entry.Strategy, entry.FallbackTag)
		groups = append(groups, entry)
	}
	return groups, nil
}

func normalizeBalancerStrategy(strategy string) string {
	return strings.ToLower(strings.TrimSpace(strategy))
}

func enrichBalancerStatuses(groups []balancerGroupView, statuses map[string]nodeStatusView) {
	if len(groups) == 0 || statuses == nil {
		return
	}
	byTag := make(map[string]balancerGroupView, len(groups))
	for _, group := range groups {
		tag := strings.TrimSpace(group.Tag)
		if tag == "" {
			continue
		}
		byTag[tag] = group
	}
	if len(byTag) == 0 {
		return
	}

	resolving := make(map[string]struct{}, len(byTag))
	resolved := make(map[string]struct{}, len(byTag))

	var resolveStatus func(string) (nodeStatusView, bool)
	resolveStatus = func(rawTag string) (nodeStatusView, bool) {
		tag := strings.TrimSpace(rawTag)
		if tag == "" {
			return nodeStatusView{}, false
		}
		if status, ok := statuses[tag]; ok {
			return status, true
		}
		group, ok := byTag[tag]
		if !ok {
			return nodeStatusView{}, false
		}
		if _, ok := resolving[tag]; ok {
			return nodeStatusView{}, false
		}
		if _, ok := resolved[tag]; ok {
			status, ok := statuses[tag]
			return status, ok
		}

		resolving[tag] = struct{}{}
		defer delete(resolving, tag)

		switch normalizeBalancerStrategy(group.Strategy) {
		case "fallback", "selector", "leastping":
			current := strings.TrimSpace(group.CurrentTarget)
			if current != "" {
				if currentStatus, ok := resolveStatus(current); ok {
					statuses[tag] = currentStatus
				}
			}
		case "leastload", "loadbalancer", "loadbalance", "roundrobin", "random":
			delays := make([]int64, 0, len(group.PrincipleTargets))
			memberSeen := make(map[string]struct{}, len(group.PrincipleTargets))
			var lastSeen int64
			var lastTry int64
			for _, rawMember := range group.PrincipleTargets {
				member := strings.TrimSpace(rawMember)
				if member == "" {
					continue
				}
				if _, ok := memberSeen[member]; ok {
					continue
				}
				memberSeen[member] = struct{}{}
				memberStatus, ok := resolveStatus(member)
				if !ok || !memberStatus.Alive {
					continue
				}
				delays = append(delays, memberStatus.Delay)
				if memberStatus.LastSeenTime > lastSeen {
					lastSeen = memberStatus.LastSeenTime
				}
				if memberStatus.LastTryTime > lastTry {
					lastTry = memberStatus.LastTryTime
				}
			}
			if len(delays) > 0 {
				statuses[tag] = nodeStatusView{
					Alive:        true,
					Delay:        medianDelay(delays),
					LastSeenTime: lastSeen,
					LastTryTime:  lastTry,
				}
			}
		}

		resolved[tag] = struct{}{}
		status, ok := statuses[tag]
		return status, ok
	}

	for tag := range byTag {
		_, _ = resolveStatus(tag)
	}
}

func medianDelay(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i] < values[j]
	})
	mid := len(values) / 2
	if len(values)%2 == 1 {
		return values[mid]
	}
	return (values[mid-1] + values[mid]) / 2
}

func isManualSelectable(strategy, fallbackTag string) bool {
	switch normalizeBalancerStrategy(strategy) {
	case "selector", "leastping":
		return true
	default:
		return false
	}
}

func filterGroupsByTags(groups []balancerGroupView, tags []string) []balancerGroupView {
	if len(tags) == 0 {
		return groups
	}
	byTag := make(map[string]balancerGroupView, len(groups))
	for _, group := range groups {
		if group.Tag == "" {
			continue
		}
		byTag[group.Tag] = group
	}
	out := make([]balancerGroupView, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, raw := range tags {
		tag := strings.TrimSpace(raw)
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		if group, ok := byTag[tag]; ok {
			out = append(out, group)
			continue
		}
		out = append(out, balancerGroupView{
			Tag:              tag,
			CurrentTarget:    "",
			OverrideTarget:   "",
			PrincipleTargets: []string{},
			Strategy:         "",
			FallbackTag:      "",
			ManualSelectable: false,
			Error:            "balancer not found",
		})
	}
	return out
}

func balancerOverrideHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, router, _ := getNodesDependencies()
	if router == nil {
		http.Error(w, "router unavailable", http.StatusServiceUnavailable)
		return
	}
	overrider, ok := router.(routing.BalancerOverrider)
	if !ok {
		http.Error(w, "override unsupported", http.StatusNotImplemented)
		return
	}
	var payload struct {
		BalancerTag string `json:"balancerTag"`
		Target      string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	balancerTag := strings.TrimSpace(payload.BalancerTag)
	if balancerTag == "" {
		http.Error(w, "balancerTag is required", http.StatusBadRequest)
		return
	}
	if err := overrider.SetOverrideTarget(balancerTag, strings.TrimSpace(payload.Target)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := updateUIStateOverride(balancerTag, payload.Target); err != nil {
		errors.LogWarningInner(context.Background(), err, "failed to persist ui override")
	}
	writeJSON(w, map[string]bool{"ok": true})
}

type probeModePayload struct {
	Mode string `json:"mode"`
}

type observatoryProbeTrigger interface {
	TriggerProbe(context.Context) (int, error)
}

func observatoryProbeTriggerHandler(w http.ResponseWriter, r *http.Request) {
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
	_, _, obs := getNodesDependencies()
	if obs == nil {
		http.Error(w, "observatory unavailable", http.StatusServiceUnavailable)
		return
	}
	trigger, ok := obs.(observatoryProbeTrigger)
	if !ok {
		http.Error(w, "probe trigger unsupported", http.StatusNotImplemented)
		return
	}
	count, err := trigger.TriggerProbe(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "probe trigger failed", err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":        true,
		"scheduled": true,
		"targets":   count,
	})
}

func observatoryProbeHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, _, obs := getNodesDependencies()
	if obs == nil {
		http.Error(w, "observatory unavailable", http.StatusServiceUnavailable)
		return
	}
	controller, ok := obs.(interface {
		SetProbeMode(string) error
		GetProbeMode() string
	})
	if !ok {
		switch r.Method {
		case http.MethodGet:
			settings := reloadSettingsSnapshot()
			writeJSON(w, map[string]interface{}{
				"mode":      normalizeProbeMode(settings.ProbeMode),
				"supported": false,
			})
		case http.MethodPost:
			var payload probeModePayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "invalid json body", http.StatusBadRequest)
				return
			}
			normalized := normalizeProbeMode(payload.Mode)
			next, err := updateSettings(map[string]interface{}{"probeMode": normalized})
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "failed to persist probe mode", err.Error())
				return
			}
			writeJSON(w, map[string]interface{}{
				"ok":        true,
				"mode":      normalizeProbeMode(next.ProbeMode),
				"supported": false,
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]string{"mode": controller.GetProbeMode()})
	case http.MethodPost:
		var payload probeModePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		if err := controller.SetProbeMode(payload.Mode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true, "mode": controller.GetProbeMode()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
