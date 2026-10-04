package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	dnsapp "github.com/ImAubrey/acore/app/dns"
	applog "github.com/ImAubrey/acore/app/log"
	observatoryapp "github.com/ImAubrey/acore/app/observatory"
	routercfg "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common/cmdarg"
	xerrors "github.com/ImAubrey/acore/common/errors"
	clog "github.com/ImAubrey/acore/common/log"
	cserial "github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/extension"
	"github.com/ImAubrey/acore/features/inbound"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	feature_stats "github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/transport/internet"
	"google.golang.org/protobuf/proto"
)

var controlOnce sync.Once
var restartMu sync.Mutex
var restartBusy bool

type restartTaskStatus struct {
	ID            int64  `json:"id"`
	Mode          string `json:"mode"`
	InProgress    bool   `json:"inProgress"`
	Ok            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	RolledBack    bool   `json:"rolledBack,omitempty"`
	RollbackOk    bool   `json:"rollbackOk,omitempty"`
	RollbackError string `json:"rollbackError,omitempty"`
}

type hotReloadRequest struct {
	Targets []string `json:"targets,omitempty"`
}

var hotReloadAllowedTargets = map[string]struct{}{
	"all":          {},
	"routing":      {},
	"outbounds":    {},
	"inbounds":     {},
	"subscription": {},
	"main":         {},
	"dns":          {},
	"observatory":  {},
}

var restartStatusMu sync.RWMutex
var restartStatus *restartTaskStatus

var logLevelBracketRe = regexp.MustCompile(`(?i)\[(error|warning|info|debug|trace)\]`)
var logLevelTokenRe = regexp.MustCompile(`(?i)\b(error|fatal|panic|warn(?:ing)?|info|debug|trace)\b`)

func registerControlRoutes() {
	controlOnce.Do(func() {
		http.HandleFunc("/core/restart", restartHandler)
		http.HandleFunc("/core/restart/status", restartStatusHandler)
		http.HandleFunc("/core/hotreload", hotReloadHandler)
		http.HandleFunc("/logs", logsHandler)
		http.HandleFunc("/logs/config", logsConfigHandler)
		http.HandleFunc("/logs/stream", logsStreamHandler)
	})
}

func cloneRestartTaskStatus(in *restartTaskStatus) *restartTaskStatus {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func setRestartTaskStatus(next *restartTaskStatus) {
	restartStatusMu.Lock()
	restartStatus = next
	restartStatusMu.Unlock()
}

func getRestartTaskStatus() *restartTaskStatus {
	restartStatusMu.RLock()
	defer restartStatusMu.RUnlock()
	return cloneRestartTaskStatus(restartStatus)
}

func finishRestartTaskStatus(id int64, mode string, err error) {
	ok := err == nil
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	setRestartTaskStatus(&restartTaskStatus{
		ID:         id,
		Mode:       mode,
		InProgress: false,
		Ok:         ok,
		Error:      msg,
	})
}

func restartStatusHandler(w http.ResponseWriter, r *http.Request) {
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

	status := getRestartTaskStatus()
	want := strings.TrimSpace(r.URL.Query().Get("id"))
	if want != "" && status != nil {
		if strconv.FormatInt(status.ID, 10) != want {
			status = nil
		}
	}

	writeJSON(w, map[string]interface{}{
		"restart": status,
	})
}

func hotReloadHandler(w http.ResponseWriter, r *http.Request) {
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
	targets, err := decodeHotReloadTargets(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid hot reload request", err.Error())
		return
	}

	if !beginRestart() {
		writeJSONError(w, http.StatusConflict, "restart in progress", "a restart is already running")
		return
	}

	id := time.Now().UnixMilli()
	setRestartTaskStatus(&restartTaskStatus{
		ID:         id,
		Mode:       "hotReload",
		InProgress: true,
		Ok:         true, // avoid rendering as "danger" while running
	})

	config, files, format, err := buildRestartConfig()
	if err != nil {
		endRestart()
		finishRestartTaskStatus(id, "hotReload", err)
		writeJSONError(w, http.StatusBadRequest, "hot reload is not configured", err.Error())
		return
	}
	if err := validateRestartConfig(config); err != nil {
		endRestart()
		finishRestartTaskStatus(id, "hotReload", err)
		writeJSONError(w, http.StatusBadRequest, "config validation failed", err.Error())
		return
	}

	expandedTargets := expandHotReloadTargets(targets)
	mode := decideHotReloadMode(expandedTargets)
	writeJSON(w, map[string]interface{}{
		"ok": true,
		"id": id,
		"hotReload": map[string]interface{}{
			"needsRestart": false,
			"warnings":     []string{},
		},
		"reload": map[string]interface{}{
			"mode":      mode,
			"scheduled": true,
			"files":     files,
			"format":    format,
			"targets":   targets,
		},
	})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	go func(cfg *core.Config) {
		defer endRestart()
		if err := applyHotReload(cfg, expandedTargets); err != nil {
			xerrors.LogErrorInner(context.Background(), err, "failed to apply hot reload")
			finishRestartTaskStatus(id, "hotReload", err)
			return
		}
		finishRestartTaskStatus(id, "hotReload", nil)
	}(config)
}

type hotReloadAction string

const (
	hotReloadActionOutbounds    hotReloadAction = "outbounds"
	hotReloadActionInbounds     hotReloadAction = "inbounds"
	hotReloadActionRouting      hotReloadAction = "routing"
	hotReloadActionSubscription hotReloadAction = "subscription"
	hotReloadActionDNS          hotReloadAction = "dns"
	hotReloadActionObservatory  hotReloadAction = "observatory"
	hotReloadActionLog          hotReloadAction = "log"
)

func hotReloadActionsForTarget(target string) ([]hotReloadAction, error) {
	switch target {
	case "all":
		return []hotReloadAction{
			hotReloadActionOutbounds,
			hotReloadActionInbounds,
			hotReloadActionRouting,
			hotReloadActionSubscription,
			hotReloadActionDNS,
			hotReloadActionObservatory,
			hotReloadActionLog,
		}, nil
	case "outbounds":
		return []hotReloadAction{hotReloadActionOutbounds}, nil
	case "inbounds":
		return []hotReloadAction{hotReloadActionInbounds}, nil
	case "routing":
		return []hotReloadAction{hotReloadActionRouting}, nil
	case "subscription":
		return []hotReloadAction{hotReloadActionSubscription}, nil
	case "dns":
		return []hotReloadAction{hotReloadActionDNS}, nil
	case "observatory":
		return []hotReloadAction{hotReloadActionObservatory}, nil
	case "main":
		return []hotReloadAction{
			hotReloadActionDNS,
			hotReloadActionObservatory,
			hotReloadActionLog,
		}, nil
	default:
		return nil, errors.New("dynamic hot reload is not supported for target: " + target)
	}
}

func buildHotReloadPlan(targets []string) ([]hotReloadAction, error) {
	if len(targets) == 0 {
		targets = []string{"routing"}
	}
	seen := make(map[hotReloadAction]struct{}, len(targets))
	plan := make([]hotReloadAction, 0, len(targets))
	for _, target := range targets {
		actions, err := hotReloadActionsForTarget(target)
		if err != nil {
			return nil, err
		}
		for _, action := range actions {
			if _, ok := seen[action]; ok {
				continue
			}
			seen[action] = struct{}{}
			plan = append(plan, action)
		}
	}
	return plan, nil
}

func applyHotReload(config *core.Config, targets []string) error {
	plan, err := buildHotReloadPlan(targets)
	if err != nil {
		return err
	}
	for _, action := range plan {
		switch action {
		case hotReloadActionOutbounds:
			if err := applyHotReloadOutbounds(config); err != nil {
				return err
			}
		case hotReloadActionInbounds:
			if err := applyHotReloadInbounds(config); err != nil {
				return err
			}
		case hotReloadActionRouting:
			if err := applyHotReloadRules(config); err != nil {
				return err
			}
		case hotReloadActionSubscription:
			if err := applyHotReloadSubscription(); err != nil {
				return err
			}
		case hotReloadActionDNS:
			if err := applyHotReloadDNS(config); err != nil {
				return err
			}
		case hotReloadActionObservatory:
			if err := applyHotReloadObservatory(config); err != nil {
				return err
			}
		case hotReloadActionLog:
			if err := applyHotReloadLog(config); err != nil {
				return err
			}
		default:
			return errors.New("unknown hot reload action: " + string(action))
		}
	}
	return nil
}

func decideHotReloadMode(targets []string) string {
	expanded := expandHotReloadTargets(targets)
	if len(expanded) == 1 && expanded[0] == "routing" {
		return "rulesOnly"
	}
	return "dynamic"
}

func decodeHotReloadTargets(r *http.Request) ([]string, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, nil
	}
	req := hotReloadRequest{}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if invalid := invalidHotReloadTargets(req.Targets); len(invalid) > 0 {
		return nil, errors.New("unsupported hot reload target(s): " + strings.Join(invalid, ", "))
	}
	normalized := normalizeHotReloadTargets(req.Targets)
	if len(req.Targets) > 0 && len(normalized) == 0 {
		return nil, errors.New("no valid hot reload targets")
	}
	return normalized, nil
}

func normalizeHotReloadTargets(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, raw := range targets {
		target := strings.ToLower(strings.TrimSpace(raw))
		if target == "" {
			continue
		}
		if _, ok := hotReloadAllowedTargets[target]; !ok {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func invalidHotReloadTargets(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, raw := range targets {
		target := strings.ToLower(strings.TrimSpace(raw))
		if target == "" {
			continue
		}
		if _, ok := hotReloadAllowedTargets[target]; ok {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

func expandHotReloadTargets(targets []string) []string {
	if len(targets) == 0 {
		return []string{"routing"}
	}
	expanded := make([]string, 0, len(targets))
	for _, target := range targets {
		if target == "all" {
			expanded = append(expanded, "outbounds", "inbounds", "routing", "subscription", "main")
			continue
		}
		expanded = append(expanded, target)
	}
	seen := make(map[string]struct{}, len(expanded))
	out := make([]string, 0, len(expanded))
	for _, target := range expanded {
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

func applyHotReloadOutbounds(config *core.Config) error {
	inst := getRuntimeInstance()
	if inst == nil {
		return errors.New("running instance unavailable")
	}
	om, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok || om == nil {
		return errors.New("outbound manager unavailable")
	}
	ctx := context.Background()
	return applyHotReloadWithRollback(
		func() ([]*core.OutboundHandlerConfig, error) {
			return snapshotCurrentOutbounds(om, ctx)
		},
		func() ([]*core.OutboundHandlerConfig, error) {
			return normalizeOutboundReloadConfigs(config.Outbound)
		},
		func(configs []*core.OutboundHandlerConfig) error {
			return replaceOutbounds(inst, om, ctx, configs)
		},
		"outbound",
	)
}

func applyHotReloadInbounds(config *core.Config) error {
	inst := getRuntimeInstance()
	if inst == nil {
		return errors.New("running instance unavailable")
	}
	im, ok := inst.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok || im == nil {
		return errors.New("inbound manager unavailable")
	}
	ctx := context.Background()
	return applyHotReloadWithRollback(
		func() ([]*core.InboundHandlerConfig, error) {
			return snapshotCurrentInbounds(im, ctx)
		},
		func() ([]*core.InboundHandlerConfig, error) {
			return normalizeInboundReloadConfigs(config.Inbound)
		},
		func(configs []*core.InboundHandlerConfig) error {
			return replaceInbounds(inst, im, ctx, configs)
		},
		"inbound",
	)
}

func applyHotReloadWithRollback[T any](
	snapshot func() ([]T, error),
	normalize func() ([]T, error),
	replace func([]T) error,
	kind string,
) error {
	previous, err := snapshot()
	if err != nil {
		return err
	}
	next, err := normalize()
	if err != nil {
		return err
	}
	if err := replace(next); err != nil {
		if rollbackErr := replace(previous); rollbackErr != nil {
			return errors.Join(err, errors.New(kind+" rollback failed: "+rollbackErr.Error()))
		}
		return err
	}
	return nil
}

func cloneTypedMessage(msg *cserial.TypedMessage) *cserial.TypedMessage {
	if msg == nil {
		return nil
	}
	cloned, ok := proto.Clone(msg).(*cserial.TypedMessage)
	if !ok {
		return nil
	}
	return cloned
}

func normalizeTaggedReloadConfigs[T any](
	configs []T,
	isNil func(T) bool,
	clone func(T) (T, bool),
	tagOf func(T) string,
	setTag func(T, string),
	kind string,
) ([]T, error) {
	seen := make(map[string]struct{}, len(configs))
	out := make([]T, 0, len(configs))
	for _, cfg := range configs {
		if isNil(cfg) {
			continue
		}
		cloned, ok := clone(cfg)
		if !ok || isNil(cloned) {
			return nil, errors.New("invalid " + kind + " config type")
		}
		tag := strings.TrimSpace(tagOf(cloned))
		if tag == "" {
			return nil, errors.New("dynamic hot reload does not support untagged " + kind + "s")
		}
		if _, exists := seen[tag]; exists {
			return nil, errors.New("duplicate " + kind + " tag: " + tag)
		}
		seen[tag] = struct{}{}
		setTag(cloned, tag)
		out = append(out, cloned)
	}
	return out, nil
}

func normalizeOutboundReloadConfigs(configs []*core.OutboundHandlerConfig) ([]*core.OutboundHandlerConfig, error) {
	return normalizeTaggedReloadConfigs(
		configs,
		func(cfg *core.OutboundHandlerConfig) bool {
			return cfg == nil
		},
		func(cfg *core.OutboundHandlerConfig) (*core.OutboundHandlerConfig, bool) {
			cloned, ok := proto.Clone(cfg).(*core.OutboundHandlerConfig)
			return cloned, ok
		},
		func(cfg *core.OutboundHandlerConfig) string {
			return cfg.Tag
		},
		func(cfg *core.OutboundHandlerConfig, tag string) {
			cfg.Tag = tag
		},
		"outbound",
	)
}

func normalizeInboundReloadConfigs(configs []*core.InboundHandlerConfig) ([]*core.InboundHandlerConfig, error) {
	return normalizeTaggedReloadConfigs(
		configs,
		func(cfg *core.InboundHandlerConfig) bool {
			return cfg == nil
		},
		func(cfg *core.InboundHandlerConfig) (*core.InboundHandlerConfig, bool) {
			cloned, ok := proto.Clone(cfg).(*core.InboundHandlerConfig)
			return cloned, ok
		},
		func(cfg *core.InboundHandlerConfig) string {
			return cfg.Tag
		},
		func(cfg *core.InboundHandlerConfig, tag string) {
			cfg.Tag = tag
		},
		"inbound",
	)
}

func snapshotTaggedHandlers[T any, C any](
	handlers []T,
	isNil func(T) bool,
	tagOf func(T) string,
	buildConfig func(tag string, handler T) C,
	kind string,
) ([]C, error) {
	seen := make(map[string]struct{}, len(handlers))
	out := make([]C, 0, len(handlers))
	for _, handler := range handlers {
		if isNil(handler) {
			continue
		}
		tag := strings.TrimSpace(tagOf(handler))
		if tag == "" {
			return nil, errors.New("dynamic hot reload does not support untagged " + kind + "s")
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, buildConfig(tag, handler))
	}
	return out, nil
}

func snapshotCurrentOutbounds(om outbound.Manager, ctx context.Context) ([]*core.OutboundHandlerConfig, error) {
	return snapshotTaggedHandlers(
		om.ListHandlers(ctx),
		func(handler outbound.Handler) bool {
			return handler == nil
		},
		func(handler outbound.Handler) string {
			return handler.Tag()
		},
		func(tag string, handler outbound.Handler) *core.OutboundHandlerConfig {
			return &core.OutboundHandlerConfig{
				Tag:            tag,
				SenderSettings: cloneTypedMessage(handler.SenderSettings()),
				ProxySettings:  cloneTypedMessage(handler.ProxySettings()),
			}
		},
		"outbound",
	)
}

func snapshotCurrentInbounds(im inbound.Manager, ctx context.Context) ([]*core.InboundHandlerConfig, error) {
	return snapshotTaggedHandlers(
		im.ListHandlers(ctx),
		func(handler inbound.Handler) bool {
			return handler == nil
		},
		func(handler inbound.Handler) string {
			return handler.Tag()
		},
		func(tag string, handler inbound.Handler) *core.InboundHandlerConfig {
			return &core.InboundHandlerConfig{
				Tag:              tag,
				ReceiverSettings: cloneTypedMessage(handler.ReceiverSettings()),
				ProxySettings:    cloneTypedMessage(handler.ProxySettings()),
			}
		},
		"inbound",
	)
}

func collectUniqueTags[T any](
	handlers []T,
	isNil func(T) bool,
	tagOf func(T) string,
	kind string,
) ([]string, error) {
	seen := make(map[string]struct{}, len(handlers))
	tags := make([]string, 0, len(handlers))
	for _, handler := range handlers {
		if isNil(handler) {
			continue
		}
		tag := strings.TrimSpace(tagOf(handler))
		if tag == "" {
			return nil, errors.New("dynamic hot reload does not support untagged " + kind + "s")
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	return tags, nil
}

func removeAllTaggedOutbounds(om outbound.Manager, ctx context.Context) error {
	tags, err := collectUniqueTags(
		om.ListHandlers(ctx),
		func(handler outbound.Handler) bool {
			return handler == nil
		},
		func(handler outbound.Handler) string {
			return handler.Tag()
		},
		"outbound",
	)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		if existing := om.GetHandler(tag); existing != nil {
			_ = existing.Close()
		}
		if err := om.RemoveHandler(ctx, tag); err != nil {
			return err
		}
	}
	return nil
}

func removeAllTaggedInbounds(im inbound.Manager, ctx context.Context) error {
	tags, err := collectUniqueTags(
		im.ListHandlers(ctx),
		func(handler inbound.Handler) bool {
			return handler == nil
		},
		func(handler inbound.Handler) string {
			return handler.Tag()
		},
		"inbound",
	)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		if err := im.RemoveHandler(ctx, tag); err != nil {
			return err
		}
	}
	return nil
}

func replaceTaggedHandlers[T any](
	configs []T,
	isNil func(T) bool,
	removeAll func() error,
	addHandler func(T) error,
) error {
	if err := removeAll(); err != nil {
		return err
	}
	for _, cfg := range configs {
		if isNil(cfg) {
			continue
		}
		if err := addHandler(cfg); err != nil {
			return err
		}
	}
	return nil
}

func replaceOutbounds(inst *core.Instance, om outbound.Manager, ctx context.Context, configs []*core.OutboundHandlerConfig) error {
	return replaceTaggedHandlers(
		configs,
		func(cfg *core.OutboundHandlerConfig) bool {
			return cfg == nil
		},
		func() error {
			return removeAllTaggedOutbounds(om, ctx)
		},
		func(cfg *core.OutboundHandlerConfig) error {
			return core.AddOutboundHandler(inst, cfg)
		},
	)
}

func replaceInbounds(inst *core.Instance, im inbound.Manager, ctx context.Context, configs []*core.InboundHandlerConfig) error {
	return replaceTaggedHandlers(
		configs,
		func(cfg *core.InboundHandlerConfig) bool {
			return cfg == nil
		},
		func() error {
			return removeAllTaggedInbounds(im, ctx)
		},
		func(cfg *core.InboundHandlerConfig) error {
			return core.AddInboundHandler(inst, cfg)
		},
	)
}

func applyHotReloadSubscription() error {
	inst := getRuntimeInstance()
	if inst == nil {
		return errors.New("running instance unavailable")
	}
	return inst.ReloadSubscriptionRuntime()
}

func applyHotReloadDNS(config *core.Config) error {
	inst := getRuntimeInstance()
	if inst == nil {
		return errors.New("running instance unavailable")
	}
	msg := findAppTypedMessage(config, cserial.GetMessageType(&dnsapp.Config{}))
	if msg == nil {
		return nil
	}
	raw, err := msg.GetInstance()
	if err != nil {
		return err
	}
	nextCfg, ok := raw.(*dnsapp.Config)
	if !ok {
		return errors.New("invalid dns config type")
	}
	client, ok := inst.GetFeature(dns.ClientType()).(interface{ Reload(*dnsapp.Config) error })
	if !ok || client == nil {
		return errors.New("dns client does not support dynamic reload")
	}
	if err := client.Reload(nextCfg); err != nil {
		return err
	}
	return initSystemDialerFromInstance(inst)
}

func applyHotReloadObservatory(config *core.Config) error {
	inst := getRuntimeInstance()
	if inst == nil {
		return errors.New("running instance unavailable")
	}
	msg := findAppTypedMessage(config, cserial.GetMessageType(&observatoryapp.Config{}))
	if msg == nil {
		return nil
	}
	raw, err := msg.GetInstance()
	if err != nil {
		return err
	}
	nextCfg, ok := raw.(*observatoryapp.Config)
	if !ok {
		return errors.New("invalid observatory config type")
	}
	obs, ok := inst.GetFeature(extension.ObservatoryType()).(interface {
		Reload(*observatoryapp.Config) error
	})
	if !ok || obs == nil {
		return errors.New("observatory does not support dynamic reload")
	}
	if err := obs.Reload(nextCfg); err != nil {
		return err
	}
	_, router, _ := getNodesDependencies()
	if router != nil {
		restoreUIStateOverrides(router)
	}
	return nil
}

func applyHotReloadLog(config *core.Config) error {
	inst := getRuntimeInstance()
	if inst == nil {
		return errors.New("running instance unavailable")
	}
	msg := findAppTypedMessage(config, cserial.GetMessageType(&applog.Config{}))
	if msg == nil {
		return nil
	}
	raw, err := msg.GetInstance()
	if err != nil {
		return err
	}
	nextCfg, ok := raw.(*applog.Config)
	if !ok {
		return errors.New("invalid log config type")
	}
	logger, ok := inst.GetFeature((*applog.Instance)(nil)).(interface{ Reload(*applog.Config) error })
	if !ok || logger == nil {
		return errors.New("logger does not support dynamic reload")
	}
	return logger.Reload(nextCfg)
}

func findAppTypedMessage(config *core.Config, typeName string) *cserial.TypedMessage {
	if config == nil || typeName == "" {
		return nil
	}
	for _, app := range config.App {
		if app == nil {
			continue
		}
		if app.Type == typeName {
			return app
		}
	}
	return nil
}

func applyHotReloadRules(config *core.Config) error {
	if config == nil {
		return errors.New("config is nil")
	}

	_, router, _ := getNodesDependencies()
	if router == nil {
		return errors.New("router unavailable")
	}

	msg, err := extractRouterConfigMessage(config)
	if err != nil {
		return err
	}
	if err := router.AddRule(msg, false); err != nil {
		return err
	}

	// Keep manual balancer override behavior stable after rebuilding rules/balancers.
	restoreUIStateOverrides(router)
	return nil
}

func extractRouterConfigMessage(config *core.Config) (*cserial.TypedMessage, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}

	routerType := cserial.GetMessageType(&routercfg.Config{})
	for _, app := range config.App {
		if app == nil {
			continue
		}
		if app.Type == routerType {
			return app, nil
		}
	}

	// No router section means clearing dynamic rules/balancers.
	return cserial.ToTypedMessage(&routercfg.Config{}), nil
}

func restartHandler(w http.ResponseWriter, r *http.Request) {
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

	if !beginRestart() {
		writeJSONError(w, http.StatusConflict, "restart in progress", "a restart is already running")
		return
	}

	id := time.Now().UnixMilli()
	setRestartTaskStatus(&restartTaskStatus{
		ID:         id,
		Mode:       "restart",
		InProgress: true,
		Ok:         true, // avoid rendering as "danger" while running
	})

	config, files, format, err := buildRestartConfig()
	if err != nil {
		endRestart()
		finishRestartTaskStatus(id, "restart", err)
		writeJSONError(w, http.StatusBadRequest, "restart is not configured", err.Error())
		return
	}
	if err := validateRestartConfig(config); err != nil {
		endRestart()
		finishRestartTaskStatus(id, "restart", err)
		writeJSONError(w, http.StatusBadRequest, "config validation failed", err.Error())
		return
	}

	writeJSON(w, map[string]interface{}{
		"ok":        true,
		"id":        id,
		"mode":      "inProcess",
		"scheduled": true,
		"files":     files,
		"format":    format,
	})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	go func(cfg *core.Config) {
		defer endRestart()
		if err := restartInProcess(cfg); err != nil {
			xerrors.LogErrorInner(context.Background(), err, "failed to restart in process")
			finishRestartTaskStatus(id, "restart", err)
			return
		}
		finishRestartTaskStatus(id, "restart", nil)
	}(config)
}

func beginRestart() bool {
	restartMu.Lock()
	defer restartMu.Unlock()
	if restartBusy {
		return false
	}
	restartBusy = true
	return true
}

func endRestart() {
	restartMu.Lock()
	restartBusy = false
	restartMu.Unlock()
}

func buildRestartConfig() (*core.Config, []string, string, error) {
	files, format, err := inferRestartFiles()
	if err != nil {
		return nil, nil, "", err
	}
	if len(files) == 0 {
		return nil, nil, "", errors.New("config files are empty")
	}
	config, err := core.LoadConfig(format, cmdarg.Arg(files))
	if err != nil {
		return nil, files, format, err
	}
	return config, files, format, nil
}

type metricsGlobalsSnapshot struct {
	RuntimeInstance   *core.Instance
	MetricsAccessKey  string
	ConnManager       conntrack.Manager
	ExpvarStats       feature_stats.Manager
	ExpvarObservatory extension.Observatory
}

func snapshotMetricsGlobals() metricsGlobalsSnapshot {
	// runtimeInstance has its own lock.
	snap := metricsGlobalsSnapshot{
		RuntimeInstance:   getRuntimeInstance(),
		MetricsAccessKey:  getMetricsAccessKey(),
		ExpvarStats:       getExpvarStatsManager(),
		ExpvarObservatory: getExpvarObservatory(),
	}

	connMu.RLock()
	snap.ConnManager = connManager
	connMu.RUnlock()

	return snap
}

func restoreMetricsGlobals(snap metricsGlobalsSnapshot) {
	setRuntimeInstance(snap.RuntimeInstance)
	setMetricsAccessKey(snap.MetricsAccessKey)
	setConntrackManager(snap.ConnManager)
	setExpvarSources(snap.ExpvarStats, snap.ExpvarObservatory)
}

func validateRestartConfig(config *core.Config) error {
	if config == nil {
		return errors.New("config is nil")
	}

	prevDialer := internet.SnapshotSystemDialerState()
	prevMetrics := snapshotMetricsGlobals()

	inst, err := core.New(config)

	// Validation must not mutate the active runtime state.
	internet.RestoreSystemDialerState(prevDialer)
	restoreMetricsGlobals(prevMetrics)

	if inst != nil {
		_ = inst.Close()
	}
	return err
}

func buildNextInstanceForRestart(config *core.Config) (*core.Instance, error) {
	prevDialer := internet.SnapshotSystemDialerState()
	prevMetrics := snapshotMetricsGlobals()

	next, err := core.New(config)
	internet.RestoreSystemDialerState(prevDialer)
	if err != nil {
		// restartInProcess closes the current instance only after build succeeds. If build fails,
		// make sure global state (auth key, runtime instance pointers, expvar sources) stays intact.
		restoreMetricsGlobals(prevMetrics)
		return nil, err
	}
	return next, nil
}

func initSystemDialerFromInstance(inst *core.Instance) error {
	if inst == nil {
		return errors.New("instance is nil")
	}

	dc, ok := inst.GetFeature(dns.ClientType()).(dns.Client)
	if !ok {
		return errors.New("dns client unavailable")
	}
	om, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		return errors.New("outbound manager unavailable")
	}
	rt, ok := inst.GetFeature(routing.RouterType()).(routing.Router)
	if !ok {
		return errors.New("router unavailable")
	}
	internet.InitSystemDialer(dc, om, rt)
	return nil
}

func restartInProcess(config *core.Config) error {
	current := getRuntimeInstance()
	if current == nil {
		return errors.New("running instance unavailable")
	}

	next, err := buildNextInstanceForRestart(config)
	if err != nil {
		return err
	}

	if err := current.Close(); err != nil {
		xerrors.LogInfoInner(context.Background(), err, "failed to close current instance during restart")
	}
	if err := initSystemDialerFromInstance(next); err != nil {
		_ = next.Close()
		return err
	}
	if err := next.Start(); err != nil {
		_ = next.Close()
		return err
	}

	setRuntimeInstance(next)
	return nil
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
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

	tail := clampTailCount(r, 200)
	settings := getSettingsSnapshot()
	queryLevel, queryOK, queryProvided := parseLogLevelQuery(r)
	applyFilter := func(lines []string) []string {
		if queryProvided {
			return filterLogLinesByLevel(lines, queryLevel, queryOK)
		}
		level, ok := applog.MemoryLogLevelOverride()
		return filterLogLinesByLevel(lines, level, ok)
	}
	if strings.TrimSpace(settings.LogFile) == "" {
		lines := memoryTailLines(tail)
		lines = applyFilter(lines)
		writeJSON(w, map[string]interface{}{
			"lines":  lines,
			"path":   "memory",
			"source": "memory",
		})
		return
	}

	logPath := resolvePathFromCwd(settings.LogFile, resolveStartupCwd())
	lines, err := readLastLines(logPath, tail)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to read log file", err.Error())
		return
	}
	lines = applyFilter(lines)
	writeJSON(w, map[string]interface{}{
		"lines":  lines,
		"path":   logPath,
		"source": "file",
	})
}

type logsConfigPayload struct {
	Level *string `json:"level,omitempty"`
	Debug *bool   `json:"debug,omitempty"`
}

func logsConfigHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", metricsCORSAllowHeaders)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.Method {
	case http.MethodGet:
		levelName := "default"
		if override, ok := applog.MemoryLogLevelOverride(); ok {
			levelName = logLevelName(override)
		}
		writeJSON(w, map[string]interface{}{
			"level": levelName,
			"debug": levelName == "debug",
		})
	case http.MethodPost:
		var payload logsConfigPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		if payload.Level != nil {
			level, apply, ok := parseLogLevel(*payload.Level)
			if !ok {
				http.Error(w, "invalid log level", http.StatusBadRequest)
				return
			}
			if apply {
				applog.SetMemoryLogLevel(level)
			} else {
				applog.ClearMemoryLogLevelOverride()
			}
		} else if payload.Debug != nil {
			if *payload.Debug {
				applog.SetMemoryLogLevel(clog.Severity_Debug)
			} else {
				applog.ClearMemoryLogLevelOverride()
			}
		} else {
			http.Error(w, "missing level field", http.StatusBadRequest)
			return
		}
		levelName := "default"
		if override, ok := applog.MemoryLogLevelOverride(); ok {
			levelName = logLevelName(override)
		}
		writeJSON(w, map[string]interface{}{
			"ok":    true,
			"level": levelName,
			"debug": levelName == "debug",
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func parseLogLevel(value string) (clog.Severity, bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default":
		return 0, false, true
	case "error":
		return clog.Severity_Error, true, true
	case "warn", "warning":
		return clog.Severity_Warning, true, true
	case "info":
		return clog.Severity_Info, true, true
	case "debug":
		return clog.Severity_Debug, true, true
	default:
		return 0, false, false
	}
}

func logLevelName(level clog.Severity) string {
	switch level {
	case clog.Severity_Error:
		return "error"
	case clog.Severity_Warning:
		return "warning"
	case clog.Severity_Info:
		return "info"
	case clog.Severity_Debug:
		return "debug"
	default:
		return "default"
	}
}

func parseLogLevelQuery(r *http.Request) (clog.Severity, bool, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("level"))
	if raw == "" {
		return 0, false, false
	}
	level, apply, ok := parseLogLevel(raw)
	if !ok {
		return 0, false, false
	}
	if !apply {
		return 0, false, true
	}
	return level, true, true
}

func logLineSeverity(line string) (clog.Severity, bool) {
	if line == "" {
		return 0, false
	}
	if match := logLevelBracketRe.FindStringSubmatch(line); len(match) > 1 {
		return parseLogLineLevel(match[1])
	}
	if match := logLevelTokenRe.FindStringSubmatch(line); len(match) > 1 {
		return parseLogLineLevel(match[1])
	}
	return 0, false
}

func parseLogLineLevel(raw string) (clog.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "error", "fatal", "panic":
		return clog.Severity_Error, true
	case "warn", "warning":
		return clog.Severity_Warning, true
	case "info":
		return clog.Severity_Info, true
	case "debug", "trace":
		return clog.Severity_Debug, true
	default:
		return 0, false
	}
}

func filterLogLinesByLevel(lines []string, level clog.Severity, ok bool) []string {
	if !ok || len(lines) == 0 {
		return lines
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		if sev, matched := logLineSeverity(line); matched {
			if sev <= level {
				out = append(out, line)
			}
			continue
		}
		if level >= clog.Severity_Info {
			out = append(out, line)
		}
	}
	return out
}

func logsStreamHandler(w http.ResponseWriter, r *http.Request) {
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
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	tail := clampTailCount(r, 200)
	queryLevel, queryOK, queryProvided := parseLogLevelQuery(r)
	getFilter := func() (clog.Severity, bool) {
		if queryProvided {
			return queryLevel, queryOK
		}
		return applog.MemoryLogLevelOverride()
	}
	settings := getSettingsSnapshot()
	if strings.TrimSpace(settings.LogFile) == "" {
		lastID := int64(0)
		entries := applog.MemoryTail(tail)
		lines, newestID := memoryLinesFromEntries(entries)
		if len(lines) > 0 {
			lastID = newestID
		}
		level, ok := getFilter()
		lines = filterLogLinesByLevel(lines, level, ok)
		sendSSE(w, map[string]interface{}{
			"type":  "init",
			"lines": lines,
		})
		flusher.Flush()

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				entries := applog.MemorySince(lastID)
				if len(entries) == 0 {
					continue
				}
				lines, newest := memoryLinesFromEntries(entries)
				if len(lines) == 0 {
					continue
				}
				lastID = newest
				level, ok := getFilter()
				lines = filterLogLinesByLevel(lines, level, ok)
				if len(lines) == 0 {
					continue
				}
				sendSSE(w, map[string]interface{}{
					"type":  "append",
					"lines": lines,
				})
				flusher.Flush()
			}
		}
	}

	logPath := resolvePathFromCwd(settings.LogFile, resolveStartupCwd())
	if lines, err := readLastLines(logPath, tail); err == nil {
		level, ok := getFilter()
		lines = filterLogLinesByLevel(lines, level, ok)
		sendSSE(w, map[string]interface{}{
			"type":  "init",
			"lines": lines,
		})
	} else {
		sendSSE(w, map[string]interface{}{
			"type":    "error",
			"message": err.Error(),
		})
	}
	flusher.Flush()

	follower := newLogFollower(logPath)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			lines, err := follower.poll()
			if err != nil || len(lines) == 0 {
				continue
			}
			level, ok := getFilter()
			lines = filterLogLinesByLevel(lines, level, ok)
			if len(lines) == 0 {
				continue
			}
			sendSSE(w, map[string]interface{}{
				"type":  "append",
				"lines": lines,
			})
			flusher.Flush()
		}
	}
}

func memoryTailLines(limit int) []string {
	entries := applog.MemoryTail(limit)
	lines, _ := memoryLinesFromEntries(entries)
	return lines
}

func memoryLinesFromEntries(entries []applog.MemoryEntry) ([]string, int64) {
	if len(entries) == 0 {
		return nil, 0
	}
	lines := make([]string, 0, len(entries))
	var lastID int64
	for _, entry := range entries {
		if entry.Line == "" {
			continue
		}
		lines = append(lines, entry.Line)
		if entry.ID > lastID {
			lastID = entry.ID
		}
	}
	return lines, lastID
}

func clampTailCount(r *http.Request, fallback int) int {
	raw := r.URL.Query().Get("tail")
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	if n > 2000 {
		return 2000
	}
	return n
}

func readLastLines(path string, maxLines int) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := splitLines(string(data))
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, nil
}

func splitLines(text string) []string {
	if text == "" {
		return []string{}
	}
	parts := strings.Split(text, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	for i, line := range parts {
		parts[i] = strings.TrimSuffix(line, "\r")
	}
	return parts
}

type logFollower struct {
	path      string
	position  int64
	remainder string
}

func newLogFollower(path string) *logFollower {
	position := int64(0)
	if info, err := os.Stat(path); err == nil {
		position = info.Size()
	}
	return &logFollower{path: path, position: position}
}

func (f *logFollower) poll() ([]string, error) {
	info, err := os.Stat(f.path)
	if err != nil {
		return nil, err
	}
	if info.Size() < f.position {
		f.position = info.Size()
		f.remainder = ""
		return nil, nil
	}
	if info.Size() == f.position {
		return nil, nil
	}
	size := info.Size() - f.position
	file, err := os.Open(f.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	buf := make([]byte, size)
	_, err = file.ReadAt(buf, f.position)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	f.position = info.Size()
	text := f.remainder + string(buf)
	parts := splitLines(text)
	if len(parts) == 0 {
		return nil, nil
	}
	if strings.HasSuffix(text, "\n") {
		f.remainder = ""
		return parts, nil
	}
	f.remainder = parts[len(parts)-1]
	return parts[:len(parts)-1], nil
}

func inferRestartFiles() ([]string, string, error) {
	info, ok := core.GetStartupInfo()
	cwd := resolveStartupCwd()
	format := "auto"
	if ok {
		if info.Cwd != "" {
			cwd = info.Cwd
		}
		if info.ConfigFormat != "" {
			format = normalizeConfigFormat(info.ConfigFormat)
		}
		if files := resolveStartupConfigFiles(info.ConfigFiles, cwd); len(files) > 0 {
			return files, format, nil
		}
		if info.ConfDir != "" {
			confDir := resolvePathFromCwd(info.ConfDir, cwd)
			if files := listConfigFilesInDir(confDir, info.ConfigFormat); len(files) > 0 {
				return files, format, nil
			}
		}
		if len(info.Argv) > 0 {
			parsed := parseRunArgsForConfig(info.Argv)
			if parsed.format != "" && parsed.format != "auto" && (format == "" || format == "auto") {
				format = normalizeConfigFormat(parsed.format)
			}
			if files := resolveStartupConfigFiles(parsed.configFiles, cwd); len(files) > 0 {
				return files, format, nil
			}
			if parsed.confDir != "" {
				confDir := resolvePathFromCwd(parsed.confDir, cwd)
				if files := listConfigFilesInDir(confDir, parsed.format); len(files) > 0 {
					return files, format, nil
				}
			}
		}
	}
	if files := pickDefaultConfigFromCwd(cwd); len(files) > 0 {
		return files, format, nil
	}
	return nil, format, errors.New("startup config files not found")
}

type parsedRunArgs struct {
	configFiles []string
	confDir     string
	format      string
}

func parseRunArgsForConfig(argv []string) parsedRunArgs {
	out := parsedRunArgs{format: "auto"}
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "" || arg == "run" {
			continue
		}
		if value, consumed := readFlagValue(argv, i, []string{"config", "c"}); value != "" {
			out.configFiles = append(out.configFiles, value)
			i += consumed
			continue
		}
		if value, consumed := readFlagValue(argv, i, []string{"confdir"}); value != "" {
			out.confDir = value
			i += consumed
			continue
		}
		if value, consumed := readFlagValue(argv, i, []string{"format"}); value != "" {
			out.format = value
			i += consumed
			continue
		}
	}
	return out
}

func readFlagValue(argv []string, idx int, names []string) (string, int) {
	arg := argv[idx]
	if arg == "" {
		return "", 0
	}
	for _, name := range names {
		short := "-" + name
		long := "--" + name
		if arg == short || arg == long {
			if idx+1 < len(argv) {
				return argv[idx+1], 1
			}
			return "", 1
		}
		shortEq := short + "="
		if strings.HasPrefix(arg, shortEq) {
			return arg[len(shortEq):], 0
		}
		longEq := long + "="
		if strings.HasPrefix(arg, longEq) {
			return arg[len(longEq):], 0
		}
	}
	return "", 0
}

func normalizeConfigFormat(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "json":
		return "json"
	case "toml":
		return "toml"
	case "yaml", "yml":
		return "yaml"
	default:
		return "auto"
	}
}

func listConfigFilesInDir(dirPath string, format string) []string {
	if dirPath == "" {
		return nil
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil
	}
	format = normalizeConfigFormat(format)
	var exts []string
	switch format {
	case "json":
		exts = []string{".json", ".jsonc"}
	case "toml":
		exts = []string{".toml"}
	case "yaml":
		exts = []string{".yaml", ".yml"}
	default:
		exts = []string{".json", ".jsonc", ".toml", ".yaml", ".yml"}
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if !matchesExtension(ext, exts) {
			continue
		}
		out = append(out, filepath.Join(dirPath, entry.Name()))
	}
	return out
}

func matchesExtension(ext string, allowed []string) bool {
	for _, item := range allowed {
		if ext == item {
			return true
		}
	}
	return false
}

func resolveStartupConfigFiles(files []string, cwd string) []string {
	if len(files) == 0 {
		return nil
	}
	out := make([]string, 0, len(files))
	seen := map[string]struct{}{}
	for _, raw := range files {
		path := resolvePathFromCwd(raw, cwd)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func pickDefaultConfigFromCwd(cwd string) []string {
	suffixes := []string{".json", ".jsonc", ".toml", ".yaml", ".yml"}
	for _, suffix := range suffixes {
		path := filepath.Join(cwd, "config"+suffix)
		if fileExists(path) {
			return []string{path}
		}
	}
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
