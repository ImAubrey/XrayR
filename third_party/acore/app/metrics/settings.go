package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ImAubrey/acore/core"
)

type Settings struct {
	AcoreGrpc      string   `json:"acoreGrpc,omitempty"`
	AcoreMetrics   string   `json:"acoreMetrics,omitempty"`
	LogFile        string   `json:"logFile,omitempty"`
	RestartCommand string   `json:"restartCommand,omitempty"`
	BalancerTags   []string `json:"balancerTags,omitempty"`
	ProbeMode      string   `json:"probeMode,omitempty"`
}

type settingsStore struct {
	mu       sync.RWMutex
	path     string
	settings Settings
	raw      map[string]interface{}
}

var settingsOnce sync.Once
var settingsState settingsStore
var settingsRoutesOnce sync.Once

func registerSettingsRoutes() {
	settingsRoutesOnce.Do(func() {
		http.HandleFunc("/settings", settingsHandler)
	})
}

type startupInfoStatus struct {
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", metricsCORSAllowHeaders)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.Method {
	case http.MethodGet:
		settings := reloadSettingsSnapshot()
		resp := map[string]interface{}{
			"settings":    settings,
			"path":        getSettingsPath(),
			"startupInfo": getStartupInfoStatus(),
		}
		writeJSON(w, resp)
	case http.MethodPost:
		var raw map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		next, err := updateSettings(raw)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to persist settings", err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{
			"ok":       true,
			"settings": next,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func ensureSettingsLoaded() {
	settingsOnce.Do(func() {
		settingsState.path = resolveSettingsPath()
		settingsState.settings, settingsState.raw, _ = loadSettingsFromDisk(settingsState.path)
		if settingsState.raw == nil {
			settingsState.raw = map[string]interface{}{}
		}
	})
}

func getSettingsPath() string {
	ensureSettingsLoaded()
	settingsState.mu.RLock()
	defer settingsState.mu.RUnlock()
	return settingsState.path
}

func getSettingsSnapshot() Settings {
	ensureSettingsLoaded()
	settingsState.mu.RLock()
	defer settingsState.mu.RUnlock()
	return cloneSettings(settingsState.settings)
}

func reloadSettingsSnapshot() Settings {
	ensureSettingsLoaded()
	next, raw, err := loadSettingsFromDisk(settingsState.path)
	settingsState.mu.Lock()
	if err == nil {
		settingsState.settings = next
		settingsState.raw = raw
	}
	snapshot := cloneSettings(settingsState.settings)
	settingsState.mu.Unlock()
	return snapshot
}

func updateSettings(raw map[string]interface{}) (Settings, error) {
	normalized := normalizeSettingsMap(raw)
	return updateSettingsRaw(func(payload map[string]interface{}) error {
		current := applySettingsMap(defaultSettings(), normalizeSettingsMap(payload))
		next := applySettingsMap(current, normalized)
		applySettingsToRaw(payload, next)
		return nil
	})
}

func cloneSettings(value Settings) Settings {
	out := value
	if value.BalancerTags != nil {
		out.BalancerTags = append([]string{}, value.BalancerTags...)
	}
	return out
}

func loadSettingsFromDisk(path string) (Settings, map[string]interface{}, error) {
	base := defaultSettings()
	if path == "" {
		return base, map[string]interface{}{}, errors.New("settings path is empty")
	}
	raw, err := loadSettingsRaw(path)
	if err != nil {
		return base, raw, err
	}
	normalized := normalizeSettingsMap(raw)
	return applySettingsMap(base, normalized), raw, nil
}

func loadSettingsRaw(path string) (map[string]interface{}, error) {
	if path == "" {
		return map[string]interface{}{}, errors.New("settings path is empty")
	}
	raw, _, found, err := readObjectFile(path)
	if err != nil {
		return map[string]interface{}{}, err
	}
	if found {
		return raw, nil
	}

	// Backward compatibility: when switching to YAML mode, reuse legacy acore.ui.json if present.
	if strings.EqualFold(filepath.Base(path), "acore.ui.yaml") || strings.EqualFold(filepath.Base(path), "acore.ui.yml") {
		legacy := filepath.Join(filepath.Dir(path), "acore.ui.json")
		legacyRaw, _, legacyFound, legacyErr := readObjectFile(legacy)
		if legacyErr == nil && legacyFound {
			return legacyRaw, nil
		}
	}
	return raw, nil
}

func persistSettingsRaw(path string, raw map[string]interface{}) error {
	if path == "" {
		return errors.New("settings path is empty")
	}
	if raw == nil {
		raw = map[string]interface{}{}
	}
	return writeObjectFile(path, raw)
}

func cloneJSONValue(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		return cloneJSONMap(v)
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = cloneJSONValue(item)
		}
		return out
	default:
		return v
	}
}

func cloneJSONMap(value map[string]interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(value))
	for key, item := range value {
		out[key] = cloneJSONValue(item)
	}
	return out
}

func updateSettingsRaw(mutator func(map[string]interface{}) error) (Settings, error) {
	ensureSettingsLoaded()
	settingsState.mu.Lock()
	defer settingsState.mu.Unlock()

	payload := cloneJSONMap(settingsState.raw)
	if payload == nil {
		payload = map[string]interface{}{}
	}
	if err := mutator(payload); err != nil {
		return cloneSettings(settingsState.settings), err
	}
	if err := persistSettingsRaw(settingsState.path, payload); err != nil {
		return cloneSettings(settingsState.settings), err
	}
	settingsState.raw = payload
	settingsState.settings = applySettingsMap(defaultSettings(), normalizeSettingsMap(payload))
	return cloneSettings(settingsState.settings), nil
}

func getSettingsRawSnapshot() map[string]interface{} {
	ensureSettingsLoaded()
	settingsState.mu.RLock()
	defer settingsState.mu.RUnlock()
	return cloneJSONMap(settingsState.raw)
}

func applySettingsToRaw(raw map[string]interface{}, settings Settings) {
	if raw == nil {
		return
	}
	for key := range raw {
		if isSettingsKey(key) {
			delete(raw, key)
		}
	}
	if settings.AcoreGrpc != "" {
		raw["acoreGrpc"] = settings.AcoreGrpc
	}
	if settings.AcoreMetrics != "" {
		raw["acoreMetrics"] = settings.AcoreMetrics
	}
	if settings.LogFile != "" {
		raw["logFile"] = settings.LogFile
	}
	if settings.RestartCommand != "" {
		raw["restartCommand"] = settings.RestartCommand
	}
	if settings.BalancerTags != nil && len(settings.BalancerTags) > 0 {
		raw["balancerTags"] = append([]string{}, settings.BalancerTags...)
	}
	if settings.ProbeMode != "" {
		raw["probeMode"] = settings.ProbeMode
	}
}

func isSettingsKey(key string) bool {
	switch normalizeKey(key) {
	case "acoregrpc",
		"acoremetrics",
		"logfile",
		"restartcommand",
		"balancertags",
		"probemode":
		return true
	default:
		return false
	}
}

func resolveSettingsPath() string {
	if raw := strings.TrimSpace(os.Getenv("SETTINGS_FILE")); raw != "" {
		return resolvePathFromCwd(raw, resolveStartupCwd())
	}
	if info, ok := core.GetStartupInfo(); ok {
		mainFile, mainFormat, mainExt := findMainConfigFile(info)
		uiFileName := defaultUIFilename(mainFormat, mainExt)
		if info.ConfDir != "" {
			confDir := resolvePathFromCwd(info.ConfDir, info.Cwd)
			if confDir != "" {
				return filepath.Join(confDir, uiFileName)
			}
		}
		if mainFile != "" {
			return filepath.Join(filepath.Dir(mainFile), uiFileName)
		}
		if len(info.ConfigFiles) > 0 {
			first := resolvePathFromCwd(info.ConfigFiles[0], info.Cwd)
			if first != "" {
				return filepath.Join(filepath.Dir(first), uiFileName)
			}
		}
		if info.Cwd != "" {
			return filepath.Join(info.Cwd, uiFileName)
		}
	}
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		return filepath.Join(cwd, "acore.ui.json")
	}
	return "acore.ui.json"
}

func findMainConfigFile(info core.StartupInfo) (string, string, string) {
	files := resolveStartupConfigFiles(info.ConfigFiles, info.Cwd)
	for _, file := range files {
		format := detectConfigFormat(file)
		if format != "json" && format != "jsonc" && format != "yaml" {
			continue
		}
		data, _, found, err := readObjectFile(file)
		if err != nil || !found || data == nil {
			continue
		}
		for key, value := range data {
			if strings.EqualFold(key, "log") && value != nil {
				return file, format, filepath.Ext(file)
			}
		}
	}
	if len(files) > 0 {
		file := files[0]
		return file, detectConfigFormat(file), filepath.Ext(file)
	}
	return "", "", ""
}

func defaultUIFilename(configFormat string, configExt string) string {
	if strings.EqualFold(configFormat, "yaml") {
		if strings.EqualFold(configExt, ".yml") {
			return "acore.ui.yml"
		}
		return "acore.ui.yaml"
	}
	return "acore.ui.json"
}

func resolveStartupCwd() string {
	if info, ok := core.GetStartupInfo(); ok && info.Cwd != "" {
		return info.Cwd
	}
	cwd, _ := os.Getwd()
	return cwd
}

func defaultSettings() Settings {
	return Settings{
		AcoreGrpc:      strings.TrimSpace(os.Getenv("ACORE_GRPC")),
		AcoreMetrics:   strings.TrimSpace(os.Getenv("ACORE_METRICS")),
		LogFile:        strings.TrimSpace(os.Getenv("LOG_FILE")),
		RestartCommand: strings.TrimSpace(os.Getenv("RESTART_COMMAND")),
		BalancerTags:   parseList(os.Getenv("BALANCER_TAGS")),
		ProbeMode:      normalizeProbeMode(os.Getenv("OBSERVATORY_PROBE_MODE")),
	}
}

func applySettingsMap(base Settings, raw map[string]interface{}) Settings {
	if value, ok := raw["acoregrpc"]; ok {
		base.AcoreGrpc = toString(value)
	}
	if value, ok := raw["acoremetrics"]; ok {
		base.AcoreMetrics = toString(value)
	}
	if value, ok := raw["logfile"]; ok {
		base.LogFile = toString(value)
	}
	if value, ok := raw["restartcommand"]; ok {
		base.RestartCommand = toString(value)
	}
	if value, ok := raw["balancertags"]; ok {
		base.BalancerTags = parseList(value)
	}
	if value, ok := raw["probemode"]; ok {
		base.ProbeMode = normalizeProbeMode(toString(value))
	}
	if base.ProbeMode == "" {
		base.ProbeMode = "tcp"
	}
	return base
}

func normalizeSettingsMap(raw map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(raw))
	for key, value := range raw {
		out[normalizeKey(key)] = value
	}
	return out
}

func normalizeKey(key string) string {
	k := strings.TrimSpace(strings.ToLower(key))
	k = strings.ReplaceAll(k, "_", "")
	k = strings.ReplaceAll(k, "-", "")
	return k
}

func toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func parseList(value interface{}) []string {
	var raw []string
	switch v := value.(type) {
	case nil:
		return nil
	case []string:
		raw = v
	case []interface{}:
		for _, item := range v {
			raw = append(raw, toString(item))
		}
	case string:
		raw = splitListString(v)
	default:
		raw = []string{toString(v)}
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitListString(value string) []string {
	if value == "" {
		return nil
	}
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
}

func normalizeProbeMode(value string) string {
	raw := strings.TrimSpace(strings.ToLower(value))
	if raw == "http" {
		return "http"
	}
	return "tcp"
}

func isWindowsNamedPipePath(value string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	raw := strings.ToLower(strings.ReplaceAll(value, "/", "\\"))
	return strings.HasPrefix(raw, `\\.\pipe\`) || strings.HasPrefix(raw, `\\?\pipe\`)
}

func resolvePathFromCwd(value string, cwd string) string {
	raw := strings.TrimSpace(value)
	if raw == "" || raw == "stdin:" || strings.HasPrefix(raw, "stdin:") {
		return ""
	}
	if isWindowsNamedPipePath(raw) {
		return raw
	}
	if filepath.IsAbs(raw) {
		return raw
	}
	base := strings.TrimSpace(cwd)
	if base == "" {
		base, _ = os.Getwd()
	}
	if base == "" {
		return raw
	}
	return filepath.Join(base, raw)
}

func ensureParentDir(filePath string) error {
	if isWindowsNamedPipePath(filePath) {
		return nil
	}
	dir := filepath.Dir(filePath)
	if dir == "" || dir == "." || dir == filePath {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func getStartupInfoStatus() startupInfoStatus {
	info, ok := core.GetStartupInfo()
	if !ok {
		return startupInfoStatus{Available: false, Detail: "startup info unavailable"}
	}
	if len(info.Argv) == 0 {
		return startupInfoStatus{Available: false, Detail: "startup argv missing"}
	}
	return startupInfoStatus{Available: true}
}

func writeJSONError(w http.ResponseWriter, status int, message, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  message,
		"detail": detail,
	})
}
