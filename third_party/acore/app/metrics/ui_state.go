package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	xerrors "github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/features/routing"
)

const (
	uiStateEnvVar       = "UI_STATE_FILE"
	uiStateVersion      = 1
	uiStateContainerKey = "controller"
	uiStateStateKey     = "uiState"
)

type uiStateResponse struct {
	Path   string                 `json:"path,omitempty"`
	Format string                 `json:"format,omitempty"`
	State  map[string]interface{} `json:"state"`
}

var uiStateRoutesOnce sync.Once
var uiStatePathOnce sync.Once
var uiStateMu sync.RWMutex
var uiStatePath string

func registerUIStateRoutes() {
	uiStateRoutesOnce.Do(func() {
		http.HandleFunc("/ui/state", uiStateHandler)
	})
}

func uiStateHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", metricsCORSAllowHeaders)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.Method {
	case http.MethodGet:
		handleUIStateRead(w)
	case http.MethodPost:
		handleUIStateWrite(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleUIStateRead(w http.ResponseWriter) {
	path := getUIStatePath()
	var (
		state  map[string]interface{}
		format string
		err    error
	)
	if useEmbeddedUIState() {
		state, format, err = readUIStateFromSettings(path)
	} else {
		state, format, err = readUIStateFile(path)
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to read ui state", err.Error())
		return
	}
	writeJSON(w, uiStateResponse{
		Path:   path,
		Format: format,
		State:  state,
	})
}

func handleUIStateWrite(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	patch, err := extractUIStatePatch(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	path := getUIStatePath()
	if useEmbeddedUIState() {
		next, format, err := writeUIStateToSettings(path, patch)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to write ui state", err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{
			"ok":     true,
			"path":   path,
			"format": format,
			"state":  next,
		})
		return
	}

	current, format, err := readUIStateFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to read ui state", err.Error())
		return
	}
	next := mergeUIState(current, patch)
	next["updatedAt"] = time.Now().UTC().Format(time.RFC3339)
	if _, ok := next["version"]; !ok {
		next["version"] = uiStateVersion
	}
	ensureUIStateSelection(next)
	if err := persistUIStateFile(path, next); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to write ui state", err.Error())
		return
	}

	writeJSON(w, map[string]interface{}{
		"ok":     true,
		"path":   path,
		"format": format,
		"state":  next,
	})
}

func getUIStatePath() string {
	uiStatePathOnce.Do(func() {
		uiStateMu.Lock()
		uiStatePath = resolveUIStatePath()
		uiStateMu.Unlock()
	})
	uiStateMu.RLock()
	defer uiStateMu.RUnlock()
	return uiStatePath
}

func resolveUIStatePath() string {
	if raw := strings.TrimSpace(os.Getenv(uiStateEnvVar)); raw != "" {
		return resolvePathFromCwd(raw, resolveStartupCwd())
	}
	if settingsPath := getSettingsPath(); settingsPath != "" {
		return settingsPath
	}
	if cwd := resolveStartupCwd(); cwd != "" {
		return filepath.Join(cwd, "acore.ui.json")
	}
	return "acore.ui.json"
}

func readUIStateFile(path string) (map[string]interface{}, string, error) {
	format := detectConfigFormat(path)
	if format != "json" && format != "jsonc" && format != "yaml" {
		return map[string]interface{}{}, format, errors.New("unsupported ui state format: " + format)
	}
	state, _, _, err := readObjectFile(path)
	if err != nil {
		return nil, format, err
	}
	return extractUIStatePayload(state), format, nil
}

func persistUIStateFile(path string, state map[string]interface{}) error {
	if path == "" {
		return errors.New("ui state path is empty")
	}
	if state == nil {
		state = map[string]interface{}{}
	}
	wrapper := map[string]interface{}{
		uiStateContainerKey: map[string]interface{}{
			uiStateStateKey: state,
		},
	}
	return writeObjectFile(path, wrapper)
}

func useEmbeddedUIState() bool {
	return strings.TrimSpace(os.Getenv(uiStateEnvVar)) == ""
}

func readUIStateFromSettings(path string) (map[string]interface{}, string, error) {
	raw, err := loadSettingsRaw(path)
	if err != nil {
		return map[string]interface{}{}, uiStoreFormat(path), err
	}
	state, _ := extractEmbeddedUIState(raw)
	return state, uiStoreFormat(path), nil
}

func writeUIStateToSettings(path string, patch map[string]interface{}) (map[string]interface{}, string, error) {
	var next map[string]interface{}
	_, err := updateSettingsRaw(func(payload map[string]interface{}) error {
		current, _ := extractEmbeddedUIState(payload)
		next = mergeUIState(current, patch)
		next["updatedAt"] = time.Now().UTC().Format(time.RFC3339)
		if _, ok := next["version"]; !ok {
			next["version"] = uiStateVersion
		}
		ensureUIStateSelection(next)

		controller := map[string]interface{}{}
		if existing, ok := payload[uiStateContainerKey].(map[string]interface{}); ok {
			controller = cloneJSONMap(existing)
		}
		controller[uiStateStateKey] = next
		payload[uiStateContainerKey] = controller
		delete(payload, uiStateStateKey)
		return nil
	})
	if err != nil {
		return map[string]interface{}{}, uiStoreFormat(path), err
	}
	return next, uiStoreFormat(path), nil
}

func uiStoreFormat(path string) string {
	format := detectConfigFormat(path)
	// Treat jsonc as json, since we always write canonical JSON.
	if format == "jsonc" {
		return "json"
	}
	return format
}

func extractEmbeddedUIState(raw map[string]interface{}) (map[string]interface{}, bool) {
	if raw == nil {
		return map[string]interface{}{}, false
	}
	if controller, ok := raw[uiStateContainerKey].(map[string]interface{}); ok {
		if state, ok := controller[uiStateStateKey].(map[string]interface{}); ok {
			return cloneJSONMap(state), true
		}
		if state, ok := controller["state"].(map[string]interface{}); ok {
			return cloneJSONMap(state), true
		}
	}
	if state, ok := raw[uiStateStateKey].(map[string]interface{}); ok {
		return cloneJSONMap(state), true
	}
	if state, ok := raw["state"].(map[string]interface{}); ok {
		return cloneJSONMap(state), true
	}
	return map[string]interface{}{}, false
}

func extractUIStatePayload(raw map[string]interface{}) map[string]interface{} {
	if raw == nil {
		return map[string]interface{}{}
	}
	if state, ok := extractEmbeddedUIState(raw); ok {
		return state
	}
	return cloneJSONMap(raw)
}

func extractUIStatePatch(raw map[string]interface{}) (map[string]interface{}, error) {
	if raw == nil {
		return nil, errors.New("ui state patch is empty")
	}
	if value, ok := raw["state"]; ok {
		if len(raw) == 1 {
			state, ok := value.(map[string]interface{})
			if !ok {
				return nil, errors.New("ui state must be an object")
			}
			return state, nil
		}
	}
	patch := map[string]interface{}{}
	for key, value := range raw {
		if key == "path" || key == "state" {
			continue
		}
		patch[key] = value
	}
	if len(patch) == 0 {
		return nil, errors.New("ui state patch is empty")
	}
	return patch, nil
}

func mergeUIState(base map[string]interface{}, patch map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for key, value := range base {
		out[key] = value
	}
	for key, value := range patch {
		if value == nil {
			delete(out, key)
			continue
		}
		patchMap, ok := value.(map[string]interface{})
		if ok {
			if baseMap, ok := out[key].(map[string]interface{}); ok {
				out[key] = mergeUIState(baseMap, patchMap)
				continue
			}
		}
		out[key] = value
	}
	return out
}

func updateUIStateOverride(balancerTag, target string) error {
	tag := strings.TrimSpace(balancerTag)
	if tag == "" {
		return nil
	}
	path := getUIStatePath()
	var (
		state map[string]interface{}
		err   error
	)
	if useEmbeddedUIState() {
		state, _, err = readUIStateFromSettings(path)
	} else {
		state, _, err = readUIStateFile(path)
	}
	if err != nil {
		return err
	}
	next, changed := applyOverrideToUIState(state, tag, strings.TrimSpace(target))
	if !changed {
		return nil
	}
	return persistUIStatePayload(path, next)
}

func applyOverrideToUIState(state map[string]interface{}, tag, target string) (map[string]interface{}, bool) {
	if state == nil {
		state = map[string]interface{}{}
	}
	nodes, _ := state["nodes"].(map[string]interface{})
	if nodes == nil {
		nodes = map[string]interface{}{}
	}
	selection, _ := nodes["selection"].(map[string]interface{})
	if selection == nil {
		selection = map[string]interface{}{}
	}
	locked := ensureLegacySelectionMap(nodes, "locked")
	locks := ensureLegacySelectionMap(nodes, "locks")
	selected := ensureLegacySelectionMap(nodes, "selected")

	entry, _ := selection[tag].(map[string]interface{})
	existingTarget := strings.TrimSpace(toString(entry["target"]))
	existingLast := strings.TrimSpace(toString(entry["last"]))
	legacyTarget := strings.TrimSpace(toString(locked[tag]))
	if legacyTarget == "" {
		legacyTarget = strings.TrimSpace(toString(locks[tag]))
	}
	if legacyTarget == "" {
		legacyTarget = strings.TrimSpace(toString(selected[tag]))
	}
	last := existingLast
	if last == "" {
		if existingTarget != "" {
			last = existingTarget
		} else if legacyTarget != "" {
			last = legacyTarget
		}
	}
	if target != "" {
		last = target
	}

	changed := false
	if target != "" {
		nextEntry := map[string]interface{}{
			"mode":   "manual",
			"target": target,
			"last":   last,
		}
		if !equalJSONMap(selection[tag], nextEntry) {
			selection[tag] = nextEntry
			changed = true
		}
		if locked[tag] != target {
			locked[tag] = target
			changed = true
		}
		if locks[tag] != target {
			locks[tag] = target
			changed = true
		}
		if selected[tag] != target {
			selected[tag] = target
			changed = true
		}
	} else {
		nextEntry := map[string]interface{}{}
		if last != "" {
			nextEntry = map[string]interface{}{
				"mode":   "auto",
				"target": "",
				"last":   last,
			}
		}
		if last == "" {
			if _, ok := selection[tag]; ok {
				delete(selection, tag)
				changed = true
			}
		} else if !equalJSONMap(selection[tag], nextEntry) {
			selection[tag] = nextEntry
			changed = true
		}
		if _, ok := locked[tag]; ok {
			delete(locked, tag)
			changed = true
		}
		if _, ok := locks[tag]; ok {
			delete(locks, tag)
			changed = true
		}
		if _, ok := selected[tag]; ok {
			delete(selected, tag)
			changed = true
		}
	}

	if len(selection) > 0 {
		nodes["selection"] = selection
	} else {
		delete(nodes, "selection")
	}
	assignLegacySelectionMap(nodes, "locked", locked)
	assignLegacySelectionMap(nodes, "locks", locks)
	assignLegacySelectionMap(nodes, "selected", selected)

	state["nodes"] = nodes
	if changed {
		state["updatedAt"] = time.Now().UTC().Format(time.RFC3339)
		if _, ok := state["version"]; !ok {
			state["version"] = uiStateVersion
		}
	}
	return state, changed
}

func restoreUIStateOverrides(router routing.Router) {
	if router == nil {
		return
	}
	overrider, ok := router.(routing.BalancerOverrider)
	if !ok {
		return
	}
	path := getUIStatePath()
	var (
		state map[string]interface{}
		err   error
	)
	if useEmbeddedUIState() {
		state, _, err = readUIStateFromSettings(path)
	} else {
		state, _, err = readUIStateFile(path)
	}
	if err != nil {
		xerrors.LogWarningInner(context.Background(), err, "failed to read ui state for override restore")
		return
	}
	updated := ensureUIStateSelection(state)
	overrides := extractUIStateOverrides(state)
	if len(overrides) == 0 {
		if updated {
			if err := persistUIStatePayload(path, state); err != nil {
				xerrors.LogWarningInner(context.Background(), err, "failed to persist ui state migration")
			}
		}
		return
	}
	for tag, target := range overrides {
		if err := overrider.SetOverrideTarget(tag, target); err != nil {
			xerrors.LogWarningInner(context.Background(), err, "failed to restore balancer override: "+tag)
		}
	}
	if updated {
		if err := persistUIStatePayload(path, state); err != nil {
			xerrors.LogWarningInner(context.Background(), err, "failed to persist ui state migration")
		}
	}
}

func extractUIStateOverrides(state map[string]interface{}) map[string]string {
	if state == nil {
		return nil
	}
	nodes, ok := state["nodes"].(map[string]interface{})
	if !ok {
		return nil
	}
	out := map[string]string{}
	applySelectionOverrides(nodes, out)
	applyLegacyOverrides(nodes, out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func applySelectionOverrides(nodes map[string]interface{}, out map[string]string) {
	selection, ok := nodes["selection"].(map[string]interface{})
	if !ok {
		return
	}
	for key, value := range selection {
		tag := strings.TrimSpace(key)
		if tag == "" {
			continue
		}
		entry, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(toString(entry["mode"])))
		target := strings.TrimSpace(toString(entry["target"]))
		last := strings.TrimSpace(toString(entry["last"]))
		if mode != "" && mode != "manual" {
			continue
		}
		if mode == "" && target == "" {
			continue
		}
		if target == "" {
			target = last
		}
		if target == "" {
			continue
		}
		if _, exists := out[tag]; !exists {
			out[tag] = target
		}
	}
}

func applyLegacyOverrides(nodes map[string]interface{}, out map[string]string) {
	for _, key := range []string{"locked", "locks", "selected"} {
		raw, ok := nodes[key].(map[string]interface{})
		if !ok {
			continue
		}
		for tag, value := range raw {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			target := strings.TrimSpace(toString(value))
			if target == "" {
				continue
			}
			if _, exists := out[tag]; exists {
				continue
			}
			out[tag] = target
		}
	}
}

func ensureUIStateSelection(state map[string]interface{}) bool {
	if state == nil {
		return false
	}
	nodes, ok := state["nodes"].(map[string]interface{})
	if !ok {
		return false
	}
	selection, _ := nodes["selection"].(map[string]interface{})
	if selection == nil {
		selection = map[string]interface{}{}
	}
	legacy := collectLegacySelection(nodes)
	changed := false
	for tag, target := range legacy {
		if tag == "" || target == "" {
			continue
		}
		if _, exists := selection[tag]; exists {
			continue
		}
		selection[tag] = map[string]interface{}{
			"mode":   "manual",
			"target": target,
			"last":   target,
		}
		changed = true
	}
	if !changed {
		return false
	}
	nodes["selection"] = selection
	state["nodes"] = nodes
	state["updatedAt"] = time.Now().UTC().Format(time.RFC3339)
	if _, ok := state["version"]; !ok {
		state["version"] = uiStateVersion
	}
	return true
}

func collectLegacySelection(nodes map[string]interface{}) map[string]string {
	out := map[string]string{}
	if nodes == nil {
		return out
	}
	for _, key := range []string{"locked", "locks", "selected"} {
		raw, ok := nodes[key].(map[string]interface{})
		if !ok {
			continue
		}
		for tag, value := range raw {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			target := strings.TrimSpace(toString(value))
			if target == "" {
				continue
			}
			if _, exists := out[tag]; exists {
				continue
			}
			out[tag] = target
		}
	}
	return out
}

func persistUIStatePayload(path string, state map[string]interface{}) error {
	if useEmbeddedUIState() {
		_, err := updateSettingsRaw(func(payload map[string]interface{}) error {
			controller := map[string]interface{}{}
			if existing, ok := payload[uiStateContainerKey].(map[string]interface{}); ok {
				controller = cloneJSONMap(existing)
			}
			controller[uiStateStateKey] = state
			payload[uiStateContainerKey] = controller
			delete(payload, uiStateStateKey)
			return nil
		})
		return err
	}
	return persistUIStateFile(path, state)
}

func ensureLegacySelectionMap(nodes map[string]interface{}, key string) map[string]interface{} {
	raw, ok := nodes[key].(map[string]interface{})
	if ok && raw != nil {
		return raw
	}
	return map[string]interface{}{}
}

func assignLegacySelectionMap(nodes map[string]interface{}, key string, values map[string]interface{}) {
	if values == nil || len(values) == 0 {
		delete(nodes, key)
		return
	}
	nodes[key] = values
}

func equalJSONMap(a interface{}, b map[string]interface{}) bool {
	amap, ok := a.(map[string]interface{})
	if !ok {
		return false
	}
	if len(amap) != len(b) {
		return false
	}
	for key, value := range b {
		if amap[key] != value {
			return false
		}
	}
	return true
}
