package metrics

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var routingConfigOnce sync.Once

type routingConfigResponse struct {
	Path         string                 `json:"path,omitempty"`
	Format       string                 `json:"format,omitempty"`
	Routing      map[string]interface{} `json:"routing"`
	FoundRouting bool                   `json:"foundRouting"`
}

type firewallConfigResponse struct {
	Path          string                 `json:"path,omitempty"`
	Format        string                 `json:"format,omitempty"`
	Firewall      map[string]interface{} `json:"firewall"`
	FoundFirewall bool                   `json:"foundFirewall"`
}

type outboundsConfigResponse struct {
	Path           string        `json:"path,omitempty"`
	Format         string        `json:"format,omitempty"`
	Outbounds      []interface{} `json:"outbounds"`
	FoundOutbounds bool          `json:"foundOutbounds"`
}

type inboundsConfigResponse struct {
	Path          string        `json:"path,omitempty"`
	Format        string        `json:"format,omitempty"`
	Inbounds      []interface{} `json:"inbounds"`
	FoundInbounds bool          `json:"foundInbounds"`
}

type mainConfigResponse struct {
	Path      string                 `json:"path,omitempty"`
	Format    string                 `json:"format,omitempty"`
	Main      map[string]interface{} `json:"main"`
	FoundMain bool                   `json:"foundMain"`
}

type observatoryConfigResponse struct {
	Path             string                 `json:"path,omitempty"`
	Format           string                 `json:"format,omitempty"`
	Observatory      map[string]interface{} `json:"observatory"`
	FoundObservatory bool                   `json:"foundObservatory"`
}

type configFile struct {
	Path   string
	Format string
	Data   map[string]interface{}
}

func registerRoutingConfigRoutes() {
	routingConfigOnce.Do(func() {
		http.HandleFunc("/config/routing", routingConfigHandler)
		http.HandleFunc("/config/firewall", firewallConfigHandler)
		http.HandleFunc("/config/outbounds", outboundsConfigHandler)
		http.HandleFunc("/config/inbounds", inboundsConfigHandler)
		http.HandleFunc("/config/main", mainConfigHandler)
		http.HandleFunc("/config/observatory", observatoryConfigHandler)
	})
}

func serveConfigEndpoint(
	w http.ResponseWriter,
	r *http.Request,
	onGet func(http.ResponseWriter, *http.Request),
	onPost func(http.ResponseWriter, *http.Request),
) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", metricsCORSAllowHeaders)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if onGet == nil {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		onGet(w, r)
	case http.MethodPost:
		if onPost == nil {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		onPost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func routingConfigHandler(w http.ResponseWriter, r *http.Request) {
	serveConfigEndpoint(w, r, handleRoutingConfigRead, handleRoutingConfigWrite)
}

func firewallConfigHandler(w http.ResponseWriter, r *http.Request) {
	serveConfigEndpoint(w, r, handleFirewallConfigRead, handleFirewallConfigWrite)
}

func outboundsConfigHandler(w http.ResponseWriter, r *http.Request) {
	serveConfigEndpoint(w, r, handleOutboundsConfigRead, handleOutboundsConfigWrite)
}

func observatoryConfigHandler(w http.ResponseWriter, r *http.Request) {
	serveConfigEndpoint(w, r, handleObservatoryConfigRead, handleObservatoryConfigWrite)
}

func inboundsConfigHandler(w http.ResponseWriter, r *http.Request) {
	serveConfigEndpoint(w, r, handleInboundsConfigRead, handleInboundsConfigWrite)
}

func mainConfigHandler(w http.ResponseWriter, r *http.Request) {
	serveConfigEndpoint(w, r, handleMainConfigRead, handleMainConfigWrite)
}

func extractPreferredPath(raw map[string]interface{}) (string, error) {
	if raw == nil {
		return "", nil
	}
	value, ok := raw["path"]
	if !ok || value == nil {
		return "", nil
	}
	path, ok := value.(string)
	if !ok {
		return "", errors.New("path must be a string")
	}
	return strings.TrimSpace(path), nil
}

func handleRoutingConfigRead(w http.ResponseWriter, r *http.Request) {
	preferred := strings.TrimSpace(r.URL.Query().Get("path"))
	config, foundRouting, err := findRoutingConfig(preferred)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	routing := map[string]interface{}{}
	if config != nil && config.Data != nil {
		if raw, ok := config.Data["routing"].(map[string]interface{}); ok {
			routing = raw
		}
	}
	resp := routingConfigResponse{
		Path:         config.Path,
		Format:       config.Format,
		Routing:      routing,
		FoundRouting: foundRouting,
	}
	writeJSON(w, resp)
}

func handleRoutingConfigWrite(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	patch, err := extractRoutingPatch(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	preferredPath, err := extractPreferredPath(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	config, _, err := findRoutingConfig(preferredPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	if config == nil || config.Data == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid config", "config root is empty")
		return
	}

	root := config.Data
	if root == nil {
		root = map[string]interface{}{}
	}
	currentRouting := map[string]interface{}{}
	if rawRouting, ok := root["routing"].(map[string]interface{}); ok {
		for key, value := range rawRouting {
			currentRouting[key] = value
		}
	}
	for key, value := range patch {
		currentRouting[key] = value
	}
	root["routing"] = currentRouting

	if err := writeObjectFile(config.Path, root); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to write config", err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"path": config.Path,
	})
}

func handleFirewallConfigRead(w http.ResponseWriter, r *http.Request) {
	preferred := strings.TrimSpace(r.URL.Query().Get("path"))
	config, foundFirewall, err := findFirewallConfig(preferred)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	firewall := map[string]interface{}{}
	if config != nil && config.Data != nil {
		if raw, ok := config.Data["firewall"].(map[string]interface{}); ok {
			firewall = raw
		}
	}
	resp := firewallConfigResponse{
		Path:          config.Path,
		Format:        config.Format,
		Firewall:      firewall,
		FoundFirewall: foundFirewall,
	}
	writeJSON(w, resp)
}

func handleFirewallConfigWrite(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	firewallPatch, err := extractFirewallPatch(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	preferredPath, err := extractPreferredPath(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	config, _, err := findFirewallConfig(preferredPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	if config == nil || config.Data == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid config", "config root is empty")
		return
	}

	root := config.Data
	root["firewall"] = firewallPatch
	if err := writeObjectFile(config.Path, root); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to write config", err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"path": config.Path,
	})
}

func handleOutboundsConfigRead(w http.ResponseWriter, r *http.Request) {
	handleArrayConfigRead(
		w,
		r,
		"outbounds",
		findOutboundsConfig,
		func(config *configFile, values []interface{}, found bool) interface{} {
			return outboundsConfigResponse{
				Path:           config.Path,
				Format:         config.Format,
				Outbounds:      values,
				FoundOutbounds: found,
			}
		},
	)
}

func handleOutboundsConfigWrite(w http.ResponseWriter, r *http.Request) {
	handleArrayConfigWrite(w, r, "outbounds", findOutboundsConfig, extractOutbounds)
}

func handleInboundsConfigRead(w http.ResponseWriter, r *http.Request) {
	handleArrayConfigRead(
		w,
		r,
		"inbounds",
		findInboundsConfig,
		func(config *configFile, values []interface{}, found bool) interface{} {
			return inboundsConfigResponse{
				Path:          config.Path,
				Format:        config.Format,
				Inbounds:      values,
				FoundInbounds: found,
			}
		},
	)
}

func handleInboundsConfigWrite(w http.ResponseWriter, r *http.Request) {
	handleArrayConfigWrite(w, r, "inbounds", findInboundsConfig, extractInbounds)
}

func readArraySection(data map[string]interface{}, key string) []interface{} {
	values := []interface{}{}
	if data == nil {
		return values
	}
	raw, ok := data[key].([]interface{})
	if !ok {
		return values
	}
	return raw
}

func handleArrayConfigRead(
	w http.ResponseWriter,
	r *http.Request,
	key string,
	findConfig func(string) (*configFile, bool, error),
	buildResponse func(*configFile, []interface{}, bool) interface{},
) {
	preferred := strings.TrimSpace(r.URL.Query().Get("path"))
	config, found, err := findConfig(preferred)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	if config == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid config", "config file not found")
		return
	}
	values := readArraySection(config.Data, key)
	writeJSON(w, buildResponse(config, values, found))
}

func handleArrayConfigWrite(
	w http.ResponseWriter,
	r *http.Request,
	key string,
	findConfig func(string) (*configFile, bool, error),
	extractValues func(map[string]interface{}) ([]interface{}, error),
) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	values, err := extractValues(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	preferredPath, err := extractPreferredPath(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	config, _, err := findConfig(preferredPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	if config == nil || config.Data == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid config", "config root is empty")
		return
	}

	root := config.Data
	root[key] = values
	if err := writeObjectFile(config.Path, root); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to write config", err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"path": config.Path,
	})
}

func handleMainConfigRead(w http.ResponseWriter, r *http.Request) {
	preferred := strings.TrimSpace(r.URL.Query().Get("path"))
	configs, primary, err := loadConfigCandidates(preferred)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	mainData := mergeMainConfigData(configs, primary)
	resp := mainConfigResponse{
		Main:      mainData,
		FoundMain: hasPrimaryConfigSections(mainData),
	}
	if primary != nil {
		resp.Path = primary.Path
		resp.Format = primary.Format
	}
	writeJSON(w, resp)
}

func handleMainConfigWrite(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	preferredPath, err := extractPreferredPath(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mainRaw, ok := raw["main"]
	if !ok {
		http.Error(w, "main must be provided", http.StatusBadRequest)
		return
	}
	mainPatch, ok := mainRaw.(map[string]interface{})
	if !ok {
		http.Error(w, "main must be an object", http.StatusBadRequest)
		return
	}

	configs, primary, err := loadConfigCandidates(preferredPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	if primary == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid config", "config file not found")
		return
	}

	dirty := map[string]*configFile{}
	observatoryPatch, observatoryProvided, observatoryDefaultKey, err := extractObservatoryMainPatch(mainPatch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if observatoryProvided {
		target, targetKey := pickMainSectionTargetConfig(configs, primary, []string{"observatory", "Observatory"}, observatoryDefaultKey)
		if target == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid config", "config file not found")
			return
		}
		if target.Data == nil {
			target.Data = map[string]interface{}{}
		}
		target.Data[targetKey] = cloneJSONValue(observatoryPatch)
		if targetKey == "observatory" {
			delete(target.Data, "Observatory")
		} else if targetKey == "Observatory" {
			delete(target.Data, "observatory")
		}
		dirty[target.Path] = target
	}

	logPatch, logProvided, err := extractMainObjectPatch(mainPatch, "log")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if logProvided {
		target, targetKey := pickMainSectionTargetConfig(configs, primary, []string{"log"}, "log")
		if target == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid config", "config file not found")
			return
		}
		if target.Data == nil {
			target.Data = map[string]interface{}{}
		}
		target.Data[targetKey] = cloneJSONValue(logPatch)
		dirty[target.Path] = target
	}

	metricsPatch, metricsProvided, err := extractMainObjectPatch(mainPatch, "metrics")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if metricsProvided {
		target, targetKey := pickMainSectionTargetConfig(configs, primary, []string{"metrics"}, "metrics")
		if target == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid config", "config file not found")
			return
		}
		if target.Data == nil {
			target.Data = map[string]interface{}{}
		}
		target.Data[targetKey] = cloneJSONValue(metricsPatch)
		dirty[target.Path] = target
	}

	statsPatch, statsProvided, err := extractMainObjectPatch(mainPatch, "stats")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if statsProvided {
		target, targetKey := pickMainSectionTargetConfig(configs, primary, []string{"stats"}, "stats")
		if target == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid config", "config file not found")
			return
		}
		if target.Data == nil {
			target.Data = map[string]interface{}{}
		}
		target.Data[targetKey] = cloneJSONValue(statsPatch)
		dirty[target.Path] = target
	}

	if len(dirty) == 0 {
		http.Error(w, "main patch has no editable sections", http.StatusBadRequest)
		return
	}

	for _, cfg := range configs {
		if cfg == nil || cfg.Path == "" {
			continue
		}
		if _, ok := dirty[cfg.Path]; !ok {
			continue
		}
		if err := writeObjectFile(cfg.Path, cfg.Data); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to write config", err.Error())
			return
		}
	}

	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"path": primary.Path,
	})
}

func handleObservatoryConfigRead(w http.ResponseWriter, r *http.Request) {
	preferred := strings.TrimSpace(r.URL.Query().Get("path"))
	config, _, err := findObservatoryConfig(preferred)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	observatory, hasObservatory := getConfigSection(config.Data, "observatory")
	resp := observatoryConfigResponse{
		Path:             config.Path,
		Format:           config.Format,
		Observatory:      observatory,
		FoundObservatory: hasObservatory,
	}
	writeJSON(w, resp)
}

func handleObservatoryConfigWrite(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	preferredPath, err := extractPreferredPath(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var observatoryPatch map[string]interface{}
	if value, ok := raw["observatory"]; ok {
		typed, ok := value.(map[string]interface{})
		if !ok {
			http.Error(w, "observatory must be an object", http.StatusBadRequest)
			return
		}
		observatoryPatch = typed
	}

	if observatoryPatch == nil {
		http.Error(w, "observatory patch is empty", http.StatusBadRequest)
		return
	}

	config, _, err := findObservatoryConfig(preferredPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	if config == nil || config.Data == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid config", "config root is empty")
		return
	}

	root := config.Data
	if observatoryPatch != nil {
		root["observatory"] = observatoryPatch
	}
	if err := writeObjectFile(config.Path, root); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to write config", err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"path": config.Path,
	})
}

func extractRoutingPatch(raw map[string]interface{}) (map[string]interface{}, error) {
	if raw == nil {
		return nil, errors.New("routing patch is empty")
	}
	var patch map[string]interface{}
	if value, ok := raw["routing"]; ok {
		typed, ok := value.(map[string]interface{})
		if !ok {
			return nil, errors.New("routing must be an object")
		}
		patch = typed
	} else {
		patch = map[string]interface{}{}
		for key, value := range raw {
			if key == "path" {
				continue
			}
			patch[key] = value
		}
	}
	if len(patch) == 0 {
		return nil, errors.New("routing patch is empty")
	}
	if rules, ok := patch["rules"]; ok {
		if _, ok := rules.([]interface{}); !ok {
			return nil, errors.New("routing.rules must be an array")
		}
	}
	if balancers, ok := patch["balancers"]; ok {
		if _, ok := balancers.([]interface{}); !ok {
			return nil, errors.New("routing.balancers must be an array")
		}
	}
	return patch, nil
}

func extractFirewallPatch(raw map[string]interface{}) (map[string]interface{}, error) {
	if raw == nil {
		return nil, errors.New("firewall patch is empty")
	}
	var patch map[string]interface{}
	if value, ok := raw["firewall"]; ok {
		typed, ok := value.(map[string]interface{})
		if !ok {
			return nil, errors.New("firewall must be an object")
		}
		patch = typed
	} else {
		patch = map[string]interface{}{}
		for key, value := range raw {
			if key == "path" {
				continue
			}
			patch[key] = value
		}
	}
	if len(patch) == 0 {
		return nil, errors.New("firewall patch is empty")
	}
	if rules, ok := patch["rule"]; ok {
		if _, ok := rules.([]interface{}); !ok {
			return nil, errors.New("firewall.rule must be an array")
		}
	}
	return patch, nil
}

func findRoutingConfig(preferredPath string) (*configFile, bool, error) {
	return findConfigWithSection(preferredPath, hasRouting)
}

func findFirewallConfig(preferredPath string) (*configFile, bool, error) {
	return findConfigWithSection(preferredPath, hasFirewall)
}

func findOutboundsConfig(preferredPath string) (*configFile, bool, error) {
	return findConfigWithSection(preferredPath, hasOutbounds)
}

func findInboundsConfig(preferredPath string) (*configFile, bool, error) {
	return findConfigWithSection(preferredPath, hasInbounds)
}

func loadConfigCandidates(preferredPath string) ([]*configFile, *configFile, error) {
	candidates, err := findConfigCandidates()
	if err != nil {
		return nil, nil, err
	}
	candidates = filterExistingFiles(candidates)
	if len(candidates) == 0 {
		return nil, nil, errors.New("config file not found")
	}

	preferredResolved, err := resolvePreferredConfigPathFromCandidates(preferredPath, candidates)
	if err != nil {
		return nil, nil, err
	}

	loaded := make([]*configFile, 0, len(candidates))
	for _, path := range candidates {
		cfg, err := readConfigFile(path)
		if err != nil {
			continue
		}
		loaded = append(loaded, cfg)
	}
	if len(loaded) == 0 {
		return nil, nil, errors.New("config file could not be read")
	}

	if preferredResolved != "" {
		for _, cfg := range loaded {
			if cfg != nil && sameFilePath(cfg.Path, preferredResolved) {
				return loaded, cfg, nil
			}
		}
	}

	return loaded, pickPrimaryConfigFromLoaded(loaded), nil
}

func findPrimaryConfig(preferredPath string) (*configFile, bool, error) {
	_, primary, err := loadConfigCandidates(preferredPath)
	if err != nil {
		return nil, false, err
	}
	if primary == nil {
		return nil, false, errors.New("config file could not be read")
	}
	return primary, hasPrimaryConfigSections(primary.Data), nil
}

func mergeMainConfigData(configs []*configFile, primary *configFile) map[string]interface{} {
	merged := map[string]interface{}{}
	primaryPath := ""
	if primary != nil {
		primaryPath = primary.Path
	}
	for _, cfg := range configs {
		if cfg == nil || cfg.Data == nil || cfg.Path == primaryPath {
			continue
		}
		merged = mergeJSONMaps(merged, cfg.Data)
	}
	if primary != nil && primary.Data != nil {
		merged = mergeJSONMaps(merged, primary.Data)
	}
	return merged
}

func mergeJSONMaps(base map[string]interface{}, overlay map[string]interface{}) map[string]interface{} {
	if base == nil {
		base = map[string]interface{}{}
	}
	if overlay == nil {
		return base
	}
	for key, value := range overlay {
		existingMap, hasExistingMap := base[key].(map[string]interface{})
		nextMap, hasNextMap := value.(map[string]interface{})
		if hasExistingMap && hasNextMap {
			base[key] = mergeJSONMaps(cloneJSONMap(existingMap), nextMap)
			continue
		}
		base[key] = cloneJSONValue(value)
	}
	return base
}

func resolvePreferredConfigPathFromCandidates(preferredPath string, candidates []string) (string, error) {
	if strings.TrimSpace(preferredPath) == "" {
		return "", nil
	}

	resolved := resolvePathFromCwd(preferredPath, resolveStartupCwd())
	if resolved == "" {
		return "", errors.New("preferred path is empty")
	}
	if !isRegularFile(resolved) {
		return "", errors.New("preferred path is not a regular file")
	}

	for _, current := range candidates {
		if sameFilePath(current, resolved) {
			return resolved, nil
		}
	}
	return "", errors.New("preferred path is outside active config files")
}

func sameFilePath(a string, b string) bool {
	cleanA := filepath.Clean(a)
	cleanB := filepath.Clean(b)
	return cleanA == cleanB || strings.EqualFold(cleanA, cleanB)
}

func pickPrimaryConfigFromLoaded(loaded []*configFile) *configFile {
	if len(loaded) == 0 {
		return nil
	}
	fallback := loaded[0]

	// Prefer files that are likely the primary/root config and contain main editor sections.
	for _, cfg := range loaded {
		if cfg != nil && isLikelyPrimaryConfigFilename(cfg.Path) && hasMainEditorSections(cfg.Data) {
			return cfg
		}
	}

	// Next, accept any config containing main editor sections.
	for _, cfg := range loaded {
		if cfg != nil && hasMainEditorSections(cfg.Data) {
			return cfg
		}
	}

	// Then prefer likely primary filenames that still look like valid Acore config roots.
	for _, cfg := range loaded {
		if cfg != nil && isLikelyPrimaryConfigFilename(cfg.Path) && hasPrimaryConfigSections(cfg.Data) {
			return cfg
		}
	}

	// If a likely primary filename exists but has not yet defined sections, still prefer it.
	for _, cfg := range loaded {
		if cfg != nil && isLikelyPrimaryConfigFilename(cfg.Path) {
			return cfg
		}
	}

	// Fallback to any file that has top-level Acore sections.
	for _, cfg := range loaded {
		if cfg != nil && hasPrimaryConfigSections(cfg.Data) {
			return cfg
		}
	}

	return fallback
}

func pickMainSectionTargetConfig(configs []*configFile, primary *configFile, keys []string, defaultKey string) (*configFile, string) {
	for _, cfg := range configs {
		if cfg == nil || cfg.Data == nil {
			continue
		}
		for _, key := range keys {
			if _, ok := cfg.Data[key]; ok {
				return cfg, key
			}
		}
	}
	if primary != nil {
		for _, key := range keys {
			if _, ok := primary.Data[key]; ok {
				return primary, key
			}
		}
		return primary, defaultKey
	}
	if len(configs) > 0 {
		return configs[0], defaultKey
	}
	return nil, defaultKey
}

func extractMainObjectPatch(mainPatch map[string]interface{}, key string) (map[string]interface{}, bool, error) {
	value, ok := mainPatch[key]
	if !ok {
		return nil, false, nil
	}
	typed, ok := value.(map[string]interface{})
	if !ok {
		return nil, false, errors.New(key + " must be an object")
	}
	return typed, true, nil
}

func extractObservatoryMainPatch(mainPatch map[string]interface{}) (map[string]interface{}, bool, string, error) {
	lower, lowerFound, err := extractMainObjectPatch(mainPatch, "observatory")
	if err != nil {
		return nil, false, "", err
	}
	upper, upperFound, err := extractMainObjectPatch(mainPatch, "Observatory")
	if err != nil {
		return nil, false, "", err
	}
	if lowerFound && upperFound {
		merged := mergeJSONMaps(cloneJSONMap(upper), lower)
		return merged, true, "observatory", nil
	}
	if lowerFound {
		return lower, true, "observatory", nil
	}
	if upperFound {
		return upper, true, "Observatory", nil
	}
	return nil, false, "observatory", nil
}

func findObservatoryConfig(preferredPath string) (*configFile, bool, error) {
	return findConfigWithSection(preferredPath, hasObservatory)
}

func findConfigWithSection(preferredPath string, hasSection func(map[string]interface{}) bool) (*configFile, bool, error) {
	candidates, err := findConfigCandidates()
	if err != nil {
		return nil, false, err
	}
	candidates = filterExistingFiles(candidates)
	if len(candidates) == 0 {
		return nil, false, errors.New("config file not found")
	}
	if preferredPath != "" {
		resolved, err := resolvePreferredConfigPathFromCandidates(preferredPath, candidates)
		if err != nil {
			return nil, false, err
		}
		cfg, err := readConfigFile(resolved)
		if err != nil {
			return nil, false, err
		}
		return cfg, hasSection(cfg.Data), nil
	}

	var fallback *configFile
	for _, path := range candidates {
		cfg, err := readConfigFile(path)
		if err != nil {
			continue
		}
		if fallback == nil {
			fallback = cfg
		}
		if hasSection(cfg.Data) {
			return cfg, true, nil
		}
	}

	if fallback != nil {
		return fallback, false, nil
	}
	return nil, false, errors.New("config file could not be read")
}

func findConfigCandidates() ([]string, error) {
	files, _, err := inferRestartFiles()
	if err == nil && len(files) > 0 {
		return files, nil
	}
	if defaults := pickDefaultConfigFromCwd(resolveStartupCwd()); len(defaults) > 0 {
		return defaults, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("config file not found")
}

func hasRouting(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	_, ok := data["routing"].(map[string]interface{})
	return ok
}

func hasFirewall(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	_, ok := data["firewall"].(map[string]interface{})
	return ok
}

func hasOutbounds(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	_, ok := data["outbounds"].([]interface{})
	return ok
}

func hasInbounds(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	_, ok := data["inbounds"].([]interface{})
	return ok
}

func hasObservatory(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	if _, ok := data["observatory"].(map[string]interface{}); ok {
		return true
	}
	return false
}

func hasPrimaryConfigSections(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	// Prefer files that look like real Acore config roots instead of sidecar files.
	keys := []string{
		"inbounds",
		"outbounds",
		"routing",
		"dns",
		"DNS",
		"log",
		"metrics",
		"stats",
		"observatory",
		"Observatory",
	}
	for _, key := range keys {
		if _, ok := data[key]; ok {
			return true
		}
	}
	return false
}

func hasMainEditorSections(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	keys := []string{
		"log",
		"metrics",
		"stats",
		"observatory",
		"Observatory",
	}
	for _, key := range keys {
		if _, ok := data[key]; ok {
			return true
		}
	}
	return false
}

func isLikelyPrimaryConfigFilename(path string) bool {
	if path == "" {
		return false
	}
	name := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(name, "acore.ui.") || strings.HasPrefix(name, "acore-ui.") {
		return false
	}

	ext := strings.ToLower(filepath.Ext(name))
	base := strings.TrimSuffix(name, ext)
	switch base {
	case "config", "main", "acore":
		return true
	}

	if strings.HasPrefix(base, "main-") || strings.HasPrefix(base, "main_") {
		return true
	}
	if strings.HasSuffix(base, "-main") || strings.HasSuffix(base, "_main") {
		return true
	}
	if strings.Contains(base, ".main") {
		return true
	}
	if strings.HasPrefix(base, "config-") || strings.HasPrefix(base, "config_") {
		return true
	}
	if strings.HasSuffix(base, "-config") || strings.HasSuffix(base, "_config") {
		return true
	}
	if strings.Contains(base, ".config") {
		return true
	}
	return false
}

func getConfigSection(data map[string]interface{}, key string) (map[string]interface{}, bool) {
	if data == nil {
		return nil, false
	}
	raw, ok := data[key]
	if !ok {
		return nil, false
	}
	typed, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false
	}
	return typed, true
}

func extractOutbounds(raw map[string]interface{}) ([]interface{}, error) {
	value, ok := raw["outbounds"]
	if !ok {
		return nil, errors.New("outbounds must be provided")
	}
	list, ok := value.([]interface{})
	if !ok {
		return nil, errors.New("outbounds must be an array")
	}
	return list, nil
}

func extractInbounds(raw map[string]interface{}) ([]interface{}, error) {
	value, ok := raw["inbounds"]
	if !ok {
		return nil, errors.New("inbounds must be provided")
	}
	list, ok := value.([]interface{})
	if !ok {
		return nil, errors.New("inbounds must be an array")
	}
	return list, nil
}

func filterExistingFiles(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, raw := range paths {
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		if !isRegularFile(raw) {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func readConfigFile(path string) (*configFile, error) {
	format := detectConfigFormat(path)
	if format != "json" && format != "jsonc" && format != "yaml" {
		return nil, errors.New("unsupported config format: " + format)
	}
	data, _, _, err := readObjectFile(path)
	if err != nil {
		return nil, err
	}
	return &configFile{
		Path:   path,
		Format: format,
		Data:   data,
	}, nil
}

func detectConfigFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return "json"
	case ".jsonc":
		return "jsonc"
	case ".toml":
		return "toml"
	case ".yaml", ".yml":
		return "yaml"
	default:
		return "json"
	}
}

func stripJSONComments(input string) string {
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
