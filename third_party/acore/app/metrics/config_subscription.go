package metrics

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

var subscriptionConfigOnce sync.Once

type subscriptionConfigResponse struct {
	Path              string                 `json:"path,omitempty"`
	Format            string                 `json:"format,omitempty"`
	Subscription      map[string]interface{} `json:"subscription"`
	FoundSubscription bool                   `json:"foundSubscription"`
}

func registerSubscriptionConfigRoutes() {
	subscriptionConfigOnce.Do(func() {
		http.HandleFunc("/config/subscription", subscriptionConfigHandler)
	})
}

func subscriptionConfigHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", metricsCORSAllowHeaders)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.Method {
	case http.MethodGet:
		handleSubscriptionConfigRead(w, r)
	case http.MethodPost:
		handleSubscriptionConfigWrite(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleSubscriptionConfigRead(w http.ResponseWriter, r *http.Request) {
	preferred := strings.TrimSpace(r.URL.Query().Get("path"))
	config, foundSubscription, err := findSubscriptionConfig(preferred)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	subscription := map[string]interface{}{}
	if config != nil && config.Data != nil {
		if raw, ok := config.Data["subscription"].(map[string]interface{}); ok {
			subscription = raw
		}
	}
	writeJSON(w, subscriptionConfigResponse{
		Path:              config.Path,
		Format:            config.Format,
		Subscription:      subscription,
		FoundSubscription: foundSubscription,
	})
}

func handleSubscriptionConfigWrite(w http.ResponseWriter, r *http.Request) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	preferredPath := ""
	if value, ok := raw["path"]; ok {
		if str, ok := value.(string); ok {
			preferredPath = strings.TrimSpace(str)
		} else if value != nil {
			http.Error(w, "path must be a string", http.StatusBadRequest)
			return
		}
	}

	var subscriptionPatch map[string]interface{}
	subscriptionValue, hasSubscription := raw["subscription"]
	if hasSubscription {
		if subscriptionValue == nil {
			subscriptionPatch = nil
		} else if obj, ok := subscriptionValue.(map[string]interface{}); ok {
			subscriptionPatch = obj
		} else {
			http.Error(w, "subscription must be an object or null", http.StatusBadRequest)
			return
		}
	}

	config, _, err := findSubscriptionConfig(preferredPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read config", err.Error())
		return
	}
	if config == nil || config.Data == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid config", "config root is empty")
		return
	}

	root := config.Data
	if !hasSubscription {
		writeJSON(w, map[string]interface{}{"ok": true, "path": config.Path})
		return
	}

	if subscriptionPatch == nil {
		delete(root, "subscription")
	} else {
		root["subscription"] = subscriptionPatch
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

func findSubscriptionConfig(preferredPath string) (*configFile, bool, error) {
	return findConfigWithSection(preferredPath, hasSubscription)
}

func hasSubscription(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	_, ok := data["subscription"].(map[string]interface{})
	return ok
}
