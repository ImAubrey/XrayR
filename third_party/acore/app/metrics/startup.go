package metrics

import (
	"net/http"
	"sync"

	"github.com/ImAubrey/acore/core"
)

var startupOnce sync.Once

func registerStartupRoutes() {
	startupOnce.Do(func() {
		http.HandleFunc("/startup", startupHandler)
	})
}

type startupInfoResponse struct {
	Argv         []string `json:"argv,omitempty"`
	ConfigFiles  []string `json:"configFiles,omitempty"`
	ConfDir      string   `json:"confDir,omitempty"`
	ConfigFormat string   `json:"configFormat,omitempty"`
	Cwd          string   `json:"cwd,omitempty"`
}

func startupHandler(w http.ResponseWriter, r *http.Request) {
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
	info, ok := core.GetStartupInfo()
	if !ok {
		http.Error(w, "startup info unavailable", http.StatusNotFound)
		return
	}
	writeJSON(w, startupInfoResponse{
		Argv:         info.Argv,
		ConfigFiles:  info.ConfigFiles,
		ConfDir:      info.ConfDir,
		ConfigFormat: info.ConfigFormat,
		Cwd:          info.Cwd,
	})
}
