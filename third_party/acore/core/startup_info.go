package core

import "sync/atomic"

// StartupInfo records runtime startup parameters for external consumers.
type StartupInfo struct {
	Argv         []string
	ConfigFiles  []string
	ConfDir      string
	ConfigFormat string
	Cwd          string
}

var startupInfo atomic.Value

// SetStartupInfo stores startup info for later retrieval.
func SetStartupInfo(info StartupInfo) {
	info.Argv = append([]string{}, info.Argv...)
	info.ConfigFiles = append([]string{}, info.ConfigFiles...)
	startupInfo.Store(info)
}

// GetStartupInfo returns the stored startup info, if any.
func GetStartupInfo() (StartupInfo, bool) {
	if v := startupInfo.Load(); v != nil {
		return v.(StartupInfo), true
	}
	return StartupInfo{}, false
}
