//go:build windows
// +build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
)

func LineSeparator() string {
	return "\r\n"
}

// GetAssetLocation searches for `file` in the env dir and the executable dir
func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)
	return filepath.Join(assetPath, file)
}

// GetCertLocation searches for `file` in the env dir and the executable dir
func GetCertLocation(file string) string {
	certPath := NewEnvFlag(CertLocation).GetValue(getExecutableDir)
	return filepath.Join(certPath, file)
}

// GetToolLocation searches for `file` in the env dir, executable dir, and PATH.
func GetToolLocation(file string) string {
	name := file
	if filepath.Ext(name) == "" {
		name += ".exe"
	}
	toolPath := NewEnvFlag(ToolLocation).GetValue(getExecutableDir)
	defPath := filepath.Join(toolPath, name)
	if _, err := os.Stat(defPath); err == nil {
		return defPath
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if name != file {
		if p, err := exec.LookPath(file); err == nil {
			return p
		}
	}
	return defPath
}
