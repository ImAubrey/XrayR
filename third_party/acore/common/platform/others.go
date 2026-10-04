//go:build !windows
// +build !windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
)

func LineSeparator() string {
	return "\n"
}

// GetAssetLocation searches for `file` in the env dir, the executable dir, and certain locations
func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)
	defPath := filepath.Join(assetPath, file)
	for _, p := range []string{
		defPath,
		filepath.Join("/usr/local/share/acore/", file),
		filepath.Join("/usr/share/acore/", file),
		filepath.Join("/opt/share/acore/", file),
	} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}

		// asset found
		return p
	}

	// asset not found, let the caller throw out the error
	return defPath
}

// GetCertLocation searches for `file` in the env dir and the executable dir
func GetCertLocation(file string) string {
	certPath := NewEnvFlag(CertLocation).GetValue(getExecutableDir)
	return filepath.Join(certPath, file)
}

// GetToolLocation searches for `file` in the env dir, executable dir, and PATH.
func GetToolLocation(file string) string {
	toolPath := NewEnvFlag(ToolLocation).GetValue(getExecutableDir)
	defPath := filepath.Join(toolPath, file)
	if _, err := os.Stat(defPath); err == nil {
		return defPath
	}
	if p, err := exec.LookPath(file); err == nil {
		return p
	}
	return defPath
}
