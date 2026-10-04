package platform // import "github.com/ImAubrey/acore/common/platform"

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ConfigLocation  = "acore.location.config"
	ConfdirLocation = "acore.location.confdir"
	AssetLocation   = "acore.location.asset"
	CertLocation    = "acore.location.cert"
	ToolLocation    = "acore.location.tool"

	UseReadV         = "acore.buf.readv"
	UseFreedomSplice = "acore.buf.splice"
	UseVmessPadding  = "acore.vmess.padding"
	UseCone          = "acore.cone.disabled"

	BufferSize           = "acore.ray.buffer.size"
	BrowserDialerAddress = "acore.browser.dialer"
	XUDPLog              = "acore.xudp.show"
	XUDPBaseKey          = "acore.xudp.basekey"
	UDPGSOMaxSize        = "acore.udp.gso.max_size"

	// RealityDestDialMaxConcurrency limits concurrent outbound dials to REALITY "dest".
	// This is a safety knob to avoid accidentally overwhelming the target site when the
	// server is under high connection churn or attack. 0 disables.
	RealityDestDialMaxConcurrency = "acore.reality.dest_dial.max_concurrency"
	// RealityDestDialMaxQPS limits the rate (connections/second) of outbound dials to REALITY "dest".
	// 0 disables.
	RealityDestDialMaxQPS = "acore.reality.dest_dial.max_qps"
)

type EnvFlag struct {
	Name    string
	AltName string
}

func NewEnvFlag(name string) EnvFlag {
	return EnvFlag{
		Name:    name,
		AltName: NormalizeEnvName(name),
	}
}

func (f EnvFlag) GetValue(defaultValue func() string) string {
	if v, found := os.LookupEnv(f.Name); found {
		return v
	}
	if len(f.AltName) > 0 {
		if v, found := os.LookupEnv(f.AltName); found {
			return v
		}
	}

	return defaultValue()
}

func (f EnvFlag) GetValueAsInt(defaultValue int) int {
	useDefaultValue := false
	s := f.GetValue(func() string {
		useDefaultValue = true
		return ""
	})
	if useDefaultValue {
		return defaultValue
	}
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return defaultValue
	}
	return int(v)
}

func NormalizeEnvName(name string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(name)), ".", "_")
}

func getExecutableDir() string {
	exec, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exec)
}

func GetConfigurationPath() string {
	configPath := NewEnvFlag(ConfigLocation).GetValue(getExecutableDir)
	return filepath.Join(configPath, "config.json")
}

// GetConfDirPath reads "acore.location.confdir"
func GetConfDirPath() string {
	configPath := NewEnvFlag(ConfdirLocation).GetValue(func() string { return "" })
	return configPath
}
